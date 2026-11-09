"""Deploy the agent to AgentCore Runtime as `acgw_agent` (HTTP protocol, PingOne JWT authorizer). Idempotent.

    python agent/deploy.py             # everything below
    python agent/deploy.py --prepare   # only the secret, workload identity and login hints (enough to run locally)

1. Secret `acgw/approvals-client` (approvals app credentials, from spike/.state.json; never printed).
2. Workload identity `acgw-agent` (the step-up exchange binds the approved CIBA token to it).
3. Login hints: PingOne user id -> username for the demo users (CIBA needs a username; the token has only `sub`).
4. arm64 zip per docs/contracts.md "Packaging", uploaded to s3://acgw-agent-<account>-<region>.
5. Execution role `acgw-agent-runtime`: Bedrock invoke, workload-token and token-vault APIs, the secret, logs.
6. Runtime `acgw_agent`, its JWT authorizer audience = its own invocation URL, `Authorization` allowlisted.
7. PingOne resource `acgw-spike agent-runtime`: audience -> the runtime URL (sign-in tokens are minted for it).

IDs are saved in agent/.state.json. Reads .env and spike/.state.json; writes neither.
"""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.parse
import zipfile

import boto3
import httpx
from dotenv import load_dotenv

AGENT = pathlib.Path(__file__).resolve().parent
ROOT = AGENT.parent
BUILD = AGENT / "build"
STATE_FILE = AGENT / ".state.json"
SPIKE_STATE = ROOT / "spike" / ".state.json"
load_dotenv(ROOT / ".env")

RUNTIME_NAME = "acgw_agent"
ROLE_NAME = "acgw-agent-runtime"
WORKLOAD_NAME = "acgw-agent"
SECRET_NAME = "acgw/approvals-client"
AGENT_OBO_PROVIDER = "acgw-spike-agent-obo"
MODEL_ID = "us.anthropic.claude-sonnet-5-5"
AGENT_RESOURCE = "acgw-spike agent-runtime"
DEMO_USERS = ("alice", "bob", "curtis")
SOURCES = ("main.py", "acgw")


def env(name, default=None):
    value = os.environ.get(name) or default
    if value is None:
        raise SystemExit(f"Missing {name} in .env")
    return value


def load_json(path):
    return json.loads(path.read_text()) if path.exists() else {}


def save_state(update):
    state = load_json(STATE_FILE)
    state.update(update)
    STATE_FILE.write_text(json.dumps(state, indent=2))
    return state


def pingone_urls():
    tld, env_id = env("PINGONE_REGION", "com"), env("PINGONE_ENV_ID")
    issuer = f"https://auth.pingone.{tld}/{env_id}/as"
    return {"issuer": issuer, "discovery": f"{issuer}/.well-known/openid-configuration",
            "token": f"{issuer}/token", "api": f"https://api.pingone.{tld}/v1/environments/{env_id}"}


def gateway_url():
    """GATEWAY_URL from the environment, else the spike's Gateway (switch to Gateway v2 by setting GATEWAY_URL)."""
    return os.environ.get("GATEWAY_URL") or load_json(SPIKE_STATE)["gateway_url"]


def aws_session():
    return boto3.Session(profile_name=env("AWS_PROFILE", "gte"), region_name=env("AWS_REGION", "us-east-2"))


class PingOne:
    """PingOne Management API with the worker app from .env."""

    def __init__(self):
        urls = pingone_urls()
        self.api = urls["api"]
        r = httpx.post(urls["token"], data={"grant_type": "client_credentials"}, timeout=30,
                       auth=(env("PINGONE_WORKER_CLIENT_ID"), env("PINGONE_WORKER_CLIENT_SECRET")))
        r.raise_for_status()
        self.headers = {"Authorization": f"Bearer {r.json()['access_token']}"}

    def req(self, method, path, **kw):
        r = httpx.request(method, self.api + path, headers=self.headers, timeout=30, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:500]}")
        return r.json() if r.content else {}

    def items(self, path, key, **params):
        return self.req("GET", path, params=params).get("_embedded", {}).get(key, [])


# --- prepare: what a local run needs ---------------------------------------------------------------------------

def ensure_secret(session):
    """One secret with the approvals app's client credentials. Updated only when they change."""
    app = load_json(SPIKE_STATE)["ping"]["apps"]["approvals"]
    value = json.dumps({"client_id": app["id"], "client_secret": app["secret"]})
    sm = session.client("secretsmanager")
    try:
        current = sm.get_secret_value(SecretId=SECRET_NAME)
        if current["SecretString"] != value:
            sm.put_secret_value(SecretId=SECRET_NAME, SecretString=value)
        return current["ARN"]
    except sm.exceptions.ResourceNotFoundException:
        return sm.create_secret(Name=SECRET_NAME, SecretString=value,
                                Description="acgw demo: PingOne approvals (CIBA) app credentials")["ARN"]


def ensure_workload_identity(session):
    ctl = session.client("bedrock-agentcore-control")
    try:
        return ctl.get_workload_identity(name=WORKLOAD_NAME)["workloadIdentityArn"]
    except ctl.exceptions.ResourceNotFoundException:
        return ctl.create_workload_identity(name=WORKLOAD_NAME)["workloadIdentityArn"]


def login_hints(p1):
    """PingOne user id -> username for the demo users: CIBA's login_hint is a username, the token carries `sub`."""
    hints = {}
    for username in DEMO_USERS:
        for user in p1.items("/users", "users", filter=f'username eq "{username}"'):
            hints[user["id"]] = user["username"]
    return hints


def prepare(session, p1):
    state = save_state({
        "region": session.region_name,
        "secret_arn": ensure_secret(session),
        "workload": WORKLOAD_NAME,
        "workload_arn": ensure_workload_identity(session),
        "login_hints": login_hints(p1),
    })
    print(f"Secret {SECRET_NAME}, workload identity {WORKLOAD_NAME}, login hints for {sorted(state['login_hints'].values())}")
    return state


# --- build ------------------------------------------------------------------------------------------------------

def build_zip():
    """arm64 / CPython 3.12 wheels only, no bin/ or __pycache__, explicit file modes (docs/contracts.md)."""
    out = BUILD / "package"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "--target", str(out), "--platform", "manylinux2014_aarch64",
         "--implementation", "cp", "--python-version", "3.12", "--only-binary=:all:", "--no-compile",
         "-r", str(AGENT / "requirements.txt")],
        check=True,
    )
    shutil.rmtree(out / "bin", ignore_errors=True)
    for name in SOURCES:
        src = AGENT / name
        if src.is_dir():
            shutil.copytree(src, out / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy(src, out / name)
    for cache in list(out.rglob("__pycache__")):
        shutil.rmtree(cache, ignore_errors=True)
    zip_path = BUILD / "deployment.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(out.rglob("*")):
            name = str(path.relative_to(out))
            if path.is_dir():
                info = zipfile.ZipInfo(name + "/")
                info.external_attr = 0o40755 << 16
                z.writestr(info, b"")
            else:
                info = zipfile.ZipInfo(name)
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, path.read_bytes())
    print(f"Built {zip_path.relative_to(ROOT)} ({zip_path.stat().st_size // 1_000_000} MB)")
    return zip_path


def upload(session, zip_path):
    s3 = session.client("s3")
    account = session.client("sts").get_caller_identity()["Account"]
    bucket = f"acgw-agent-{account}-{session.region_name}"
    try:
        s3.head_bucket(Bucket=bucket)
    except s3.exceptions.ClientError:
        cfg = {} if session.region_name == "us-east-1" else {
            "CreateBucketConfiguration": {"LocationConstraint": session.region_name}}
        s3.create_bucket(Bucket=bucket, **cfg)
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    key = f"{RUNTIME_NAME}/deployment.zip"
    s3.upload_file(str(zip_path), bucket, key)
    return bucket, key


# --- runtime ----------------------------------------------------------------------------------------------------

def ensure_role(session, bucket, secret_arn):
    iam = session.client("iam")
    account, region = session.client("sts").get_caller_identity()["Account"], session.region_name
    provider = session.client("bedrock-agentcore-control").get_oauth2_credential_provider(name=AGENT_OBO_PROVIDER)
    vault_secret = provider.get("clientSecretArn", {}).get("secretArn")
    workloads = f"arn:aws:bedrock-agentcore:{region}:{account}:workload-identity-directory/default"
    statements = [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
                                       "logs:DescribeLogGroups", "logs:DescribeLogStreams"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords",
                                       "cloudwatch:PutMetricData"], "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"},
        {"Effect": "Allow", "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
         "Resource": ["arn:aws:bedrock:*::foundation-model/anthropic.*",
                      f"arn:aws:bedrock:{region}:{account}:inference-profile/*"]},
        {"Effect": "Allow", "Action": ["bedrock-agentcore:GetWorkloadAccessToken",
                                       "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                                       "bedrock-agentcore:GetWorkloadAccessTokenForUserId"],
         "Resource": [workloads, f"{workloads}/workload-identity/*"]},
        {"Effect": "Allow", "Action": "bedrock-agentcore:GetResourceOauth2Token",
         "Resource": [f"arn:aws:bedrock-agentcore:{region}:{account}:token-vault/default",
                      provider["credentialProviderArn"], workloads, f"{workloads}/workload-identity/*"]},
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
         "Resource": [secret_arn] + ([vault_secret] if vault_secret else [])},
    ]
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": account}}}]}
    try:
        arn = iam.create_role(RoleName=ROLE_NAME, AssumeRolePolicyDocument=json.dumps(trust),
                              Description="acgw demo agent on AgentCore Runtime")["Role"]["Arn"]
        created = True
    except iam.exceptions.EntityAlreadyExistsException:
        arn, created = iam.get_role(RoleName=ROLE_NAME)["Role"]["Arn"], False
    iam.put_role_policy(RoleName=ROLE_NAME, PolicyName="agent",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
    if created:
        time.sleep(15)  # let the new role propagate before Runtime assumes it
    return arn


def runtime_url(region, arn):
    return f"https://bedrock-agentcore.{region}.amazonaws.com/runtimes/{urllib.parse.quote(arn, safe='')}/invocations"


def runtime_spec(role_arn, bucket, key, audience, state):
    return {
        "agentRuntimeArtifact": {"codeConfiguration": {
            "code": {"s3": {"bucket": bucket, "prefix": key}},
            "runtime": "PYTHON_3_12",
            "entryPoint": ["main.py"],
        }},
        "roleArn": role_arn,
        "networkConfiguration": {"networkMode": "PUBLIC"},
        "protocolConfiguration": {"serverProtocol": "HTTP"},
        "authorizerConfiguration": {"customJWTAuthorizer": {
            "discoveryUrl": pingone_urls()["discovery"], "allowedAudience": [audience]}},
        # The agent reads the user's token claims (identity events, p1.permissions) from the forwarded header.
        "requestHeaderConfiguration": {"requestHeaderAllowlist": ["Authorization"]},
        "environmentVariables": {
            "GATEWAY_URL": gateway_url(),
            "PINGONE_ISSUER": pingone_urls()["issuer"],
            "AGENT_OBO_PROVIDER": AGENT_OBO_PROVIDER,
            "WORKLOAD_NAME": WORKLOAD_NAME,
            "MODEL_ID": os.environ.get("AGENT_MODEL_ID", MODEL_ID),
            "LOGIN_HINTS": json.dumps(state["login_hints"]),
            "AWS_DEFAULT_REGION": state["region"],
        },
    }


def wait_ready(ctl, runtime_id):
    for _ in range(120):
        runtime = ctl.get_agent_runtime(agentRuntimeId=runtime_id)
        if runtime["status"] == "READY":
            return runtime
        if runtime["status"].endswith("FAILED"):
            raise RuntimeError(f"runtime {runtime['status']}: {runtime.get('failureReason', 'no reason given')}")
        time.sleep(5)
    raise TimeoutError("runtime never became READY")


def upsert_runtime(session, spec_for):
    """Create or update the runtime; `spec_for(audience)` builds the spec. The audience is the runtime's own URL,
    which exists only after creation, so a new runtime is created with a placeholder and then updated."""
    ctl = session.client("bedrock-agentcore-control")
    runtimes = ctl.list_agent_runtimes(maxResults=100)["agentRuntimes"]
    existing = next((r for r in runtimes if r["agentRuntimeName"] == RUNTIME_NAME), None)
    if existing and existing["status"].endswith("FAILED"):
        ctl.delete_agent_runtime(agentRuntimeId=existing["agentRuntimeId"])  # a failed runtime can't be updated
        while any(r["agentRuntimeName"] == RUNTIME_NAME
                  for r in ctl.list_agent_runtimes(maxResults=100)["agentRuntimes"]):
            time.sleep(5)
        existing = None
    if not existing:
        placeholder = load_json(SPIKE_STATE)["ping"]["audiences"]["agent"]
        runtime_id = ctl.create_agent_runtime(agentRuntimeName=RUNTIME_NAME, **spec_for(placeholder))["agentRuntimeId"]
        wait_ready(ctl, runtime_id)
    else:
        runtime_id = existing["agentRuntimeId"]
    arn = ctl.get_agent_runtime(agentRuntimeId=runtime_id)["agentRuntimeArn"]
    url = runtime_url(session.region_name, arn)
    ctl.update_agent_runtime(agentRuntimeId=runtime_id, **spec_for(url))
    runtime = wait_ready(ctl, runtime_id)
    return {"id": runtime_id, "arn": arn, "url": url, "version": runtime["agentRuntimeVersion"]}


def point_pingone_at(p1, url):
    """Sign-in tokens for the agent get aud = the runtime URL (contract: PingOne resources table)."""
    resource = next((r for r in p1.items("/resources", "resources") if r.get("name") == AGENT_RESOURCE), None)
    if not resource:
        raise RuntimeError(f"PingOne resource {AGENT_RESOURCE!r} not found")
    if resource.get("audience") == url:
        return False
    body = {k: resource[k] for k in ("name", "description", "audience", "accessTokenValiditySeconds",
                                      "applicationPermissionsSettings", "introspectEndpointAuthMethod")
            if k in resource}
    body["audience"] = url
    p1.req("PUT", f"/resources/{resource['id']}", json=body)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prepare", action="store_true", help="only the secret, workload identity and login hints")
    args = parser.parse_args()

    session, p1 = aws_session(), PingOne()
    state = prepare(session, p1)
    if args.prepare:
        return
    bucket, key = upload(session, build_zip())
    role_arn = ensure_role(session, bucket, state["secret_arn"])
    print(f"Deploying runtime {RUNTIME_NAME} (a few minutes)...")
    runtime = upsert_runtime(session, lambda audience: runtime_spec(role_arn, bucket, key, audience, state))
    changed = point_pingone_at(p1, runtime["url"])
    save_state({"bucket": bucket, "role_arn": role_arn, "runtime": runtime, "gateway_url": gateway_url(),
                "model_id": os.environ.get("AGENT_MODEL_ID", MODEL_ID)})
    print(f"Runtime {runtime['id']} v{runtime['version']} READY\n  {runtime['url']}")
    print("PingOne agent-runtime audience " + ("updated: sign in again (spike/login.py) for a token the runtime "
                                                 "accepts." if changed else "already points at the runtime."))


if __name__ == "__main__":
    main()
