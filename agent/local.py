"""Run the agent on this machine, and call it (locally or on Runtime) the way the chat app will.

    python agent/local.py serve                       # http://127.0.0.1:8080 (/invocations, /ping)
    python agent/local.py invoke "who am I?"          # as spike/.state.json's user_token, against localhost
    python agent/local.py invoke --runtime "who am I?"  # against the deployed runtime (agent/.state.json)

`serve` needs `python agent/deploy.py --prepare` once (secret, workload identity, login hints) and AWS
credentials. Events print one per line; identity claims are decoded claims, never raw tokens.
"""
import argparse
import json
import os
import sys
import uuid

import httpx

from deploy import AGENT_OBO_PROVIDER, SPIKE_STATE, STATE_FILE, WORKLOAD_NAME, gateway_url, load_json, \
    pingone_urls


def serve(port):
    state = load_json(STATE_FILE)
    if "login_hints" not in state:
        raise SystemExit("Run `python agent/deploy.py --prepare` first.")
    os.environ.update({
        "GATEWAY_URL": gateway_url(),
        "PINGONE_ISSUER": pingone_urls()["issuer"],
        "AGENT_OBO_PROVIDER": AGENT_OBO_PROVIDER,
        "WORKLOAD_NAME": state.get("workload", WORKLOAD_NAME),
        "LOGIN_HINTS": json.dumps(state["login_hints"]),
        "AGENT_HOST": "127.0.0.1",
        "AGENT_PORT": str(port),
    })
    import main  # noqa: PLC0415 - reads the environment above at import

    main.app.run(host="127.0.0.1", port=port)


def invoke(prompt, runtime, session_id, token_key, port):
    token = load_json(SPIKE_STATE).get(token_key)
    if not token:
        raise SystemExit(f"No {token_key} in spike/.state.json: run spike/login.py first.")
    if runtime:
        url = load_json(STATE_FILE)["runtime"]["url"] + "?qualifier=DEFAULT"
    else:
        url = f"http://127.0.0.1:{port}/invocations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
    }
    with httpx.stream("POST", url, headers=headers, json={"prompt": prompt}, timeout=300) as r:
        if r.status_code != 200:
            r.read()
            raise SystemExit(f"HTTP {r.status_code}: {r.text[:500]}")
        text_open = False
        for line in r.iter_lines():
            if not line.startswith("data:"):
                continue
            event = json.loads(line[5:])
            if event.get("type") == "text":
                sys.stdout.write(event["delta"])
                sys.stdout.flush()
                text_open = True
                continue
            if text_open:
                print()
                text_open = False
            print(json.dumps(event))


def main():
    parser = argparse.ArgumentParser(description="Run or call the agent locally.")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8080)
    i = sub.add_parser("invoke")
    i.add_argument("prompt")
    i.add_argument("--runtime", action="store_true", help="call the deployed runtime instead of localhost")
    i.add_argument("--session", default=f"local-{uuid.uuid4()}", help="runtimeSessionId (>= 33 characters)")
    i.add_argument("--token", default="user_token", help="key of the user token in spike/.state.json")
    i.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if args.command == "serve":
        serve(args.port)
    else:
        invoke(args.prompt, args.runtime, args.session, args.token, args.port)


if __name__ == "__main__":
    main()
