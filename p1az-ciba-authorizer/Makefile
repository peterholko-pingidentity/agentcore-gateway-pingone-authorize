.PHONY: build test package clean docker-build docker-package

build:
	cargo lambda build --release --arm64 --bin bedrock

test:
	cargo test

package: build
	cp README.published.md target/lambda/bedrock/README.md
	cd target/lambda/bedrock && zip bootstrap.zip bootstrap README.md
	rm target/lambda/bedrock/README.md

clean:
	cargo clean

# Fork: build without cargo-lambda, in an Amazon Linux 2023 arm64 container
# (same glibc as the provided.al2023 Lambda runtime). Needs Docker.
docker-build:
	# Cargo's build directory lives on a Docker volume, not the bind mount: builds
	# writing through Docker Desktop's macOS file sharing intermittently fail with
	# "can't find crate". Only the finished binary is copied back to the host.
	mkdir -p target-lambda
	docker run --rm --platform linux/arm64 -v "$(CURDIR)":/src -w /src \
		-v p1az-cargo-registry:/root/.cargo/registry -v p1az-cargo-target:/target \
		public.ecr.aws/amazonlinux/amazonlinux:2023 bash -c '\
		dnf install -y -q gcc >/dev/null && \
		curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal && \
		. $$HOME/.cargo/env && CARGO_TARGET_DIR=/target CARGO_PROFILE_RELEASE_STRIP=symbols cargo build --release --bin bedrock && \
		cp /target/release/bedrock /src/target-lambda/bootstrap'
	mkdir -p target/lambda/bedrock
	cp target-lambda/bootstrap target/lambda/bedrock/bootstrap

docker-package: docker-build
	cp README.published.md target/lambda/bedrock/README.md
	cd target/lambda/bedrock && rm -f bootstrap.zip && zip -q bootstrap.zip bootstrap README.md
	rm target/lambda/bedrock/README.md
