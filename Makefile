# gurgl developer tasks.
# Deploy target host (an ssh alias / FQDN / IP). Override: make deploy HOST=my-mac
HOST ?=

.PHONY: build test lint fmt run install update deploy clean

build:
	cargo build

test:
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings
	cargo fmt --check

fmt:
	cargo fmt

# Run the bundled example diff (no capture backend needed).
run:
	cargo run -- --config examples/gurgl.toml diff example-mcp

# Install into ~/.gurgl (Linux or macOS).
install:
	./install.sh

# Update in place: pull the latest source, then reinstall. gurgl never
# self-updates (it makes no network calls of its own) — this is the update path.
update:
	git pull --ff-only
	./install.sh

# Build+install on a remote host. Required: make deploy HOST=my-mac
deploy:
	@test -n "$(HOST)" || { echo "set HOST, e.g. make deploy HOST=my-mac"; exit 2; }
	./scripts/deploy.sh $(HOST)

clean:
	cargo clean
