Run the full local check gate for gurgl and fix anything that fails:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
cargo run -- --config examples/gurgl.toml diff example-mcp
```

Report the outcome of each step. `cargo test` must be green; clippy must be
warning-clean; the example `diff` must surface the new stable unknown host
(`beacon.unknown-cdn.example`) and must NOT report the intermittent host
(`edge-42.rollout-cohort.example`) as a finding. If clippy flags dead code that
is genuinely wired-but-not-yet-called scaffold, note it rather than deleting the
wiring.
