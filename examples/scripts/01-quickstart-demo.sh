#!/usr/bin/env bash
#
# 01 - Quickstart: the whole gurgl idea in one run, ZERO capture backend needed.
#
# Walks the bundled example snapshots: the annotated demo diff, then list ->
# show -> diff -> explain -> allow against examples/gurgl.toml. Nothing here
# launches a sandbox or a proxy, so it works the moment you have the binary -
# even straight from a source checkout before install.sh.
#
# Usage: ./01-quickstart-demo.sh
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$DIR/lib/common.sh"
need_gurgl

CFG="$GURGL_EXAMPLE_CONFIG"
SRV=example-mcp

title "gurgl demo (data baked into the binary - no config needed)"
note "The three readings that matter: a known-vendor telemetry host, a stable"
note "UNKNOWN host (the signal), and an intermittent host the reproduction gate"
note "deliberately keeps quiet about."
run "$GURGL" demo || true

title "1. What has been captured?  (gurgl list)"
run "$GURGL" --config "$CFG" list

title "2. The hosts one version contacted  (gurgl show)"
note "REPRO=stable means seen in every trial; SEEN is trials-observed / total."
run "$GURGL" --config "$CFG" show "$SRV"

title "3. The core signal: what changed between versions  (gurgl diff)"
note "New STABLE unknown hosts are the finding. This is the postmark-mcp pattern:"
note "a package that starts beaconing somewhere new after an update."
run "$GURGL" --config "$CFG" diff "$SRV"
note "(Plain 'diff' is for reading - it exits 0/2, never 1, even with drift above."
note " For a CI gate that exits 1 on new stable scrutiny hosts, add --check: see 04-ci-gate.sh.)"

title "4. The same capture in plain language  (gurgl explain)"
run "$GURGL" --config "$CFG" explain "$SRV"

title "5. Turn observation into an enforceable allowlist  (gurgl allow)"
note "Feed this to a squid proxy / OpenSnitch / the Anthropic sandbox-runtime."
run "$GURGL" --config "$CFG" allow "$SRV" --format squid

title "Done"
say "That is the whole loop on demo data. Next, point gurgl at a REAL server:"
say "  ./02-vet-before-adopt.sh --npx '@modelcontextprotocol/server-filesystem' /tmp"
say "Remember: gurgl reports presence, never a clean bill of health (docs/THREAT-MODEL.md)."
