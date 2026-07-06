#!/usr/bin/env bash
#
# 10 - The live showpiece: watch REAL egress stream in, phase by phase.
#
# Wires up a no-API-key fetch MCP server with the bundled fetch-demo flight plan
# in a THROWAWAY config + store, then runs `gurgl watch`. In a terminal you get
# the live dashboard: a trial progress bar, per-phase timers, and hosts colored
# by class as they are contacted - including redirect hops the plan never named.
#
# Usage:
#   ./10-live-fetch-demo.sh                 # the repeated-trial battery (fast: 2 trials)
#   ./10-live-fetch-demo.sh --for 30s       # run once, then monitor 30s for background beacons
#   ./10-live-fetch-demo.sh --until-closed  # monitor until you press Ctrl-C
#   ./10-live-fetch-demo.sh --trials 5      # more trials = a stronger reproduction gate
#
# Needs: mitmproxy + a sandbox backend + network + npx. It preflights with
# `gurgl doctor` and stops with guidance if a capture here would be blocked.
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$DIR/lib/common.sh"
need_gurgl

TRIALS=2
WATCH_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --for)          shift; req_arg $# "--for needs a duration"; WATCH_ARGS=(--for "$1") ;;
    --until-closed) WATCH_ARGS=(--until-closed) ;;
    --trials)       shift; req_arg $# "--trials needs a number"; TRIALS=$1 ;;
    -h|--help)      print_header "$0"; exit 0 ;;
    *)              die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

have npx || die "this demo launches the fetch server via npx; install Node.js first."

FETCH_PLAN="$GURGL_REPO_ROOT/flightplans/fetch-demo.toml"
DEF_PLAN="$GURGL_REPO_ROOT/flightplans/default.toml"
[ -f "$FETCH_PLAN" ] || die "missing $FETCH_PLAN (run from a gurgl checkout)."

TMP=$(mk_tmpdir)
cleanup() { _rc=$?; rm -rf "$TMP"; return $_rc; }  # preserve exit status: an EXIT trap's final status leaks to the shell
trap cleanup EXIT

CFG="$TMP/gurgl.toml"
# Absolute flight-plan paths: a per-server flightplan resolves relative to the
# config file, and this config lives in a throwaway temp dir.
{
  printf 'store = "snapshots"\n'
  printf 'flightplan = "%s"\n' "$DEF_PLAN"
  printf 'mitmdump = "mitmdump"\n'
  printf 'trials = %s\n\n' "$TRIALS"
  printf '[[servers]]\n'
  printf 'name = "fetch"\n'
  printf 'command = "npx"\n'
  printf 'args = ["-y", "@tokenizin/mcp-npx-fetch"]\n'
  printf 'flightplan = "%s"\n' "$FETCH_PLAN"
} > "$CFG"

title "Preflight: can this machine capture faithfully?"
if "$GURGL" doctor >&2; then
  ok "doctor is happy"
else
  die "gurgl doctor says a capture here would be blocked (see above). Fix that, then re-run."
fi

title "Watching the fetch server drive the fetch-demo flight plan"
note "The plan fetches example.com, api.github.com/meta, and rust-lang.org. Watch"
note "the npm registry appear at startup, then each fetched host - and any redirect"
note "hop the server follows that the plan never listed."
note "Config + snapshots are in a temp dir and discarded on exit."
say ""

RC=0
"$GURGL" --config "$CFG" watch fetch ${WATCH_ARGS[@]+"${WATCH_ARGS[@]}"} || RC=$?

say ""
if [ "$RC" = 0 ]; then
  step "The capture (from the throwaway store, before it is discarded):"
  "$GURGL" --config "$CFG" show fetch >&2 || true
  say ""
  ok "That is a real egress capture. In your own store it would be a snapshot you"
  ok "own, diff, and commit. Presence only, though - never a clean bill of health."
else
  err "watch exited $RC. If it was Ctrl-C that is a clean stop; otherwise see the output above."
fi
exit "$RC"
