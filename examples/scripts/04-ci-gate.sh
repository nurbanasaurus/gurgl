#!/usr/bin/env bash
#
# 04 - A CI / pre-commit gate on committed snapshots. NO capture backend needed.
#
# If you commit your snapshot store to git (they are plain JSON receipts), a CI
# job can gate merges on egress drift without mitmproxy or a sandbox - `diff`
# only reads JSON. This iterates every captured server, runs the drift check,
# and fails the build if any server grew a new stable host that needs scrutiny.
#
# Exit code: 0 = no drift at this threshold, 1 = drift needs review, 2 = error.
#
# Usage:
#   ./04-ci-gate.sh                       # gate the bundled example store (demo: it WILL trip)
#   ./04-ci-gate.sh --store ./snapshots   # gate a project-local committed store
#   ./04-ci-gate.sh --config ~/.gurgl/gurgl.toml
#   ./04-ci-gate.sh --any                 # trip on ANY new stable host, not just scrutiny ones
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$DIR/lib/common.sh"
need_gurgl
need_jq

# Default to the bundled example config so this runs immediately and shows a
# real "drift caught" failure (example-mcp gains a stable unknown at 1.3.0).
CFG=(--config "$GURGL_EXAMPLE_CONFIG")
CHECK=--check           # scrutiny hosts only (unknown / telemetry?)
EXPLICIT_TARGET=0

while [ $# -gt 0 ]; do
  case "$1" in
    # --config and --store accumulate (gurgl accepts both); the first user-given
    # target flag clears the bundled-example default.
    --store)     shift; req_arg $# "--store needs a dir"
                 [ "$EXPLICIT_TARGET" = 1 ] || CFG=(); EXPLICIT_TARGET=1; CFG+=(--store "$1") ;;
    --config|-c) shift; req_arg $# "--config needs a path"
                 [ "$EXPLICIT_TARGET" = 1 ] || CFG=(); EXPLICIT_TARGET=1; CFG+=(--config "$1") ;;
    --any)       CHECK=--check=any ;;
    -h|--help)   print_header "$0"; exit 0 ;;
    *)           die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done
[ "$EXPLICIT_TARGET" = 1 ] || note "No --store/--config given; gating the bundled example store (a demo failure)."

title "gurgl CI gate ($CHECK)"

# Emit "name<TAB>baseline?" so a server with an accepted baseline is gated
# against IT (--baseline), matching the selection criterion; others gate latest-two.
TAB=$(printf '\t')
SERVERS=$("$GURGL" "${CFG[@]}" --json list \
  | jq -r '.servers[] | select((.versions|length) >= 2 or .baseline != null)
           | [.name, (if .baseline then "baseline" else "" end)] | @tsv')
if [ -z "$SERVERS" ]; then
  ok "No server has two comparable versions yet - nothing to gate. Passing."
  exit 0
fi

FAILED=
ERRORED=
# Feed the loop via a here-string, not a pipe, so FAILED/ERRORED set inside the
# loop survive into the parent shell (a piped `while` runs in a subshell).
while IFS="$TAB" read -r s bmode; do
  [ -n "$s" ] || continue
  BASE=()
  [ "$bmode" = baseline ] && BASE=(--baseline)
  RC=0
  OUT=$("$GURGL" "${CFG[@]}" --json diff "$s" ${BASE[@]+"${BASE[@]}"} $CHECK 2>/dev/null) || RC=$?
  case "$RC" in
    0) ok   "$s: no drift" ;;
    1)
      # jq '//' does NOT fall through on an empty array, so branch on length:
      # under --any, drift may be all non-scrutiny hosts (needs_scrutiny empty).
      HOSTS=$(printf '%s' "$OUT" | jq -r 'if (.needs_scrutiny|length) > 0 then .needs_scrutiny else (.stable_added // []) end | join(", ")')
      err  "$s: DRIFT - new stable host(s) needing review: ${HOSTS:-run: gurgl diff $s}"
      FAILED="$FAILED $s"
      ;;
    *) err "$s: gurgl diff errored (exit $RC)"; ERRORED="$ERRORED $s" ;;
  esac
done <<EOF
$SERVERS
EOF

say ""
if [ -n "$ERRORED" ]; then
  die "errored on:$ERRORED"
elif [ -n "$FAILED" ]; then
  err "Gate FAILED. Drift on:$FAILED"
  say "Review with:  gurgl diff <server>   then ack/accept once reviewed. See docs/RECIPES.md."
  exit 1
else
  ok "Gate passed: no server drifted at this threshold."
  note "Passing means no NEW stable hosts - not a proof of safety (docs/THREAT-MODEL.md)."
  exit 0
fi
