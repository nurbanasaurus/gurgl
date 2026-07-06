#!/usr/bin/env bash
#
# 06 - A machine-readable scrutiny report across every captured server, built on
# `gurgl --json` + jq. NO capture backend needed (reads stored snapshots).
#
# gurgl is an egress inventory you can script. This walks the latest capture of
# every server and emits a CSV of the STABLE hosts that matched no known rule
# (class unknown or self-named-telemetry) - the hosts a human should look at.
# CSV goes to stdout (pipe it, redirect it, open it in a sheet); the summary and
# all narration go to stderr, so the pipe stays clean.
#
# Usage:
#   ./06-scrutiny-report.sh                       # demo: the bundled example store
#   ./06-scrutiny-report.sh --config ~/.gurgl/gurgl.toml > scrutiny.csv
#   ./06-scrutiny-report.sh --all-classes         # include EVERY stable host, not just scrutiny ones
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$DIR/lib/common.sh"
need_gurgl
need_jq

CFG=(--config "$GURGL_EXAMPLE_CONFIG")
FILTER='select(.class=="unknown" or .class=="telemetry?")'
EXPLICIT_TARGET=0

while [ $# -gt 0 ]; do
  case "$1" in
    # --config/--store accumulate; the first user target flag clears the default.
    --config|-c)   shift; req_arg $# "--config needs a path"
                   [ "$EXPLICIT_TARGET" = 1 ] || CFG=(); EXPLICIT_TARGET=1; CFG+=(--config "$1") ;;
    --store)       shift; req_arg $# "--store needs a dir"
                   [ "$EXPLICIT_TARGET" = 1 ] || CFG=(); EXPLICIT_TARGET=1; CFG+=(--store "$1") ;;
    --all-classes) FILTER='.' ;;
    -h|--help)     print_header "$0"; exit 0 ;;
    *)             die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

title "Scrutiny report"
SERVERS=$("$GURGL" "${CFG[@]}" --json list | jq -r '.servers[].name')
[ -n "$SERVERS" ] || { warn "No captured servers in this store."; exit 0; }

# CSV header on stdout.
printf 'server,version,host,class,phases,seen_in_trials\n'

COUNT=0
while IFS= read -r s; do
  [ -n "$s" ] || continue
  ROWS=$("$GURGL" "${CFG[@]}" --json show "$s" | jq -r --arg s "$s" '
    .snapshot as $snap
    | $snap.hosts[]
    | select(.reproducibility=="stable")
    | '"$FILTER"'
    | [$s, $snap.version, .name, .class, (.phases|join("|")), (.seen_in_trials|tostring)]
    | @csv')
  if [ -n "$ROWS" ]; then
    printf '%s\n' "$ROWS"
    N=$(printf '%s\n' "$ROWS" | grep -c '.')
    COUNT=$((COUNT + N))
    warn "$s: $N host(s) to review"
  else
    ok "$s: nothing flagged"
  fi
done <<EOF
$SERVERS
EOF

say ""
if [ "$COUNT" -gt 0 ]; then
  warn "$COUNT host(s) across all servers matched no known rule. CSV is on stdout."
  note "This is a to-review list, NOT an accusation: a stable unknown host can be"
  note "perfectly legitimate. Confirm each, then 'gurgl ack' the ones you expect."
else
  ok "Nothing needs scrutiny under these flight plans."
fi
