#!/usr/bin/env bash
#
# 09 - Scaffold a per-server flight plan from what a server actually advertises.
#
# The default flight plan calls one auto-picked read-only tool with no args - so
# a tool that only reaches the network when GIVEN input (a `fetch` needs a URL, a
# `search` needs a query) shows only startup egress. `gurgl plan` launches the
# server ONCE in the sandbox (no proxy, no capture, no mitmproxy needed), reads
# its tools/list, and writes a DRAFT plan with one read-only-looking step per
# tool and REPLACE_ME placeholders. gurgl NEVER runs the draft or fuzzes args -
# you review it, fill the placeholders, and wire it up.
#
# Usage:
#   ./09-scaffold-flightplan.sh <server> [-o file] [--config <path>] [--force]
#   ./09-scaffold-flightplan.sh filesystem-mcp
#
# Needs a sandbox backend (bubblewrap on Linux, sandbox-exec on macOS) to launch
# the server - but NOT mitmproxy. It runs untrusted third-party code in the
# sandbox to enumerate tools, same disclosure as `watch` (docs/THREAT-MODEL.md).
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$DIR/lib/common.sh"
need_gurgl

SERVER=
OUTARG=()
CFG=()
FORCE=()

while [ $# -gt 0 ]; do
  case "$1" in
    -o)          shift; req_arg $# "-o needs a path"; OUTARG=(-o "$1") ;;
    --config|-c) shift; req_arg $# "--config needs a path"; CFG=(--config "$1") ;;
    --force)     FORCE=(--force) ;;
    -h|--help)   print_header "$0"; exit 0 ;;
    -*)          die "unknown flag: $1 (try --help)" ;;
    *)           SERVER=$1 ;;
  esac
  shift
done
[ -n "$SERVER" ] || die "name a server from your gurgl.toml, e.g. '$0 filesystem-mcp'"

title "Scaffolding a draft flight plan for '$SERVER'"
note "Launching the server once in the sandbox to read its advertised tools."
RC=0
run "$GURGL" ${CFG[@]+"${CFG[@]}"} plan "$SERVER" ${OUTARG[@]+"${OUTARG[@]}"} ${FORCE[@]+"${FORCE[@]}"} || RC=$?

if [ "$RC" != 0 ]; then
  say ""
  err "gurgl plan exited $RC. Common causes: server not in your config, a missing"
  err "sandbox backend, or the draft already exists (re-run with --force to replace)."
  exit "$RC"
fi

say ""
title "Next steps (gurgl did NOT run the draft)"
say "  1. Open the draft and REVIEW every step - the placeholders are inert."
say "  2. Replace REPLACE_ME with real, read-only inputs (a safe URL, a benign query)."
say "  3. Delete any tool step you do not want exercised."
say "  4. Wire it into gurgl.toml so watch uses it:"
say ""
say "       [[servers]]"
say "       name = \"$SERVER\""
say "       flightplan = \"flightplans/$SERVER.toml\""
say ""
warn "A custom plan is a NEW method: its fingerprint differs from 'default', so"
warn "snapshots taken under it are not directly comparable to default-plan ones."
say ""
say "Then capture with the richer plan:  gurgl watch $SERVER"
