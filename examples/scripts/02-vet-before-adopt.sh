#!/usr/bin/env bash
#
# 02 - Vet an MCP server BEFORE you wire it into Claude Code / Cursor / etc.
#
# The headline use case: learn a server's network footprint in a throwaway
# sandbox before it ever touches your real environment. A filesystem tool that
# talks to one host is boring - that is the point. A "markdown converter"
# contacting six unknowns is a decision you now get to make consciously.
#
# Two ways to call it:
#   ./02-vet-before-adopt.sh <server-name>          # a server already in your gurgl.toml
#   ./02-vet-before-adopt.sh --npx <pkg> [args...]  # a fresh npm package, in a throwaway config+store
#
# Examples:
#   ./02-vet-before-adopt.sh filesystem-mcp
#   ./02-vet-before-adopt.sh --npx '@modelcontextprotocol/server-filesystem' /tmp
#
# Needs the capture backend (mitmproxy + a sandbox); it preflights with
# `gurgl doctor` and stops with guidance if a capture here would be blocked.
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$DIR/lib/common.sh"
need_gurgl
need_jq

MODE=named
SERVER=
CONFIG_ARG=
TMP=

usage() { print_header "$0"; exit 2; }

# Escape a string for a TOML basic ("...") string: backslash first, then quote.
# (bash 3.2 supports ${var//pat/repl}; npm names never need it, but a path arg might.)
toml_esc() { _s=$1; _s=${_s//\\/\\\\}; _s=${_s//\"/\\\"}; printf '%s' "$_s"; }

[ $# -ge 1 ] || usage
case "$1" in -h|--help) print_header "$0"; exit 0 ;; esac
if [ "$1" = "--npx" ]; then
  MODE=npx; shift
  [ $# -ge 1 ] || die "--npx needs a package name, e.g. --npx '@scope/pkg' [args...]"
  PKG=$1; shift
else
  SERVER=$1; shift
  if [ $# -ge 2 ] && [ "$1" = "--config" ]; then CONFIG_ARG="$2"; shift 2; fi
fi

cleanup() { _rc=$?; [ -n "$TMP" ] && rm -rf "$TMP"; return $_rc; }  # preserve exit status: an EXIT trap's final status leaks to the shell
trap cleanup EXIT

if [ "$MODE" = npx ]; then
  # Build a disposable config + store so vetting never pollutes your real one.
  TMP=$(mk_tmpdir)
  SERVER=candidate
  CONFIG_ARG="$TMP/gurgl.toml"
  {
    printf 'store = "snapshots"\n'
    printf 'flightplan = "%s/flightplans/default.toml"\n' "$GURGL_REPO_ROOT"
    printf 'trials = 3\n\n'
    printf '[[servers]]\n'
    printf 'name = "%s"\n' "$SERVER"
    printf 'command = "npx"\n'
    printf 'args = ["-y", "%s"' "$(toml_esc "$PKG")"
    for a in "$@"; do printf ', "%s"' "$(toml_esc "$a")"; done
    printf ']\n'
  } > "$CONFIG_ARG"
  note "Throwaway config for '$PKG' at $CONFIG_ARG (store + snapshots discarded on exit)."
fi

CFG=()
[ -n "$CONFIG_ARG" ] && CFG=(--config "$CONFIG_ARG")

title "Preflight: is a faithful capture possible on this machine?"
if "$GURGL" doctor >&2; then
  ok "doctor is happy"
else
  die "gurgl doctor says a capture here would be blocked (see above). Fix that, then re-run."
fi

title "Capturing '$SERVER' in a sandbox, behind the proxy"
note "This launches untrusted third-party code in a sandbox and drives a scripted"
note "MCP session N times. New here? Read docs/THREAT-MODEL.md."
run "$GURGL" ${CFG[@]+"${CFG[@]}"} watch "$SERVER" --plain

title "What it contacted"
run "$GURGL" ${CFG[@]+"${CFG[@]}"} show "$SERVER"

title "In plain language, with the honest limits"
run "$GURGL" ${CFG[@]+"${CFG[@]}"} explain "$SERVER"

# Pull out just the hosts that deserve a human decision.
title "Verdict helper"
SCRUTINY=$("$GURGL" ${CFG[@]+"${CFG[@]}"} --json show "$SERVER" \
  | jq -r '.snapshot.hosts[]
           | select(.reproducibility=="stable")
           | select(.class=="unknown" or .class=="telemetry?")
           | .name')

if [ -z "$SCRUTINY" ]; then
  ok "No stable UNKNOWN or self-named-telemetry hosts. Footprint looks unremarkable"
  ok "under this flight plan - which is NOT a clean bill of health (docs/THREAT-MODEL.md)."
else
  warn "Stable host(s) matching no known rule - review each before you trust this server:"
  printf '%s\n' "$SCRUTINY" | while IFS= read -r h; do warn "    $h"; done
  say ""
  say "To decide: grep the package source for the hostname to see what dials it."
  if [ "$MODE" = npx ]; then
    # The capture lives in a throwaway store deleted on exit, so 'gurgl ack' here
    # would target nothing. Adopt it into your real config first, then ack there.
    say "Expected? -> add this server to ~/.gurgl/gurgl.toml, re-capture with"
    say "             'gurgl watch <name>', then 'gurgl ack <name> <host> --note ...'."
    say "Not expected? -> do not adopt it."
  else
    ACKCFG=""
    [ -n "$CONFIG_ARG" ] && ACKCFG=" --config $CONFIG_ARG"
    say "Expected? -> gurgl$ACKCFG ack $SERVER <host> --note '...'   Not expected? -> do not adopt it."
  fi
fi
