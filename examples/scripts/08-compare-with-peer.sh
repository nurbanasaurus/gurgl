#!/usr/bin/env bash
#
# 08 - Share a capture, and compare yours against a peer's. NO backend needed.
#
# `gurgl export` writes a scrubbed, shareable "shared capture" (stable hosts
# only, host CLASS dropped, guardrails baked in). `gurgl diff --against`
# compares your local capture to one. It is EXPLORATORY, never a verdict:
# exit codes are 0 (compared) or 2 (error), never a pass/fail - a stranger's
# capture must never be your gate.
#
# Usage:
#   ./08-compare-with-peer.sh                              # self-demo on the bundled store
#   ./08-compare-with-peer.sh --export <server> [-o file.json] [--as-name NAME]
#   ./08-compare-with-peer.sh --against <server> <peer.shared.json>
#   (add --config <path> to use your own store)
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$DIR/lib/common.sh"
need_gurgl

CFG=(--config "$GURGL_EXAMPLE_CONFIG")
MODE=demo
SERVER=
PEER=
OUTFILE=
ASNAME=
TMP=

while [ $# -gt 0 ]; do
  case "$1" in
    --export)    MODE=export; shift; req_arg $# "--export needs a server"; SERVER=$1 ;;
    --against)   MODE=against; shift; req_arg $# "--against needs a server"; SERVER=$1
                 shift; req_arg $# "--against needs a peer file"; PEER=$1 ;;
    -o)          shift; req_arg $# "-o needs a path"; OUTFILE=$1 ;;
    --as-name)   shift; req_arg $# "--as-name needs a value"; ASNAME=$1 ;;
    --config|-c) shift; req_arg $# "--config needs a path"; CFG=(--config "$1") ;;
    --store)     shift; req_arg $# "--store needs a dir"; CFG=(--store "$1") ;;
    -h|--help)   print_header "$0"; exit 0 ;;
    *)           die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

cleanup() { _rc=$?; [ -n "$TMP" ] && rm -rf "$TMP"; return $_rc; }  # preserve exit status: an EXIT trap's final status leaks to the shell
trap cleanup EXIT

case "$MODE" in
  export)
    title "Exporting a shared capture of $SERVER"
    ASARG=(); [ -n "$ASNAME" ] && ASARG=(--as-name "$ASNAME")
    if [ -n "$OUTFILE" ]; then
      run "$GURGL" "${CFG[@]}" export "$SERVER" ${ASARG[@]+"${ASARG[@]}"} -o "$OUTFILE"
      ok "wrote $OUTFILE"
    else
      run "$GURGL" "${CFG[@]}" export "$SERVER" ${ASARG[@]+"${ASARG[@]}"}
    fi
    say ""
    warn "Exporting is not publishing; SHARING it is. If the file names a vendor,"
    warn "read docs/PUBLISHING.md first (entity + insurance, coordinated disclosure,"
    warn "never punch down). The scrub drops host class on purpose: what a host IS"
    warn "is the reader's call, not the publisher's to assert."
    ;;

  against)
    [ -f "$PEER" ] || die "peer file not found: $PEER (must be a LOCAL path - gurgl never fetches a URL)"
    title "Comparing your $SERVER capture against $PEER"
    RC=0
    run "$GURGL" "${CFG[@]}" diff "$SERVER" --against "$PEER" || RC=$?
    say ""
    note "Exit was $RC (0=compared, 2=error - never 1: this is exploratory, not a gate)."
    note "A match is NOT a pass; more or fewer hosts than the peer is expected, not proof."
    exit "$RC"   # propagate 0/2 to the caller (never a pass/fail gate, but an error is still an error)
    ;;

  demo)
    title "Self-demo: export example-mcp, then diff your capture against it"
    TMP=$(mk_tmpdir)
    SHARED="$TMP/example-mcp.shared.json"
    step "1) Export a shared capture (stable hosts only, no verdict):"
    "$GURGL" "${CFG[@]}" export example-mcp -o "$SHARED"
    ok "wrote $SHARED"
    say ""
    step "2) Compare your latest capture against it (exploratory only):"
    RC=0
    run "$GURGL" "${CFG[@]}" diff example-mcp --against "$SHARED" || RC=$?
    say ""
    note "Here you exported and compared the SAME store, so the sets overlap. With a"
    note "real peer file, 'hosts YOU saw that they did not' is the interesting column"
    note "- but it is a version/cohort/flight-plan difference to investigate, never a"
    note "verdict. Exit was $RC (0 or 2 only; --against never returns 1)."
    ;;
esac
