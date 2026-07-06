#!/usr/bin/env bash
#
# 05 - Observe -> enforce. Turn a capture into allowlists for every engine gurgl
# targets, in one go. NO capture backend needed (reads the stored snapshot).
#
# gurgl only observes; it pairs with tools that decide or block. This emits all
# three allowlist formats so you can wire the observation into whatever you run:
#   - sandbox-runtime  (Anthropic sandbox-runtime: enforce on the running agent)
#   - opensnitch       (OpenSnitch/Little Snitch-style per-app firewall rules)
#   - squid            (a squid or other egress-proxy ACL at a network chokepoint)
#
# Usage:
#   ./05-emit-allowlists.sh                              # demo: example-mcp from the bundled store
#   ./05-emit-allowlists.sh <server> [version] --out <dir>
#   ./05-emit-allowlists.sh <server> --config ~/.gurgl/gurgl.toml
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$DIR/lib/common.sh"
need_gurgl

CFG=(--config "$GURGL_EXAMPLE_CONFIG")
SERVER=example-mcp
VERSION=
OUT=

POSITIONAL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out)       shift; req_arg $# "--out needs a dir"; OUT=$1 ;;
    --config|-c) shift; req_arg $# "--config needs a path"; CFG=(--config "$1") ;;
    --store)     shift; req_arg $# "--store needs a dir"; CFG=(--store "$1") ;;
    -h|--help)   print_header "$0"; exit 0 ;;
    -*)          die "unknown flag: $1 (try --help)" ;;
    *)
      POSITIONAL=$((POSITIONAL + 1))
      if   [ "$POSITIONAL" = 1 ]; then SERVER=$1
      elif [ "$POSITIONAL" = 2 ]; then VERSION=$1
      else die "unexpected extra argument: $1 (usage: <server> [version])"; fi
      ;;
  esac
  shift
done

[ -n "$OUT" ] || OUT=$(mk_tmpdir)
mkdir -p "$OUT"

# gurgl allow takes an optional [version] positional before --format.
VERARG=()
[ -n "$VERSION" ] && VERARG=("$VERSION")

title "Emitting allowlists for $SERVER${VERSION:+@$VERSION}"

emit() {
  fmt=$1; ext=$2
  file="$OUT/$SERVER.$ext"
  "$GURGL" "${CFG[@]}" allow "$SERVER" ${VERARG[@]+"${VERARG[@]}"} --format "$fmt" > "$file"
  ok "$fmt -> $file"
}

emit sandbox-runtime sandbox-runtime.txt
emit opensnitch      opensnitch.json
emit squid           squid.conf

title "How to apply each"
say "  sandbox-runtime : pass the domain list as the network allowlist to the sandbox"
say "                    (Observe with gurgl, enforce with the sandbox - the strongest combo.)"
say "  opensnitch      : import the rule, or drop the JSON into OpenSnitch's rules dir"
say "  squid           : include the ACL in squid.conf and reload squid"
say ""
warn "An allowlist reflects only what was OBSERVED under the flight plan. It is a"
warn "starting point to review, not a complete contract - a tool can still contact"
warn "a host it simply did not reach under this plan (docs/THREAT-MODEL.md)."
say ""
step "Preview (squid):"
cat "$OUT/$SERVER.squid.conf" >&2
