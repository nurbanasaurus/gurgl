#!/usr/bin/env bash
# Deploy gurgl to a remote host (e.g. over Tailscale/SSH) and build+install it
# there natively - so Linux->macOS (e.g. an Apple-Silicon Mac) works without a
# cross-compile SDK dance. Installs into ~/.gurgl on the target.
#
# Usage: scripts/deploy.sh <host>
#   <host> is anything ssh understands: an ~/.ssh/config alias, a MagicDNS
#   FQDN, or an IP. Example: scripts/deploy.sh my-mac
#
# NOTE: don't pass a bare hostname that looks like a hex number (e.g. "0x69")  - 
# getaddrinfo parses it as an integer (0x69 = 105 -> 0.0.0.105). Use an
# ~/.ssh/config Host alias, a MagicDNS FQDN, or an IP instead.
set -euo pipefail

host="${1:-}"
if [ -z "$host" ]; then
  echo "usage: $0 <host>   (an ssh alias, FQDN, or IP)" >&2
  exit 2
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v rsync >/dev/null 2>&1 || { echo "rsync is required locally" >&2; exit 1; }

echo ">> syncing gurgl source to ${host}:~/gurgl-src/ ..."
rsync -az --delete \
  --exclude target --exclude .git \
  "${here}/" "${host}:gurgl-src/"

echo ">> building + installing on ${host} (via install.sh, incl. deps) ..."
# Delegate to install.sh on the target so the remote gets the same behaviour as a
# local install: Rust toolchain, gurgl into ~/.gurgl, AND runtime deps. Pass any
# extra args (e.g. --no-deps) straight through.
ssh "${host}" bash -s -- "${@:2}" <<'REMOTE'
set -euo pipefail
. "$HOME/.cargo/env" 2>/dev/null || true
cd "$HOME/gurgl-src"
bash ./install.sh "$@"
echo "   installed: $("${GURGL_HOME:-$HOME/.gurgl}/bin/gurgl" --version 2>/dev/null || echo "gurgl")"
REMOTE

echo ">> done. On ${host}:  ~/.gurgl/bin/gurgl --help"
echo "   (add ~/.gurgl/bin to PATH there:  . ~/.gurgl/env )"
