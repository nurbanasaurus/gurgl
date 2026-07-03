#!/usr/bin/env bash
# Deploy gurgl to a remote host (e.g. over Tailscale/SSH) and build+install it
# there natively — so Linux->macOS (e.g. an Apple-Silicon Mac) works without a
# cross-compile SDK dance. Installs into ~/.gurgl on the target.
#
# Usage: scripts/deploy.sh <host>
#   <host> is anything ssh understands: an ~/.ssh/config alias, a MagicDNS
#   FQDN, or an IP. Example: scripts/deploy.sh my-mac
#
# NOTE: don't pass a bare hostname that looks like a hex number (e.g. "0x69") —
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

echo ">> building + installing on ${host} ..."
ssh "${host}" bash -s <<'REMOTE'
set -euo pipefail
if ! command -v cargo >/dev/null 2>&1; then
  echo "   installing Rust on remote ..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
fi
. "$HOME/.cargo/env" 2>/dev/null || true
cd "$HOME/gurgl-src"
GURGL_HOME="${GURGL_HOME:-$HOME/.gurgl}"
mkdir -p "$GURGL_HOME"
if [ -f Cargo.lock ]; then
  cargo install --path . --root "$GURGL_HOME" --locked --force
else
  cargo install --path . --root "$GURGL_HOME" --force
fi
echo "   installed: $("$GURGL_HOME/bin/gurgl" --version 2>/dev/null || echo "$GURGL_HOME/bin/gurgl")"
REMOTE

echo ">> done. On ${host}:  ~/.gurgl/bin/gurgl --help"
echo "   (add ~/.gurgl/bin to PATH there:  . ~/.gurgl/env )"
