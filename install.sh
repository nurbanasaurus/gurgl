#!/usr/bin/env bash
# gurgl installer — Linux & macOS.
#
# Installs the Rust toolchain if missing, builds gurgl, and installs everything
# under a single self-contained home: ~/.gurgl (override with $GURGL_HOME).
#
#   ~/.gurgl/bin/gurgl      the binary
#   ~/.gurgl/gurgl.toml     your config          (created by `gurgl init`)
#   ~/.gurgl/flightplans/   the scripted battery (created by `gurgl init`)
#   ~/.gurgl/snapshots/     captured egress
#   ~/.gurgl/mitmproxy/     the lab CA           (created on first `watch`)
#   ~/.gurgl/env            `source` it to put ~/.gurgl/bin on PATH
#
# Reports (but does not install) the runtime deps that only `gurgl watch` needs.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
os="$(uname -s)"
GURGL_HOME="${GURGL_HOME:-$HOME/.gurgl}"

# 1. Rust toolchain
if ! command -v cargo >/dev/null 2>&1; then
  echo ">> installing Rust (rustup) ..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
fi
# shellcheck disable=SC1090,SC1091
. "$HOME/.cargo/env" 2>/dev/null || true

# 2. build + install gurgl into ~/.gurgl/bin
echo ">> installing gurgl into ${GURGL_HOME} ..."
mkdir -p "$GURGL_HOME"
if [ -f "$here/Cargo.lock" ]; then
  cargo install --path "$here" --root "$GURGL_HOME" --locked --force
else
  cargo install --path "$here" --root "$GURGL_HOME" --force
fi

# 3. a sourceable env file (rustup-style) to add gurgl to PATH
cat > "$GURGL_HOME/env" <<EOF
# Adds gurgl to your PATH. Source it from your shell profile:
#   . "\$HOME/.gurgl/env"
case ":\${PATH}:" in
  *:"$GURGL_HOME/bin":*) ;;
  *) export PATH="$GURGL_HOME/bin:\$PATH" ;;
esac
EOF

# 4. runtime dependency advisory (only needed for `gurgl watch`)
echo
echo "runtime deps for 'gurgl watch' (NOT needed for list/show/diff/allow):"
if command -v mitmdump >/dev/null 2>&1; then
  echo "  [ok]      mitmdump"
else
  echo "  [missing] mitmproxy (mitmdump)  —  macOS: brew install mitmproxy  |  Linux: pipx install mitmproxy"
fi
case "$os" in
  Darwin)
    command -v sandbox-exec >/dev/null 2>&1 \
      && echo "  [ok]      sandbox-exec (Seatbelt)" \
      || echo "  [missing] sandbox-exec  —  ships with macOS; unexpected if absent" ;;
  Linux)
    command -v bwrap >/dev/null 2>&1 \
      && echo "  [ok]      bwrap (bubblewrap)" \
      || echo "  [missing] bubblewrap  —  apt install bubblewrap  /  dnf install bubblewrap" ;;
esac

echo
if command -v gurgl >/dev/null 2>&1 && [ "$(command -v gurgl)" = "$GURGL_HOME/bin/gurgl" ]; then
  echo ">> done. gurgl is on your PATH. Next:"
else
  echo ">> done. Add gurgl to your PATH (once):"
  echo "     echo '. \"\$HOME/.gurgl/env\"' >> ~/.$(basename "${SHELL:-bash}")rc"
  echo "     . \"$GURGL_HOME/env\""
  echo "   then:"
fi
echo "     gurgl init          # writes ~/.gurgl/gurgl.toml + default flight plan"
echo "     gurgl --config \"$here/examples/gurgl.toml\" diff example-mcp   # try it now"
