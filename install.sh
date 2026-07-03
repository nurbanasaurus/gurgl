#!/usr/bin/env bash
# gurgl installer - Linux & macOS.
#
# Installs the Rust toolchain if missing, builds gurgl, installs everything under
# a single self-contained home (~/.gurgl, override with $GURGL_HOME), AND installs
# the runtime dependencies `gurgl watch` needs (a sandbox backend + mitmproxy).
#
#   ~/.gurgl/bin/gurgl        the binary
#   ~/.gurgl/bin/mitmdump     symlink to the capture proxy (when installed via venv)
#   ~/.gurgl/gurgl.toml       your config          (created by `gurgl init`)
#   ~/.gurgl/flightplans/     the scripted battery (created by `gurgl init`)
#   ~/.gurgl/snapshots/       captured egress
#   ~/.gurgl/mitmproxy/       the lab CA           (created on first `watch`)
#   ~/.gurgl/mitmproxy-venv/  mitmproxy's Python env (only if installed via venv)
#   ~/.gurgl/env              `source` it to put ~/.gurgl/bin on PATH
#
# Usage: ./install.sh [--no-deps]
#   --no-deps   install only the gurgl binary; skip sandbox/mitmproxy setup.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
os="$(uname -s)"
GURGL_HOME="${GURGL_HOME:-$HOME/.gurgl}"

WITH_DEPS=1
MODIFY_PATH=1
for arg in "$@"; do
  case "$arg" in
    --no-deps) WITH_DEPS=0 ;;
    --no-modify-path) MODIFY_PATH=0 ;;
    *) echo "unknown option: $arg (see: $0 --help)"; [ "$arg" = "--help" ] && exit 0 || exit 2 ;;
  esac
done

# --- 1. Rust toolchain -------------------------------------------------------
# Make an existing rustup toolchain visible even in a non-login shell first, so
# we don't needlessly reinstall it when run over SSH.
# shellcheck disable=SC1090,SC1091
. "$HOME/.cargo/env" 2>/dev/null || true
if ! command -v cargo >/dev/null 2>&1; then
  echo ">> installing Rust (rustup) ..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
  . "$HOME/.cargo/env" 2>/dev/null || true
fi

# --- 2. build + install gurgl into ~/.gurgl/bin ------------------------------
echo ">> installing gurgl into ${GURGL_HOME} ..."
mkdir -p "$GURGL_HOME"
if [ -f "$here/Cargo.lock" ]; then
  cargo install --path "$here" --root "$GURGL_HOME" --locked --force
else
  cargo install --path "$here" --root "$GURGL_HOME" --force
fi

# --- 3. a sourceable env file (rustup-style) to add gurgl to PATH ------------
cat > "$GURGL_HOME/env" <<EOF
# Adds gurgl to your PATH. Source it from your shell profile:
#   . "\$HOME/.gurgl/env"
case ":\${PATH}:" in
  *:"$GURGL_HOME/bin":*) ;;
  *) export PATH="$GURGL_HOME/bin:\$PATH" ;;
esac
EOF

# 3b. wire the env file into the shell profile so future shells find gurgl.
# (A script can't change the *current* shell's PATH -- that needs a `source`,
# printed at the end -- but it can set up every new shell.)
PROFILE_TOUCHED=""
if [ "$MODIFY_PATH" -eq 1 ]; then
  case "$(basename "${SHELL:-bash}")" in
    zsh)  profiles="$HOME/.zshrc $HOME/.zprofile" ;;
    bash) profiles="$HOME/.bashrc $HOME/.bash_profile" ;;
    fish) profiles="" ;;  # fish uses its own path handling; instruct below
    *)    profiles="$HOME/.profile" ;;
  esac
  for p in $profiles; do
    touch "$p"
    if ! grep -qF '.gurgl/env' "$p" 2>/dev/null; then
      printf '\n. "%s/env"\n' "$GURGL_HOME" >> "$p"
      PROFILE_TOUCHED="$PROFILE_TOUCHED $p"
    fi
  done
fi

# 3c. create ~/.gurgl/gurgl.toml + the default flight plan so `gurgl watch` has
# something to run immediately (idempotent: leaves an existing config alone).
GURGL_HOME="$GURGL_HOME" "$GURGL_HOME/bin/gurgl" init >/dev/null 2>&1 || true

# 3d. surface the MCP servers already configured on this machine (Claude, Cursor,
# Windsurf, Cline, ...) so you see right away what gurgl can watch. Listing only;
# it does not modify anything (re-run `gurgl discover --import` to add them).
echo
echo ">> scanning for MCP servers already configured on this machine ..."
GURGL_HOME="$GURGL_HOME" "$GURGL_HOME/bin/gurgl" discover 2>/dev/null || true

# --- 4. runtime dependencies for `gurgl watch` -------------------------------
install_sandbox() {
  case "$os" in
    Darwin)
      command -v sandbox-exec >/dev/null 2>&1 \
        && { echo "  sandbox-exec (Seatbelt): already present"; return 0; } \
        || { echo "  [!] sandbox-exec missing (ships with macOS - unexpected)"; return 1; } ;;
    Linux)
      command -v bwrap >/dev/null 2>&1 && { echo "  bubblewrap: already present"; return 0; }
      local pm=""
      if   command -v apt-get >/dev/null 2>&1; then pm="apt-get install -y bubblewrap"
      elif command -v dnf     >/dev/null 2>&1; then pm="dnf install -y bubblewrap"
      elif command -v pacman  >/dev/null 2>&1; then pm="pacman -S --noconfirm bubblewrap"
      elif command -v zypper  >/dev/null 2>&1; then pm="zypper install -y bubblewrap"
      else echo "  [!] no known package manager for bubblewrap - install it manually"; return 1; fi
      if sudo -n true 2>/dev/null; then
        echo "  installing bubblewrap:  sudo $pm"; sudo $pm
      else
        echo "  [!] bubblewrap needs sudo - run:  sudo $pm"; return 1
      fi ;;
  esac
}

install_mitmproxy() {
  command -v mitmdump >/dev/null 2>&1 && { echo "  mitmproxy (mitmdump): already present"; return 0; }
  if command -v brew >/dev/null 2>&1; then
    echo "  installing mitmproxy via Homebrew ..."; brew install mitmproxy && return 0
  fi
  if command -v pipx >/dev/null 2>&1; then
    echo "  installing mitmproxy via pipx ..."; pipx install mitmproxy && return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    local venv="$GURGL_HOME/mitmproxy-venv"
    echo "  installing mitmproxy into a dedicated venv (${venv}) ..."
    if python3 -m venv "$venv" 2>/dev/null && [ -x "$venv/bin/python" ]; then
      "$venv/bin/python" -m pip install --quiet --upgrade pip 2>/dev/null || true
      if "$venv/bin/python" -m pip install --quiet mitmproxy && [ -x "$venv/bin/mitmdump" ]; then
        ln -sf "$venv/bin/mitmdump" "$GURGL_HOME/bin/mitmdump"
        echo "  linked ${GURGL_HOME}/bin/mitmdump"
        return 0
      fi
    fi
    echo "  [!] venv install failed - install mitmproxy manually (see docs/INSTALL.md)"; return 1
  fi
  echo "  [!] no brew/pipx/python3 found - install mitmproxy manually (see docs/INSTALL.md)"; return 1
}

if [ "$WITH_DEPS" -eq 1 ]; then
  echo
  echo ">> installing runtime deps for 'gurgl watch' (skip with --no-deps) ..."
  install_sandbox   || true
  install_mitmproxy || true
fi

# --- 5. final advisory + next steps -----------------------------------------
echo
echo "runtime deps for 'gurgl watch' (NOT needed for list/show/diff/allow):"
if [ -x "$GURGL_HOME/bin/mitmdump" ] || command -v mitmdump >/dev/null 2>&1; then
  echo "  [ok]      mitmdump"
else
  echo "  [missing] mitmproxy (mitmdump)  -  see docs/INSTALL.md"
fi
case "$os" in
  Darwin) command -v sandbox-exec >/dev/null 2>&1 \
    && echo "  [ok]      sandbox-exec (Seatbelt)" || echo "  [missing] sandbox-exec" ;;
  Linux)  command -v bwrap >/dev/null 2>&1 \
    && echo "  [ok]      bwrap (bubblewrap)" || echo "  [missing] bubblewrap" ;;
esac

echo
if command -v gurgl >/dev/null 2>&1 && [ "$(command -v gurgl)" = "$GURGL_HOME/bin/gurgl" ]; then
  echo ">> done. gurgl is already on this shell's PATH."
else
  echo ">> done."
  if [ -n "$PROFILE_TOUCHED" ]; then
    echo "   Added gurgl to your PATH for new shells (edited:$PROFILE_TOUCHED)."
  elif [ "$MODIFY_PATH" -eq 0 ]; then
    echo "   Skipped PATH setup (--no-modify-path)."
  fi
  # A script can't change the CURRENT shell's PATH; the user must source it.
  echo "   For THIS terminal, run:   . \"$GURGL_HOME/env\""
fi
echo "   then try:"
echo "     gurgl discover      # find MCP servers already configured on this machine"
echo "     gurgl watch         # capture egress for the servers in ~/.gurgl/gurgl.toml"
echo "     gurgl --config \"$here/examples/gurgl.toml\" diff example-mcp   # offline demo"
