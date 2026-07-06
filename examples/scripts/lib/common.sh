# shellcheck shell=bash
# Shared helpers for the gurgl example scripts.
#
# This file is SOURCED, never run. It stays portable to the oldest bash a user
# is likely to have (macOS still ships bash 3.2), so: no associative arrays, no
# ${var,,}, no mapfile, no `echo -e`, no GNU-only flags. printf everywhere.
#
# Status/narration goes to stderr so a script's stdout stays clean and pipeable
# (an allowlist, a CSV report, a JSON blob). die() exits 2 to match gurgl's own
# "2 = error" contract.

# Guard against being executed directly.
if [ -z "${BASH_SOURCE:-}" ] || [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  printf 'lib/common.sh is a library; source it, do not run it.\n' >&2
  exit 2
fi

# --- locate ourselves and the repo (no readlink -f; that is GNU-only) --------
_gurgl_resolve_dir() {
  # Resolve the directory of $1, following one level of symlink portably.
  _src=$1
  while [ -h "$_src" ]; do
    _dir=$(cd -P "$(dirname "$_src")" && pwd)
    _src=$(readlink "$_src")
    case $_src in
      /*) ;;
      *) _src=$_dir/$_src ;;
    esac
  done
  cd -P "$(dirname "$_src")" && pwd
}

GURGL_LIB_DIR=$(_gurgl_resolve_dir "${BASH_SOURCE[0]}")
GURGL_SCRIPTS_DIR=$(cd "$GURGL_LIB_DIR/.." && pwd)
GURGL_EXAMPLES_DIR=$(cd "$GURGL_SCRIPTS_DIR/.." && pwd)
GURGL_REPO_ROOT=$(cd "$GURGL_EXAMPLES_DIR/.." && pwd)
GURGL_EXAMPLE_CONFIG="$GURGL_EXAMPLES_DIR/gurgl.toml"
export GURGL_LIB_DIR GURGL_SCRIPTS_DIR GURGL_EXAMPLES_DIR GURGL_REPO_ROOT GURGL_EXAMPLE_CONFIG

# --- colors (stderr only, TTY-gated, NO_COLOR-aware) -------------------------
if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$(printf '\033[0m'); C_BOLD=$(printf '\033[1m'); C_DIM=$(printf '\033[2m')
  C_RED=$(printf '\033[31m'); C_GRN=$(printf '\033[32m')
  C_YLW=$(printf '\033[33m'); C_CYN=$(printf '\033[36m')
else
  C_RESET=; C_BOLD=; C_DIM=; C_RED=; C_GRN=; C_YLW=; C_CYN=
fi

# --- narration helpers (all to stderr) ---------------------------------------
say()   { printf '%s\n' "$*" >&2; }
title() { printf '\n%s== %s ==%s\n' "$C_BOLD" "$*" "$C_RESET" >&2; }
step()  { printf '%s>>%s %s\n' "$C_CYN" "$C_RESET" "$*" >&2; }
note()  { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RESET" >&2; }
ok()    { printf '%s[ok]%s %s\n' "$C_GRN" "$C_RESET" "$*" >&2; }
warn()  { printf '%s[warn]%s %s\n' "$C_YLW" "$C_RESET" "$*" >&2; }
err()   { printf '%s[err]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()   { err "$*"; exit 2; }  # exit 2 == gurgl's "error" code; keep usage errors OFF 0/1

# Echo a command (dimmed) then run it, so a demo shows exactly what it invoked.
run() { printf '%s$ %s%s\n' "$C_DIM" "$*" "$C_RESET" >&2; "$@"; }

# Print a script's leading '#' comment header (from line 3 to the first
# non-comment line) as help text, stripping the leading "# ". Robust to header
# edits - no hardcoded line ranges to drift out of sync.
print_header() { awk 'NR<3{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$1" >&2; }

# Guard a flag's value in an arg-parse loop. Call right AFTER `shift`, passing
# the remaining count; dies (exit 2, not 1) when the value is missing:
#   --config|-c) shift; req_arg $# "--config needs a path"; CFG=(--config "$1") ;;
req_arg() { [ "$1" -gt 0 ] || die "$2"; }

# --- platform ----------------------------------------------------------------
os_name() {
  case "$(uname -s)" in
    Darwin) printf 'macos' ;;
    Linux)  printf 'linux' ;;
    *)      printf 'other' ;;
  esac
}

have() { command -v "$1" >/dev/null 2>&1; }

# Desktop notification, best-effort, cross-platform. Never fails the caller.
notify() {
  _title=$1; _body=$2
  case "$(os_name)" in
    macos) have osascript && osascript -e "display notification \"$_body\" with title \"$_title\"" >/dev/null 2>&1 ;;
    linux) have notify-send && notify-send "$_title" "$_body" >/dev/null 2>&1 ;;
    *)     : ;;
  esac
  return 0
}

# --- locate the gurgl binary -------------------------------------------------
# These scripts ship inside the gurgl repo, so they prefer the repo's OWN build:
# whatever you last `cargo build`-ed is the code this tree documents. Precedence:
#   1. $GURGL_BIN            explicit override (use this to point at your install)
#   2. target/release        the repo build (install.sh produces this too)
#   3. target/debug          a plain `cargo build`
#   4. gurgl on PATH         a global install for users who kept no source tree
#   5. ~/.gurgl/bin/gurgl    the standard install location, even if not on PATH
# The override matters on a dev box whose global install has gone stale relative
# to the checkout - set GURGL_BIN=$(command -v gurgl) to force the installed one.
find_gurgl() {
  if [ -n "${GURGL_BIN:-}" ] && [ -x "$GURGL_BIN" ]; then
    printf '%s' "$GURGL_BIN"; return 0
  fi
  for _c in "$GURGL_REPO_ROOT/target/release/gurgl" \
            "$GURGL_REPO_ROOT/target/debug/gurgl"; do
    if [ -x "$_c" ]; then printf '%s' "$_c"; return 0; fi
  done
  _p=$(command -v gurgl 2>/dev/null || true)
  if [ -n "$_p" ]; then printf '%s' "$_p"; return 0; fi
  if [ -x "$HOME/.gurgl/bin/gurgl" ]; then printf '%s' "$HOME/.gurgl/bin/gurgl"; return 0; fi
  return 1
}

# Set $GURGL to a usable binary or exit with guidance.
need_gurgl() {
  # A set-but-broken override is a mistake to surface, not to paper over by
  # silently falling through to a different binary.
  if [ -n "${GURGL_BIN:-}" ] && [ ! -x "$GURGL_BIN" ]; then
    die "GURGL_BIN is set but not executable: $GURGL_BIN"
  fi
  GURGL=$(find_gurgl) || die "gurgl not found. Install it (see docs/INSTALL.md: ./install.sh) or set GURGL_BIN=/path/to/gurgl."
  export GURGL
}

need_jq() {
  have jq || die "this script needs 'jq' (https://jqlang.github.io/jq/). Install it, e.g. 'brew install jq' or 'apt install jq'."
}

# Make a temp dir (portable: -d works on GNU and BSD mktemp). The CALLER owns
# cleanup: install a status-preserving `trap` on EXIT, e.g.
#   cleanup() { _rc=$?; [ -n "$TMP" ] && rm -rf "$TMP"; return $_rc; }; trap cleanup EXIT
mk_tmpdir() {
  _d=$(mktemp -d "${TMPDIR:-/tmp}/gurgl-example.XXXXXX") || die "mktemp failed"
  printf '%s' "$_d"
}
