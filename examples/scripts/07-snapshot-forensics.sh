#!/usr/bin/env bash
#
# 07 - Cheap forensics: "when did this host first show up in my captures?"
# NO backend needed.
#
# Snapshots are plain JSON receipts you own. Commit them to git and you have a
# timestamped, diffable history of what your tools contacted. This answers the
# question that history exists for: given a host (or a substring), which is the
# earliest capture IN THIS STORE that observed it, and when. (That is a floor on
# first contact, not proof of it - a host may have been reached before your first
# capture, or between captures. docs/THREAT-MODEL.md.)
#
# Usage:
#   ./07-snapshot-forensics.sh sentry                 # demo against the bundled store
#   ./07-snapshot-forensics.sh beacon --config ~/.gurgl/gurgl.toml
#   ./07-snapshot-forensics.sh evil.example --store ./snapshots --git
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$DIR/lib/common.sh"
need_gurgl
need_jq

CFG=(--config "$GURGL_EXAMPLE_CONFIG")
NEEDLE=
GIT=0
STORE_DIR=
EXPLICIT_TARGET=0

while [ $# -gt 0 ]; do
  case "$1" in
    # --config/--store accumulate; the first user target flag clears the default.
    --config|-c) shift; req_arg $# "--config needs a path"
                 [ "$EXPLICIT_TARGET" = 1 ] || CFG=(); EXPLICIT_TARGET=1; CFG+=(--config "$1") ;;
    --store)     shift; req_arg $# "--store needs a dir"; STORE_DIR=$1
                 [ "$EXPLICIT_TARGET" = 1 ] || CFG=(); EXPLICIT_TARGET=1; CFG+=(--store "$STORE_DIR") ;;
    --git)       GIT=1 ;;
    -h|--help)   print_header "$0"; exit 0 ;;
    -*)          die "unknown flag: $1 (try --help)" ;;
    *)           NEEDLE=$1 ;;
  esac
  shift
done
[ -n "$NEEDLE" ] || die "give a host or substring to search for, e.g. '$0 sentry'"

# Portable unix-timestamp -> date. GNU `date -d @TS` first (BSD `date -d` wants a
# DST flag and rejects it, falling through); then BSD/macOS `date -r TS`.
fmt_ts() {
  _ts=$1
  date -d "@$_ts" +'%Y-%m-%d %H:%M' 2>/dev/null && return 0
  date -r "$_ts" +'%Y-%m-%d %H:%M' 2>/dev/null && return 0
  printf '%s' "$_ts"
}

title "Searching all captures for host matching: $NEEDLE"

SERVERS=$("$GURGL" "${CFG[@]}" --json list | jq -r '.servers[].name')
[ -n "$SERVERS" ] || { warn "No captured servers in this store."; exit 0; }

# Collect "captured_at<TAB>server<TAB>version<TAB>matched-host" for every hit.
HITS=$(
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    VERSIONS=$("$GURGL" "${CFG[@]}" --json list | jq -r --arg s "$s" '.servers[] | select(.name==$s) | .versions[]')
    while IFS= read -r v; do
      [ -n "$v" ] || continue
      # || exit 2: a failed show/jq must abort the whole search, not be silently
      # swallowed by the command substitution into a false "no match" result.
      "$GURGL" "${CFG[@]}" --json show "$s" "$v" | jq -r --arg s "$s" --arg v "$v" --arg n "$NEEDLE" '
        .snapshot as $snap
        | $snap.hosts[]
        | select(.name | ascii_downcase | contains($n | ascii_downcase))
        | [($snap.captured_at|tostring), $s, $v, .name] | @tsv' || exit 2
    done <<VEOF
$VERSIONS
VEOF
  done <<SEOF
$SERVERS
SEOF
)

if [ -z "$HITS" ]; then
  ok "No captured host matches '$NEEDLE' in this store."
  ok "(Absence here means it was not OBSERVED under these flight plans - not proof"
  ok " the host is never contacted. docs/THREAT-MODEL.md.)"
  exit 0
fi

# Earliest hit in this store = a FLOOR on first contact, not "first appeared".
FIRST=$(printf '%s\n' "$HITS" | sort -n | head -1)
F_TS=$(printf '%s' "$FIRST" | cut -f1)
F_SRV=$(printf '%s' "$FIRST" | cut -f2)
F_VER=$(printf '%s' "$FIRST" | cut -f3)
F_HOST=$(printf '%s' "$FIRST" | cut -f4)

warn "First observed: $F_HOST"
warn "    earliest capture in this store that saw it: $F_SRV@$F_VER, captured $(fmt_ts "$F_TS")"
say ""
step "Every capture that saw a matching host (oldest first):"
printf '%s\n' "$HITS" | sort -n | while IFS="$(printf '\t')" read -r ts srv ver host; do
  printf '    %-19s  %s@%s  ->  %s\n' "$(fmt_ts "$ts")" "$srv" "$ver" "$host" >&2
done

if [ "$GIT" = 1 ]; then
  say ""
  title "git history for the hostname in the snapshot files"
  # Honor --store and $GURGL_HOME; a custom store set only via --config is not
  # known here, so tell the user to pass --store to point --git at it.
  GITDIR="${STORE_DIR:-${GURGL_HOME:-$HOME/.gurgl}/snapshots}"
  [ -n "$STORE_DIR" ] || note "--git inspects $GITDIR; pass --store <dir> to point it elsewhere."
  if git -C "$GITDIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    note "commits that added/removed the string '$NEEDLE' in $GITDIR:"
    git -C "$GITDIR" log --oneline -S "$NEEDLE" -- . >&2 || true
  else
    warn "$GITDIR is not a git repo. Commit your snapshot store to get this timeline:"
    warn "    git -C \"$GITDIR\" init && git -C \"$GITDIR\" add . && git -C \"$GITDIR\" commit -m 'baseline'"
  fi
fi
