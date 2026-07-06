#!/usr/bin/env bash
#
# 03 - The weekly drift audit, productionized. gurgl's core routine.
#
# Captures every configured server, diffs each against its accepted baseline
# (else its previous version), logs the run, and raises a desktop notification
# only when something actually needs review. Exit code mirrors gurgl's:
#   0 = no drift    1 = drift needs scrutiny    2 = error
# so you can drop this straight into cron / systemd / launchd.
#
# Usage:
#   ./03-weekly-drift-audit.sh              # run the audit now
#   ./03-weekly-drift-audit.sh --install    # print the cron/systemd/launchd line for your OS
#   ./03-weekly-drift-audit.sh --config <path>   # audit a specific config
#
# A new STABLE unknown host after an update is the postmark-mcp pattern - a
# package that turns malicious in a patch release. This is the one attack class
# an egress diff catches almost for free.
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$DIR/lib/common.sh"
need_gurgl

CONFIG_ARG=
LOGDIR="${GURGL_LOG_DIR:-$HOME/.gurgl/logs}"

while [ $# -gt 0 ]; do
  case "$1" in
    --install)     ACTION=install ;;
    --config|-c)   shift; req_arg $# "--config needs a path"; CONFIG_ARG=$1 ;;
    -h|--help)     print_header "$0"; exit 0 ;;
    *)             die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

if [ "${ACTION:-run}" = install ]; then
  SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
  title "Schedule this audit"
  case "$(os_name)" in
    linux)
      say "cron (weekly, Monday 09:17):  crontab -e  and add:"
      say "  17 9 * * 1  $SELF >/dev/null 2>&1"
      say ""
      say "or a systemd user timer - see docs/RECIPES.md for the .service/.timer pair."
      ;;
    macos)
      say "launchd: create ~/Library/LaunchAgents/monster.grep.gurgl-audit.plist"
      say "with a StartCalendarInterval pointing ProgramArguments at:"
      say "  $SELF"
      say "then: launchctl load ~/Library/LaunchAgents/monster.grep.gurgl-audit.plist"
      say ""
      say "cron also works on macOS:  17 9 * * 1  $SELF >/dev/null 2>&1"
      ;;
    *) say "Schedule '$SELF' however your system does periodic jobs." ;;
  esac
  exit 0
fi

CFG=()
[ -n "$CONFIG_ARG" ] && CFG=(--config "$CONFIG_ARG")

mkdir -p "$LOGDIR"
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="$LOGDIR/audit-$STAMP.log"

title "gurgl drift audit  ($(date))"
note "Capturing every configured server and diffing against its baseline."
note "Log: $LOG"

# watch --all --diff: capture each, compare to baseline, exit 1 on drift.
# --plain because we are piping to a file. We tee so you see it live too.
RC=0
"$GURGL" ${CFG[@]+"${CFG[@]}"} watch --all --diff --plain 2>&1 | tee "$LOG" >&2 || RC=${PIPESTATUS[0]}

say ""
case "$RC" in
  0)
    ok "No egress drift. (Quiet means 'no NEW stable hosts under this flight plan'"
    ok "- not 'verified safe'. The trusted-channel limit still applies.)"
    ;;
  1)
    warn "Egress drift detected - one or more servers need review."
    notify "gurgl" "egress drift needs review"
    say ""
    say "Review loop:"
    say "  gurgl diff <server>                      # what changed, with next steps"
    say "  gurgl ack <server> <host> --note '...'   # reviewed + expected -> quiet next time"
    say "  gurgl accept <server>                    # done reviewing -> new baseline"
    ;;
  *)
    err "gurgl errored (exit $RC). See $LOG."
    ;;
esac
exit "$RC"
