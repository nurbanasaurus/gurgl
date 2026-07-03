# Recipes

Copy-paste automation built on gurgl's exit-code contract
(`0` = no drift, `1` = drift needing scrutiny, `2` = error) and `--json` output.
Everything here runs locally; gurgl itself never phones home, and the schedule
is yours (cron/systemd/launchd), never a background daemon of gurgl's.

## The weekly drift audit (cron)

Capture every configured server, compare each to its accepted baseline (else
its previous version), and log the result. Only writes noise to the log when
something actually needs scrutiny.

```cron
# m h dom mon dow  command
17 9 * * 1  . "$HOME/.gurgl/env" && gurgl watch --all --diff --plain >> "$HOME/.gurgl/logs/audit.log" 2>&1 || notify-send "gurgl: egress drift needs review"
```

`notify-send` is Linux; on macOS use
`osascript -e 'display notification "egress drift needs review" with title "gurgl"'`.
Create the log dir once: `mkdir -p ~/.gurgl/logs`.

The review loop when it fires:

```sh
gurgl diff <server>                 # what changed, with next steps
gurgl ack <server> <host> --note "..."   # reviewed and expected -> quiet from now on
gurgl accept <server>               # done reviewing -> new baseline
```

## CI gate on committed snapshots (no capture deps)

If you commit `~/.gurgl/snapshots` (or a project-local store) to git, a CI job
can gate on drift without mitmproxy or a sandbox - `diff` only reads JSON:

```sh
gurgl --store ./snapshots diff my-server --check || {
  echo "new stable hosts need review - see gurgl diff my-server"; exit 1;
}
```

## Scripting with --json

```sh
# Hosts that need scrutiny (acks already subtracted):
gurgl --json diff my-server | jq -r '.needs_scrutiny[]'

# Every stable host in the latest capture:
gurgl --json show my-server | jq -r '.snapshot.hosts[] | select(.reproducibility=="stable") | .name'

# MCP servers on this machine that are actually enabled:
gurgl --json discover | jq -r '.servers[] | select(.status=="enabled") | .name'
```

## systemd timer instead of cron (Linux)

`~/.config/systemd/user/gurgl-audit.service`:

```ini
[Unit]
Description=gurgl egress drift audit

[Service]
Type=oneshot
ExecStart=%h/.gurgl/bin/gurgl watch --all --diff --plain
StandardOutput=append:%h/.gurgl/logs/audit.log
StandardError=append:%h/.gurgl/logs/audit.log
```

`~/.config/systemd/user/gurgl-audit.timer`:

```ini
[Unit]
Description=weekly gurgl audit

[Timer]
OnCalendar=Mon 09:17
Persistent=true

[Install]
WantedBy=timers.target
```

Enable with `systemctl --user enable --now gurgl-audit.timer`.

## launchd (macOS)

`~/Library/LaunchAgents/monster.grep.gurgl-audit.plist` with a
`StartCalendarInterval` for the same weekly run; point `ProgramArguments` at
`$HOME/.gurgl/bin/gurgl` with `watch --all --diff --plain`. Load once with
`launchctl load ~/Library/LaunchAgents/monster.grep.gurgl-audit.plist`.

---

Remember what a quiet audit means: **no new stable hosts under this flight
plan** - not "verified safe". The trusted-channel limit still applies
(docs/THREAT-MODEL.md).
