# gurgl mitmproxy addon.
#
# Runs under `mitmdump -s assets/mitm_flows.py`. It appends one JSON line per
# connection the proxy handles to $GURGL_FLOWOUT, recording the DESTINATION HOST
# and a wall-clock timestamp. gurgl maps timestamps to flight-plan phases on its
# side (the addon can't see gurgl's phase, and mitmdump's environment is fixed at
# launch, so time is the reliable join key).
#
# We record the HOST and TIME ONLY, never request/response bodies. gurgl is an
# egress *inventory* tool, not a payload interceptor - see docs/THREAT-MODEL.md.
#
# Two hooks, deliberately:
#
#  - request() records flow.request.host - the authority mitmproxy actually dials
#    upstream (the CONNECT target / absolute-form request URL host). NOT
#    pretty_host: pretty_host prefers the HTTP Host header, which the observed
#    server fully controls and can spoof, and mitmproxy's own docs warn it "may
#    be manipulated by malicious actors". The single field the whole inventory,
#    diff, and allowlist are built from must be the real destination, not an
#    attacker-chosen string.
#
#  - http_connect() records the CONNECT target too, before TLS. Its host is known
#    even when interception then FAILS (the client pins its cert or does not
#    trust the lab CA - the macOS system-python case gurgl's doctor warns about),
#    so a contacted host is never silently dropped: the coverage gap is recorded,
#    not hidden (THREAT-MODEL.md: mark gaps, never report silence as safety).
#    request() also fires when interception succeeds; gurgl dedups (host, phase),
#    so the duplicate collapses.

import json
import os
import time


class FlowLogger:
    def __init__(self):
        self.path = os.environ.get("GURGL_FLOWOUT", "flows.jsonl")

    def _record(self, host, connect):
        if not host:
            return
        rec = {"host": host, "time": time.time()}
        if connect:
            # Seen at CONNECT; TLS interception may not have succeeded. Recorded
            # so the host is not lost; gurgl treats it as an observed contact.
            rec["connect"] = True
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
        except OSError:
            # Never let a logging failure disturb the proxied connection.
            pass

    def http_connect(self, flow):
        try:
            host = flow.request.host
        except Exception:
            return
        self._record(host, connect=True)

    def request(self, flow):
        try:
            host = flow.request.host
        except Exception:
            return
        self._record(host, connect=False)


addons = [FlowLogger()]
