# gurgl mitmproxy addon.
#
# Runs under `mitmdump -s assets/mitm_flows.py`. For every request that passes
# through the proxy it appends one JSON line to $GURGL_FLOWOUT recording the
# destination host and a wall-clock timestamp. gurgl maps timestamps to
# flight-plan phases on its side (the addon can't see gurgl's phase, and
# mitmdump's environment is fixed at launch, so time is the reliable join key).
#
# We record the HOST and TIME ONLY, never request/response bodies. gurgl is an
# egress *inventory* tool, not a payload interceptor — see docs/THREAT-MODEL.md.

import json
import os
import time


class FlowLogger:
    def __init__(self):
        self.path = os.environ.get("GURGL_FLOWOUT", "flows.jsonl")

    def request(self, flow):
        try:
            host = flow.request.pretty_host
        except Exception:
            return
        rec = {"host": host, "time": time.time()}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")


addons = [FlowLogger()]
