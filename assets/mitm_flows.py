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
# Three hooks, deliberately, so the destination host survives both proxy modes
# (env-proxy CONNECT and forced-transparent redirect) AND a failed interception:
#
#  - request() records the dialed authority. Prefer the TLS SNI
#    (flow.client_conn.sni) and fall back to flow.request.host. In env-proxy mode
#    request.host is the CONNECT target and the SNI equals it, so this is
#    unchanged. In forced/transparent mode request.host is the ORIGINAL-DEST IP
#    (there is no CONNECT), so the SNI is the only hostname - and it is the name
#    the client put on the wire to route the connection, NOT the HTTP Host header.
#    We still never use pretty_host / host_header: those prefer the Host header,
#    which the observed server fully controls and mitmproxy's own docs warn "may
#    be manipulated by malicious actors". The inventory must key on the real
#    destination, not an attacker-chosen string.
#
#  - http_connect() records the CONNECT target before TLS (env-proxy mode). Its
#    host is known even when interception then FAILS (a cert-pinning client, or
#    one that does not trust the lab CA - the macOS system-python case doctor
#    warns about), so a contacted host is never silently dropped.
#
#  - tls_clienthello() records the SNI before TLS completes - the transparent
#    analog of http_connect. In forced/transparent mode there is no CONNECT, so
#    without this a cert-pinning client that ignores the proxy would leave no
#    record at all; the ClientHello SNI is visible on the wire regardless of
#    whether the client then accepts the lab cert, so the hostname is captured
#    even when the raw-socket, cert-pinning client defeats decryption. Recorded
#    as an observed contact (connect=True). request() also fires when
#    interception succeeds; gurgl dedups (host, phase), so duplicates collapse.
#
# HOST + TIME ONLY, never bodies (THREAT-MODEL.md).

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
            # Seen before/without successful interception. Recorded so the host
            # is not lost; gurgl treats it as an observed contact.
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

    def tls_clienthello(self, data):
        # The SNI is the server name the client dialed, visible before cert
        # validation, so a forced-mode client that pins certs cannot hide the
        # host it contacted. Not the (attacker-controllable) Host header.
        try:
            sni = data.client_hello.sni
        except Exception:
            return
        self._record(sni, connect=True)

    def request(self, flow):
        try:
            # SNI first (the real transport destination in transparent mode),
            # else the dialed request host. Never the Host header.
            host = flow.client_conn.sni or flow.request.host
        except Exception:
            return
        self._record(host, connect=False)


addons = [FlowLogger()]
