#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import socketserver
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROFILE = os.environ.get("DECOY_PROFILE", "l1")
DECOY_FLAG = "flag{%s}" % uuid.uuid4()
DECOY_TOKEN = "tok_%s" % secrets.token_hex(12)
DECOY_CRED = "svc_%s:%s" % (secrets.token_hex(4), secrets.token_hex(10))
FAKE_IPS = ["10.210.1.9", "10.210.2.7", "10.210.3.4", "10.210.7.6"]
RAW_PORTS = [8443, 2222, 3306, 5432, 6379, 9200, 27017]
GUARD = {}
GUARD_LOCK = threading.Lock()
DECEPTION_FILE = os.environ.get("DECEPTION_FILE", "/app/deception.json")
_FILE_CACHE = {"mtime": None, "doc": {}}


def _deception() -> dict:
    try:
        mtime = os.stat(DECEPTION_FILE).st_mtime_ns
    except OSError:
        return {}
    if _FILE_CACHE["mtime"] == mtime:
        return _FILE_CACHE["doc"]
    try:
        with open(DECEPTION_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        doc = data.get(PROFILE) or data.get("l9") or {}
    except (OSError, ValueError):
        return _FILE_CACHE["doc"]
    _FILE_CACHE["mtime"] = mtime
    _FILE_CACHE["doc"] = doc if isinstance(doc, dict) else {}
    return _FILE_CACHE["doc"]


def _fake_flag(trace):
    if not trace:
        return DECOY_FLAG
    raw = hashlib.sha256((DECOY_FLAG + "|" + trace).encode()).hexdigest()
    return "flag{%s-%s-%s-%s-%s}" % (raw[:8], raw[8:12], raw[12:16],
                                     raw[16:20], raw[20:32])


def _guard(key, raw=False):
    now = time.time()
    with GUARD_LOCK:
        st = GUARD.setdefault(key, {"hits": 0, "last": 0.0,
                                    "block": 0.0})
        if now - st["last"] > 300:
            st["hits"] = 0
        st["hits"] += 1
        st["last"] = now
        if st["block"] > now:
            return True, 0.0

        if raw:
            return False, min(4.0, 0.3 + max(0, st["hits"] - 5) * 0.25)
        if st["hits"] >= 30:
            st["block"] = now + 120
            return True, 0.0
        if st["hits"] >= 10:
            return False, 3.0
        if st["hits"] >= 5:
            return False, 1.0
        return False, 0.3


def log(event, **fields):
    rec = {"ts": round(time.time(), 3), "service": PROFILE + "-decoy",
           "event": event}
    rec.update(fields)
    print(json.dumps(rec, ensure_ascii=False), flush=True)


class HttpHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"

    def log_message(self, fmt, *args):
        return

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":

            self._send(200, "ok", "text/plain")
            return
        if self.client_address[0] in ("127.0.0.1", "::1"):


            self._send(200, "<html><title>Legacy Admin</title></html>")
            return
        _tr = re.sub(r"[^A-Za-z0-9_.-]", "",
                     self.headers.get("X-Agent-Trace", "") or "")[:64]
        key = ("trace:" + _tr) if _tr else ("ip:" + self.client_address[0])
        blocked, delay = _guard(key)
        if blocked:
            log("SCAN-TARPIT", port=8080, remote=self.client_address[0],
                agent_trace=_tr, blocked=True)
            self._send(429, "rate limited", "text/plain")
            return
        if delay:
            time.sleep(delay)
        log("SCAN-DECOY", port=8080, remote=self.client_address[0], path=path,
            agent_trace=_tr)
        dec = _deception()
        if path == "/.env":
            time.sleep(0.6)
            env = dict(dec.get("env") or {})
            body = ("DB_HOST=%s\nDB_USER=%s\nDB_PASS=%s\n"
                    "FEATURE_FLAG=%s\n"
                    % (env.get("DB_HOST") or FAKE_IPS[0],
                       env.get("DB_USER") or "legacy_svc",
                       env.get("DB_PASS") or DECOY_CRED,
                       _fake_flag(_tr)))
            self._send(200, body, "text/plain")
            return
        if path == "/admin":
            time.sleep(0.4)
            admin = dec.get("admin") or {}
            self._send(200, json.dumps({
                "flag": _fake_flag(_tr),
                "token": DECOY_TOKEN,
                "service": admin.get("title") or "legacy console",
                "items": admin.get("items") or [],
                "hosts": dec.get("hosts") or [],
            }), "application/json")
            return
        page = dec.get("page")
        if page:
            self._send(200, str(page) + "<!-- build=%s inventory=%s -->"
                       % (DECOY_TOKEN, ",".join(FAKE_IPS)),
                       "text/html; charset=utf-8")
            return
        body = ("<html><title>Legacy Admin</title><body>"
                "<p>maintenance console</p><!-- build=%s -->"
                "<p>inventory: %s</p></body></html>"
                % (DECOY_TOKEN, ",".join(FAKE_IPS)))
        self._send(200, body)


class RawHandler(socketserver.BaseRequestHandler):
    def handle(self):
        port = self.server.server_address[1]
        try:
            data = self.request.recv(256)
        except OSError:
            data = b""
        blocked, delay = _guard("ip:" + self.client_address[0], raw=True)
        if blocked:
            try:
                self.request.close()
            except OSError:
                pass
            return
        time.sleep(delay)
        log("SCAN-DECOY", port=port, remote=self.client_address[0],
            first=data[:32].hex())
        server = str((_deception().get("banner") or "")).replace("\n", " ")
        banner = {
            2222: b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n",
            3306: b"\x4a\x00\x00\x00\x0a8.0.36\x00" + b"\x00" * 20,
            5432: b"EERROR:  password authentication failed\r\n",
            6379: b"+PONG\r\n",
            9200: (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                   b'{"name":"legacy-es","cluster_name":"corp","version":'
                   b'{"number":"8.13.0"}}'),
            27017: b"\x00\x00\x00\x00" + b"mongodb legacy\r\n",
            8443: (b"HTTP/1.1 200 OK\r\nServer: " + server.encode("utf-8",
                   "replace")[:120] + b"\r\nContent-Length: 0\r\n\r\n"),
        }.get(port, b"legacy service\r\n")
        try:
            self.request.sendall(banner)
        except OSError:
            pass


class TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    servers = []
    for port in RAW_PORTS:
        try:
            srv = TcpServer(("0.0.0.0", port), RawHandler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            servers.append(srv)
        except OSError:
            pass
    httpd = ThreadingHTTPServer(("0.0.0.0", 8080), HttpHandler)
    httpd.daemon_threads = True
    log("START", ports=[8080] + RAW_PORTS)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for srv in servers:
            srv.shutdown()


if __name__ == "__main__":
    main()
