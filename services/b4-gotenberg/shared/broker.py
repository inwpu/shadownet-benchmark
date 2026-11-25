from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

DATA = Path(os.environ.get("BROKER_DATA", "/data"))
AGENT_FLAGS = Path(os.environ.get("AGENT_FLAGS_FILE",
                                  str(DATA / "agent_flags.json")))
TRACES = Path(os.environ.get("TRACES_FILE", str(DATA / "traces.json")))
SERVICE_KEYS = Path(os.environ.get("SERVICE_KEYS", "/srv/service_keys.json"))
SERVICE_FLAGS = Path(os.environ.get("SERVICE_FLAGS", "/srv/service_flags.json"))
PORT = int(os.environ.get("PORT", "8100"))

_LOCK = threading.Lock()
_CACHE: dict[str, tuple[int, object]] = {}


def _load(path: Path, default):
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        return default
    with _LOCK:
        cached = _CACHE.get(str(path))
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cached[1] if cached else default
        _CACHE[str(path)] = (mtime, data)
        return data


def keys() -> dict[str, str]:
    data = _load(SERVICE_KEYS, {})
    return ({str(k): str(v) for k, v in data.items()}
            if isinstance(data, dict) else {})


def service_flags() -> dict[str, list[str]]:
    data = _load(SERVICE_FLAGS, {})
    if not isinstance(data, dict):
        return {}
    return {str(k): [str(x) for x in v] if isinstance(v, list) else []
            for k, v in data.items()}


def agent_flags() -> dict[str, dict[str, str]]:
    data = _load(AGENT_FLAGS, {})
    if not isinstance(data, dict):
        return {}
    return {str(agent): {str(fid): str(value)
                         for fid, value in values.items()}
            for agent, values in data.items() if isinstance(values, dict)}


def traces() -> dict[str, str]:
    data = _load(TRACES, {})
    return ({str(k): str(v) for k, v in data.items()}
            if isinstance(data, dict) else {})


def agent_for_trace(trace: str) -> str:
    if not trace:
        return ""
    digest = hashlib.sha256(trace.encode()).hexdigest()
    for agent, value in traces().items():
        if (hmac.compare_digest(value, trace)
                or hmac.compare_digest(value, digest)):
            return agent
    return ""


class Handler(BaseHTTPRequestHandler):
    server_version = "ESN-FlagBroker/1.0"

    def log_message(self, fmt, *args):
        return

    def _send(self, code: int, obj: dict) -> None:
        raw = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            pass

    def do_GET(self):
        split = urlsplit(self.path)
        if split.path == "/healthz":
            self._send(200, {"ok": True,
                             "broker": True,
                             "agents": len(agent_flags())})
            return
        if split.path != "/v1/flag":
            self._send(404, {"error": "not found"})
            return
        query = parse_qs(split.query, keep_blank_values=True)
        service = (query.get("service") or [""])[0]
        fid = (query.get("flag") or [""])[0]
        trace = (query.get("trace") or [""])[0]
        supplied = self.headers.get("X-Broker-Key", "")
        expected = keys().get(service, "")
        if (not expected or not supplied
                or not hmac.compare_digest(expected, supplied)):
            self._send(403, {"error": "service key required"})
            return
        if fid not in service_flags().get(service, []):
            self._send(403, {"error": "flag not owned by service"})
            return
        agent = agent_for_trace(trace)
        if not agent:
            self._send(403, {"error": "registered trace required"})
            return
        value = agent_flags().get(agent, {}).get(fid, "")
        if not value:
            self._send(404, {"error": "no per-agent value"})
            return
        print(json.dumps({"event": "BROKER-FLAG", "service": service,
                          "flag": fid, "agent": agent},
                         ensure_ascii=False), flush=True)
        self._send(200, {"value": value, "agent": agent})


def serve() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.daemon_threads = True
    print(json.dumps({"event": "BROKER-START", "port": PORT}, ensure_ascii=False),
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
