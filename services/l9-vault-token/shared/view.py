from __future__ import annotations

import hashlib
import hmac
import os
import re
import time

VPORTS = [8080, 8443, 9000, 9090, 9443, 7001, 5000, 8000, 8081, 8444]
_BUCKET = 900



HONEYPOT_ROLES = ["files", "print", "backup", "mail", "proxy",
                  "vpn", "nas", "camera", "erp", "db"]

ROLE_ALIASES = {
    "jenkins": "ci", "teamcity": "ci", "ingress": "edge",
    "geoserver": "gis", "hertzbeat": "monitor", "activemq": "mq",
    "hugegraph": "graph", "php": "portal", "tomcat": "app",
    "react": "web", "gotenberg": "docs", "chartbrew": "report",
    "im": "gateway", "gitlab": "scm", "nexus": "repo", "build": "runner",
    "grafana": "metrics", "warehouse": "dw", "erp": "erp",
    "ssh": "legacy", "db": "legacy", "api": "legacy", "es": "legacy",
    "ftp": "legacy", "files": "files", "print": "print", "cctv": "cctv",
}






_PROCESS_SALT = os.urandom(32)


def _salt(gateway: dict) -> bytes:
    return _PROCESS_SALT


def _h(gateway: dict, agent: str, *parts: str) -> str:
    msg = "|".join([agent] + list(parts)).encode("utf-8", "replace")
    return hmac.new(_salt(gateway), msg, hashlib.sha256).hexdigest()


def _role(role: str) -> str:
    raw = re.sub(r"[^a-z0-9]+", "-", (role or "service").lower()).strip("-")
    return ROLE_ALIASES.get(raw, (raw or "service")[:14])


def _state(gateway: dict, agent: str, real: str, bucket: int) -> str:
    raw = _h(gateway, agent, "state", real, str(bucket))
    roll = int(raw[:2], 16) % 100
    if roll < 70:
        return "up"
    if roll < 85:
        return "maintenance"
    if roll < 95:
        return "degraded"
    return "offline"


def profile(gateway: dict, agent: str, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    bucket = int(now // _BUCKET)
    targets = gateway.get("view_targets") or {
        name: {"flag": False, "role": "service"}
        for name in (gateway.get("ports") or {})
    }
    used_names: set[str] = set()
    used_ports: set[int] = set()
    entries: list[dict] = []

    for real, meta in targets.items():
        h = _h(gateway, agent, "asset", real)
        if meta.get("honeypot"):
            role = HONEYPOT_ROLES[int(h[10:12], 16) % len(HONEYPOT_ROLES)]
        else:
            role = _role(str(meta.get("role") or "service"))
        base = "%s-%s" % (role, h[:4])
        vname = base
        n = 4
        while vname in used_names:
            n += 2
            vname = "%s-%s" % (base, h[:n])
        used_names.add(vname)

        vport = VPORTS[int(h[4:6], 16) % len(VPORTS)]
        tries = 0
        while vport in used_ports and tries < len(VPORTS):
            vport = VPORTS[(VPORTS.index(vport) + 1) % len(VPORTS)]
            tries += 1
        used_ports.add(vport)

        flag = bool(meta.get("flag"))
        hp = bool(meta.get("honeypot"))
        if flag:
            visible = True
            state = "up"
        else:

            roll = int(h[6:8], 16) % 100
            visible = roll < (68 if hp else 80)
            state = _state(gateway, agent, real, bucket)
        entries.append({
            "real": real, "virtual": vname, "port": vport,
            "role": role, "flag": flag, "honeypot": hp,
            "visible": visible, "state": state, "extra": False,
            "hash": h,
        })



    nonflag = [e for e in entries if not e["flag"]]
    for e in nonflag:
        if sum(1 for x in nonflag if x["visible"]) >= 2:
            break
        e["visible"] = True



    if nonflag:
        seed = _h(gateway, agent, "extra", str(bucket))
        if int(seed[:2], 16) % 100 < 55:
            src = nonflag[int(seed[2:4], 16) % len(nonflag)]
            vname = "%s-edge-%s" % (src["role"], seed[4:8])
            if vname not in used_names:
                used_names.add(vname)
                entries.append({
                    "real": src["real"], "virtual": vname,
                    "port": src["port"], "role": src["role"],
                    "flag": False, "honeypot": src["honeypot"],
                    "visible": True, "state": "up", "extra": True,
                    "hash": seed,
                })

    by_virtual = {e["virtual"]: e for e in entries}
    by_real: dict[str, dict] = {}
    for e in entries:
        if e["visible"] and e["real"] not in by_real:
            by_real[e["real"]] = e
    visible = [e for e in entries if e["visible"]]
    visible.sort(key=lambda e: e["hash"])
    return {
        "agent": agent, "bucket": bucket,
        "entries": entries, "by_virtual": by_virtual, "by_real": by_real,
        "discovery": [e["virtual"] for e in visible],
    }


def resolve(gateway: dict, agent: str, virtual: str,
            port: int | None = None, now: float | None = None):
    prof = profile(gateway, agent, now)
    entry = prof["by_virtual"].get(virtual)
    if not entry or not entry["visible"]:
        return None, 404
    if port is not None and int(port) != int(entry["port"]):
        return None, 403
    if entry["state"] == "maintenance":
        return entry, 503
    if entry["state"] == "offline":
        return entry, 502
    return entry, None


def scrub(text: str, prof: dict) -> str:
    if not text:
        return text
    pairs = sorted(prof["by_real"].items(), key=lambda kv: len(kv[0]),
                   reverse=True)
    for real, entry in pairs:
        text = text.replace(real, entry["virtual"])

        text = text.replace(real.replace("-", "_"),
                            entry["virtual"].replace("-", "_"))
    return text


def state_message(entry: dict) -> dict:
    return {
        "service": entry["virtual"],
        "state": entry["state"],
        "retry_after": 120 if entry["state"] == "maintenance" else 30,
    }
