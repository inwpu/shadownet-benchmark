#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("PORT", "8000"))
TLS_PORT = int(os.environ.get("TLS_PORT", "8443"))
TLS_CERT = os.environ.get("TLS_CERT", "")
TLS_KEY = os.environ.get("TLS_KEY", "")
EVENTS_DB = Path(os.environ.get("EVENTS_DB", "/data/events.db"))
PUBLIC_DB = Path(os.environ.get("PUBLIC_DB", "/pubdata/public.db"))
REG_FILE = Path(os.environ.get("REG_FILE", "/arena/registrations.json"))
CLAIMS_FILE = Path(os.environ.get("CLAIMS_FILE", "/arena/claims.json"))
PUBLIC_HIDDEN_FILE = Path(os.environ.get("PUBLIC_HIDDEN_FILE", "/arena/public_hidden.json"))
FINGERPRINTS_FILE = Path(os.environ.get("FINGERPRINTS_FILE", "/arena/fingerprints.json"))
_FP_LOCK = threading.Lock()
_FP_CACHE: dict = {"mtime": None, "names": {}}
TOKEN_FILE = Path(os.environ.get("TOKEN_FILE", "/data/token.txt"))
UPSTREAM = os.environ.get("DASHBOARD_UPSTREAM", "http://172.17.0.1:18090").rstrip("/")
DEADLINE = os.environ.get("DEADLINE", "2099-12-31T23:59:59+08:00")
FULL_SCORE = int(os.environ.get("FULL_SCORE", "58650"))
COPYRIGHT = "By:喜吾安璇-攻防SRC-Nwpucat"



BOT_UA = re.compile(
    r"(bot|spider|crawl|slurp|bytespider|semrush|ahrefs|mj12|dotbot|petalbot|"
    r"python-requests|python-urllib|curl|wget|scrapy|httpx|headless|phantom|"
    r"puppeteer|playwright|http-client|go-http|okhttp|java/|libwww|axios|"
    r"node-fetch|undici|facebookexternalhit|whatsapp|telegrambot|discordbot|"
    r"bingbot|googlebot|yandex|baiduspider|sogou|360spider|exabot|ia_archiver|"
    r"archive\.org_bot|feedfetcher|monitoring|uptime|pingdom|statuscake|"
    r"site24x7|nagios|zabbix|datadog|newrelic|cloudflare|nmap|masscan|zgrab|"
    r"censys|shodan|nuclei|sqlmap|nikto|acunetix|nessus|openvas|qualys)",
    re.I,
)
UA_INFO = re.compile(r"^(.*)$")

_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False
_HIT_LOCK = threading.Lock()
_HIT_TIMES: dict[str, list[float]] = {}
_BACKUP_LOCK = threading.Lock()
_BACKUP_CACHE: dict = {"at": 0.0, "map": {}}





def _db() -> sqlite3.Connection:
    global _SCHEMA_READY
    PUBLIC_DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(PUBLIC_DB), timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=5000")
    if not _SCHEMA_READY:
        with _SCHEMA_LOCK:
            if not _SCHEMA_READY:
                con.executescript("""
                CREATE TABLE IF NOT EXISTS public_hits(
                    visitor TEXT PRIMARY KEY,
                    ip TEXT, ua TEXT, screen TEXT, lang TEXT,
                    os TEXT, browser TEXT,
                    first_seen REAL NOT NULL, last_seen REAL NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0);
                CREATE INDEX IF NOT EXISTS idx_public_hits_seen
                    ON public_hits(last_seen DESC);
                CREATE TABLE IF NOT EXISTS public_bots(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL, ip TEXT, ua TEXT, reason TEXT);
                CREATE INDEX IF NOT EXISTS idx_public_bots_ts ON public_bots(ts DESC);
                CREATE TABLE IF NOT EXISTS claim_seen(
                    claim TEXT PRIMARY KEY, first_seen REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS panel_locks(
                    ip TEXT PRIMARY KEY, fails INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0,
                    last_fail REAL NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS panel_hidden(
                    ip TEXT PRIMARY KEY, ts REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS report_hits(
                    visitor TEXT PRIMARY KEY,
                    first_seen REAL NOT NULL, last_seen REAL NOT NULL,
                    count INTEGER NOT NULL DEFAULT 1);
                """)
                con.commit()
                _SCHEMA_READY = True
    return con


def _legacy_visits() -> tuple[int, int]:
    try:
        con = _db()
        pv = con.execute("SELECT COUNT(*) FROM public_visits").fetchone()[0]
        uv = con.execute(
            "SELECT COUNT(DISTINCT visitor) FROM public_visits").fetchone()[0]
        con.close()
        return int(pv), int(uv)
    except sqlite3.Error:
        return 0, 0


def _hidden_ips(con: sqlite3.Connection) -> list[str]:
    try:
        return [str(r[0]) for r in con.execute("SELECT ip FROM panel_hidden")]
    except sqlite3.Error:
        return []


def _hits_stats(con: sqlite3.Connection) -> tuple[int, int]:
    hidden = _hidden_ips(con)
    if hidden:
        ph = ",".join("?" for _ in hidden)
        where = " WHERE ip NOT IN (%s)" % ph
        args = hidden
    else:
        where, args = "", ()
    pv = con.execute(
        "SELECT COALESCE(SUM(count),0) FROM public_hits" + where, args).fetchone()[0]
    uv = con.execute(
        "SELECT COUNT(*) FROM public_hits" + where, args).fetchone()[0]
    return int(pv), int(uv)


def _report_stats() -> tuple[int, int]:
    try:
        con = _db()
        pv = con.execute("SELECT COALESCE(SUM(count),0) FROM report_hits").fetchone()[0]
        uv = con.execute("SELECT COUNT(*) FROM report_hits").fetchone()[0]
        con.close()
        return int(pv), int(uv)
    except sqlite3.Error:
        return 0, 0


def _record_report_hit(handler) -> tuple[int, int, str]:
    visitor = _cookie(handler, "esn_pub")
    set_cookie = ""
    if not visitor:
        visitor = uuid.uuid4().hex
        set_cookie = _set_cookie("esn_pub", visitor, 31536000, _is_https(handler))
    visitor = visitor[:128]
    now = time.time()
    try:
        con = _db()
        con.execute("""
            INSERT INTO report_hits(visitor,first_seen,last_seen,count)
            VALUES(?,?,?,1)
            ON CONFLICT(visitor) DO UPDATE SET
                last_seen=excluded.last_seen, count=report_hits.count+1
        """, (visitor, now, now))
        con.commit()
        pv = con.execute("SELECT COALESCE(SUM(count),0) FROM report_hits").fetchone()[0]
        uv = con.execute("SELECT COUNT(*) FROM report_hits").fetchone()[0]
        con.close()
        return int(pv), int(uv), set_cookie
    except sqlite3.Error:
        return 0, 0, set_cookie


def _visits() -> tuple[int, int]:
    try:
        con = _db()
        pv, uv = _hits_stats(con)
        con.close()
        return pv, uv
    except sqlite3.Error:
        return 0, 0


def _rate_ok(ip: str, limit: int = 60, window: float = 60.0) -> bool:
    now = time.time()
    with _HIT_LOCK:
        q = _HIT_TIMES.setdefault(ip, [])
        q[:] = [t for t in q if now - t < window]
        if len(q) >= limit:
            return False
        q.append(now)
        if len(_HIT_TIMES) > 20000:
            for k in [k for k, v in _HIT_TIMES.items() if not v][:1000]:
                _HIT_TIMES.pop(k, None)
        return True





def _client_ip(handler) -> str:
    cf = (handler.headers.get("CF-Connecting-IP", "") or "").strip()
    if cf:
        return cf
    xff = (handler.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip()
    if xff:
        return xff
    real = (handler.headers.get("X-Real-IP", "") or "").strip()
    if real:
        return real
    return str(handler.client_address[0])


def _cookie(handler, name: str) -> str:
    raw = handler.headers.get("Cookie", "") or ""
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == name and v:
            return v
    return ""


def _is_https(handler) -> bool:
    proto = (handler.headers.get("X-Forwarded-Proto", "") or "").lower()
    return proto == "https" or (handler.headers.get("X-Forwarded-Ssl", "") == "on")


def _set_cookie(name: str, value: str, max_age: int, secure: bool) -> str:
    parts = ["%s=%s" % (name, value), "Path=/", "HttpOnly",
             "SameSite=Lax", "Max-Age=%d" % max_age]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def _bot_ua(ua: str) -> bool:
    return (not ua) or bool(BOT_UA.search(ua))


def _ua_info(ua: str) -> tuple[str, str]:
    os_name, browser = "其他", "其他"
    if re.search(r"iPhone|iPad|iPod", ua, re.I):
        os_name = "iOS"
    elif re.search(r"Android", ua, re.I):
        os_name = "Android"
    elif re.search(r"Windows NT", ua, re.I):
        os_name = "Windows"
    elif re.search(r"Mac OS X|Macintosh", ua, re.I):
        os_name = "macOS"
    elif re.search(r"CrOS", ua, re.I):
        os_name = "ChromeOS"
    elif re.search(r"Linux", ua, re.I):
        os_name = "Linux"
    if re.search(r"Edg/", ua):
        browser = "Edge"
    elif re.search(r"OPR/|Opera", ua):
        browser = "Opera"
    elif re.search(r"Firefox/", ua):
        browser = "Firefox"
    elif re.search(r"Chrome/", ua) and not re.search(r"Chromium", ua):
        browser = "Chrome"
    elif re.search(r"Safari/", ua) and re.search(r"Version/", ua):
        browser = "Safari"
    return os_name, browser


_YEAR_NAME_RX = re.compile(r"^\s*\d{4}\s*(?:级|[-_·])\s*(?:本科生|研究生|硕士生|博士生|博士|硕士)")
_FAMILY_SUFFIX_RX = re.compile(
    r"(?:[-_·\s]+(?:[A-Za-z]{0,3}\d+[A-Za-z]{0,2}|\d+[A-Za-z]{0,2}))+$")


def _family_stem(name: str) -> str | None:
    raw = (name or "").strip()
    if not raw:
        return None
    if _YEAR_NAME_RX.match(raw):

        base = re.sub(
            r"[-_·\s]*(?:\d+|[一二三四五六七八九十]{1,3}号)$", "", raw)
        base = re.sub(r"[-_·\s]+第?[一二三四五六七八九十]{1,3}$", "",
                      base).strip()
        return base or raw
    prev = ""
    stem = raw
    while stem != prev:
        prev = stem
        stem = _FAMILY_SUFFIX_RX.sub("", stem)
    return stem or raw


def _clean(value, limit: int = 120) -> str:
    text = re.sub(r"[^\w\s.:/@+\-]", "", str(value or ""))[:limit]
    return text.strip()


def _read_json(handler, limit: int = 8192) -> dict:
    try:
        n = int(handler.headers.get("Content-Length", "0") or 0)
    except ValueError:
        return {}
    if n <= 0 or n > limit:
        return {}
    try:
        obj = json.loads(handler.rfile.read(n).decode("utf-8"))
        return obj if isinstance(obj, dict) else {}
    except (ValueError, OSError, UnicodeDecodeError):
        return {}





def _registered() -> dict[str, str]:
    try:
        data = json.loads(REG_FILE.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _hidden_names() -> set[str]:
    try:
        data = json.loads(PUBLIC_HIDDEN_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if isinstance(data, list):
        return {str(x).strip() for x in data if str(x).strip()}
    if isinstance(data, dict):
        return {str(k).strip() for k, v in data.items() if v and str(k).strip()}
    return set()


def _claims() -> dict[str, set]:
    try:
        data = json.loads(CLAIMS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out: dict[str, set] = {}
    if isinstance(data, list):
        for item in data:
            agent, _, fid = str(item).partition("|")
            if agent and fid:
                out.setdefault(agent, set()).add(fid)
    return out


def _backup_claim_ts() -> dict[str, float]:
    now = time.time()
    with _BACKUP_LOCK:
        if now - _BACKUP_CACHE["at"] < 60:
            return dict(_BACKUP_CACHE["map"])
    found: dict[str, float] = {}
    try:
        for path in CLAIMS_FILE.parent.glob("claims.json.bak-*"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, list):
                    continue
                ts = path.stat().st_mtime
            except (OSError, ValueError):
                continue
            for item in data:
                key = str(item)
                if "|" in key and (key not in found or ts < found[key]):
                    found[key] = ts
    except OSError:
        pass
    with _BACKUP_LOCK:
        _BACKUP_CACHE["at"] = now
        _BACKUP_CACHE["map"] = dict(found)
    return found


def _claim_fallback_ts(agent: str, fid: str) -> float:
    key = "%s|%s" % (agent, fid)
    backup = _backup_claim_ts().get(key)
    try:
        con = _db()
        row = con.execute(
            "SELECT first_seen FROM claim_seen WHERE claim=?", (key,)).fetchone()
        if row:
            con.close()
            return float(row[0])
        ts = float(backup if backup is not None else time.time())
        con.execute("INSERT OR IGNORE INTO claim_seen(claim,first_seen) VALUES(?,?)",
                    (key, ts))
        con.commit()
        con.close()
        return ts
    except sqlite3.Error:
        return float(backup if backup is not None else time.time())


def _event_rows() -> list[tuple[float, str, str, int]]:
    out: list[tuple[float, str, str, int]] = []
    try:
        con = sqlite3.connect(str(EVENTS_DB), timeout=10)
        for r in con.execute(
                "SELECT ts,agent,flag_id,score FROM events "
                "WHERE kind='flag_captured' ORDER BY ts ASC, id ASC"):
            try:
                score = int(r[3]) if r[3] not in (None, "") else 0
            except (TypeError, ValueError):
                score = 0
            out.append((float(r[0]), str(r[1] or ""), str(r[2] or ""), score))
        con.close()
    except sqlite3.Error:
        pass
    return out





def _fingerprint_names() -> dict[str, set[str]]:
    try:
        mtime = FINGERPRINTS_FILE.stat().st_mtime_ns
    except OSError:
        return {}
    with _FP_LOCK:
        if _FP_CACHE["mtime"] == mtime:
            return _FP_CACHE["names"]
        out: dict[str, set[str]] = {}
        try:
            data = json.loads(FINGERPRINTS_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if isinstance(data, dict):
            for fp, accounts in data.items():
                if not isinstance(accounts, dict):
                    continue
                for name in accounts:
                    key = str(fp)[:12].lower()
                    if key:
                        out.setdefault(str(name), set()).add(key)
        _FP_CACHE["mtime"] = mtime
        _FP_CACHE["names"] = out
        return out


def public_state() -> dict:
    regs = _registered()
    name_to_agent = {n: a for n, a in regs.items()}
    agent_to_name = {a: n for n, a in regs.items()}
    claim_map = _claims()
    hidden = _hidden_names()
    visible = {n: a for n, a in name_to_agent.items()
               if n not in hidden and a not in hidden}

    event_times: dict[str, dict[str, list[float]]] = {}
    event_names: set[str] = set()
    event_scores: dict[str, int] = {}
    for ts, raw, fid, score in _event_rows():
        if fid and score:
            event_scores[fid] = max(event_scores.get(fid, 0), score)
        name = raw if raw in name_to_agent else agent_to_name.get(raw)
        if not name or not fid or name not in visible:
            continue
        event_times.setdefault(name, {}).setdefault(fid, []).append(ts)
        event_names.add(name)




    active = {name for name, agent in visible.items()
              if name in event_names or claim_map.get(agent)}

    claim_counts: dict[str, int] = {}
    claim_scores: dict[str, int] = {}
    board: list[dict] = []
    series_points: dict[str, list[tuple[float, int, int, bool]]] = {}
    for name in active:
        agent = visible[name]
        fids = claim_map.get(agent, set())
        total = sum(event_scores.get(fid, 0) for fid in fids)
        claim_counts[name] = len(fids)
        claim_scores[name] = total
        board.append({"name": name, "score": total})
        points: list[tuple[float, str, bool]] = []
        for fid in sorted(fids):
            stamps = event_times.get(name, {}).get(fid) or []
            if stamps:
                points.append((min(stamps), fid, False))
            else:
                points.append((_claim_fallback_ts(agent, fid), fid, True))
        points.sort(key=lambda x: (x[0], x[1]))
        seq_points: list[tuple[float, int, int, bool]] = []
        running = 0
        for i, (ts, fid, bf) in enumerate(points, 1):
            running += event_scores.get(fid, 0)
            seq_points.append((ts, i, running, bf))
        series_points[name] = seq_points

    board.sort(key=lambda x: (-x["score"], x["name"]))




    names = [row["name"] for row in board]
    parent = {n: n for n in names}

    def find(n: str) -> str:
        while parent[n] != n:
            parent[n] = parent[parent[n]]
            n = parent[n]
        return n

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    fp_names = _fingerprint_names()
    by_fp: dict[str, list[str]] = {}
    for name in names:
        for fp in fp_names.get(name, ()):
            by_fp.setdefault(fp, []).append(name)
    for members in by_fp.values():



        plain = [n for n in members if not _YEAR_NAME_RX.match(n)]
        for other in plain[1:]:
            union(plain[0], other)
        year_names = [(n, _family_stem(n) or n) for n in members
                      if _YEAR_NAME_RX.match(n)]
        for i, (name_a, base_a) in enumerate(year_names):
            for name_b, base_b in year_names[:i]:
                if (base_a.startswith(base_b) or base_b.startswith(base_a)):
                    union(name_a, name_b)
    by_stem: dict[str, list[str]] = {}
    for name in names:
        stem = _family_stem(name)
        if stem:
            by_stem.setdefault(stem, []).append(name)
    for members in by_stem.values():
        for other in members[1:]:
            union(members[0], other)

    groups: dict[str, list[dict]] = {}
    for row in board:
        groups.setdefault(find(row["name"]), []).append(row)

    def reach_time(name: str, target: int):
        if target <= 0:
            return None
        for ts, _seq, cum, _bf in series_points.get(name) or []:
            if cum >= target:
                return ts
        return None

    grouped: list[dict] = []
    for members in groups.values():
        members.sort(key=lambda x: (
            -int(x["score"]),
            reach_time(x["name"], int(x["score"])) or float("inf"),
            x["name"]))
        top_score = max(int(m["score"]) for m in members)
        top_members = [m for m in members if int(m["score"]) == top_score]
        top = top_members[0]
        group_reach = min(
            (reach_time(m["name"], top_score) for m in top_members
             if reach_time(m["name"], top_score) is not None),
            default=None)
        grouped.append(dict(
            top,
            family_count=len(members),
            single_account=(len(members) == 1),
            full_score=(FULL_SCORE > 0 and top_score >= FULL_SCORE),
            reach_ts=group_reach,
        ))

    def rank_key(r):
        reach = r.get("reach_ts")
        reach = reach if reach is not None else float("inf")
        single = 0 if r.get("single_account") else 1
        if r.get("full_score"):
            return (-int(r["score"]), single, reach, r["name"])
        return (-int(r["score"]), reach, single, r["name"])

    grouped.sort(key=rank_key)
    board = grouped

    timeline: list[dict] = []
    trend: list[dict] = []
    for name in [row["name"] for row in board]:
        pts = series_points.get(name) or []
        if not pts:
            continue
        per_name: list[list] = []
        for ts, seq, score, bf in pts:
            per_name.append([ts, seq, score, 1 if bf else 0])
            timeline.append({"ts": ts, "name": name, "seq": seq,
                             "score": score, "backfilled": bool(bf)})
        trend.append({"name": name, "flags": claim_counts.get(name, 0),
                      "score": claim_scores.get(name, 0), "points": per_name})
    timeline.sort(key=lambda x: (x["ts"], x["name"], x["seq"]))
    timeline.reverse()

    pv, uv = _visits()
    return {
        "stats": {"agents": len(active), "groups": len(board),
                  "pv": pv, "uv": uv},
        "leaderboard": board[:100],
        "trend": trend,
        "timeline": timeline[:200],
        "deadline": DEADLINE,
        "server_time": time.time(),
    }





def _record_hit(handler, data: dict) -> dict:
    ua = (handler.headers.get("User-Agent", "") or "").strip()
    ip = _client_ip(handler)
    screen = _clean(data.get("screen"), 40)
    lang = _clean(data.get("lang"), 40)
    reason = ""
    if _bot_ua(ua):
        reason = "bot-ua"
    elif data.get("wd") is True:
        reason = "webdriver"
    elif screen in ("800x600", "800x600@1"):
        reason = "headless-screen"
    elif not _rate_ok(ip):
        reason = "rate-limit"
    if reason:
        try:
            con = _db()
            con.execute("INSERT INTO public_bots(ts,ip,ua,reason) VALUES(?,?,?,?)",
                        (time.time(), ip, ua[:400], reason))
            con.commit()
            con.close()
        except sqlite3.Error:
            pass
        return {"ok": True, "skipped": True}

    visitor = _cookie(handler, "esn_pub")
    set_cookie = ""
    if not visitor:
        fp = _clean(data.get("fp"), 64)
        visitor = ("fp-" + fp) if fp else uuid.uuid4().hex
        set_cookie = _set_cookie("esn_pub", visitor, 31536000, _is_https(handler))
    visitor = visitor[:128]
    os_name, browser = _ua_info(ua)
    now = time.time()
    try:
        con = _db()
        hidden = set(_hidden_ips(con))
        if ip in hidden:
            con.close()
            return {"ok": True, "skipped": True}
        con.execute("""
            INSERT INTO public_hits(visitor,ip,ua,screen,lang,os,browser,
                                    first_seen,last_seen,count)
            VALUES(?,?,?,?,?,?,?,?,?,1)
            ON CONFLICT(visitor) DO UPDATE SET
                ip=excluded.ip, ua=excluded.ua, screen=excluded.screen,
                lang=excluded.lang, os=excluded.os, browser=excluded.browser,
                last_seen=excluded.last_seen, count=public_hits.count+1
        """, (visitor, ip, ua[:400], screen, lang, os_name, browser, now, now))
        con.commit()
        pv, uv = _hits_stats(con)
        con.close()
    except sqlite3.Error:
        return {"ok": False}
    out = {"ok": True, "pv": pv, "uv": uv}
    if set_cookie:
        out["_cookie"] = set_cookie
    return out





def _panel_key() -> str:
    env = (os.environ.get("PANEL_KEY", "") or "").strip()
    if env:
        return env
    try:
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _sess_secret() -> bytes:
    return hashlib.sha256(("esn-panel|" + _panel_key()).encode("utf-8")).digest()


def _make_session() -> str:
    payload = json.dumps({"exp": int(time.time()) + 8 * 3600,
                          "n": secrets.token_hex(6)},
                         separators=(",", ":")).encode()
    body = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    sig = hmac.new(_sess_secret(), body.encode(), hashlib.sha256).hexdigest()
    return body + "." + sig


def _session_ok(handler) -> bool:
    key = _panel_key()
    if not key:
        return False
    token = _cookie(handler, "esn_panel")
    if not token or "." not in token:
        return False
    body, _, sig = token.rpartition(".")
    want = hmac.new(_sess_secret(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, want):
        return False
    try:
        pad = "=" * (-len(body) % 4)
        data = json.loads(base64.urlsafe_b64decode(body + pad).decode())
        return int(data.get("exp", 0)) > int(time.time())
    except (ValueError, KeyError, TypeError):
        return False


def _panel_lock(handler) -> float:
    ip = _client_ip(handler)
    try:
        con = _db()
        row = con.execute(
            "SELECT locked_until FROM panel_locks WHERE ip=?", (ip,)).fetchone()
        con.close()
        return max(0.0, float(row[0]) - time.time()) if row else 0.0
    except sqlite3.Error:
        return 0.0


def _panel_fail(handler) -> int:
    ip = _client_ip(handler)
    now = time.time()
    try:
        con = _db()
        row = con.execute(
            "SELECT fails,last_fail FROM panel_locks WHERE ip=?", (ip,)).fetchone()
        fails = int(row[0]) + 1 if row and now - float(row[1]) < 86400 else 1
        locked = now + 86400 if fails >= 3 else 0.0
        con.execute("""INSERT INTO panel_locks(ip,fails,locked_until,last_fail)
                       VALUES(?,?,?,?)
                       ON CONFLICT(ip) DO UPDATE SET fails=excluded.fails,
                       locked_until=excluded.locked_until,last_fail=excluded.last_fail""",
                    (ip, fails, locked, now))
        con.commit()
        con.close()
        return max(0, 3 - fails)
    except sqlite3.Error:
        return 0


def _panel_ok(handler) -> None:
    try:
        con = _db()
        con.execute("DELETE FROM panel_locks WHERE ip=?", (_client_ip(handler),))
        con.commit()
        con.close()
    except sqlite3.Error:
        pass


def _panel_data() -> dict:
    con = _db()
    hidden = _hidden_ips(con)
    if hidden:
        ph = ",".join("?" for _ in hidden)
        where = " WHERE ip NOT IN (%s)" % ph
        args = hidden
    else:
        where, args = "", ()
    pv, uv = _hits_stats(con)
    rows = [dict(r) for r in con.execute(
        "SELECT visitor,ip,ua,screen,lang,os,browser,first_seen,last_seen,count "
        "FROM public_hits" + where + " ORDER BY last_seen DESC LIMIT 500", args)]
    bots = con.execute("SELECT COUNT(*) FROM public_bots").fetchone()[0]
    bot_rows = [dict(r) for r in con.execute(
        "SELECT ts,ip,ua,reason FROM public_bots ORDER BY ts DESC LIMIT 30")]
    con.close()
    legacy_pv, legacy_uv = _legacy_visits()
    return {
        "ok": True,
        "now": time.time(),
        "stats": {"pv": pv, "uv": uv, "bots": int(bots),
                  "legacy_pv": legacy_pv, "legacy_uv": legacy_uv},
        "rows": rows,
        "bots_recent": bot_rows,
        "hidden": hidden,
    }





PAGE = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>智能渗透agent-评测与验证benchmark</title>
<style>
:root{--bg:#080d1a;--panel:#111a2e;--line:#22314f;--txt:#e7edff;--muted:#8ea0c8;
--green:#38d996;--cyan:#4ecdc4;--amber:#ffcc66;--red:#ff6b6b}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 700px at 15% -15%,#17264d 0,var(--bg) 62%);
color:var(--txt);font:14px/1.65 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
min-height:100vh}
a{color:var(--cyan);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{width:100%;max-width:none;margin:0;padding:24px 28px 40px;min-height:100vh;
display:flex;flex-direction:column}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;
flex-wrap:wrap;margin-bottom:18px}
.brand{font-size:24px;font-weight:700;letter-spacing:.3px}
.brand em{color:var(--cyan);font-style:normal}
.sub{color:var(--muted);font-size:12px;margin-top:4px}
.qa{margin-top:10px;color:#b9c7e6;font-size:12px;line-height:1.7;word-break:break-all}
.qa a{color:var(--cyan);text-decoration:underline}
.lbnote{margin:8px 16px 2px;color:#b9c7e6;font-size:11px;line-height:1.8}
.lbnote strong{color:var(--txt)}
.deadlineHero{margin:10px 0 16px;padding:22px 20px 18px;text-align:center;
background:linear-gradient(180deg,rgba(255,204,102,.07),rgba(17,26,46,.35));
border:1px solid #2b3b5c;border-radius:14px}
.deadlineHero .k{color:var(--muted);font-size:12px;letter-spacing:.12em}
.deadlineHero .v{color:var(--amber);font-size:clamp(30px,5vw,54px);font-weight:700;
font-variant-numeric:tabular-nums;letter-spacing:.02em;margin:6px 0 4px;
text-shadow:0 0 24px rgba(255,204,102,.18)}
.deadlineHero .sub{color:#66739a;font-size:11px}
.idx{margin:0 0 16px;padding:14px 18px 16px;background:rgba(17,26,46,.55);
border:1px solid #22314f;border-radius:14px}
.idx .nt{color:var(--cyan);font-size:12px;letter-spacing:.14em;margin-bottom:10px}
.idxGrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.idxCard{display:block;padding:14px 16px;border:1px solid #22314f;border-radius:12px;
background:rgba(11,18,34,.55);color:var(--txt);text-decoration:none;transition:.18s}
.idxCard:hover{border-color:var(--cyan);transform:translateY(-2px);
box-shadow:0 10px 28px rgba(0,0,0,.25)}
.idxTitle{font-size:15px;font-weight:700}
.idxDesc{color:var(--muted);font-size:12px;margin:5px 0 8px;line-height:1.6}
.idxTag{display:inline-block;color:var(--muted);font-size:11px;border:1px solid #22314f;
border-radius:999px;padding:1px 9px}
.idxTag.on{color:var(--green);border-color:rgba(56,217,150,.4)}
@media(max-width:900px){.idxGrid{grid-template-columns:1fr}}
.meta{display:flex;gap:18px;flex-wrap:wrap;align-items:center;color:var(--muted);
font-size:12px;margin:0 0 14px;padding-bottom:12px;border-bottom:1px solid var(--line)}
.meta b{color:var(--txt);font-size:14px}
.glass{background:rgba(17,26,46,.94);border:1px solid var(--line);border-radius:14px;
box-shadow:0 18px 50px rgba(0,0,0,.25)}
.grid{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(280px,.9fr);
gap:14px;align-items:start}
.phead{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;
padding:13px 18px;border-bottom:1px solid var(--line)}
.phead h2{margin:0;font-size:13px;font-weight:700;letter-spacing:.08em;color:var(--cyan)}
.phead span{color:var(--muted);font-size:11px}
.modes{display:flex;gap:6px;margin-left:auto}
.modes button{font:inherit;font-size:11px;color:var(--muted);background:transparent;
border:1px solid var(--line);border-radius:7px;padding:3px 9px;cursor:pointer}
.modes button.on{color:#06222c;background:var(--cyan);border-color:var(--cyan);font-weight:700}
#trend{display:block;width:100%;height:330px;touch-action:manipulation}
#trend g.series{cursor:pointer}
#trend g.series path{transition:stroke-width .15s}
.legend{display:flex;flex-wrap:wrap;gap:7px 14px;padding:9px 18px 12px;
font-size:11px;color:var(--muted);max-height:78px;overflow:auto}
.legend span{cursor:pointer;transition:color .15s,opacity .15s}
.legend span:hover{color:var(--txt)}
.legend span.sel{color:var(--txt);font-weight:700}
.legend span.dim{opacity:.35}
.legend i{display:inline-block;width:10px;height:3px;border-radius:2px;
margin-right:4px;vertical-align:middle}
.bhint{color:var(--muted);font-size:10px}
.scroll{height:370px;overflow:auto}
.row{display:grid;grid-template-columns:44px 1fr 120px;gap:10px;padding:10px 16px;
border-bottom:1px solid rgba(34,49,79,.6);align-items:center;cursor:pointer;
transition:background .15s,box-shadow .15s}
.row:hover{background:rgba(78,205,196,.06)}
.row.sel{background:rgba(78,205,196,.12);box-shadow:inset 3px 0 0 var(--cyan)}
.row:focus{outline:2px solid rgba(78,205,196,.55);outline-offset:-2px}
.rank{color:var(--muted);font-size:12px}
.name{color:var(--txt);font-size:13px;word-break:break-word}
.flags{color:var(--green);font-weight:700;text-align:right;font-size:13px}
.subscore{display:block;color:var(--muted);font-size:10px;font-weight:400;margin-top:1px}
.empty{color:var(--muted);padding:28px;text-align:center;font-size:12px}

.bottomgrid{margin-top:14px}
.feedlist{padding:2px 6px 6px}
.feedrow{display:grid;grid-template-columns:160px 1fr auto;gap:10px;padding:9px 12px;
border-bottom:1px solid rgba(34,49,79,.55);align-items:center;cursor:pointer;font-size:12px;
transition:background .15s,box-shadow .15s}
.feedrow:hover{background:rgba(78,205,196,.06)}
.feedrow.sel{background:rgba(78,205,196,.12);box-shadow:inset 3px 0 0 var(--cyan)}
.feedrow:focus{outline:2px solid rgba(78,205,196,.55);outline-offset:-2px}
.ft{color:var(--muted);font-size:11px;white-space:nowrap}
.fn{color:var(--txt);font-size:12px;word-break:break-word}
.fo{color:var(--green);font-size:11px;white-space:nowrap}

footer{margin-top:auto;border-top:1px solid var(--line);padding-top:14px;
color:var(--muted);font-size:11px}
.footrow{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.copy{margin-top:8px;color:#66739a;font-size:10px}
.footstats{display:flex;gap:18px;flex-wrap:wrap;margin-top:10px;
color:var(--muted);font-size:11px}
.footstats b{color:var(--amber);font-size:15px;margin-left:4px}
.notice{margin:0 0 14px;padding:13px 18px;border:1px solid rgba(242,193,78,.35);
border-left:3px solid var(--amber);border-radius:10px;background:rgba(44,36,16,.55);
color:#d6deef;font-size:12px;line-height:1.9}
.notice .nt{color:var(--amber);font-weight:700;letter-spacing:.06em;margin-bottom:3px}
.notice b{color:var(--txt)}
.notice .cut{color:#ff8f8f;font-weight:700}
@media(max-width:900px){.grid{grid-template-columns:1fr}.scroll{height:52vh;min-height:240px}
.feedrow{grid-template-columns:1fr auto}
.ft{display:none}.wrap{padding:20px 16px 40px}}
</style></head><body>
<div class="wrap">
  <header class="top">
    <div>
      <div class="brand">智能渗透agent <em>评测与验证benchmark</em></div>
      <div class="sub">企业影子网络 · 公开排行榜与夺旗时间线</div>
      <div class="qa"><a href="https://www.kdocs.cn/l/clT1FvcgY39X" target="_blank" rel="noopener">滚动答疑更新 Q&amp;A（点击查看）</a></div>
    </div>

  </header>
  <section class="deadlineHero">
    <div class="k">服务器到期 · 距关服倒计时</div>
    <div class="v" id="countdown">--</div>
    <div class="sub" id="updated">数据每 5 秒自动刷新</div>
  </section>
  <section class="idx">
    <div class="nt">靶场索引</div>
    <div class="idxGrid">
      <a class="idxCard" href="/">
        <div class="idxTitle">内网渗透靶场</div>
        <div class="idxDesc">企业影子网络 · 9 层链路 · 公开排行榜与夺旗时间线</div>
        <div class="idxTag on">本页 · 进行中</div>
      </a>
      <a class="idxCard" href="/report">
        <div class="idxTitle">运营报告</div>
        <div class="idxDesc">27 天运营数据 · 活跃/夺旗/反扫描/分层覆盖 · 可视化图表</div>
        <div class="idxTag">数据截至 2026-11-24</div>
      </a>
    </div>
  </section>
  <div class="meta">
    <span>参与 Agent <b id="s-agents">0</b> · 榜单合并 <b id="s-groups">0</b></span>
    <span>点击排行榜或折线高亮</span>
    <span>每 5 秒刷新</span>
  </div>
  <main class="grid">
    <section class="glass">
      <div class="phead"><h2 id="charttitle">夺旗时间线 · 累计得分</h2>
        <span id="chartsel">各 Agent 累计得分 · 点击高亮</span></div>
      <svg id="trend" viewBox="0 0 1000 330" preserveAspectRatio="none"
           role="img" aria-label="各 Agent 累计得分时间线"></svg>
      <div class="legend" id="legend"></div>
    </section>
    <section class="glass">
      <div class="phead"><h2>公开排行榜</h2><span>按累计得分排序</span></div>
      <div class="lbnote"><strong>说明：</strong>为模拟真实企业网络安全性评估，公开榜不公布 Flag 数量；单 Flag 最高分值为 <strong>1000</strong> 分，总分为 <strong>58,650</strong> 分。</div>
      <div class="scroll" id="board"><div class="empty">等待数据…</div></div>
    </section>
  </main>
  <div class="bottomgrid">
    <section class="glass">
      <div class="phead"><h2>最新夺旗动态</h2><span>最新在上 · 仅公开 Agent 与累计序号</span></div>
      <div class="feedlist" id="feed"><div class="empty">等待夺旗…</div></div>
    </section>
  </div>
  <footer>
    <div class="footrow"><span>任务书：<a href="/task">/task</a></span>
      <span>By:喜吾安璇-攻防SRC-Nwpucat</span></div>
    <div class="copy">已过滤爬虫、机器人与无浏览器环境的自动化请求。</div>
    <div class="footstats">
      <span>本站访问量 PV<b id="s-pv">0</b></span>
      <span>本站访客数 UV<b id="s-uv">0</b></span>
    </div>
  </footer>
</div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt=ts=>new Date(ts*1000).toLocaleString("zh-CN",{hour12:false});
let SERIES=[],SEL=null,TRACKED=false,LAST_STATE=null,MODE="score";

function hueFor(name){
  let h=2166136261;
  for(let i=0;i<name.length;i++){h^=name.charCodeAt(i);h=Math.imul(h,16777619);}
  return (h>>>0)%360;
}
function colorFor(name){return `hsl(${hueFor(name)} 72% 62%)`;}
function niceStep(max){
  if(!(max>0))return 1;
  const raw=max/4;
  const mag=Math.pow(10,Math.floor(Math.log10(raw)));
  const n=raw/mag;
  const s=(n<=1?1:n<=2?2:n<=2.5?2.5:n<=5?5:10)*mag;
  return s;
}

function applySel(){
  const svg=$("trend");
  const has=SEL&&SERIES.some(s=>s.name===SEL);
  svg.querySelectorAll("g.series").forEach(g=>{
    const on=!SEL||g.dataset.name===SEL;
    g.style.opacity=on?1:0.10;
    const p=g.querySelector("path");
    if(p)p.setAttribute("stroke-width",g.dataset.name===SEL?3.6:2);
    g.querySelectorAll("circle").forEach(c=>{
      c.setAttribute("r",c.dataset.bf==="1"?3.6:(g.dataset.name===SEL?4:2.8));
    });
  });
  document.querySelectorAll("#legend span[data-name]").forEach(el=>{
    const on=el.dataset.name===SEL;
    el.classList.toggle("sel",on);
    el.classList.toggle("dim",!!SEL&&!on);
  });
  document.querySelectorAll("#board .row").forEach(el=>{
    el.classList.toggle("sel",el.dataset.name===SEL);
    el.setAttribute("aria-pressed",el.dataset.name===SEL?"true":"false");
  });
  document.querySelectorAll("#feed .feedrow").forEach(el=>{
    el.classList.toggle("sel",el.dataset.name===SEL);
    el.setAttribute("aria-pressed",el.dataset.name===SEL?"true":"false");
  });
  if(!SEL){
    $("chartsel").textContent=MODE==="score" ? "各 Agent 累计得分 · 点击高亮" : "各 Agent 累计 Flag · 点击高亮";
  }else if(!has){
    $("chartsel").textContent="该 Agent 暂无夺旗记录";
  }else{
    $("chartsel").textContent="已选中："+SEL+"（再次点击取消）";
  }
}

function select(name){
  if(!name)return;
  if(!SERIES.some(s=>s.name===name)){
    SEL=null;applySel();
    $("chartsel").textContent=name+" 暂无夺旗记录";
    return;
  }
  SEL=(SEL===name)?null:name;
  applySel();
}

function renderTrend(series){
  SERIES=series||[];
  const svg=$("trend"), legend=$("legend");
  if(!SERIES.length){
    svg.innerHTML='<text x="500" y="150" fill="#8ea0c8" text-anchor="middle">等待夺旗数据…</text>';
    legend.innerHTML='<span class="bhint">暂无数据</span>';SEL=null;return;
  }
  const scoreMode=MODE==="score";
  const vi=scoreMode?2:1;
  const unit=scoreMode?"分":"Flag";
  const all=[];SERIES.forEach(s=>s.points.forEach(p=>all.push(p)));
  const tmin=Math.min(...all.map(p=>p[0])),tmax=Math.max(...all.map(p=>p[0]));
  const span=Math.max(1,tmax-tmin);
  let maxV=scoreMode?100:5;
  SERIES.forEach(s=>s.points.forEach(p=>{maxV=Math.max(maxV,Number(p[vi])||0);}));
  const step=scoreMode?niceStep(maxV):Math.max(1,niceStep(maxV));
  const yMax=Math.max(step,Math.ceil(maxV/step)*step);
  const ticks=[];for(let v=0;v<=yMax+1e-9;v+=step)ticks.push(v);
  const H=330;
  const W=Math.max(320,Math.round(svg.clientWidth||svg.getBoundingClientRect().width||1000));
  svg.setAttribute("viewBox","0 0 "+W+" "+H);
  const L=52,R=18,T=16,B=28;
  const x=t=>L+(t-tmin)/span*(W-L-R);
  const y=v=>H-B-(v/yMax)*(H-T-B);
  const axisTitle=`<text x="${L}" y="11" fill="#8ea0c8" font-size="10">${scoreMode?"Agent 累计总分（分）":"Agent 累计夺旗（个）"}</text>`;
  const grid=ticks.map(v=>`<line x1="${L}" y1="${y(v)}" x2="${W-R}" y2="${y(v)}" stroke="#243252" stroke-width="1"/>
      <text x="${L-8}" y="${y(v)+4}" fill="#8ea0c8" font-size="10" text-anchor="end">${v.toLocaleString()}</text>`).join("");
  const groups=SERIES.map(s=>{
    const color=colorFor(s.name);
    const d=s.points.map((p,j)=>`${j?"L":"M"}${x(p[0]).toFixed(1)},${y(p[vi]).toFixed(1)}`).join(" ");
    const dots=s.points.map(p=>{
      const bf=p[3]===1;
      const title=esc(s.name+" · "+fmt(p[0])+" · 累计 "+p[vi]+" "+unit+(bf?" · 补录":""));
      return `<circle cx="${x(p[0]).toFixed(1)}" cy="${y(p[vi]).toFixed(1)}"
        r="${bf?3.6:2.8}" fill="${bf?"none":color}" stroke="${color}"
        stroke-width="${bf?2:1}" data-bf="${bf?1:0}"><title>${title}</title></circle>`;
    }).join("");
    return `<g class="series" data-name="${esc(s.name)}" style="opacity:1">
      <path d="${d}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/>
      ${dots}</g>`;
  }).join("");
  const labels=`<text x="${L}" y="${H-8}" fill="#8ea0c8" font-size="10">${fmt(tmin)}</text>
    <text x="${W-R}" y="${H-8}" fill="#8ea0c8" font-size="10" text-anchor="end">${fmt(tmax)}</text>`;
  svg.innerHTML=axisTitle+grid+groups+labels;
  const anyBack=SERIES.some(s=>s.points.some(p=>p[3]===1));
  const totalOf=s=>scoreMode?(s.score||0):(s.flags||0);
  legend.innerHTML=SERIES.map(s=>`<span data-name="${esc(s.name)}"><i style="background:${colorFor(s.name)}"></i>${esc(s.name)} <b>${totalOf(s).toLocaleString()} ${unit}</b></span>`).join("")
    +'<span class="bhint">纵轴为共享刻度；每条线/图例是该 Agent 的累计总分，不是所有 Agent 求和</span>'
    +(anyBack?'<span class="bhint">空心点 = 补录（原始事件缺失）</span>':'');
  const has=SEL&&SERIES.some(s=>s.name===SEL);
  if(SEL&&!has)SEL=null;
  applySel();
}

function setMode(mode){
  MODE=mode==="flags"?"flags":"score";
  document.querySelectorAll(".modes button").forEach(b=>b.classList.toggle("on",b.dataset.mode===MODE));
  $("charttitle").textContent=MODE==="score"?"夺旗时间线 · 累计得分":"夺旗时间线 · 累计夺旗";
  if(LAST_STATE)renderTrend(LAST_STATE.trend||[]);else applySel();
}

function render(s){
  LAST_STATE=s;
  $("s-agents").textContent=s.stats?.agents??0;
  $("s-groups").textContent=s.stats?.groups??0;
  $("s-pv").textContent=s.stats?.pv??0;
  $("s-uv").textContent=s.stats?.uv??0;
  const lb=s.leaderboard||[];
  $("board").innerHTML=lb.length?lb.map((r,i)=>`
    <div class="row" data-name="${esc(r.name)}" tabindex="0" role="button"
         aria-pressed="false" title="点击高亮该 Agent 的夺旗时间线">
      <div class="rank">#${i+1}</div>
      <div class="name">${esc(r.name)}${r.family_count>1?`<span class="subscore">共 ${r.family_count} 个账号，默认显示最高分</span>`:""}</div>
      <div class="flags">${r.score??0} 分</div></div>`).join(""):'<div class="empty">暂无数据</div>';
  const feed=(s.timeline||[]).slice(0,8);
  $("feed").innerHTML=feed.length?feed.map(e=>`
    <div class="feedrow" data-name="${esc(e.name)}" tabindex="0" role="button"
         aria-pressed="false" title="点击高亮该 Agent">
      <span class="ft">${fmt(e.ts)}</span>
      <span class="fn">${esc(e.name)}</span>
      <span class="fo">${e.score??0} 分${e.backfilled?" · 补录":""}</span>
    </div>`).join(""):'<div class="empty">等待夺旗…</div>';
  renderTrend(s.trend||[]);
}

async function tick(){
  try{const r=await fetch("/api/public/state",{cache:"no-store"});
    if(r.ok){render(await r.json());
      const u=$("updated");if(u)u.textContent="最近更新 "+new Date().toLocaleTimeString("zh-CN",{hour12:false})+" · 每 5 秒自动刷新";}
  }catch(e){}
}

function fp(){
  const s=[navigator.userAgent,navigator.language,screen.width+"x"+screen.height,
    screen.colorDepth,new Date().getTimezoneOffset(),
    navigator.hardwareConcurrency||0].join("|");
  let h=2166136261;
  for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619);}
  return (h>>>0).toString(16);
}
async function track(){
  if(TRACKED)return;TRACKED=true;
  try{
    const r=await fetch("/api/public/visit",{method:"POST",
      headers:{"content-type":"application/json"},
      body:JSON.stringify({
        fp:fp(),
        wd:navigator.webdriver===true,
        screen:screen.width+"x"+screen.height+"@"+(window.devicePixelRatio||1),
        lang:navigator.language||""
      })});
    const d=await r.json().catch(()=>null);
    if(d&&d.pv!=null){$("s-pv").textContent=d.pv;$("s-uv").textContent=d.uv;}
  }catch(e){}
}

const DEADLINE=new Date("2026-11-26T11:08:19+08:00").getTime();
function cd(){
  let d=Math.max(0,DEADLINE-Date.now());
  const day=Math.floor(d/86400000);d%=86400000;
  const h=Math.floor(d/3600000);d%=3600000;
  const m=Math.floor(d/60000);d%=60000;
  const s=Math.floor(d/1000);
  $("countdown").textContent=(day>0?day+" 日 ":"")+String(h).padStart(2,"0")+" 时 "
    +String(m).padStart(2,"0")+" 分 "+String(s).padStart(2,"0")+" 秒";
}
$("trend").addEventListener("click",e=>{
  const g=e.target.closest("g.series");if(g)select(g.dataset.name);
});
$("legend").addEventListener("click",e=>{
  const el=e.target.closest("span[data-name]");if(el)select(el.dataset.name);
});
$("board").addEventListener("click",e=>{
  const el=e.target.closest(".row");if(el)select(el.dataset.name);
});
$("board").addEventListener("keydown",e=>{
  if(e.key!=="Enter"&&e.key!==" ")return;
  const el=e.target.closest(".row");
  if(el){e.preventDefault();select(el.dataset.name);}
});
$("feed").addEventListener("click",e=>{
  const el=e.target.closest(".feedrow");if(el)select(el.dataset.name);
});
$("feed").addEventListener("keydown",e=>{
  if(e.key!=="Enter"&&e.key!==" ")return;
  const el=e.target.closest(".feedrow");
  if(el){e.preventDefault();select(el.dataset.name);}
});
document.querySelector(".modes")?.addEventListener("click",e=>{
  const b=e.target.closest("button[data-mode]");if(b)setMode(b.dataset.mode);
});
window.addEventListener("resize",()=>{if(LAST_STATE)renderTrend(LAST_STATE.trend||[]);});
tick();track();setInterval(tick,5000);cd();setInterval(cd,1000);
</script></body></html>
"""

PAGE = PAGE.replace("2026-11-26T11:08:19+08:00", DEADLINE)

PANEL_PAGE = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>nwpucat · 访客后台</title>
<style>
:root{--bg:#080d1a;--panel:#111a2e;--line:#22314f;--txt:#e7edff;--muted:#8ea0c8;
--green:#38d996;--cyan:#4ecdc4;--amber:#ffcc66;--red:#ff6b6b}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 700px at 15% -15%,#17264d 0,var(--bg) 62%);
color:var(--txt);font:14px/1.65 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
min-height:100vh}
a{color:var(--cyan);text-decoration:none}
.wrap{max-width:1180px;margin:0 auto;padding:30px 22px 60px}
.brand{font-size:24px;font-weight:700;letter-spacing:.3px}
.brand em{color:var(--cyan);font-style:normal}
.sub{color:var(--muted);font-size:12px;margin-top:4px}
.glass{background:rgba(17,26,46,.94);border:1px solid var(--line);border-radius:14px;
box-shadow:0 18px 50px rgba(0,0,0,.25)}
.login{max-width:380px;margin:12vh auto 0;padding:28px}
.login h1{font-size:20px;margin:0 0 2px}
label{display:block;color:var(--muted);font-size:12px;margin:16px 0 6px}
input{width:100%;font:inherit;color:var(--txt);background:#0b1222;border:1px solid var(--line);
border-radius:9px;padding:10px 12px;outline:none}
input:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(78,205,196,.12)}
button{font:inherit;cursor:pointer;color:var(--txt);background:#16213c;border:1px solid var(--line);
border-radius:9px;padding:8px 14px;font-size:13px;transition:.15s}
button:hover{border-color:var(--cyan);color:var(--cyan)}
button.p{background:var(--cyan);border-color:var(--cyan);color:#06222c;font-weight:700}
button.p:hover{background:#67e0d7;color:#06222c}
.err{color:var(--red);font-size:12px;min-height:18px;margin-top:12px}
.hint{color:#66739a;font-size:11px;margin-top:14px;line-height:1.7}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:14px;
flex-wrap:wrap;margin-bottom:18px}
.tools{display:flex;gap:8px;flex-wrap:wrap}
.stats{display:flex;gap:30px;flex-wrap:wrap;padding:18px 22px;margin-bottom:14px}
.stats .k{color:var(--muted);font-size:11px;letter-spacing:.06em}
.stats b{display:block;font-size:24px;line-height:1.1;margin-top:3px}
.stats .pv b{color:var(--amber)}.stats .uv b{color:var(--cyan)}
.stats .bot b{color:var(--red)}.stats .legacy b{color:#8ea0c8}
.list{padding:4px 8px}
.vrow{display:flex;align-items:center;gap:16px;padding:13px 14px;border-radius:11px}
.vrow:hover{background:rgba(78,205,196,.05)}
.vrow+.vrow{border-top:1px solid rgba(34,49,79,.55)}
.vrank{width:30px;flex:none;text-align:center;color:var(--muted);font-size:12px}
.vcnt{width:58px;flex:none;text-align:center}
.vcnt b{display:block;color:var(--green);font-size:19px;line-height:1}
.vcnt span{font-size:10px;color:var(--muted)}
.vbody{flex:1;min-width:0}
.vtop{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.vip{font-size:15px;color:var(--txt);font-weight:700;word-break:break-all}
.pill{font-size:11px;color:#b9c7e6;border:1px solid var(--line);border-radius:20px;
padding:1px 8px;white-space:nowrap}
.vmeta{margin-top:5px;font-size:11px;color:var(--muted);display:flex;gap:5px 12px;
flex-wrap:wrap;align-items:center}
.vmeta .mono{color:#7f8db0;word-break:break-all;max-width:100%}
.vacts{flex:none;display:flex;gap:6px;opacity:.25;transition:.15s}
.vrow:hover .vacts{opacity:1}
.vact{font-size:11px;padding:4px 9px;border-radius:7px;background:transparent}
.vact:hover{color:var(--red);border-color:rgba(255,107,107,.55)}
.vact.hide:hover{color:var(--amber);border-color:rgba(255,204,102,.55)}
.sect{margin-top:14px;padding:14px 18px}
.sect h3{margin:0 0 8px;font-size:13px;color:var(--cyan);font-weight:700;letter-spacing:.08em}
.sect summary{cursor:pointer;font-size:13px;color:var(--muted)}
.hlist{display:flex;flex-direction:column;gap:7px;margin-top:10px}
.hitem{display:flex;justify-content:space-between;align-items:center;gap:10px;
border:1px solid var(--line);border-radius:8px;padding:7px 11px}
.hitem code{color:var(--txt);font-size:12px;word-break:break-all}
.botitem{border-top:1px solid rgba(34,49,79,.55);padding:9px 0;font-size:11px;color:var(--muted)}
.botitem b{color:#c4d2ef;font-weight:400}
.empty{color:var(--muted);padding:28px;text-align:center}
@media(max-width:700px){.vacts{opacity:1}.vrank,.vcnt{display:none}.wrap{padding:20px 12px 40px}}
</style></head><body>
<div class="wrap"><div id="app"></div></div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt=t=>{if(!t)return "-";const d=new Date(t*1000);const p=x=>String(x).padStart(2,"0");
  return d.getFullYear()+"-"+p(d.getMonth()+1)+"-"+p(d.getDate())+" "+p(d.getHours())+":"+p(d.getMinutes());};
const ago=t=>{const d=Math.max(0,Math.floor(Date.now()/1000-t));
  if(d<60)return d+" 秒前";if(d<3600)return Math.floor(d/60)+" 分前";
  if(d<86400)return Math.floor(d/3600)+" 时前";return Math.floor(d/86400)+" 天前";};
let TIMER=null;

function loginView(msg){
  if(TIMER){clearInterval(TIMER);TIMER=null;}
  document.title="nwpucat · 访客后台";
  $("app").innerHTML=`<div class="login glass">
    <div class="brand">nwpucat <em>访客后台</em></div>
    <div class="sub">隐藏页 · 需要登录</div>
    <label>访问 key</label>
    <input id="k" type="password" autocomplete="current-password" placeholder="请输入管理员 key">
    <div class="err" id="e">${esc(msg||"")}</div>
    <button class="p" id="go" style="width:100%;margin-top:4px">登录</button>
    <div class="hint">使用看板管理员 key 登录。仅站长可见。连续 3 次错误将锁定该 IP 24 小时。</div></div>`;
  $("go").onclick=doLogin;
  $("k").onkeydown=e=>{if(e.key==="Enter")doLogin();};
  setTimeout(()=>$("k")&&$("k").focus(),30);
}
async function doLogin(){
  const k=$("k").value,e=$("e");
  e.textContent="验证中…";
  try{
    const r=await fetch("/api/panel/login",{method:"POST",
      headers:{"content-type":"application/json"},body:JSON.stringify({key:k})});
    const d=await r.json().catch(()=>({}));
    if(d.ok){dashboard();return;}
    if(r.status===423||d.locked){
      e.textContent="该 IP 已锁定，约 "+Math.ceil((d.retry_after||86400)/3600)+" 小时后恢复。";
      return;
    }
    e.textContent="key 错误"+(d.remaining!=null?"，还剩 "+d.remaining+" 次机会":"")+"。";
  }catch(err){e.textContent="网络错误，请重试。";}
}
async function load(){
  const r=await fetch("/api/panel/data",{cache:"no-store"});
  if(r.status===401||r.status===503){loginView(r.status===503?"未配置访客后台 key。":"登录已过期，请重新登录。");return null;}
  return r.json();
}
function dashboard(){
  document.title="nwpucat · 访客后台";
  $("app").innerHTML=`<div class="top"><div>
      <div class="brand">nwpucat <em>访客统计</em></div>
      <div class="sub" id="meta">加载中…</div></div>
    <div class="tools"><button id="rf">刷新</button><button id="out">退出</button></div></div>
    <div class="glass stats" id="stats"></div>
    <div class="glass"><div class="list" id="tb"><div class="empty">加载中…</div></div></div>
    <details class="glass sect" id="hbox"><summary>隐藏名单 <b id="hcount">0</b> 个 IP</summary>
      <div class="hlist" id="hlist"></div></details>
    <details class="glass sect"><summary>最近拦截的机器人</summary>
      <div id="bots"></div></details>
    <div class="sect" style="color:#66739a;font-size:11px">
      访问统计只计入执行了页面脚本的真实浏览器；爬虫、headless、webdriver、
      空 UA 与 800x600 无头屏幕默认不计入 PV/UV。</div>`;
  $("rf").onclick=render;
  $("out").onclick=async()=>{await fetch("/api/panel/logout",{method:"POST"});loginView("已退出。");};
  render();
  if(TIMER)clearInterval(TIMER);
  TIMER=setInterval(render,10000);
}
async function render(){
  const d=await load();if(!d||!d.ok)return;
  const s=d.stats||{};
  $("meta").textContent="数据更新于 "+fmt(d.now||Date.now()/1000)+" · 每 10 秒自动刷新";
  $("stats").innerHTML=`
    <div class="pv"><div class="k">访问量 PV</div><b>${s.pv??0}</b></div>
    <div class="uv"><div class="k">访客数 UV</div><b>${s.uv??0}</b></div>
    <div class="bot"><div class="k">已拦截机器人</div><b>${s.bots??0}</b></div>
    <div class="legacy"><div class="k">旧口径（含爬虫，仅供参考）</div><b>${s.legacy_pv??0} PV / ${s.legacy_uv??0} UV</b></div>`;
  const rows=d.rows||[];
  $("tb").innerHTML=rows.length?rows.map((v,i)=>`
    <div class="vrow">
      <div class="vrank">#${i+1}</div>
      <div class="vcnt"><b>${v.count??0}</b><span>次</span></div>
      <div class="vbody">
        <div class="vtop"><span class="vip">${esc(v.ip||"未知 IP")}</span>
          <span class="pill">${esc(v.os||"?")} · ${esc(v.browser||"?")}</span>
          ${v.screen?`<span class="pill">${esc(v.screen)}</span>`:""}
          ${v.lang?`<span class="pill">${esc(v.lang)}</span>`:""}</div>
        <div class="vmeta"><span>首次 ${fmt(v.first_seen)}</span>
          <span>最近 ${fmt(v.last_seen)} · ${ago(v.last_seen)}</span>
          <span class="mono">${esc((v.ua||"").slice(0,160))}</span></div>
      </div>
      <div class="vacts">
        <button class="vact" data-del="${esc(v.visitor)}">删除</button>
        ${v.ip?`<button class="vact hide" data-hide="${esc(v.ip)}">隐藏 IP</button>`:""}
      </div>
    </div>`).join(""):'<div class="empty">暂无已过滤的访客记录</div>';
  const hidden=d.hidden||[];
  $("hcount").textContent=hidden.length;
  $("hlist").innerHTML=hidden.length?hidden.map(ip=>`
    <div class="hitem"><code>${esc(ip)}</code>
      <button class="vact" data-unhide="${esc(ip)}">移出</button></div>`).join("")
    :'<div class="empty" style="padding:10px">暂无隐藏 IP</div>';
  const bots=d.bots_recent||[];
  $("bots").innerHTML=bots.length?bots.map(b=>`
    <div class="botitem"><b>${esc(b.ip||"-")}</b> · ${esc(b.reason||"-")} · ${fmt(b.ts)}
      <div style="color:#66739a;word-break:break-all">${esc((b.ua||"").slice(0,180))}</div></div>`).join("")
    :'<div class="empty" style="padding:10px">暂无拦截记录</div>';
}
$("app").addEventListener("click",async e=>{
  const del=e.target.closest("[data-del]");
  const hide=e.target.closest("[data-hide]");
  const un=e.target.closest("[data-unhide]");
  try{
    if(del){
      const r=await fetch("/api/panel/delete",{method:"POST",
        headers:{"content-type":"application/json"},
        body:JSON.stringify({visitor:del.dataset.del})});
      if(r.ok)render();return;
    }
    if(hide){
      const r=await fetch("/api/panel/hide",{method:"POST",
        headers:{"content-type":"application/json"},
        body:JSON.stringify({ip:hide.dataset.hide})});
      if(r.ok)render();return;
    }
    if(un){
      const r=await fetch("/api/panel/unhide",{method:"POST",
        headers:{"content-type":"application/json"},
        body:JSON.stringify({ip:un.dataset.unhide})});
      if(r.ok)render();return;
    }
  }catch(err){}
});
(async()=>{const r=await fetch("/api/panel/data",{cache:"no-store"});
  if(r.ok){dashboard();render();}else{loginView();}})();
</script></body></html>
"""

BOT_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="robots" content="noindex,nofollow,noarchive"><title>Forbidden</title></head>
<body style="font:14px monospace;background:#080d1a;color:#8ea0c8;padding:40px">
Forbidden. Human browsers only.</body></html>"""





class Handler(BaseHTTPRequestHandler):
    server_version = "ESN-Public/1.1"

    def log_message(self, _fmt, *args):
        return

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if urlparse(self.path).path.startswith("/api/public") or \
                urlparse(self.path).path == "/healthz":
            self.send_header("Access-Control-Allow-Origin", "*")
        for k, v in (headers or {}).items():
            if v:
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _json(self, code, obj, headers=None):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   "application/json; charset=utf-8", headers)

    def _send_head(self, code, length, ctype, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (headers or {}).items():
            if v:
                self.send_header(k, v)
        self.end_headers()

    def _proxy(self, method: str) -> bool:
        path = self.path
        lengths = int(self.headers.get("Content-Length", "0") or 0)
        data = self.rfile.read(min(lengths, 64 * 1024)) if method == "POST" else None
        headers = {}
        for k in ("Content-Type", "Cookie", "X-Agent-Token", "User-Agent",
                  "Accept", "Accept-Language"):
            v = self.headers.get(k)
            if v:
                headers[k] = v
        req = urllib.request.Request(UPSTREAM + path, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read()
                code = resp.status
                ctype = resp.headers.get("Content-Type", "application/json")
                out = {"Set-Cookie": resp.headers.get("Set-Cookie", "")}
        except urllib.error.HTTPError as exc:
            body, code = exc.read(), exc.code
            ctype = exc.headers.get("Content-Type", "application/json")
            out = {"Set-Cookie": exc.headers.get("Set-Cookie", "")}
        except Exception:
            return False
        self._send(code, body, ctype, {k: v for k, v in out.items() if v})
        return True


    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            if _bot_ua((self.headers.get("User-Agent", "") or "").strip()):
                self._send(403, BOT_PAGE, "text/html; charset=utf-8",
                           {"X-Robots-Tag": "noindex,nofollow,noarchive"})
                return
            visitor = _cookie(self, "esn_pub")
            headers = {"X-Robots-Tag": "noindex,nofollow,noarchive"}
            if not visitor:
                headers["Set-Cookie"] = _set_cookie(
                    "esn_pub", uuid.uuid4().hex, 31536000, _is_https(self))
            self._send(200, PAGE, "text/html; charset=utf-8", headers)
            return
        if path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /\n",
                       "text/plain; charset=utf-8")
            return
        if path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return
        if path == "/panel":
            self._send(200, PANEL_PAGE, "text/html; charset=utf-8",
                       {"X-Robots-Tag": "noindex,nofollow,noarchive",
                        "X-Frame-Options": "DENY"})
            return
        if path == "/healthz":
            self._json(200, {"ok": True})
            return
        if path in ("/report", "/report.html"):
            try:
                body = (Path(__file__).resolve().parent / "report.html").read_text(
                    encoding="utf-8")
            except OSError:
                self._json(404, {"error": "report not found"})
                return
            pv, uv, cookie = _record_report_hit(self)
            body = body.replace("{{REPORT_PV}}", str(pv)).replace(
                "{{REPORT_UV}}", str(uv))
            headers = {"X-Robots-Tag": "noindex,nofollow,noarchive"}
            if cookie:
                headers["Set-Cookie"] = cookie
            self._send(200, body, "text/html; charset=utf-8", headers)
            return
        if path == "/api/public/report/stats":
            pv, uv = _report_stats()
            self._json(200, {"pv": pv, "uv": uv},
                       {"X-Robots-Tag": "noindex,nofollow,noarchive"})
            return
        if path == "/report/chart.umd.min.js":
            try:
                body = (Path(__file__).resolve().parent / "chart.umd.min.js").read_bytes()
                self._send(200, body, "application/javascript; charset=utf-8")
            except OSError:
                self._send(404, b"", "text/plain")
            return
        if path == "/api/public/state":
            self._json(200, public_state(),
                       {"X-Robots-Tag": "noindex,nofollow,noarchive"})
            return
        if path == "/api/panel/data":
            if not _panel_key():
                self._json(503, {"ok": False, "error": "panel key not configured"})
                return
            if not _session_ok(self):
                self._json(401, {"ok": False})
                return
            self._json(200, _panel_data(),
                       {"X-Robots-Tag": "noindex,nofollow,noarchive",
                        "X-Frame-Options": "DENY"})
            return
        if path in ("/task", "/task.md", "/article", "/article.html",
                    "/api/task", "/me", "/api/my/state"):
            if self._proxy("GET"):
                return
        self._json(404, {"error": "not found"})


    def do_HEAD(self):
        path = urlparse(self.path).path
        if path == "/":
            body = PAGE.encode("utf-8")
            self._send_head(200, len(body), "text/html; charset=utf-8",
                            {"X-Robots-Tag": "noindex,nofollow,noarchive"})
            return
        if path == "/panel":
            body = PANEL_PAGE.encode("utf-8")
            self._send_head(200, len(body), "text/html; charset=utf-8",
                            {"X-Robots-Tag": "noindex,nofollow,noarchive",
                             "X-Frame-Options": "DENY"})
            return
        if path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /\n"
            self._send_head(200, len(body), "text/plain; charset=utf-8")
            return
        if path == "/healthz":
            body = b'{"ok": true}'
            self._send_head(200, len(body), "application/json; charset=utf-8")
            return
        if path == "/api/public/state":
            body = json.dumps(public_state(), ensure_ascii=False).encode("utf-8")
            self._send_head(200, len(body), "application/json; charset=utf-8")
            return
        self._send_head(404, 0, "application/json; charset=utf-8")


    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/public/visit":
            data = _read_json(self)
            out = _record_hit(self, data)
            headers = {}
            cookie = out.pop("_cookie", "")
            if cookie:
                headers["Set-Cookie"] = cookie
            self._json(200, out, headers)
            return
        if path == "/api/panel/login":
            if not _panel_key():
                self._json(503, {"ok": False, "error": "panel key not configured"})
                return
            retry = _panel_lock(self)
            if retry > 0:
                self._json(423, {"ok": False, "locked": True,
                                 "retry_after": int(retry)})
                return
            body = _read_json(self, 4096)
            supplied = str(body.get("key", ""))
            if supplied and hmac.compare_digest(supplied, _panel_key()):
                _panel_ok(self)
                cookie = _set_cookie("esn_panel", _make_session(), 28800,
                                     _is_https(self))
                self._json(200, {"ok": True}, {"Set-Cookie": cookie})
                return
            remaining = _panel_fail(self)
            self._json(401, {"ok": False, "remaining": remaining})
            return
        if path == "/api/panel/logout":
            cookie = _set_cookie("esn_panel", "", 0, _is_https(self))
            self._json(200, {"ok": True}, {"Set-Cookie": cookie})
            return
        if path in ("/api/panel/delete", "/api/panel/hide",
                    "/api/panel/unhide"):
            if not _session_ok(self):
                self._json(401, {"ok": False})
                return
            body = _read_json(self)
            try:
                con = _db()
                if path == "/api/panel/delete":
                    visitor = str(body.get("visitor", ""))[:128]
                    con.execute("DELETE FROM public_hits WHERE visitor=?", (visitor,))
                elif path == "/api/panel/hide":
                    ip = _clean(body.get("ip"), 64)
                    if ip:
                        con.execute("INSERT OR IGNORE INTO panel_hidden(ip,ts) "
                                    "VALUES(?,?)", (ip, time.time()))
                else:
                    ip = _clean(body.get("ip"), 64)
                    con.execute("DELETE FROM panel_hidden WHERE ip=?", (ip,))
                con.commit()
                con.close()
            except sqlite3.Error:
                self._json(500, {"ok": False})
                return
            self._json(200, {"ok": True})
            return
        if path == "/api/my/visit":
            if self._proxy("POST"):
                return
        self._json(404, {"error": "not found"})


def main():
    _db().close()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.daemon_threads = True
    print("public site listening on %d" % PORT, flush=True)
    if TLS_CERT and TLS_KEY:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(TLS_CERT, TLS_KEY)
            tls = ThreadingHTTPServer(("0.0.0.0", TLS_PORT), Handler)
            tls.daemon_threads = True
            tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
            threading.Thread(target=tls.serve_forever, daemon=True).start()
            print("public site TLS listening on %d" % TLS_PORT, flush=True)
        except Exception as exc:
            print("TLS disabled: %r" % (exc,), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
