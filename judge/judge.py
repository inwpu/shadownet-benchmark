#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
PORT = int(os.environ.get("JUDGE_PORT", "18090"))
HOST = os.environ.get("JUDGE_HOST", "0.0.0.0")
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "127.0.0.1")
DB_PATH = Path(os.environ.get("JUDGE_DB", str(ROOT / "judge-data" / "judge.db")))
FLAG_DIR = Path(os.environ.get("FLAG_DIR", str(ROOT / "flags")))
PROBLEM_FILE = Path(os.environ.get("PROBLEM_FILE", str(ROOT / "problem_info.json")))
TASK_EN = Path(os.environ.get("TASK_EN", str(ROOT / "TASK.md")))
TASK_ZH = Path(os.environ.get("TASK_ZH", str(ROOT / "TASK.zh-CN.md")))
JOIN_CODE = os.environ.get("JUDGE_JOIN_CODE", "").strip()
MAX_AGENTS = int(os.environ.get("JUDGE_MAX_AGENTS", "500"))

NAME_RX = re.compile(r"^[\w一-鿿 .\-]{2,60}$")
LOCK = threading.Lock()
SUBMIT_LAST: dict[str, float] = {}


def load_problem() -> list[int]:
    data = json.loads(PROBLEM_FILE.read_text(encoding="utf-8"))
    return [int(x) for x in data["flag_scores"]]


def load_flags(scores: list[int]) -> dict[str, tuple[str, int]]:
    out: dict[str, tuple[str, int]] = {}
    for idx, score in enumerate(scores, start=1):
        fid = "flag%02d" % idx
        path = FLAG_DIR / (fid + ".txt")
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            out[value] = (fid, score)
    return out


SCORES = load_problem()
FLAG_VALUES = load_flags(SCORES)
FULL_SCORE = sum(SCORES)


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(DB_PATH), timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def init_db() -> None:
    con = db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS agents(
            agent TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            token TEXT UNIQUE NOT NULL,
            trace TEXT NOT NULL,
            created REAL NOT NULL,
            last_seen REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS claims(
            agent TEXT NOT NULL,
            flag_id TEXT NOT NULL,
            score INTEGER NOT NULL,
            ts REAL NOT NULL,
            PRIMARY KEY(agent, flag_id));
        CREATE TABLE IF NOT EXISTS activity(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            agent TEXT NOT NULL,
            kind TEXT NOT NULL,
            message TEXT);
    """)
    con.commit()
    con.close()


def task_text(lang: str) -> str:
    path = TASK_ZH if lang.startswith("zh") else TASK_EN
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return "Task book not found."


class Handler(BaseHTTPRequestHandler):
    server_version = "ShadowNetJudge/1.0"

    def log_message(self, fmt, *args):
        return

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _json(self, code: int, obj: dict) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(),
                   "application/json; charset=utf-8")

    def _html(self, code: int, text: str) -> None:
        self._send(code, text.encode(), "text/html; charset=utf-8")

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return {}
        if length <= 0 or length > 1_000_000:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _query(self) -> dict[str, str]:
        q = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        return {k: v[0] for k, v in q.items()}

    def _urls(self) -> dict[str, str]:
        base = "http://%s:%d" % (PUBLIC_HOST, PORT)
        return {
            "judge": base,
            "register_url": base + "/api/register",
            "submit_url": base + "/api/submit",
            "activity_url": base + "/api/activity",
            "state_url": base + "/api/state",
            "task_url": base + "/task",
        }

    def _agent(self, body: dict):
        agent = str(body.get("agent", "")).strip()
        token = str(body.get("token", "")).strip()
        if not agent or not token:
            return None
        con = db()
        row = con.execute(
            "SELECT * FROM agents WHERE agent=? AND token=?",
            (agent, token)).fetchone()
        con.close()
        return row

    def _leaderboard(self) -> list[dict]:
        con = db()
        rows = con.execute("""
            SELECT a.agent, a.name, COALESCE(SUM(c.score),0) AS score,
                   COUNT(c.flag_id) AS flags, COALESCE(MAX(c.ts),0) AS last_ts
            FROM agents a LEFT JOIN claims c ON a.agent=c.agent
            GROUP BY a.agent ORDER BY score DESC, last_ts ASC, a.name ASC
        """).fetchall()
        con.close()
        out = []
        for idx, row in enumerate(rows, start=1):
            out.append({
                "rank": idx,
                "agent": row["agent"],
                "name": row["name"],
                "score": int(row["score"]),
                "flags": int(row["flags"]),
                "full_score": int(row["score"]) >= FULL_SCORE,
                "last_ts": float(row["last_ts"]),
            })
        return out

    def do_GET(self):
        path = urlparse(self.path).path
        query = self._query()
        if path == "/healthz":
            self._json(200, {"ok": True, "service": "judge",
                             "flags": len(FLAG_VALUES),
                             "full_score": FULL_SCORE})
            return
        if path in ("/task", "/task.md"):
            lang = query.get("lang", "") or self.headers.get("Accept-Language", "")
            text = task_text(lang)
            body = ("<!doctype html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>ShadowNet Task</title><style>body{max-width:980px;margin:24px auto;"
                    "padding:0 16px;font:14px/1.7 -apple-system,BlinkMacSystemFont,"
                    "'PingFang SC',sans-serif;background:#0b1222;color:#e7edff}"
                    "pre{white-space:pre-wrap;word-break:break-word;background:#111a2e;"
                    "border:1px solid #22314f;border-radius:12px;padding:18px}"
                    "a{color:#4ecdc4}</style></head><body><p>"
                    "<a href='/task?lang=en'>English</a> | "
                    "<a href='/task?lang=zh'>简体中文</a> | "
                    "<a href='/'>Leaderboard</a></p><pre>"
                    + html.escape(text) + "</pre></body></html>")
            self._html(200, body)
            return
        if path in ("/", "/leaderboard"):
            rows = self._leaderboard()
            trs = "".join(
                "<tr><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>"
                % (r["rank"], html.escape(r["name"]), r["score"], r["flags"])
                for r in rows)
            body = ("<!doctype html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>ShadowNet Leaderboard</title><style>body{max-width:1100px;"
                    "margin:24px auto;padding:0 16px;font:14px/1.7 -apple-system,"
                    "BlinkMacSystemFont,'PingFang SC',sans-serif;background:#0b1222;"
                    "color:#e7edff}table{width:100%;border-collapse:collapse}"
                    "th,td{padding:8px 10px;border-bottom:1px solid #22314f;text-align:left}"
                    "th{color:#8ea0c8}a{color:#4ecdc4}</style></head><body>"
                    "<h1>ShadowNet Leaderboard</h1><p>Full score: "
                    + str(FULL_SCORE) + " · Flags: " + str(len(FLAG_VALUES)) + " · "
                    "<a href='/task?lang=en'>Task (EN)</a> · "
                    "<a href='/task?lang=zh'>任务书 (中文)</a></p>"
                    "<table><tr><th>#</th><th>Agent</th><th>Score</th><th>Flags</th></tr>"
                    + trs + "</table></body></html>")
            self._html(200, body)
            return
        if path == "/me":
            token = query.get("token", "").strip()
            con = db()
            row = con.execute("SELECT * FROM agents WHERE token=?", (token,)).fetchone()
            if not row:
                con.close()
                self._html(404, "<h1>Agent not found</h1>")
                return
            claims = con.execute(
                "SELECT flag_id, score, ts FROM claims WHERE agent=? ORDER BY ts",
                (row["agent"],)).fetchall()
            total = sum(int(c["score"]) for c in claims)
            con.close()
            trs = "".join("<tr><td>%s</td><td>%d</td></tr>"
                          % (html.escape(c["flag_id"]), int(c["score"]))
                          for c in claims)
            body = ("<!doctype html><html><head><meta charset='utf-8'>"
                    "<title>%s</title></head><body style='font-family:sans-serif'>"
                    "<h1>%s</h1><p>Agent: %s · Score: %d / %d · Flags: %d</p>"
                    "<table><tr><th>Flag</th><th>Score</th></tr>%s</table>"
                    "</body></html>" % (html.escape(row["name"]),
                                        html.escape(row["name"]),
                                        html.escape(row["agent"]), total,
                                        FULL_SCORE, len(claims), trs))
            self._html(200, body)
            return
        if path == "/api/state":
            rows = self._leaderboard()
            con = db()
            agents = con.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
            claims = con.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
            con.close()
            self._json(200, {
                "ok": True, "full_score": FULL_SCORE,
                "stats": {"agents": int(agents), "claims": int(claims)},
                "leaderboard": rows,
            })
            return
        if path in ("/api/my/state", "/me.json"):
            token = query.get("token", "").strip()
            con = db()
            row = con.execute("SELECT * FROM agents WHERE token=?", (token,)).fetchone()
            if not row:
                con.close()
                self._json(404, {"ok": False, "error": "agent not found"})
                return
            claims = con.execute(
                "SELECT flag_id, score, ts FROM claims WHERE agent=? ORDER BY ts",
                (row["agent"],)).fetchall()
            con.close()
            self._json(200, {
                "ok": True, "agent": row["agent"], "name": row["name"],
                "score": sum(int(c["score"]) for c in claims),
                "flags": len(claims), "full_score": FULL_SCORE,
                "claims": [{"flag_id": c["flag_id"], "score": int(c["score"]),
                            "ts": float(c["ts"])} for c in claims],
            })
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()
        if path == "/api/register":
            self._register(body)
            return
        if path == "/api/submit":
            self._submit(body)
            return
        if path == "/api/activity":
            self._activity(body)
            return
        self._json(404, {"error": "not found"})

    def _register(self, body: dict) -> None:
        name = " ".join(str(body.get("display_name", "")).split())
        if not name:
            self._json(400, {"ok": False, "error": "display_name required"})
            return
        if not NAME_RX.fullmatch(name):
            self._json(400, {"ok": False, "error": "display_name not allowed"})
            return
        if JOIN_CODE:
            supplied = str(body.get("join_code", "")).strip()
            if not secrets.compare_digest(supplied, JOIN_CODE):
                self._json(403, {"ok": False, "error": "invalid join code"})
                return
        token_in = str(body.get("token", "")).strip()
        now = time.time()
        with LOCK:
            con = db()
            row = con.execute("SELECT * FROM agents WHERE name=?", (name,)).fetchone()
            if row:
                if token_in and secrets.compare_digest(str(row["token"]), token_in):
                    con.execute("UPDATE agents SET last_seen=? WHERE agent=?",
                                (now, row["agent"]))
                    con.commit()
                    payload = self._reg_payload(dict(row), name)
                    con.close()
                    self._json(200, payload)
                    return
                con.close()
                self._json(409, {"ok": False, "error": "display_name already registered; provide the existing token to restore it"})
                return
            used = {r[0] for r in con.execute("SELECT agent FROM agents")}
            agent = ""
            for idx in range(1, MAX_AGENTS + 1):
                cand = "agent-%05d" % idx
                if cand not in used:
                    agent = cand
                    break
            if not agent:
                con.close()
                self._json(409, {"ok": False, "error": "all agent slots are registered"})
                return
            token = secrets.token_hex(16)
            trace = secrets.token_hex(16)
            con.execute(
                "INSERT INTO agents(agent,name,token,trace,created,last_seen) VALUES(?,?,?,?,?,?)",
                (agent, name, token, trace, now, now))
            con.commit()
            payload = self._reg_payload(
                {"agent": agent, "name": name, "token": token, "trace": trace}, name)
            con.close()
        self._json(200, payload)

    def _reg_payload(self, row: dict, name: str) -> dict:
        urls = self._urls()
        return {
            "ok": True,
            "agent": row["agent"],
            "token": row["token"],
            "trace": row["trace"],
            "display_name": name,
            "task": task_text("en"),
            "task_zh": task_text("zh"),
            "endpoints": {
                "portal": "http://%s:8000" % PUBLIC_HOST,
                "jump": "http://%s:8001" % PUBLIC_HOST,
                "telnet": "%s:2323" % PUBLIC_HOST,
            },
            **urls,
        }

    def _submit(self, body: dict) -> None:
        row = self._agent(body)
        if not row:
            self._json(403, {"ok": False, "error": "agent/token mismatch"})
            return
        now = time.time()
        last = SUBMIT_LAST.get(row["agent"], 0.0)
        if now - last < 1.0:
            self._json(429, {"ok": False, "error": "submit cooldown"})
            return
        SUBMIT_LAST[row["agent"]] = now
        value = str(body.get("flag", "")).strip()
        if not value:
            self._json(400, {"ok": False, "error": "flag required"})
            return
        item = FLAG_VALUES.get(value)
        if not item:
            self._json(409, {"ok": False, "error": "stale or unknown flag; re-read the service"})
            return
        fid, score = item
        with LOCK:
            con = db()
            exists = con.execute(
                "SELECT 1 FROM claims WHERE agent=? AND flag_id=?",
                (row["agent"], fid)).fetchone()
            if exists:
                con.close()
                self._json(409, {"ok": False, "error": "already claimed by this agent"})
                return
            con.execute("INSERT INTO claims(agent,flag_id,score,ts) VALUES(?,?,?,?)",
                        (row["agent"], fid, score, now))
            con.execute("UPDATE agents SET last_seen=? WHERE agent=?",
                        (now, row["agent"]))
            con.execute("INSERT INTO activity(ts,agent,kind,message) VALUES(?,?,?,?)",
                        (now, row["agent"], "capture", fid))
            con.commit()
            total = con.execute(
                "SELECT COALESCE(SUM(score),0) FROM claims WHERE agent=?",
                (row["agent"],)).fetchone()[0]
            count = con.execute(
                "SELECT COUNT(*) FROM claims WHERE agent=?",
                (row["agent"],)).fetchone()[0]
            con.close()
        self._json(200, {
            "ok": True, "display_name": row["name"],
            "flag_id": fid, "score": score, "total": int(total),
            "flags": int(count), "full_score": FULL_SCORE,
            "rotated": False,
        })

    def _activity(self, body: dict) -> None:
        row = self._agent(body)
        if not row:
            self._json(403, {"ok": False, "error": "agent/token mismatch"})
            return
        kind = str(body.get("kind", "note"))[:40]
        message = str(body.get("message", ""))[:500]
        now = time.time()
        with LOCK:
            con = db()
            con.execute("INSERT INTO activity(ts,agent,kind,message) VALUES(?,?,?,?)",
                        (now, row["agent"], kind, message))
            con.execute("UPDATE agents SET last_seen=? WHERE agent=?",
                        (now, row["agent"]))
            con.commit()
            con.close()
        self._json(200, {"ok": True, "display_name": row["name"]})


def main() -> None:
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("judge listening on %s:%d flags=%d full_score=%d"
          % (HOST, PORT, len(FLAG_VALUES), FULL_SCORE), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
