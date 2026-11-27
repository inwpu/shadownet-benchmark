#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = os.environ.get("COMPOSE_PROJECT", "shadownet-benchmark")
FLAG_DIR = ROOT / "flags"
ENV_FILE = ROOT / ".env"
JUDGE_DIR = ROOT / "judge-data"
JUDGE_PID = JUDGE_DIR / "judge.pid"
JUDGE_PORT = int(os.environ.get("JUDGE_PORT", "18090"))
JUDGE_URL = "http://127.0.0.1:%d" % JUDGE_PORT


def load_flag_count() -> int:
    info = json.loads((ROOT / "problem_info.json").read_text(encoding="utf-8"))
    return len(info["flag_scores"])


def read_env() -> dict[str, str]:
    data = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            data[key.strip()] = value.strip()
    return data


def prepare() -> None:
    count = load_flag_count()
    FLAG_DIR.mkdir(exist_ok=True)
    env = read_env()
    for idx in range(1, count + 1):
        name = "flag%02d.txt" % idx
        path = FLAG_DIR / name
        if not path.exists():
            path.write_text("flag{%s}\n" % uuid.uuid4(), encoding="utf-8")
        path.chmod(0o444)
        env["DYNAMIC_FLAG_PATH_%d" % idx] = str(path)
    if count == 1:
        env["DYNAMIC_FLAG_PATH"] = str(FLAG_DIR / "flag01.txt")
    env.setdefault("DEPLOY_SECRET", secrets.token_hex(32))
    env.setdefault("VIEW_SALT", secrets.token_hex(32))
    env.setdefault("FLAG_BROKER_DIR", str(ROOT / "broker-data"))
    env.setdefault("HXCTF_REQUIRE_TRACE", "0")
    lines = ["%s=%s" % (key, value) for key, value in sorted(env.items())]
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (ROOT / "broker-data").mkdir(exist_ok=True)
    JUDGE_DIR.mkdir(exist_ok=True)


def judge_ok() -> bool:
    try:
        with urllib.request.urlopen(JUDGE_URL + "/healthz", timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def start_judge() -> int:
    if judge_ok():
        print("judge already running: " + JUDGE_URL)
        return 0
    JUDGE_DIR.mkdir(exist_ok=True)
    log = open(JUDGE_DIR / "judge.log", "ab")
    env = os.environ.copy()
    env.update({
        "JUDGE_PORT": str(JUDGE_PORT),
        "PUBLIC_HOST": os.environ.get("PUBLIC_HOST", "127.0.0.1"),
        "JUDGE_DB": str(JUDGE_DIR / "judge.db"),
    })
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "judge" / "judge.py")],
        cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True)
    JUDGE_PID.write_text(str(proc.pid), encoding="utf-8")
    for _ in range(30):
        if judge_ok():
            print("judge: %s  task: %s/task?lang=zh" % (JUDGE_URL, JUDGE_URL))
            return 0
        time.sleep(0.5)
    print("judge failed to start; see %s" % (JUDGE_DIR / "judge.log"))
    return 1


def stop_judge() -> None:
    if not JUDGE_PID.exists():
        return
    try:
        pid = int(JUDGE_PID.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        JUDGE_PID.unlink(missing_ok=True)
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    JUDGE_PID.unlink(missing_ok=True)
    print("judge stopped")


def compose(*args: str, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-p", PROJECT, *args],
        cwd=str(ROOT),
        text=True,
        capture_output=capture,
    )


def services() -> list[dict]:
    proc = compose("ps", "--format", "json", capture=True)
    out = (proc.stdout or "").strip()
    if not out:
        return []
    try:
        parsed = json.loads(out)
        return parsed if isinstance(parsed, list) else [parsed]
    except ValueError:
        items = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    items.append(json.loads(line))
                except ValueError:
                    pass
        return items


def status() -> int:
    items = services()
    expected = compose("config", "--services", capture=True).stdout or ""
    expected_set = {x.strip() for x in expected.splitlines() if x.strip()}
    bad = []
    for svc in items:
        name = svc.get("Service") or svc.get("Name") or "?"
        state = svc.get("State") or "?"
        health = svc.get("Health") or "none"
        if state != "running" or health not in ("none", "", "healthy"):
            bad.append("%s state=%s health=%s" % (name, state, health))
    print("services: %d/%d running" % (len(items), len(expected_set)))
    for line in bad:
        print("NOT READY", line)
    return 0 if items and not bad and len(items) == len(expected_set) else 1


def up(build: bool, timeout: int, judge: bool) -> int:
    prepare()
    if build:
        print("docker compose up -d --build")
        proc = compose("up", "-d", "--build")
    else:
        print("docker compose up -d")
        proc = compose("up", "-d")
    if proc.returncode != 0:
        return proc.returncode
    started = time.time()
    while time.time() - started < timeout:
        if status() == 0:
            print("all services healthy")
            print("entry points: http://127.0.0.1:8000  http://127.0.0.1:8001  telnet 127.0.0.1:2323")
            return start_judge() if judge else 0
        time.sleep(10)
    print("timeout after %ds" % timeout)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["up", "status", "down", "logs"])
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--no-judge", action="store_true")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    if args.action == "up":
        return up(not args.no_build, args.timeout, not args.no_judge)
    if args.action == "status":
        rc = status()
        print("judge: %s" % ("running" if judge_ok() else "not running"))
        return rc
    if args.action == "down":
        stop_judge()
        return compose("down").returncode
    return compose("logs", "--tail=100").returncode


if __name__ == "__main__":
    sys.exit(main())
