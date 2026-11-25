#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = os.environ.get("COMPOSE_PROJECT", "shadownet-benchmark")
FLAG_DIR = ROOT / "flags"
ENV_FILE = ROOT / ".env"


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


def up(build: bool, timeout: int) -> int:
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
            return 0
        time.sleep(10)
    print("timeout after %ds" % timeout)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["up", "status", "down", "logs"])
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    if args.action == "up":
        return up(not args.no_build, args.timeout)
    if args.action == "status":
        return status()
    if args.action == "down":
        return compose("down").returncode
    return compose("logs", "--tail=100").returncode


if __name__ == "__main__":
    sys.exit(main())
