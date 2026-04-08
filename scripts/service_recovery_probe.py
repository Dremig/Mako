#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import json
import socket
import subprocess
import time
import urllib.parse
from pathlib import Path


def probe_tcp(host: str, port: int, timeout: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except OSError as exc:
        return False, str(exc)


def probe_http(url: str, timeout: int) -> dict[str, object]:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(host, port, timeout=timeout)
    started = time.monotonic()
    try:
        conn.request("GET", path, headers={"User-Agent": "mako-service-recovery/1.0"})
        resp = conn.getresponse()
        body = resp.read(256)
        return {
            "ok": True,
            "status": int(resp.status),
            "reason": resp.reason,
            "body_len": len(body),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error_kind": "",
            "error": "",
        }
    except http.client.RemoteDisconnected as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "",
            "body_len": 0,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error_kind": "empty_reply",
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "",
            "body_len": 0,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error_kind": exc.__class__.__name__,
            "error": str(exc),
        }
    finally:
        conn.close()


def load_container_logs(container_id: str) -> str:
    if not container_id.strip():
        return ""
    proc = subprocess.run(
        ["docker", "logs", "--tail", "40", container_id.strip()],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.stdout.strip()[:1200]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded readiness and protocol checks for an unstable web target")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--artifact-dir", default="", help="Optional artifact dir for writing JSON")
    parser.add_argument("--attempts", type=int, default=3, help="HTTP readiness attempts")
    parser.add_argument("--wait-seconds", type=int, default=12, help="Total wait budget across attempts")
    parser.add_argument("--timeout", type=int, default=6, help="Per-probe timeout")
    parser.add_argument("--container-id", default="", help="Optional local benchmark container id for docker logs")
    parser.add_argument("--out", default="", help="Optional JSON output path")
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    tcp_connect, tcp_error = probe_tcp(host, port, args.timeout)
    http_attempts: list[dict[str, object]] = []
    ready_http = False
    sleep_step = max(0.0, float(args.wait_seconds) / max(args.attempts, 1))
    for attempt in range(max(args.attempts, 1)):
        item = probe_http(args.url, args.timeout)
        http_attempts.append(item)
        if item.get("ok") is True:
            ready_http = True
            break
        if attempt + 1 < max(args.attempts, 1) and sleep_step > 0:
            time.sleep(sleep_step)

    https_url = urllib.parse.urlunparse(("https", parsed.netloc, parsed.path or "/", "", parsed.query, ""))
    https_probe = probe_http(https_url, args.timeout)

    last_http = http_attempts[-1] if http_attempts else {}
    classification = "unexpected_http_failure"
    if ready_http:
        classification = "http_ready"
    elif not tcp_connect:
        classification = "port_unreachable"
    elif str(last_http.get("error_kind", "")) == "empty_reply":
        classification = "service_not_ready_or_non_http"

    out = {
        "url": args.url,
        "tcp_connect": tcp_connect,
        "tcp_error": tcp_error,
        "ready_http": ready_http,
        "http_status": int(last_http.get("status", 0) or 0),
        "http_error_kind": str(last_http.get("error_kind", "")),
        "https_error_kind": str(https_probe.get("error_kind", "")),
        "empty_http_reply": str(last_http.get("error_kind", "")) == "empty_reply",
        "classification": classification,
        "suggested_url": args.url if ready_http else "",
        "attempts": http_attempts,
        "container_logs_excerpt": load_container_logs(args.container_id),
    }
    payload = json.dumps(out, ensure_ascii=False)

    out_path = args.out
    if not out_path and args.artifact_dir:
        out_path = str(Path(args.artifact_dir) / "service_recovery_probe.json")
    if out_path:
        Path(out_path).write_text(payload + "\n", encoding="utf-8")
    print(payload)


if __name__ == "__main__":
    main()
