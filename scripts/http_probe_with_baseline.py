#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path


def _request_once(url: str, method: str, timeout: int, headers: dict[str, str], body: str, content_type: str) -> dict[str, object]:
    payload = body.encode("utf-8") if body else None
    req = urllib.request.Request(url=url, data=payload, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    if payload is not None and content_type:
        req.add_header("Content-Type", content_type)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read()
            header_items = list(resp.headers.items())
            return {
                "status": int(resp.status),
                "body_len": len(content),
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "body_text": content.decode("utf-8", errors="replace"),
                "headers": header_items,
            }
    except urllib.error.HTTPError as exc:
        content = exc.read()
        header_items = list(exc.headers.items())
        return {
            "status": int(exc.code),
            "body_len": len(content),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "body_text": content.decode("utf-8", errors="replace"),
            "headers": header_items,
        }


def _write_artifacts(probe: dict[str, object]) -> dict[str, str]:
    artifact_dir = Path(os.getenv("AGENT_ARTIFACT_DIR", ".")).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    body_text = str(probe.get("body_text", ""))
    headers = probe.get("headers", [])

    header_lines: list[str] = []
    cookie_lines: list[str] = []
    if isinstance(headers, list):
        for item in headers:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            key = str(item[0]).strip()
            value = str(item[1]).strip()
            if not key:
                continue
            header_lines.append(f"{key}: {value}")
            if key.lower() == "set-cookie" and value:
                cookie_lines.append(value)

    body_path = artifact_dir / "root.body"
    body_html_path = artifact_dir / "root.body.html"
    headers_path = artifact_dir / "root.headers"
    cookies_path = artifact_dir / "root.cookies.txt"
    body_path.write_text(body_text, encoding="utf-8")
    body_html_path.write_text(body_text, encoding="utf-8")
    headers_path.write_text("\n".join(header_lines), encoding="utf-8")
    cookies_path.write_text("\n".join(cookie_lines), encoding="utf-8")
    return {
        "artifact_dir": str(artifact_dir),
        "body_file": str(body_path),
        "body_html_file": str(body_html_path),
        "headers_file": str(headers_path),
        "cookies_file": str(cookies_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe endpoint and emit baseline diff summary")
    parser.add_argument("--url", required=True, help="Target probe URL")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--baseline-url", default="", help="Optional baseline URL; default is --url")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout in seconds")
    parser.add_argument("--body", default="", help="Request body")
    parser.add_argument("--content-type", default="", help="Content-Type for body requests")
    parser.add_argument("--header", action="append", default=[], help="Additional header in Key:Value format")
    args = parser.parse_args()

    method = args.method.strip().upper() or "GET"
    baseline_url = args.baseline_url.strip() or args.url.strip()
    headers: dict[str, str] = {}
    for raw in args.header:
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            headers[key] = value

    baseline = _request_once(baseline_url, "GET", args.timeout, headers, "", "")
    probe = _request_once(args.url.strip(), method, args.timeout, headers, args.body, args.content_type)
    artifacts = _write_artifacts(probe)

    out = {
        "baseline": baseline,
        "probe": probe,
        "artifacts": artifacts,
        "diff": {
            "status_diff": int(probe["status"]) - int(baseline["status"]),
            "body_len_diff": int(probe["body_len"]) - int(baseline["body_len"]),
            "elapsed_ms_diff": int(probe["elapsed_ms"]) - int(baseline["elapsed_ms"]),
        },
    }
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
