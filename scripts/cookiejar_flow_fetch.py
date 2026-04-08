#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _normalize_url(base_url: str, raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", raw.lstrip("/"))


def _request_once(
    opener: urllib.request.OpenerDirector,
    url: str,
    method: str,
    timeout: int,
    headers: dict[str, str],
    body: str,
    content_type: str,
) -> dict[str, object]:
    payload = body.encode("utf-8") if body else None
    req = urllib.request.Request(url=url, data=payload, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    if payload is not None and content_type:
        req.add_header("Content-Type", content_type)
    started = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            content = resp.read()
            return {
                "url": url,
                "status": int(resp.status),
                "body_len": len(content),
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
    except urllib.error.HTTPError as exc:
        content = exc.read()
        return {
            "url": url,
            "status": int(exc.code),
            "body_len": len(content),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run optional login then fetch target with persistent cookie jar")
    parser.add_argument("--base-url", required=True, help="Base URL for relative paths")
    parser.add_argument("--cookiejar", required=True, help="Cookie jar file path")
    parser.add_argument("--login-url", default="", help="Optional login URL (absolute or relative)")
    parser.add_argument("--login-method", default="POST", help="Login HTTP method")
    parser.add_argument("--login-body", default="", help="Login request body")
    parser.add_argument("--login-content-type", default="application/x-www-form-urlencoded", help="Login body content-type")
    parser.add_argument("--fetch-url", required=True, help="Fetch URL (absolute or relative)")
    parser.add_argument("--fetch-method", default="GET", help="Fetch HTTP method")
    parser.add_argument("--fetch-body", default="", help="Fetch request body")
    parser.add_argument("--timeout", type=int, default=20, help="Timeout in seconds")
    parser.add_argument("--header", action="append", default=[], help="Additional header in Key:Value format")
    args = parser.parse_args()

    jar_path = Path(args.cookiejar).resolve()
    jar_path.parent.mkdir(parents=True, exist_ok=True)
    jar = http.cookiejar.MozillaCookieJar(str(jar_path))
    if jar_path.exists() and jar_path.stat().st_size > 0:
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except Exception:
            pass

    headers: dict[str, str] = {}
    for raw in args.header:
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            headers[key] = value

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    result: dict[str, object] = {}

    if args.login_url.strip():
        login_url = _normalize_url(args.base_url, args.login_url)
        result["login"] = _request_once(
            opener,
            login_url,
            args.login_method.strip().upper() or "POST",
            args.timeout,
            headers,
            args.login_body,
            args.login_content_type,
        )

    fetch_url = _normalize_url(args.base_url, args.fetch_url)
    result["fetch"] = _request_once(
        opener,
        fetch_url,
        args.fetch_method.strip().upper() or "GET",
        args.timeout,
        headers,
        args.fetch_body,
        "",
    )
    result["cookie_count"] = len(jar)

    jar.save(ignore_discard=True, ignore_expires=True)
    if not jar_path.exists():
        os.makedirs(jar_path.parent, exist_ok=True)
        jar_path.touch()

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
