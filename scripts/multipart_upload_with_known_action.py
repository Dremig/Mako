#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Upload file to a known multipart action URL")
    parser.add_argument("--action-url", required=True, help="Absolute upload action URL")
    parser.add_argument("--file", required=True, help="Local file to upload")
    parser.add_argument("--field-name", default="deployWar", help="Multipart field name")
    parser.add_argument("--cookiejar", default="", help="Cookie jar path for -b/-c")
    parser.add_argument("--username", default="", help="Optional basic-auth username")
    parser.add_argument("--password", default="", help="Optional basic-auth password")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout seconds")
    parser.add_argument("--header", action="append", default=[], help="Additional header in Key:Value format")
    args = parser.parse_args()

    payload = Path(args.file).resolve()
    if not payload.exists():
        raise RuntimeError(f"upload file does not exist: {payload}")

    cmd = [
        "curl",
        "-sS",
        "-i",
        "--max-time",
        str(max(1, args.timeout)),
        "-X",
        "POST",
        "-F",
        f"{args.field_name}=@{payload}",
    ]
    if args.cookiejar.strip():
        jar = str(Path(args.cookiejar).resolve())
        cmd.extend(["-b", jar, "-c", jar])
    if args.username.strip() and args.password.strip():
        cmd.extend(["-u", f"{args.username}:{args.password}"])
    for raw in args.header:
        if ":" in raw:
            cmd.extend(["-H", raw.strip()])
    cmd.append(args.action_url.strip())

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"curl upload failed (rc={proc.returncode}): {proc.stderr.strip()}")
    sys.stdout.write(proc.stdout)


if __name__ == "__main__":
    main()
