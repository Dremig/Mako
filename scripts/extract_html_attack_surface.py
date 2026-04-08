#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import urllib.parse
from pathlib import Path


def normalize_candidate(raw: str, base_url: str) -> str:
    value = raw.strip()
    if not value or value.startswith(("javascript:", "mailto:", "#", "data:")):
        return ""
    parsed_base = urllib.parse.urlparse(base_url)
    joined = urllib.parse.urljoin(base_url, value)
    parsed = urllib.parse.urlparse(joined)
    if parsed.scheme not in {"http", "https", ""}:
        return ""
    if parsed.netloc and parsed_base.netloc and parsed.netloc != parsed_base.netloc:
        return ""
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return path[:180]


def uniq(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = raw.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def extract_forms(html: str, base_url: str) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for match in re.finditer(r"<form\b(.*?)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
        attrs = match.group(1)
        body = match.group(2)
        action_match = re.search(r'action=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        action = normalize_candidate(action_match.group(1), base_url) if action_match else ""
        method = (method_match.group(1).strip().upper() if method_match else "GET")[:12]
        inputs: list[str] = []
        hidden: dict[str, str] = {}
        for tag in re.finditer(r"<(?:input|textarea|select)\b[^>]*>", body, re.IGNORECASE):
            block = tag.group(0)
            name_match = re.search(r'name=["\']([^"\']+)["\']', block, re.IGNORECASE)
            if not name_match:
                continue
            name = name_match.group(1).strip()[:60]
            if not name:
                continue
            inputs.append(name)
            type_match = re.search(r'type=["\']([^"\']+)["\']', block, re.IGNORECASE)
            if type_match and type_match.group(1).strip().lower() == "hidden":
                value_match = re.search(r'value=["\']([^"\']*)["\']', block, re.IGNORECASE)
                hidden[name] = (value_match.group(1).strip() if value_match else "")[:120]
        forms.append(
            {
                "action": action,
                "method": method,
                "inputs": uniq(inputs),
                "hidden": hidden,
            }
        )
    return forms


def extract_candidates(html: str, base_url: str) -> list[str]:
    candidates: list[str] = []

    for match in re.finditer(r'\b(?:href|src|action)=["\']([^"\']+)["\']', html, re.IGNORECASE):
        normalized = normalize_candidate(match.group(1), base_url)
        if normalized:
            candidates.append(normalized)

    for match in re.finditer(r'["\']((?:/|\./)[^"\']{1,160})["\']', html):
        normalized = normalize_candidate(match.group(1), base_url)
        if normalized:
            candidates.append(normalized)

    for match in re.finditer(r'["\']([A-Za-z0-9_\-./]{1,120}\.(?:php|html|js|json|txt|pdf|xml))["\']', html, re.IGNORECASE):
        normalized = normalize_candidate(match.group(1), base_url)
        if normalized:
            candidates.append(normalized)

    return uniq(candidates)


def extract_filenames(html: str) -> list[str]:
    filenames: list[str] = []
    for match in re.finditer(r'["\']([A-Za-z0-9_.\-]{1,120}\.(?:pdf|txt|js|json|xml|csv|zip|tar|gz))["\']', html, re.IGNORECASE):
        filenames.append(match.group(1).strip())
    return uniq(filenames)


def extract_comments(html: str) -> list[str]:
    comments: list[str] = []
    for match in re.finditer(r"<!--(.*?)-->", html, re.DOTALL):
        value = re.sub(r"\s+", " ", match.group(1)).strip()
        if value:
            comments.append(value[:240])
    return uniq(comments)


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract likely routes, forms, and assets from an HTML body")
    parser.add_argument("--html-file", required=True, help="Path to HTML file")
    parser.add_argument("--base-url", required=True, help="Base URL used to normalize candidates")
    parser.add_argument("--out", default="", help="Optional JSON output path")
    args = parser.parse_args()

    html = Path(args.html_file).read_text(encoding="utf-8", errors="ignore")
    forms = extract_forms(html, args.base_url)
    candidate_paths = extract_candidates(html, args.base_url)
    for form in forms:
        action = str(form.get("action", "")).strip()
        if action:
            candidate_paths.append(action)
    candidate_paths = uniq(candidate_paths)

    out = {
        "base_url": args.base_url,
        "html_file": args.html_file,
        "candidate_paths": candidate_paths[:80],
        "forms": forms[:20],
        "filenames": extract_filenames(html)[:40],
        "comments": extract_comments(html)[:20],
    }
    payload = json.dumps(out, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    print(payload)


if __name__ == "__main__":
    main()
