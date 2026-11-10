#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="python3"
fi

PYTHONPATH="$ROOT_DIR" PYTHONUNBUFFERED=1 "$PYTHON_BIN" -u -m web_agent.followup \
  --root "$ROOT_DIR" \
  --env ".env" \
  "$@"
