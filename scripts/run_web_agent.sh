#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target_url> [objective] [hint]"
  echo "Example: $0 'http://127.0.0.1:8080/' 'Find SQL injection and get flag' 'GET parameter id, SQLi challenge'"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$1"
OBJECTIVE="${2:-Find SQL injection and retrieve flag}"
HINT="${3:-blackbox web SQL injection challenge}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-artifacts/mako}"
MAKO_RUNTIME_MODE="${MAKO_RUNTIME_MODE:-pure}"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="python3"
fi

case "$MAKO_RUNTIME_MODE" in
  pure)
    PYTHONPATH="$ROOT_DIR" PYTHONUNBUFFERED=1 "$PYTHON_BIN" -u -m web_agent.pure_sdk_agent \
      --root "$ROOT_DIR" \
      --env ".env" \
      --target "$TARGET" \
      --objective "$OBJECTIVE" \
      --hint "$HINT" \
      --artifact-dir "$ARTIFACT_ROOT"
    ;;
  governed)
    PYTHONPATH="$ROOT_DIR" PYTHONUNBUFFERED=1 "$PYTHON_BIN" -u -m web_agent.cmd_agent \
      --root "$ROOT_DIR" \
      --env ".env" \
      --target "$TARGET" \
      --objective "$OBJECTIVE" \
      --hint "$HINT" \
      --cmd-timeout 120 \
      --max-steps 16 \
      --artifact-dir "$ARTIFACT_ROOT"
    ;;
  *)
    echo "Unsupported MAKO_RUNTIME_MODE: $MAKO_RUNTIME_MODE (expected pure or governed)" >&2
    exit 2
    ;;
esac
