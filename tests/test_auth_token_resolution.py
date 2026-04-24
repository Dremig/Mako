from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from rag.common import require_openai_auth_token


@contextmanager
def _pushd(path: Path):
    prev = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(prev)


class AuthTokenResolutionTests(unittest.TestCase):
    def test_prefers_repo_auth_json_access_token(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            payload = {
                "auth_mode": "chatgpt",
                "tokens": {
                    "access_token": "at_test_token",
                },
            }
            (root / "auth.json").write_text(json.dumps(payload), encoding="utf-8")
            with patch.dict(os.environ, {}, clear=False):
                token = require_openai_auth_token(root=root)
            self.assertEqual(token, "at_test_token")

    def test_rejects_api_key_when_no_access_token(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with _pushd(root), patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False):
                with self.assertRaises(RuntimeError) as ctx:
                    require_openai_auth_token(root=root)
            self.assertIn("OPENAI_API_KEY is disabled by policy", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
