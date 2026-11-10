from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from web_agent.claude_runtime import load_claude_sdk_config


class ClaudeConfigTests(unittest.TestCase):
    def test_api_key_config_is_isolated_and_metadata_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "ANTHROPIC_API_KEY": "secret-api-key",
                "ANTHROPIC_AUTH_TOKEN": "",
                "ANTHROPIC_MODEL": "fixture-model",
                "ANTHROPIC_BASE_URL": "https://gateway.example",
            },
            clear=True,
        ):
            config = load_claude_sdk_config(Path(td))
        self.assertEqual(config.model, "fixture-model")
        self.assertEqual(config.env["ANTHROPIC_API_KEY"], "secret-api-key")
        self.assertEqual(config.env["ANTHROPIC_AUTH_TOKEN"], "")
        self.assertNotIn("secret-api-key", repr(config))
        self.assertNotIn("secret-api-key", str(config.public_metadata()))
        self.assertNotIn("secret-api-key", config.signature())
        self.assertIn("claude-agent-sdk", config.signature())

    def test_auth_token_mode_clears_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "ANTHROPIC_API_KEY": "",
                "ANTHROPIC_AUTH_TOKEN": "secret-token",
                "ANTHROPIC_MODEL": "fixture-model",
            },
            clear=True,
        ):
            config = load_claude_sdk_config(Path(td))
        self.assertEqual(config.env["ANTHROPIC_API_KEY"], "")
        self.assertEqual(config.env["ANTHROPIC_AUTH_TOKEN"], "secret-token")

    def test_two_credential_modes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ,
            {
                "ANTHROPIC_API_KEY": "key",
                "ANTHROPIC_AUTH_TOKEN": "token",
                "ANTHROPIC_MODEL": "fixture-model",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "only one"):
                load_claude_sdk_config(Path(td))

    def test_missing_explicit_credentials_does_not_fall_back_to_user_login(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ, {"ANTHROPIC_MODEL": "fixture-model"}, clear=True
        ):
            with self.assertRaisesRegex(RuntimeError, "Missing Claude credentials"):
                load_claude_sdk_config(Path(td))

if __name__ == "__main__":
    unittest.main()
