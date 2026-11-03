import asyncio
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from claude_agent_sdk import AssistantMessage, ResultMessage, ToolUseBlock

from demo import Config, deny_tool, run_case


def result(**changes):
    fields = dict(subtype="success", duration_ms=1, duration_api_ms=1,
                  is_error=False, num_turns=1, session_id="fixture",
                  usage={}, result="SDK_DEMO_OK")
    fields.update(changes)
    return ResultMessage(**fields)


class DemoTests(unittest.IsolatedAsyncioTestCase):
    config = Config("https://example.invalid", "fixture", "secret-for-test")

    async def run_messages(self, *messages):
        async def fake_query(**kwargs):
            # Check the SDK boundary, not just a local flag in the report.
            options = kwargs["options"]
            self.assertEqual(options.tools, [])
            self.assertTrue(options.strict_mcp_config)
            self.assertEqual(options.setting_sources, [])
            self.assertEqual(options.permission_mode, "dontAsk")
            for message in messages:
                yield message
        with patch("demo.query", fake_query):
            return await run_case("text", self.config, 1)

    async def test_error_result_is_not_success_even_with_expected_answer(self):
        record = await self.run_messages(result(is_error=True))
        self.assertFalse(record["passed"])

    async def test_missing_final_result_fails(self):
        record = await self.run_messages()
        self.assertFalse(record["passed"])

    async def test_tool_request_fails(self):
        record = await self.run_messages(AssistantMessage(
            content=[ToolUseBlock(id="t", name="Read", input={"file_path": "unused"})],
            model="fixture",
        ), result())
        self.assertFalse(record["passed"])
        denial = await deny_tool({}, None, None)
        self.assertEqual(denial["hookSpecificOutput"]["permissionDecision"], "deny")

    async def test_exception_does_not_disclose_key(self):
        async def failing(**kwargs):
            raise RuntimeError(self.config.key)
            yield  # make it an async generator
        with patch("demo.query", failing):
            record = await run_case("text", self.config, 1)
        self.assertFalse(record["passed"])
        self.assertNotIn(self.config.key, str(record))

    async def test_timeout_fails(self):
        async def stalled(**kwargs):
            await asyncio.sleep(10)
            yield result()
        with patch("demo.query", stalled):
            record = await run_case("text", self.config, 0.01)
        self.assertEqual(record["error"], "TimeoutError")

    async def test_invalid_json_result_fails(self):
        async def malformed(**kwargs):
            yield result(result='{"total": "five", "unit": "books"}')
        with patch("demo.query", malformed):
            record = await run_case("json", self.config, 1)
        self.assertFalse(record["passed"])

    def test_environment_overrides_env_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / ".env"
            path.write_text("GLM_API_KEY=file-value\nGLM_MODEL=fixture\n"
                            "GLM_ANTHROPIC_BASE_URL=https://example.invalid\n")
            with patch.dict(os.environ, {"GLM_API_KEY": "environment-value"}, clear=True):
                config = Config.load(path)
                self.assertEqual(config.key, "environment-value")

    def test_missing_credentials_fails_without_falling_back_to_user_login(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                Config.load(None)


if __name__ == "__main__":
    unittest.main()
