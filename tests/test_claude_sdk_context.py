from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from web_agent import claude_runtime as common
from web_agent.claude_runtime import (
    ClaudeSDKConfig,
    ClaudeSDKError,
    chat_completion,
    json_completion,
)


class Options:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class HookMatcher:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class TextBlock:
    def __init__(self, text: str):
        self.text = text


class ToolUseBlock:
    pass


class AssistantMessage:
    def __init__(self, content):
        self.content = content


class ResultMessage:
    def __init__(
        self,
        *,
        result: str = "ok",
        session_id: str = "session-new",
        structured_output=None,
        subtype: str = "success",
        is_error: bool = False,
        terminal_reason: str | None = None,
        data: dict | None = None,
        raw: dict | None = None,
    ):
        self.result = result
        self.session_id = session_id
        self.structured_output = structured_output
        self.subtype = subtype
        self.is_error = is_error
        self.terminal_reason = terminal_reason
        self.data = data
        self.raw = raw


def fake_sdk(*messages, delay: float = 0.0, error: Exception | None = None):
    calls: list[dict] = []

    async def query(**kwargs):
        calls.append(kwargs)
        if delay:
            await asyncio.sleep(delay)
        if error is not None:
            raise error
        for message in messages:
            yield message

    sdk = SimpleNamespace(
        ClaudeAgentOptions=Options,
        HookMatcher=HookMatcher,
        AssistantMessage=AssistantMessage,
        ResultMessage=ResultMessage,
        TextBlock=TextBlock,
        ToolUseBlock=ToolUseBlock,
        query=query,
        calls=calls,
    )
    return sdk


class ClaudeSDKContextTests(unittest.TestCase):
    def config(self, timeout: float = 1.0, *, native_structured_output: bool = False) -> ClaudeSDKConfig:
        return ClaudeSDKConfig(
            model="fixture-model",
            cwd=Path.cwd(),
            env={"ANTHROPIC_API_KEY": "secret-for-test", "ANTHROPIC_AUTH_TOKEN": ""},
            timeout_sec=timeout,
            max_turns=1,
            native_structured_output=native_structured_output,
        )

    def test_sdk_boundary_disables_tools_and_resumes_session(self) -> None:
        sdk = fake_sdk(
            AssistantMessage([TextBlock("hello")]),
            ResultMessage(result="hello", session_id="session-next"),
        )
        context = {"session_id": "session-prev"}
        with patch("web_agent.claude_runtime._sdk_bindings", return_value=sdk):
            text = chat_completion(
                config=self.config(),
                messages=[
                    {"role": "system", "content": "system"},
                    {"role": "user", "content": "user"},
                ],
                session_context=context,
            )
        self.assertEqual(text, "hello")
        self.assertEqual(context["session_id"], "session-next")
        options = sdk.calls[0]["options"]
        self.assertEqual(options.tools, [])
        self.assertEqual(options.allowed_tools, [])
        self.assertEqual(options.setting_sources, [])
        self.assertEqual(options.mcp_servers, {})
        self.assertTrue(options.strict_mcp_config)
        self.assertEqual(options.plugins, [])
        self.assertEqual(options.permission_mode, "dontAsk")
        self.assertEqual(options.max_turns, 1)
        self.assertEqual(options.resume, "session-prev")
        self.assertIn("PreToolUse", options.hooks)

    def test_structured_output_uses_native_output_format(self) -> None:
        schema = {
            "type": "object",
            "properties": {"answer": {"type": "integer"}},
            "required": ["answer"],
            "additionalProperties": False,
        }
        sdk = fake_sdk(ResultMessage(structured_output={"answer": 42}, result=""))
        with patch("web_agent.claude_runtime._sdk_bindings", return_value=sdk):
            value = json_completion(
                config=self.config(native_structured_output=True),
                system_prompt="system",
                user_prompt="user",
                json_schema_name="fixture",
                json_schema=schema,
            )
        self.assertEqual(value, {"answer": 42})
        self.assertEqual(
            sdk.calls[0]["options"].output_format,
            {"type": "json_schema", "schema": schema},
        )

    def test_structured_output_text_fallback_is_locally_validated(self) -> None:
        schema = {
            "type": "object",
            "properties": {"answer": {"const": "ok"}},
            "required": ["answer"],
            "additionalProperties": False,
        }
        sdk = fake_sdk(ResultMessage(structured_output=None, result='{"answer":"ok"}'))
        with patch("web_agent.claude_runtime._sdk_bindings", return_value=sdk):
            value = json_completion(
                config=self.config(),
                system_prompt="system",
                user_prompt="user",
                json_schema_name="fixture",
                json_schema=schema,
            )
        self.assertEqual(value, {"answer": "ok"})
        self.assertFalse(hasattr(sdk.calls[0]["options"], "output_format"))

    def test_native_structured_result_error_retries_as_strict_json_text(self) -> None:
        schema = {
            "type": "object",
            "properties": {"answer": {"const": "ok"}},
            "required": ["answer"],
            "additionalProperties": False,
        }
        fallback = common._QueryResult(
            text='{"answer":"ok"}', structured_output=None, session_id="fallback-session"
        )
        context: dict[str, object] = {}
        with patch(
            "web_agent.claude_runtime._complete",
            side_effect=[ClaudeSDKError("Claude Agent SDK request failed (ResultError)"), fallback],
        ) as complete:
            value = json_completion(
                config=self.config(native_structured_output=True),
                system_prompt="system",
                user_prompt="user",
                json_schema_name="fixture",
                json_schema=schema,
                session_context=context,
            )
        self.assertEqual(value, {"answer": "ok"})
        self.assertEqual(complete.call_count, 2)
        self.assertIsNone(complete.call_args_list[1].kwargs["output_format"])
        self.assertIn("Return exactly one valid JSON object", complete.call_args_list[1].kwargs["messages"][0]["content"])

    def test_structured_timeout_does_not_enter_gateway_fallback(self) -> None:
        with patch(
            "web_agent.claude_runtime._complete",
            side_effect=ClaudeSDKError("Claude Agent SDK request timed out"),
        ) as complete:
            with self.assertRaisesRegex(ClaudeSDKError, "timed out"):
                json_completion(
                    config=self.config(native_structured_output=True),
                    system_prompt="system",
                    user_prompt="user",
                    json_schema_name="fixture",
                    json_schema={"type": "object"},
                )
        self.assertEqual(complete.call_count, 1)

    def test_unexpected_tool_request_fails(self) -> None:
        sdk = fake_sdk(
            AssistantMessage([ToolUseBlock()]),
            ResultMessage(),
        )
        with patch("web_agent.claude_runtime._sdk_bindings", return_value=sdk):
            with self.assertRaisesRegex(ClaudeSDKError, "disabled tool"):
                chat_completion(
                    config=self.config(),
                    messages=[{"role": "user", "content": "user"}],
                )

    def test_exception_does_not_disclose_secret(self) -> None:
        secret = "secret-for-test"
        sdk = fake_sdk(error=RuntimeError(secret))
        with patch("web_agent.claude_runtime._sdk_bindings", return_value=sdk):
            with self.assertRaises(ClaudeSDKError) as ctx:
                chat_completion(
                    config=self.config(),
                    messages=[{"role": "user", "content": "user"}],
                )
        self.assertNotIn(secret, str(ctx.exception))

    def test_timeout_is_sanitized(self) -> None:
        sdk = fake_sdk(ResultMessage(), delay=0.1)
        with patch("web_agent.claude_runtime._sdk_bindings", return_value=sdk):
            with self.assertRaisesRegex(ClaudeSDKError, "timed out"):
                chat_completion(
                    config=self.config(timeout=0.01),
                    messages=[{"role": "user", "content": "user"}],
                )

    def test_local_message_chain_replays_without_resume(self) -> None:
        sdk = fake_sdk(ResultMessage(result="next", session_id="local-session"))
        context = {
            "session_id": "must-not-resume",
            "use_local_msgchain": True,
            "replay_messages": [
                {"role": "user", "content": "seed"},
                {"role": "assistant", "content": "seed-ok"},
            ],
        }
        with patch("web_agent.claude_runtime._sdk_bindings", return_value=sdk):
            value = chat_completion(
                config=self.config(),
                messages=[
                    {"role": "system", "content": "system"},
                    {"role": "user", "content": "again"},
                ],
                session_context=context,
            )
        self.assertEqual(value, "next")
        options = sdk.calls[0]["options"]
        self.assertFalse(hasattr(options, "resume"))
        prompt = sdk.calls[0]["prompt"]
        self.assertIn("seed", prompt)
        self.assertIn("seed-ok", prompt)
        self.assertIn("again", prompt)
        self.assertEqual(
            context["replay_messages"][-2:],
            [
                {"role": "user", "content": "again"},
                {"role": "assistant", "content": "next"},
            ],
        )

    def test_local_message_chain_overflow_archives_long_term_memory(self) -> None:
        sdk = fake_sdk(ResultMessage(result="ack"))
        context = {
            "use_local_msgchain": True,
            "replay_messages": [
                {"role": "user", "content": "seed one alpha"},
                {"role": "assistant", "content": "ok one"},
                {"role": "user", "content": "seed two beta"},
                {"role": "assistant", "content": "ok two"},
                {"role": "user", "content": "seed three gamma"},
                {"role": "assistant", "content": "ok three"},
                {"role": "user", "content": "seed four delta"},
                {"role": "assistant", "content": "ok four"},
            ],
        }
        with patch("web_agent.claude_runtime._sdk_bindings", return_value=sdk), patch.dict(
            "os.environ", {"CLAUDE_REPLAY_MAX_MESSAGES": "8"}, clear=False
        ):
            chat_completion(
                config=self.config(),
                messages=[{"role": "user", "content": "new turn gamma"}],
                session_context=context,
            )
        self.assertEqual(len(context["replay_messages"]), 8)
        self.assertGreaterEqual(len(context.get("long_term_memory", [])), 1)
        self.assertIn("seed one alpha", context["long_term_memory"][0]["summary"])

    def test_long_term_recall_is_injected_into_system_prompt(self) -> None:
        sdk = fake_sdk(ResultMessage(result="recalled"))
        context = {
            "use_local_msgchain": True,
            "replay_messages": [],
            "long_term_memory": [
                {
                    "summary": "user confirmed marker zeta-31415",
                    "keywords": ["marker", "zeta-31415", "confirmed"],
                },
                {
                    "summary": "tested login flow with cookie",
                    "keywords": ["login", "flow", "cookie"],
                },
            ],
        }
        with patch("web_agent.claude_runtime._sdk_bindings", return_value=sdk):
            chat_completion(
                config=self.config(),
                messages=[
                    {"role": "system", "content": "system"},
                    {"role": "user", "content": "what is the marker value?"},
                ],
                session_context=context,
            )
        system_prompt = sdk.calls[0]["options"].system_prompt
        self.assertIn("Long-term memory recall", system_prompt)
        self.assertIn("zeta-31415", system_prompt)
        self.assertNotIn("tested login flow", system_prompt)

    def test_noncompleted_terminal_reason_is_failure(self) -> None:
        sdk = fake_sdk(ResultMessage(result="looks-ok", terminal_reason="api_error"))
        with patch("web_agent.claude_runtime._sdk_bindings", return_value=sdk):
            with self.assertRaisesRegex(ClaudeSDKError, "did not complete"):
                chat_completion(
                    config=self.config(),
                    messages=[{"role": "user", "content": "user"}],
                )

    def test_refusal_stop_reason_is_failure(self) -> None:
        sdk = fake_sdk(ResultMessage(result="declined", raw={"stop_reason": "refusal"}))
        with patch("web_agent.claude_runtime._sdk_bindings", return_value=sdk):
            with self.assertRaisesRegex(ClaudeSDKError, "refused"):
                chat_completion(
                    config=self.config(),
                    messages=[{"role": "user", "content": "user"}],
                )


if __name__ == "__main__":
    unittest.main()
