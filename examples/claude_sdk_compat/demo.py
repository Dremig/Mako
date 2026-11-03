"""Fixed, tool-free SDK compatibility checks; not a Mako runtime adapter."""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time
from urllib.parse import urlsplit
import uuid

from claude_agent_sdk import (
    AssistantMessage, ClaudeAgentOptions, HookMatcher, ResultMessage,
    TextBlock, ToolUseBlock, query,
)
from dotenv import dotenv_values
from jsonschema import validate

SCHEMA = {
    "type": "object",
    "properties": {"total": {"const": 5}, "unit": {"const": "books"}},
    "required": ["total", "unit"],
    "additionalProperties": False,
}
CASES = {
    "text": "DEMO_TEXT: Reply with exactly SDK_DEMO_OK and nothing else.",
    "json": (
        'DEMO_JSON: A shelf has 2 books and receives 3 more. '
        'Return only a JSON object with keys total (integer) and unit ("books"). '
        'No markdown, explanation, or tool calls.'
    ),
}


@dataclass(frozen=True)
class Config:
    base_url: str
    model: str
    key: str
    auth_mode: str = "api-key"

    @classmethod
    def load(cls, env_file: Path | None) -> "Config":
        values = dict(dotenv_values(env_file)) if env_file else {}
        values.update(os.environ)
        names = ("GLM_ANTHROPIC_BASE_URL", "GLM_MODEL", "GLM_API_KEY")
        if any(not str(values.get(name) or "").strip() for name in names):
            raise ValueError("请设置 GLM_ANTHROPIC_BASE_URL、GLM_MODEL、GLM_API_KEY")
        base_url = str(values[names[0]]).strip().rstrip("/")
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("真实服务地址必须是 HTTPS，且不含凭据、查询参数或片段")
        auth = str(values.get("GLM_AUTH_MODE") or "api-key")
        if auth not in {"api-key", "bearer"}:
            raise ValueError("GLM_AUTH_MODE 必须为 api-key 或 bearer")
        return cls(base_url, str(values[names[1]]), str(values[names[2]]), auth)


async def deny_tool(_input, _tool_use_id, _context):
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": "This compatibility demo has no tools.",
    }}


def check_answer(case: str, text: str):
    if case == "text":
        if text.strip() != "SDK_DEMO_OK":
            raise ValueError("文本响应与固定预期不符")
        return text.strip()
    value = json.loads(text)
    validate(value, SCHEMA)
    return value


def redact(value, secret: str):
    if isinstance(value, str):
        return value.replace(secret, "[REDACTED]") if secret else value
    if isinstance(value, dict):
        return {str(k): redact(v, secret) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secret) for v in value]
    return value


async def run_case(case: str, config: Config, timeout: float) -> dict:
    started = time.monotonic()
    # SDK state lives outside the user's Claude settings and project workspace.
    with tempfile.TemporaryDirectory(prefix="sdk-compat-") as temp:
        root = Path(temp)
        cwd = root / "workspace"
        cwd.mkdir()
        sdk_env = {
            "ANTHROPIC_BASE_URL": config.base_url,
            "ANTHROPIC_API_KEY": config.key if config.auth_mode == "api-key" else "",
            "ANTHROPIC_AUTH_TOKEN": config.key if config.auth_mode == "bearer" else "",
            "ANTHROPIC_MODEL": config.model,
            "CLAUDE_CONFIG_DIR": str(root / "config"),
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_AUTOUPDATER": "1",
            "API_TIMEOUT_MS": str(int(timeout * 1000)),
            "ANTHROPIC_SMALL_FAST_MODEL": config.model,
            "CLAUDE_CODE_USE_BEDROCK": "0",
            "CLAUDE_CODE_USE_VERTEX": "0",
        }
        options = ClaudeAgentOptions(
            model=config.model,
            system_prompt="Answer the fixed compatibility check using text only. Do not use tools.",
            tools=[],
            permission_mode="dontAsk",
            setting_sources=[],
            mcp_servers={},
            strict_mcp_config=True,
            plugins=[],
            hooks={"PreToolUse": [HookMatcher(hooks=[deny_tool])]},
            max_turns=1,
            thinking={"type": "disabled"},
            cwd=str(cwd),
            env=sdk_env,
            stderr=lambda _line: None,  # Never persist raw CLI stderr or credentials.
        )
        messages = []
        text_parts = []
        result = None
        try:
            async with asyncio.timeout(timeout):
                async for message in query(prompt=CASES[case], options=options):
                    messages.append(type(message).__name__)
                    if isinstance(message, AssistantMessage):
                        for block in message.content:
                            if isinstance(block, ToolUseBlock):
                                raise ValueError("模型请求了工具，文本兼容性检查失败")
                            if isinstance(block, TextBlock):
                                text_parts.append(block.text)
                    if isinstance(message, ResultMessage):
                        result = message
            if result is None:
                raise ValueError("SDK 未返回最终结果")
            if result.is_error or result.subtype != "success":
                return {"case": case, "passed": False, "error": "sdk_result_error",
                        "subtype": str(result.subtype), "events": messages}
            answer = check_answer(case, result.result or "".join(text_parts))
            return redact({
                "case": case, "passed": True, "answer": answer,
                "events": messages, "usage": result.usage,
                "duration_sec": round(time.monotonic() - started, 3),
            }, config.key)
        except Exception as exc:
            # Exceptions from an HTTP/CLI layer can contain request data.
            return {"case": case, "passed": False,
                    "error": type(exc).__name__, "events": messages,
                    "duration_sec": round(time.monotonic() - started, 3)}


async def main_async(args) -> int:
    from mock_server import MockServer
    mock = None
    if args.live:
        config = Config.load(args.env_file)
    else:
        mock = MockServer()
        mock.start()
        config = Config(mock.url, "mock-model", "local-test-key")
    try:
        records = [await run_case(case, config, args.timeout) for case in CASES]
        report = {
            "mode": "live" if args.live else "mock",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model": config.model,
            "tools_enabled": False,
            "structured_output": "text JSON validated locally; not SDK native structured output",
            "cases": records,
            "passed": all(record["passed"] for record in records),
        }
        if mock:
            report["mock_observations"] = mock.observations
            report["passed"] = report["passed"] and bool(mock.observations) and all(
                event["tools_count"] == 0 for event in mock.observations)
        report = redact(report, config.key)
        args.output.mkdir(parents=True, exist_ok=True)
        dest = args.output / f"{report['mode']}-{uuid.uuid4().hex}.json"
        dest.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        print(f"Report: {dest}")
        return 0 if report["passed"] else 1
    finally:
        if mock:
            mock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="调用配置的真实服务；默认使用本地模拟服务")
    parser.add_argument("--env-file", type=Path, help="仅 --live 时读取，已有环境变量优先")
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "results")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout 必须大于 0")
    try:
        raise SystemExit(asyncio.run(main_async(args)))
    except ValueError as exc:
        parser.exit(2, f"配置错误：{exc}\n")


if __name__ == "__main__":
    main()
