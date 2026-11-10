from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
from typing import Any, Awaitable, Callable, TypeVar
from urllib.parse import urlsplit


class ClaudeSDKError(RuntimeError):
    """A sanitized Claude Agent SDK failure safe to persist in run logs."""


@dataclass(frozen=True)
class ClaudeSDKConfig:
    """Runtime configuration for tool-free Claude Agent SDK model calls."""

    model: str
    cwd: Path
    env: dict[str, str] = field(repr=False, compare=False)
    timeout_sec: float = 120.0
    max_turns: int = 1
    native_structured_output: bool = False

    def signature(self) -> str:
        """Stable, non-secret identity used to validate persisted sessions."""

        endpoint = self.env.get("ANTHROPIC_BASE_URL", "official").rstrip("/") or "official"
        native = "native-json" if self.native_structured_output else "local-json"
        return f"claude-agent-sdk::{endpoint}::{self.model}::{native}::{self.cwd.resolve()}"

    def public_metadata(self) -> dict[str, Any]:
        """Serializable configuration metadata with credentials omitted."""

        return {
            "runtime": "claude-agent-sdk",
            "model": self.model,
            "base_url": self.env.get("ANTHROPIC_BASE_URL", ""),
            "cwd": str(self.cwd.resolve()),
            "timeout_sec": self.timeout_sec,
            "max_turns": self.max_turns,
            "native_structured_output": self.native_structured_output,
            "signature": self.signature(),
        }


def load_dotenv(dotenv_path: Path) -> None:
    """Load simple KEY=VALUE entries without overwriting process environment."""

    if not dotenv_path.exists():
        return
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


def _positive_float_env(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a number") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum:g} and {maximum:g}")
    return value

def _env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _validate_base_url(value: str) -> str:
    base_url = value.strip().rstrip("/")
    if not base_url:
        return ""
    parsed = urlsplit(base_url)
    is_loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme not in ({"http", "https"} if is_loopback else {"https"}):
        raise RuntimeError("ANTHROPIC_BASE_URL must use HTTPS (HTTP is allowed only for loopback)")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError("ANTHROPIC_BASE_URL must be an origin without credentials, query, or fragment")
    return base_url


def load_claude_sdk_config(root: Path, cwd: Path | None = None) -> ClaudeSDKConfig:
    """Build isolated SDK configuration from explicit Anthropic credentials.

    Pointing ``CLAUDE_CONFIG_DIR`` at a project-owned directory prevents the SDK from
    silently falling back to a user's interactive Claude login.
    """

    root = root.resolve()
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    auth_token = os.getenv("ANTHROPIC_AUTH_TOKEN", "").strip()
    if api_key and auth_token:
        raise RuntimeError("Set only one of ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN")
    if not api_key and not auth_token:
        raise RuntimeError("Missing Claude credentials: set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN")

    model = os.getenv("ANTHROPIC_MODEL", "").strip()
    if not model:
        raise RuntimeError("Missing required env var: ANTHROPIC_MODEL")
    base_url = _validate_base_url(os.getenv("ANTHROPIC_BASE_URL", ""))
    timeout_sec = _positive_float_env("CLAUDE_SDK_TIMEOUT_SEC", 120.0, 1.0, 1800.0)

    config_dir_raw = os.getenv("CLAUDE_CONFIG_DIR", "").strip()
    config_dir = Path(config_dir_raw).expanduser() if config_dir_raw else root / "logs" / "claude-sdk"
    if not config_dir.is_absolute():
        config_dir = (root / config_dir).resolve()
    config_dir.mkdir(parents=True, exist_ok=True)

    run_cwd = (cwd or root).resolve()
    sdk_env = {
        # Set both variables explicitly so inherited process state cannot select a
        # second credential mode behind the caller's back.
        "ANTHROPIC_API_KEY": api_key,
        "ANTHROPIC_AUTH_TOKEN": auth_token,
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_SMALL_FAST_MODEL": model,
        "CLAUDE_CONFIG_DIR": str(config_dir),
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
        "CLAUDE_CODE_USE_BEDROCK": "0",
        "CLAUDE_CODE_USE_VERTEX": "0",
        "API_TIMEOUT_MS": str(int(timeout_sec * 1000)),
        "CLAUDE_AGENT_SDK_CLIENT_APP": "mako",
    }
    if base_url:
        sdk_env["ANTHROPIC_BASE_URL"] = base_url
    return ClaudeSDKConfig(
        model=model,
        cwd=run_cwd,
        env=sdk_env,
        timeout_sec=timeout_sec,
        # Mako owns the outer control loop. Each SDK call must remain one model turn.
        max_turns=1,
        native_structured_output=_env_truthy("CLAUDE_NATIVE_STRUCTURED_OUTPUT"),
    )


def _sdk_bindings() -> Any:
    try:
        import claude_agent_sdk
    except ImportError as exc:
        raise RuntimeError(
            "claude-agent-sdk is required; install the project dependencies before running Mako"
        ) from exc
    return claude_agent_sdk


async def _deny_tool(_input: Any, _tool_use_id: str | None, _context: Any) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "Mako executes tools in its own validated runtime loop.",
        }
    }


def _replay_max_messages() -> int:
    raw = os.getenv("CLAUDE_REPLAY_MAX_MESSAGES", "80").strip()
    try:
        value = int(raw)
    except ValueError:
        return 80
    return max(8, min(value, 400))


def _long_term_memory_enabled() -> bool:
    return os.getenv("CLAUDE_LONG_TERM_MEMORY", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _long_term_memory_max_items() -> int:
    raw = os.getenv("CLAUDE_LONG_TERM_MAX_ITEMS", "64").strip()
    try:
        value = int(raw)
    except ValueError:
        return 64
    return max(8, min(value, 256))


def _long_term_recall_topk() -> int:
    raw = os.getenv("CLAUDE_LONG_TERM_RECALL_TOPK", "3").strip()
    try:
        value = int(raw)
    except ValueError:
        return 3
    return max(1, min(value, 12))


def _memory_keywords(text: str, limit: int = 16) -> list[str]:
    stop = {
        "the",
        "and",
        "that",
        "with",
        "this",
        "from",
        "have",
        "were",
        "what",
        "when",
        "where",
        "your",
        "http",
        "https",
        "json",
        "role",
        "content",
        "user",
        "assistant",
        "system",
        "reply",
        "only",
    }
    seen: set[str] = set()
    out: list[str] = []
    for token in re.split(r"[^a-z0-9_./:-]+", text.lower()):
        if len(token) < 3 or token in stop or token in seen:
            continue
        seen.add(token)
        out.append(token)
        if len(out) >= limit:
            break
    return out


def _normalize_long_term_memory(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        summary = str(item.get("summary", "")).strip()
        keywords = item.get("keywords", [])
        if not summary:
            continue
        if not isinstance(keywords, list):
            keywords = []
        out.append(
            {
                "summary": summary,
                "keywords": [str(value).strip().lower() for value in keywords if str(value).strip()],
            }
        )
    return out


def _summarize_archived_messages(messages: list[dict[str, str]]) -> str:
    rows: list[str] = []
    for item in messages[-8:]:
        role = str(item.get("role", "")).strip() or "message"
        content = str(item.get("content", "")).strip().replace("\n", " ")
        if content:
            rows.append(f"{role}: {content[:160]}")
    return " | ".join(rows)[:1000]


def _archive_messages(context: dict[str, Any], messages: list[dict[str, str]]) -> None:
    if not messages or not _long_term_memory_enabled():
        return
    summary = _summarize_archived_messages(messages)
    if not summary:
        return
    memory = _normalize_long_term_memory(context.get("long_term_memory", []))
    memory.append({"summary": summary, "keywords": _memory_keywords(summary)})
    context["long_term_memory"] = memory[-_long_term_memory_max_items():]


def _recall_long_term_memory(
    context: dict[str, Any], messages: list[dict[str, str]]
) -> dict[str, str] | None:
    if not _long_term_memory_enabled():
        return None
    memory = _normalize_long_term_memory(context.get("long_term_memory", []))
    if not memory:
        return None
    query = " ".join(item.get("content", "") for item in messages[-3:])
    query_keywords = set(_memory_keywords(query, limit=24))
    if not query_keywords:
        return None
    scored: list[tuple[int, dict[str, Any]]] = []
    for item in memory:
        score = len(query_keywords & set(item.get("keywords", [])))
        if score:
            scored.append((score, item))
    if not scored:
        return None
    scored.sort(key=lambda pair: pair[0], reverse=True)
    summaries = [f"- {item['summary']}" for _, item in scored[:_long_term_recall_topk()]]
    return {
        "role": "system",
        "content": "Long-term memory recall:\n" + "\n".join(summaries),
    }


def _normalize_messages(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role", "")).strip().lower()
        content = str(item.get("content", ""))
        if role in {"system", "user", "assistant"} and content:
            out.append({"role": role, "content": content})
    return out


def _split_prompt(messages: list[dict[str, str]]) -> tuple[str, str]:
    system_parts = [item["content"] for item in messages if item["role"] == "system"]
    conversational = [item for item in messages if item["role"] != "system"]
    if len(conversational) == 1 and conversational[0]["role"] == "user":
        prompt = conversational[0]["content"]
    else:
        prompt = "\n\n".join(
            f"<{item['role']}>\n{item['content']}\n</{item['role']}>" for item in conversational
        )
    if not prompt.strip():
        raise ValueError("Claude SDK prompt must contain a user or assistant message")
    return "\n\n".join(system_parts).strip(), prompt


def _request_messages(
    messages: list[dict[str, str]], session_context: dict[str, Any] | None
) -> tuple[list[dict[str, str]], bool]:
    current = _normalize_messages(messages)
    local_chain = bool(isinstance(session_context, dict) and session_context.get("use_local_msgchain", False))
    if not local_chain or not isinstance(session_context, dict):
        return current, local_chain
    replay = _normalize_messages(session_context.get("replay_messages", []))
    # System instructions are supplied fresh on every call and are not duplicated in replay.
    replay = [item for item in replay if item["role"] != "system"]
    system_messages = [item for item in current if item["role"] == "system"]
    recalled = _recall_long_term_memory(session_context, current)
    if recalled is not None:
        system_messages.append(recalled)
    return system_messages + replay + [item for item in current if item["role"] != "system"], local_chain


def _update_local_replay(
    context: dict[str, Any], messages: list[dict[str, str]], assistant_text: str
) -> None:
    replay = [item for item in _normalize_messages(context.get("replay_messages", [])) if item["role"] != "system"]
    replay.extend(item for item in _normalize_messages(messages) if item["role"] != "system")
    if assistant_text.strip():
        replay.append({"role": "assistant", "content": assistant_text})
    max_keep = _replay_max_messages()
    if len(replay) > max_keep:
        _archive_messages(context, replay[:-max_keep])
    context["replay_messages"] = replay[-max_keep:]


def _safe_type_name(exc: BaseException) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "", type(exc).__name__)[:80] or "Error"


@dataclass
class _QueryResult:
    text: str
    structured_output: Any
    session_id: str


async def _query_sdk(
    *,
    config: ClaudeSDKConfig,
    system_prompt: str,
    prompt: str,
    resume: str,
    output_format: dict[str, Any] | None,
) -> _QueryResult:
    sdk = _sdk_bindings()
    text_parts: list[str] = []
    result: Any = None
    try:
        kwargs: dict[str, Any] = {
            "model": config.model,
            "system_prompt": system_prompt,
            "tools": [],
            "allowed_tools": [],
            "permission_mode": "dontAsk",
            "setting_sources": [],
            "mcp_servers": {},
            "strict_mcp_config": True,
            "plugins": [],
            "hooks": {"PreToolUse": [sdk.HookMatcher(hooks=[_deny_tool])]},
            "max_turns": 1,
            "cwd": str(config.cwd),
            "env": dict(config.env),
            # The CLI may include request bodies or credentials in stderr. Never persist it.
            "stderr": lambda _line: None,
        }
        if resume:
            kwargs["resume"] = resume
        if output_format is not None:
            kwargs["output_format"] = output_format
        options = sdk.ClaudeAgentOptions(**kwargs)
        async with asyncio.timeout(config.timeout_sec):
            async for message in sdk.query(prompt=prompt, options=options):
                if isinstance(message, sdk.AssistantMessage):
                    for block in getattr(message, "content", []) or []:
                        if isinstance(block, sdk.ToolUseBlock):
                            raise ClaudeSDKError("Claude Agent SDK requested a disabled tool")
                        if isinstance(block, sdk.TextBlock):
                            text_parts.append(str(getattr(block, "text", "")))
                if isinstance(message, sdk.ResultMessage):
                    result = message
    except TimeoutError as exc:
        raise ClaudeSDKError("Claude Agent SDK request timed out") from exc
    except ClaudeSDKError:
        raise
    except Exception as exc:
        # Do not include exception text: HTTP and CLI exceptions can contain credentials.
        raise ClaudeSDKError(f"Claude Agent SDK request failed ({_safe_type_name(exc)})") from None

    if result is None:
        raise ClaudeSDKError("Claude Agent SDK returned no final result")
    if bool(getattr(result, "is_error", False)) or str(getattr(result, "subtype", "")) != "success":
        raise ClaudeSDKError("Claude Agent SDK returned an unsuccessful result")
    terminal_reason = str(getattr(result, "terminal_reason", "") or "").strip().lower()
    if terminal_reason and terminal_reason != "completed":
        raise ClaudeSDKError("Claude Agent SDK did not complete the request")
    stop_reason = str(getattr(result, "stop_reason", "") or "").strip().lower()
    for attr in ("data", "raw"):
        payload = getattr(result, attr, None)
        if isinstance(payload, dict):
            candidate = str(payload.get("stop_reason", "") or "").strip().lower()
            if candidate:
                stop_reason = candidate
    if stop_reason == "refusal":
        raise ClaudeSDKError("Claude Agent SDK refused the request")
    structured_output = getattr(result, "structured_output", None)
    result_text = str(getattr(result, "result", "") or "").strip()
    text = result_text or "".join(text_parts).strip()
    if not text and structured_output is not None:
        # Local replay needs a representation of the assistant turn even when the
        # SDK returns structured_output without duplicating it in result text.
        text = json.dumps(structured_output, ensure_ascii=False, separators=(",", ":"))
    return _QueryResult(
        text=text,
        structured_output=structured_output,
        session_id=str(getattr(result, "session_id", "") or "").strip(),
    )


T = TypeVar("T")


def _run_sync(factory: Callable[[], Awaitable[T]]) -> T:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())
    # Synchronous public APIs are also safe when invoked by an async host.
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="mako-claude-sdk") as pool:
        return pool.submit(lambda: asyncio.run(factory())).result()


def _complete(
    *,
    config: ClaudeSDKConfig,
    messages: list[dict[str, str]],
    session_context: dict[str, Any] | None,
    output_format: dict[str, Any] | None,
) -> _QueryResult:
    request_messages, local_chain = _request_messages(messages, session_context)
    system_prompt, prompt = _split_prompt(request_messages)
    resume = ""
    if isinstance(session_context, dict) and not local_chain:
        resume = str(session_context.get("session_id", "")).strip()
    result = _run_sync(
        lambda: _query_sdk(
            config=config,
            system_prompt=system_prompt,
            prompt=prompt,
            resume=resume,
            output_format=output_format,
        )
    )
    if isinstance(session_context, dict):
        if result.session_id:
            session_context["session_id"] = result.session_id
        if local_chain:
            _update_local_replay(session_context, messages, result.text)
    return result


def chat_completion(
    *,
    config: ClaudeSDKConfig,
    messages: list[dict[str, str]],
    temperature: float = 0.2,
    session_context: dict[str, Any] | None = None,
) -> str:
    """Run one tool-free Claude SDK turn and return its text result.

    ``temperature`` remains in the application-facing API so callers do not need
    provider-specific branching. Claude Agent SDK does not expose it, so it is ignored.
    """

    del temperature
    result = _complete(
        config=config,
        messages=messages,
        session_context=session_context,
        output_format=None,
    )
    if not result.text:
        raise ClaudeSDKError("Claude Agent SDK returned no text output")
    return result.text


def _validate_json_schema(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    """Validate the JSON Schema subset used by Mako worker payloads."""

    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path} does not match const")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} is not an allowed value")
    expected = schema.get("type")
    type_ok = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }
    if isinstance(expected, str) and expected in type_ok and not type_ok[expected]:
        raise ValueError(f"{path} has wrong type")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        properties = properties if isinstance(properties, dict) else {}
        for required in schema.get("required", []) if isinstance(schema.get("required", []), list) else []:
            if required not in value:
                raise ValueError(f"{path} is missing a required property")
        if schema.get("additionalProperties") is False:
            extras = set(value) - set(properties)
            if extras:
                raise ValueError(f"{path} contains an additional property")
        for key, child in properties.items():
            if key in value and isinstance(child, dict):
                _validate_json_schema(value[key], child, f"{path}.{key}")
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for idx, item in enumerate(value):
            _validate_json_schema(item, schema["items"], f"{path}[{idx}]")


def _parse_json_object(text: str) -> dict[str, Any]:
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```(?:json)?\s*", "", candidate, flags=re.IGNORECASE)
        candidate = re.sub(r"\s*```$", "", candidate)
    try:
        value = json.loads(candidate)
    except json.JSONDecodeError:
        raise ClaudeSDKError("Claude Agent SDK returned invalid structured output") from None
    if not isinstance(value, dict):
        raise ClaudeSDKError("Claude Agent SDK structured output was not an object")
    return value


def json_completion(
    *,
    config: ClaudeSDKConfig,
    system_prompt: str,
    user_prompt: str,
    json_schema_name: str,
    json_schema: dict[str, Any],
    temperature: float = 0.1,
    session_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return schema-validated structured output for a Mako worker.

    Prefer the SDK's native ``output_format``. Anthropic-compatible gateways
    that do not implement that extension may return a sanitized ``ResultError``;
    only in that case retry once as strict JSON text and validate locally.
    Authentication, transport, timeout, and policy failures are never retried by
    this compatibility path.
    """

    del json_schema_name, temperature
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    strict_messages = [
        {
            "role": "system",
            "content": (
                system_prompt
                + "\n\nReturn exactly one valid JSON object matching the requested schema. "
                "Do not use Markdown, code fences, comments, or surrounding prose."
            ),
        },
        {"role": "user", "content": user_prompt},
    ]
    if not config.native_structured_output:
        result = _complete(
            config=config,
            messages=strict_messages,
            session_context=session_context,
            output_format=None,
        )
    else:
        try:
            result = _complete(
                config=config,
                messages=messages,
                session_context=session_context,
                output_format={"type": "json_schema", "schema": json_schema},
            )
        except ClaudeSDKError as exc:
            if "(ResultError)" not in str(exc) and "unsuccessful result" not in str(exc):
                raise
            result = _complete(
                config=config,
                messages=strict_messages,
                session_context=session_context,
                output_format=None,
            )
    value = result.structured_output
    if value is None:
        value = _parse_json_object(result.text)
    if not isinstance(value, dict):
        raise ClaudeSDKError("Claude Agent SDK structured output was not an object")
    try:
        _validate_json_schema(value, json_schema)
    except ValueError as exc:
        raise ClaudeSDKError("Claude Agent SDK structured output failed schema validation") from exc
    return value
