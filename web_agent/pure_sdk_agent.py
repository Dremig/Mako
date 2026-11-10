from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import re
import threading
from typing import Any, Sequence
import uuid

from web_agent.claude_runtime import load_dotenv
from web_agent.artifact_tools import (
    ArtifactSessionContext,
    build_artifact_mcp_server,
)
from web_agent.artifact_workspace import ArtifactWorkspace
from web_agent.session_ledger import SessionLedger
from web_agent.shared_session import shared_session_lease


DEFAULT_CONTEXT_FILE = Path("logs/claude_sdk_shared_context.json")
DEFAULT_ARTIFACT_DIR = Path("artifacts/pure_sdk")
DEFAULT_LEDGER_FILE = Path("logs/mako_session_ledger.sqlite")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sdk_bindings() -> Any:
    try:
        import claude_agent_sdk
    except ImportError as exc:
        raise RuntimeError(
            "claude-agent-sdk is required; install the project dependencies before running this agent"
        ) from exc
    return claude_agent_sdk


def _resolve_under(root: Path, path: Path) -> Path:
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _normalize_run_id(raw: str) -> str:
    value = raw.strip() or (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        + f"-{uuid.uuid4().hex[:8]}"
    )
    if not _RUN_ID_RE.fullmatch(value):
        raise ValueError("--run-id must contain only letters, digits, dot, underscore, and dash")
    return value


def sdk_signature(root: Path) -> str:
    identity = {
        "base_url": os.getenv("ANTHROPIC_BASE_URL", "").strip().rstrip("/"),
        "model": os.getenv("ANTHROPIC_MODEL", "").strip() or "default",
        "config_dir": os.getenv("CLAUDE_CONFIG_DIR", "").strip() or "default",
        "cwd": str(root.resolve()),
        "artifact_tools": "v1",
    }
    digest = hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return f"claude-agent-sdk-pure::{digest}"


_sdk_signature = sdk_signature


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


_atomic_write_json = atomic_write_json


def _safe_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {
            str(key): _safe_json_value(item)
            for key, item in value.items()
            if isinstance(key, (str, int, float, bool))
        }
    if isinstance(value, (list, tuple)):
        return [_safe_json_value(item) for item in value]
    return None


def _credential_values() -> tuple[str, ...]:
    markers = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
    values = {
        value
        for name, value in os.environ.items()
        if any(marker in name.upper() for marker in markers)
        and len(value) >= 4
    }
    return tuple(sorted(values, key=len, reverse=True))


def _redact_credentials(value: Any, secrets: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {str(key): _redact_credentials(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_credentials(item, secrets) for item in value]
    return value


def build_prompt(
    *,
    target: str,
    objective: str,
    hint: str,
    root: Path,
    artifact_dir: Path,
) -> str:
    return (
        f"Target: {target}\n"
        f"Objective: {objective}\n"
        f"Hint: {hint or 'none'}\n\n"
        "Authorization scope: The user authorizes end-to-end work on this target and "
        "objective. The local project may be used for supporting work. Do not interact "
        "with unrelated external systems.\n"
        "Work autonomously through completion using any Claude Code tools you judge useful. "
        "Preserve useful outputs in the artifact directory and return the final result.\n"
        f"Project root: {root}\n"
        f"Artifact directory: {artifact_dir}\n"
    )


def build_pure_options(
    sdk: Any,
    root: Path,
    session_id: str,
    fork_session: bool = False,
    resume_session_at: str = "",
    artifact_server: Any | None = None,
) -> Any:
    kwargs: dict[str, Any] = {
        "env": {"CLAUDE_AGENT_SDK_CLIENT_APP": "mako-pure"},
        "cwd": str(root),
        "tools": {"type": "preset", "preset": "claude_code"},
        "permission_mode": "bypassPermissions",
        "system_prompt": {"type": "preset", "preset": "claude_code"},
    }
    model = os.getenv("ANTHROPIC_MODEL", "").strip()
    if model:
        kwargs["model"] = model
    if session_id:
        kwargs["resume"] = session_id
    if fork_session:
        kwargs["fork_session"] = True
    if resume_session_at:
        kwargs["resume_session_at"] = resume_session_at
    if artifact_server is not None:
        kwargs["mcp_servers"] = {"mako_artifacts": artifact_server}
    return sdk.ClaudeAgentOptions(**kwargs)


_build_options = build_pure_options


def _receipt_ref(receipt: Any) -> str:
    if isinstance(receipt, dict):
        return str(
            receipt.get("receipt_id", "")
            or receipt.get("artifact_ref", "")
            or receipt.get("ref", "")
        ).strip()
    return str(
        getattr(receipt, "receipt_id", "")
        or getattr(receipt, "artifact_ref", "")
        or getattr(receipt, "ref", "")
    ).strip()


def _tool_result_payload(content: Any) -> tuple[bytes, str]:
    if isinstance(content, bytes):
        return content, "application/octet-stream"
    if isinstance(content, str):
        return content.encode("utf-8", errors="replace"), "text/plain; charset=utf-8"
    return (
        json.dumps(content, ensure_ascii=False, default=str).encode("utf-8"),
        "application/json",
    )


def _capture_run_files(
    workspace: Any,
    run_dir: Path,
    *,
    run_id: str,
    session_id: str,
    call_id: str,
    excluded_names: set[str] | None = None,
) -> list[str]:
    refs: list[str] = []
    excluded = set(excluded_names or set())
    if not run_dir.is_dir():
        return refs
    for path in sorted(run_dir.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        name = path.name
        if (
            name in excluded
            or name.startswith(".")
            or name.endswith((".tmp", ".temp", ".swp", "~"))
            or ".tmp." in name
            or ".staging." in name
        ):
            continue
        relative = path.relative_to(run_dir).as_posix()
        media_type = mimetypes.guess_type(path.name)[0] or ""
        try:
            receipt = workspace.capture_file(
                path,
                run_id=run_id,
                session_id=session_id,
                call_id=call_id,
                tool_name="",
                source_kind="run_file",
                source_ref=relative,
                media_type=media_type,
                metadata={"relative_path": relative},
            )
        except Exception:
            # A file may disappear or change while the SDK is still finishing.
            # Artifact capture is evidence preservation, not run authority.
            continue
        ref = _receipt_ref(receipt)
        if ref and ref not in refs:
            refs.append(ref)
    return refs


async def run_sdk_query(
    sdk: Any,
    prompt: str,
    options: Any,
    workspace: Any | None = None,
    run_id: str = "",
    session_id: str = "",
    call_id: str = "",
    artifact_context: ArtifactSessionContext | None = None,
) -> dict[str, Any]:
    if artifact_context is None:
        artifact_context = ArtifactSessionContext(session_id=session_id)
    event_types: list[str] = []
    tool_names: list[str] = []
    text_parts: list[str] = []
    final_result: Any | None = None
    error_type = ""
    observed_session_id = ""
    last_message_uuid = ""
    artifact_refs: list[str] = []
    artifact_capture_errors: list[str] = []
    tool_names_by_id: dict[str, str] = {}
    tool_result_types = tuple(
        item
        for item in (
            getattr(sdk, "ToolResultBlock", None),
            getattr(sdk, "ServerToolResultBlock", None),
        )
        if isinstance(item, type)
    )
    tool_use_types = tuple(
        item
        for item in (
            getattr(sdk, "ToolUseBlock", None),
            getattr(sdk, "ServerToolUseBlock", None),
        )
        if isinstance(item, type)
    )

    try:
        async for message in sdk.query(prompt=prompt, options=options):
            event_types.append(type(message).__name__)
            message_session_id = str(getattr(message, "session_id", "") or "").strip()
            data = getattr(message, "data", None)
            if not message_session_id and isinstance(data, dict):
                message_session_id = str(data.get("session_id", "") or "").strip()
            if message_session_id:
                observed_session_id = message_session_id
                artifact_context.session_id = message_session_id
            is_assistant = isinstance(message, sdk.AssistantMessage)
            if is_assistant:
                message_uuid = str(getattr(message, "uuid", "") or "").strip()
                if message_uuid:
                    last_message_uuid = message_uuid
            for block in getattr(message, "content", []) or []:
                if is_assistant and isinstance(block, sdk.TextBlock):
                    text = str(getattr(block, "text", ""))
                    if text:
                        text_parts.append(text)
                elif tool_use_types and isinstance(block, tool_use_types):
                    name = str(getattr(block, "name", "")).strip()
                    tool_use_id = str(
                        getattr(block, "id", "")
                        or getattr(block, "tool_use_id", "")
                        or ""
                    ).strip()
                    if name:
                        tool_names.append(name)
                    if tool_use_id:
                        tool_names_by_id[tool_use_id] = name
                elif tool_result_types and isinstance(block, tool_result_types):
                    tool_use_id = str(
                        getattr(block, "tool_use_id", "")
                        or getattr(block, "id", "")
                        or ""
                    ).strip()
                    tool_name = tool_names_by_id.get(tool_use_id, "") or str(
                        getattr(block, "name", "") or ""
                    ).strip()
                    if not tool_name and isinstance(getattr(message, "tool_use_result", None), dict):
                        tool_name = str(
                            message.tool_use_result.get("tool_name", "")
                            or message.tool_use_result.get("name", "")
                            or ""
                        ).strip()
                    if "mako_artifacts" in tool_name.lower():
                        continue
                    if workspace is not None:
                        data, media_type = _tool_result_payload(
                            getattr(block, "content", "")
                        )
                        try:
                            receipt = workspace.put_bytes(
                                data,
                                run_id=run_id,
                                session_id=artifact_context.session_id,
                                call_id=call_id,
                                tool_name=tool_name,
                                source_kind="tool_result",
                                source_ref=tool_use_id,
                                media_type=media_type,
                                metadata={
                                    "is_error": bool(getattr(block, "is_error", False))
                                },
                            )
                        except Exception as exc:
                            artifact_capture_errors.append(type(exc).__name__)
                            continue
                        ref = _receipt_ref(receipt)
                        if ref and ref not in artifact_refs:
                            artifact_refs.append(ref)
            if isinstance(message, sdk.ResultMessage):
                final_result = message
    except Exception as exc:
        # SDK/CLI exceptions may contain request content or credentials. Persist type only.
        error_type = type(exc).__name__

    subtype = str(getattr(final_result, "subtype", "") or "")
    is_error = bool(getattr(final_result, "is_error", True)) if final_result is not None else True
    session_id = str(getattr(final_result, "session_id", "") or "").strip() or observed_session_id
    usage = _safe_json_value(getattr(final_result, "usage", {})) if final_result is not None else {}
    if not isinstance(usage, dict):
        usage = {}
    cost = _safe_json_value(getattr(final_result, "total_cost_usd", None)) if final_result is not None else None
    num_turns = _safe_json_value(getattr(final_result, "num_turns", None)) if final_result is not None else None
    terminal_reason = str(getattr(final_result, "terminal_reason", "") or "").strip()
    stop_reason = str(getattr(final_result, "stop_reason", "") or "").strip()
    final_text = str(getattr(final_result, "result", "") or "").strip()
    assistant_text = final_text or "\n".join(text_parts).strip()
    success = (
        final_result is not None
        and not is_error
        and subtype == "success"
        and terminal_reason in {"", "completed"}
        and not error_type
    )
    return {
        "success": success,
        "assistant_text": assistant_text,
        "session_id": session_id,
        "last_message_uuid": last_message_uuid,
        "subtype": subtype,
        "is_error": is_error,
        "usage": usage,
        "total_cost_usd": cost,
        "num_turns": num_turns,
        "terminal_reason": terminal_reason,
        "stop_reason": stop_reason,
        "event_types": event_types,
        "tool_names": tool_names,
        "artifact_refs": artifact_refs,
        "artifact_capture_errors": artifact_capture_errors,
        "error": error_type,
    }


_run_sdk_query = run_sdk_query


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one unrestricted Claude Agent SDK loop for a complete target objective."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--env", type=Path, default=Path(".env"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--objective", required=True)
    parser.add_argument("--hint", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    parser.add_argument("--context-file", type=Path, default=DEFAULT_CONTEXT_FILE)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER_FILE)
    parser.add_argument("--new-session", action="store_true")
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    load_dotenv(_resolve_under(root, args.env))
    run_id = _normalize_run_id(str(args.run_id))
    artifact_root = _resolve_under(root, args.artifact_dir)
    run_dir = (artifact_root / run_id).resolve()
    context_path = _resolve_under(root, args.context_file)
    ledger_path = _resolve_under(root, args.ledger)
    signature = sdk_signature(root)
    prompt = build_prompt(
        target=str(args.target).strip(),
        objective=str(args.objective).strip(),
        hint=str(args.hint).strip(),
        root=root,
        artifact_dir=run_dir,
    )
    result: dict[str, Any] = {
        "success": False,
        "assistant_text": "",
        "session_id": "",
        "subtype": "",
        "is_error": True,
        "usage": {},
        "total_cost_usd": None,
        "num_turns": None,
        "terminal_reason": "",
        "stop_reason": "",
        "event_types": [],
        "tool_names": [],
        "artifact_refs": [],
        "artifact_capture_errors": [],
        "error": "RuntimeError",
        "last_message_uuid": "",
    }
    resumed_session_id = ""
    parent_run_id = ""
    call_id = uuid.uuid4().hex
    started_at = utc_now_z()
    run_registered = False

    with ArtifactWorkspace(artifact_root / "_evidence") as artifact_workspace, SessionLedger(
        ledger_path
    ) as ledger:
        try:
            with shared_session_lease(
                context_path,
                sdk_signature=signature,
                reset=False,
            ) as state:
                if args.new_session:
                    resumed_session_id = ""
                    parent_run_id = ""
                else:
                    resumed_session_id = str(state.session_id or "").strip()
                    if resumed_session_id:
                        parent_run_id = str(state.last_run_id or "").strip()
                ledger.register_run(
                    run_id,
                    parent_run_id=parent_run_id,
                    target=str(args.target).strip(),
                    objective=str(args.objective).strip(),
                    mode="pure",
                    workspace_root=str(run_dir),
                    status="running",
                    exclusive=True,
                )
                run_registered = True
                if resumed_session_id and ledger.get_session(resumed_session_id) is None:
                    ledger.register_session(
                        resumed_session_id,
                        parent_run_id or run_id,
                        sdk_signature=signature,
                        status="active",
                    )
                run_dir.mkdir(parents=True, exist_ok=True)
                if args.new_session:
                    state.session_id = ""
                    state.last_run_id = ""
                    state.updated_at = ""
                    context_path.unlink(missing_ok=True)
                sdk = _sdk_bindings()
                artifact_context = ArtifactSessionContext(
                    session_id=resumed_session_id
                )
                artifact_server = build_artifact_mcp_server(
                    sdk,
                    artifact_workspace,
                    project_root=root,
                    run_id=run_id,
                    session_id=resumed_session_id,
                    call_id=call_id,
                    artifact_context=artifact_context,
                )
                options = build_pure_options(
                    sdk,
                    root,
                    resumed_session_id,
                    fork_session=False,
                    resume_session_at="",
                    artifact_server=artifact_server,
                )
                result = asyncio.run(
                    run_sdk_query(
                        sdk,
                        prompt,
                        options,
                        workspace=artifact_workspace,
                        run_id=run_id,
                        session_id=resumed_session_id,
                        call_id=call_id,
                        artifact_context=artifact_context,
                    )
                )
                result_session_id = str(result.get("session_id", "")).strip()
                if result_session_id:
                    state.session_id = result_session_id
                state.last_run_id = run_id
        except Exception as exc:
            if not run_registered:
                raise
            result = {
                **result,
                "success": False,
                "is_error": True,
                "error": type(exc).__name__,
            }
        finally:
            if run_registered:
                ended_at = utc_now_z()
                result_session_id = str(result.get("session_id", "")).strip()
                effective_session_id = result_session_id or resumed_session_id
                artifact_refs = [
                    str(ref).strip()
                    for ref in result.get("artifact_refs", [])
                    if str(ref).strip()
                ] if isinstance(result.get("artifact_refs", []), list) else []
                for ref in _capture_run_files(
                    artifact_workspace,
                    run_dir,
                    run_id=run_id,
                    session_id=effective_session_id,
                    call_id=call_id,
                    excluded_names={"pure_sdk_run.json", "followup_result.json"},
                ):
                    if ref not in artifact_refs:
                        artifact_refs.append(ref)
                result["artifact_refs"] = artifact_refs
                if result_session_id:
                    if result_session_id == resumed_session_id:
                        ledger.touch_session(result_session_id, run_id=run_id)
                    else:
                        ledger.register_session(
                            result_session_id,
                            run_id,
                            parent_session_id=resumed_session_id,
                            sdk_signature=signature,
                            fork_reason=(
                                "sdk_session_replacement" if resumed_session_id else ""
                            ),
                            transcript_ref="",
                            status="active",
                        )
                elif resumed_session_id:
                    ledger.touch_session(resumed_session_id, run_id=run_id)

                success = bool(result.get("success", False))
                result_status = (
                    "success"
                    if success
                    else str(
                        result.get("subtype")
                        or result.get("terminal_reason")
                        or result.get("error")
                        or "failed"
                    )
                )
                usage = result.get("usage", {})
                ledger.record_call(
                    run_id,
                    effective_session_id,
                    call_id=call_id,
                    started_at=started_at,
                    ended_at=ended_at,
                    result_status=result_status,
                    usage=usage if isinstance(usage, dict) else {},
                    error_class=str(
                        result.get("error", "")
                        or (result.get("subtype", "") if result.get("is_error") else "")
                        or ""
                    ),
                    cost_usd=(
                        float(result["total_cost_usd"])
                        if isinstance(result.get("total_cost_usd"), (int, float))
                        else None
                    ),
                    num_turns=(
                        int(result["num_turns"])
                        if isinstance(result.get("num_turns"), int)
                        else None
                    ),
                    terminal_reason=str(result.get("terminal_reason", "") or ""),
                )
                ledger.finish_run(
                    run_id,
                    status="completed" if success else "failed",
                    primary_session_id=effective_session_id,
                    checkpoint_message_id=str(result.get("last_message_uuid", "") or ""),
                )

    record = _redact_credentials({
        "timestamp": utc_now_z(),
        "run_id": run_id,
        "parent_run_id": parent_run_id,
        "call_id": call_id,
        "checkpoint_message_id": str(result.get("last_message_uuid", "") or ""),
        "target": str(args.target).strip(),
        "objective": str(args.objective).strip(),
        "hint": str(args.hint).strip(),
        "artifact_dir": str(run_dir),
        "context_file": str(context_path),
        "ledger_path": str(ledger_path),
        "sdk_signature": signature,
        "model": os.getenv("ANTHROPIC_MODEL", "").strip() or "default",
        "resumed": bool(resumed_session_id),
        **result,
    }, _credential_values())
    atomic_write_json(run_dir / "pure_sdk_run.json", record)
    atomic_write_json(root / "logs" / "pure_sdk_last_run.json", record)

    assistant_text = str(record.get("assistant_text", "")).strip()
    if assistant_text:
        print(assistant_text)
    return 0 if bool(result.get("success", False)) else 1


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run(args)
    except (RuntimeError, ValueError) as exc:
        print(f"pure SDK agent failed: {type(exc).__name__}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
