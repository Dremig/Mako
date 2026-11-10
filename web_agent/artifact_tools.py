from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from web_agent.artifact_workspace import ArtifactWorkspace

if TYPE_CHECKING:
    from claude_agent_sdk.types import McpSdkServerConfig


@dataclass
class ArtifactSessionContext:
    session_id: str = ""


def _text_result(payload: Any) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            }
        ]
    }


def _error_result(exc: BaseException) -> dict[str, Any]:
    # Exception messages can contain paths, file contents, or credentials.
    result = _text_result({"error": type(exc).__name__})
    # The SDK handler contract reads snake_case and emits MCP's camelCase field.
    result["is_error"] = True
    result["isError"] = True
    return result


def build_artifact_mcp_server(
    sdk: Any,
    workspace: ArtifactWorkspace,
    *,
    project_root: Path,
    run_id: str,
    session_id: str = "",
    call_id: str = "",
    artifact_context: ArtifactSessionContext | None = None,
) -> "McpSdkServerConfig":
    """Expose the current run's artifact store as three data-only SDK tools."""

    root = project_root.resolve()

    @sdk.tool(
        "artifact_capture",
        "Capture one existing file into the content-addressed artifact workspace.",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "minLength": 1},
                "media_type": {"type": "string", "default": ""},
                "note": {"type": "string", "default": ""},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    )
    async def artifact_capture(arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            raw_path = str(arguments.get("path", "")).strip()
            if not raw_path:
                raise ValueError("path is required")
            candidate = Path(raw_path).expanduser()
            path = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
            note = str(arguments.get("note", "")).strip()
            receipt = workspace.capture_file(
                path,
                run_id=run_id,
                session_id=(
                    artifact_context.session_id
                    if artifact_context is not None
                    else session_id
                ),
                call_id=call_id,
                tool_name="artifact_capture",
                source_kind="sdk_artifact_tool",
                source_ref=raw_path,
                media_type=str(arguments.get("media_type", "")).strip(),
                metadata={"note": note} if note else {},
            )
            return _text_result(receipt)
        except Exception as exc:
            return _error_result(exc)

    @sdk.tool(
        "artifact_list",
        "List artifact receipts captured for the current run.",
        {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20},
            },
            "additionalProperties": False,
        },
    )
    async def artifact_list(arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            limit = int(arguments.get("limit", 20))
            if not 1 <= limit <= 200:
                raise ValueError("limit is out of range")
            return _text_result(workspace.list_receipts(run_id=run_id, limit=limit))
        except Exception as exc:
            return _error_result(exc)

    @sdk.tool(
        "artifact_peek",
        "Read a bounded text window or query matches from one artifact receipt.",
        {
            "type": "object",
            "properties": {
                "ref": {"type": "string", "minLength": 1},
                "start_line": {"type": "integer", "minimum": 0, "default": 0},
                "line_count": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 80},
                "query": {"type": "string", "default": ""},
            },
            "required": ["ref"],
            "additionalProperties": False,
        },
    )
    async def artifact_peek(arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            ref = str(arguments.get("ref", "")).strip()
            if not ref:
                raise ValueError("ref is required")
            start_line = int(arguments.get("start_line", 0))
            line_count = int(arguments.get("line_count", 80))
            if start_line < 0 or not 1 <= line_count <= 1000:
                raise ValueError("line window is out of range")
            result = workspace.peek(
                ref,
                start_line=start_line,
                line_count=line_count,
                query=str(arguments.get("query", "")),
            )
            return _text_result(result)
        except Exception as exc:
            return _error_result(exc)

    return sdk.create_sdk_mcp_server(
        name="mako_artifacts",
        version="1.0.0",
        tools=[artifact_capture, artifact_list, artifact_peek],
    )
