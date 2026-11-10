from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
import tempfile
import unittest
from typing import Any, Callable

from web_agent.artifact_tools import (
    ArtifactSessionContext,
    build_artifact_mcp_server,
)
from web_agent.artifact_workspace import ArtifactWorkspace


@dataclass
class FakeTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], Any]


class FakeSDK:
    def __init__(self) -> None:
        self.tools: dict[str, FakeTool] = {}
        self.server_call: dict[str, Any] = {}

    def tool(self, name: str, description: str, input_schema: dict[str, Any]):
        def decorate(handler):
            spec = FakeTool(name, description, input_schema, handler)
            self.tools[name] = spec
            return spec
        return decorate

    def create_sdk_mcp_server(self, *, name: str, version: str, tools: list[FakeTool]):
        self.server_call = {"name": name, "version": version, "tools": tools}
        return dict(self.server_call)


class FakeWorkspace:
    def __init__(self) -> None:
        self.capture_calls: list[tuple[Path, dict[str, Any]]] = []
        self.list_calls: list[dict[str, Any]] = []
        self.peek_calls: list[tuple[str, dict[str, Any]]] = []
        self.failure: BaseException | None = None

    def capture_file(self, path: Path, **kwargs: Any) -> dict[str, Any]:
        if self.failure is not None:
            raise self.failure
        self.capture_calls.append((path, dict(kwargs)))
        return {
            "receipt_id": "receipt-1",
            "ref": "artifact:abc",
            "sha256": "abc",
            "size": 12,
            "metadata": kwargs.get("metadata", {}),
        }

    def list_receipts(self, **kwargs: Any) -> list[dict[str, Any]]:
        if self.failure is not None:
            raise self.failure
        self.list_calls.append(dict(kwargs))
        return [{"receipt_id": "receipt-1", "ref": "artifact:abc"}]

    def peek(self, ref: str, **kwargs: Any) -> dict[str, Any]:
        if self.failure is not None:
            raise self.failure
        self.peek_calls.append((ref, dict(kwargs)))
        return {
            "found": True,
            "ref": ref,
            "content": "bounded content",
            "shown_lines": 2,
        }


def parse_text(result: dict[str, Any]) -> Any:
    return json.loads(result["content"][0]["text"])


class ArtifactToolsTests(unittest.TestCase):
    def build(self, root: Path):
        sdk = FakeSDK()
        workspace = FakeWorkspace()
        server = build_artifact_mcp_server(
            sdk,
            workspace,
            project_root=root,
            run_id="run-1",
            session_id="session-1",
            call_id="call-1",
        )
        return sdk, workspace, server

    def test_server_identity_and_tool_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sdk, _workspace, server = self.build(Path(td))
        self.assertEqual(server["name"], "mako_artifacts")
        self.assertEqual(server["version"], "1.0.0")
        self.assertEqual(
            [tool.name for tool in server["tools"]],
            ["artifact_capture", "artifact_list", "artifact_peek"],
        )
        self.assertEqual(sdk.tools["artifact_capture"].input_schema["required"], ["path"])
        self.assertEqual(sdk.tools["artifact_peek"].input_schema["required"], ["ref"])
        for tool in sdk.tools.values():
            self.assertFalse(tool.input_schema.get("additionalProperties", True))
            lowered = tool.description.lower()
            for cognitive_term in ("recommend", "strategy", "judge", "rank", "next step"):
                self.assertNotIn(cognitive_term, lowered)

    def test_capture_resolves_relative_path_and_metadata_contains_only_note(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            sdk, workspace, _server = self.build(root)
            result = asyncio.run(
                sdk.tools["artifact_capture"].handler(
                    {
                        "path": "outputs/report.txt",
                        "media_type": "text/plain",
                        "note": "operator requested capture",
                    }
                )
            )
        payload = parse_text(result)
        self.assertEqual(payload["ref"], "artifact:abc")
        path, kwargs = workspace.capture_calls[0]
        self.assertEqual(path, root / "outputs" / "report.txt")
        self.assertEqual(kwargs["run_id"], "run-1")
        self.assertEqual(kwargs["session_id"], "session-1")
        self.assertEqual(kwargs["call_id"], "call-1")
        self.assertEqual(kwargs["tool_name"], "artifact_capture")
        self.assertEqual(kwargs["media_type"], "text/plain")
        self.assertEqual(kwargs["metadata"], {"note": "operator requested capture"})

    def test_list_and_peek_forward_bounded_data_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sdk, workspace, _server = self.build(Path(td))
            listed = asyncio.run(
                sdk.tools["artifact_list"].handler({"limit": 7})
            )
            peeked = asyncio.run(
                sdk.tools["artifact_peek"].handler(
                    {
                        "ref": "artifact:abc",
                        "start_line": 3,
                        "line_count": 9,
                        "query": "needle",
                    }
                )
            )
        self.assertEqual(parse_text(listed)[0]["receipt_id"], "receipt-1")
        self.assertEqual(workspace.list_calls, [{"run_id": "run-1", "limit": 7}])
        self.assertEqual(parse_text(peeked)["content"], "bounded content")
        self.assertEqual(
            workspace.peek_calls,
            [
                (
                    "artifact:abc",
                    {"start_line": 3, "line_count": 9, "query": "needle"},
                )
            ],
        )

    def test_errors_expose_only_exception_type(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sdk, workspace, _server = self.build(Path(td))
            workspace.failure = RuntimeError(
                "/outside/private/path contained credential-and-body"
            )
            for name, arguments in (
                ("artifact_capture", {"path": "/outside/private/path"}),
                ("artifact_list", {}),
                ("artifact_peek", {"ref": "artifact:secret"}),
            ):
                with self.subTest(tool=name):
                    result = asyncio.run(sdk.tools[name].handler(arguments))
                    self.assertTrue(result["isError"])
                    self.assertEqual(parse_text(result), {"error": "RuntimeError"})
                    serialized = json.dumps(result)
                    self.assertNotIn("/outside/private/path", serialized)
                    self.assertNotIn("credential-and-body", serialized)

    def test_real_workspace_capture_list_and_peek_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / "result.txt").write_text("alpha\nneedle\nomega\n", encoding="utf-8")
            sdk = FakeSDK()
            with ArtifactWorkspace(root / "artifact-store") as workspace:
                build_artifact_mcp_server(
                    sdk,
                    workspace,
                    project_root=root,
                    run_id="run-real",
                    session_id="session-real",
                    call_id="call-real",
                )
                captured = parse_text(asyncio.run(
                    sdk.tools["artifact_capture"].handler(
                        {"path": "result.txt", "note": "raw output"}
                    )
                ))
                listed = parse_text(asyncio.run(
                    sdk.tools["artifact_list"].handler({})
                ))
                peeked = parse_text(asyncio.run(
                    sdk.tools["artifact_peek"].handler(
                        {"ref": captured["artifact_ref"], "query": "needle"}
                    )
                ))

            self.assertEqual(captured["receipt"]["run_id"], "run-real")
            self.assertEqual(captured["receipt"]["metadata"], {"note": "raw output"})
            self.assertEqual(listed[0]["artifact_ref"], captured["artifact_ref"])
            self.assertEqual(peeked["peek"]["text"], "needle")
            self.assertEqual(peeked["peek"]["lines"][0]["line"], 1)

    def test_capture_uses_call_time_artifact_context_session(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / "capture.txt").write_text("data", encoding="utf-8")
            sdk = FakeSDK()
            workspace = FakeWorkspace()
            context = ArtifactSessionContext(session_id="")
            build_artifact_mcp_server(
                sdk,
                workspace,
                project_root=root,
                run_id="run-1",
                session_id="parent-session",
                call_id="call-1",
                artifact_context=context,
            )
            asyncio.run(
                sdk.tools["artifact_capture"].handler({"path": "capture.txt"})
            )
            self.assertEqual(workspace.capture_calls[0][1]["session_id"], "")
            context.session_id = "observed-child"
            asyncio.run(
                sdk.tools["artifact_capture"].handler({"path": "capture.txt"})
            )
            self.assertEqual(
                workspace.capture_calls[1][1]["session_id"], "observed-child"
            )


if __name__ == "__main__":
    unittest.main()
