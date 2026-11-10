from __future__ import annotations

import asyncio
from contextlib import closing, redirect_stdout
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from web_agent import pure_sdk_agent
from web_agent.artifact_workspace import ArtifactWorkspace
from web_agent.session_ledger import SessionLedger
from web_agent.shared_session import shared_session_lease


@dataclass
class TextBlock:
    text: str


@dataclass
class ToolUseBlock:
    name: str
    input: dict[str, object]
    id: str = ""


@dataclass
class ToolResultBlock:
    tool_use_id: str
    content: object
    is_error: bool = False


@dataclass
class AssistantMessage:
    content: list[object]
    uuid: str | None = None


@dataclass
class UserMessage:
    content: list[object]


@dataclass
class ResultMessage:
    subtype: str
    is_error: bool
    session_id: str
    usage: dict[str, object]
    total_cost_usd: float | None
    num_turns: int
    result: str | None = None
    terminal_reason: str | None = "completed"
    stop_reason: str | None = None
    uuid: str | None = None


class AfterResultEvent:
    pass


class FakeOptions:
    calls: list[dict[str, object]] = []

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = dict(kwargs)
        type(self).calls.append(self.kwargs)


def fake_sdk(messages: list[object], prompts: list[str]) -> SimpleNamespace:
    async def query(*, prompt: str, options: FakeOptions):
        del options
        prompts.append(prompt)
        for message in messages:
            yield message

    def tool(_name: str, _description: str, _schema: dict[str, object]):
        return lambda function: function

    def create_sdk_mcp_server(**_kwargs: object):
        return "fake-artifact-server"

    return SimpleNamespace(
        ClaudeAgentOptions=FakeOptions,
        AssistantMessage=AssistantMessage,
        UserMessage=UserMessage,
        TextBlock=TextBlock,
        ToolUseBlock=ToolUseBlock,
        ToolResultBlock=ToolResultBlock,
        ResultMessage=ResultMessage,
        tool=tool,
        create_sdk_mcp_server=create_sdk_mcp_server,
        query=query,
    )


class PureSDKAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeOptions.calls.clear()

    def _args(self, root: Path, *extra: str):
        return pure_sdk_agent.parse_args(
            [
                "--root",
                str(root),
                "--target",
                "https://target.invalid/",
                "--objective",
                "retrieve the challenge flag",
                "--hint",
                "inspect the application",
                "--run-id",
                "run-1",
                *extra,
            ]
        )

    def test_sdk_signature_versions_artifact_tool_surface(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            root = Path(td)
            identity = {
                "base_url": "",
                "model": "default",
                "config_dir": "default",
                "cwd": str(root.resolve()),
                "artifact_tools": "v1",
            }
            digest = hashlib.sha256(
                json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()
            self.assertEqual(
                pure_sdk_agent.sdk_signature(root),
                f"claude-agent-sdk-pure::{digest}",
            )

    def test_sdk_defaults_resume_shared_session_and_consume_complete_stream(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            produced = root / "artifacts" / "pure_sdk" / "run-1" / "result.txt"
            produced.parent.mkdir(parents=True, exist_ok=True)
            produced.write_text("captured run file", encoding="utf-8")
            context_path = root / "logs" / "claude_sdk_shared_context.json"
            env = {
                "ANTHROPIC_MODEL": "fixture-model",
                "ANTHROPIC_BASE_URL": "https://gateway.invalid",
                "ANTHROPIC_API_KEY": "credential-must-not-persist",
                "CLAUDE_CONFIG_DIR": str(root / "claude-config"),
            }
            prompts: list[str] = []
            messages = [
                AssistantMessage(
                    [
                        TextBlock("working credential-must-not-persist"),
                        ToolUseBlock(
                            "Bash",
                            {"command": "secret-tool-input"},
                            id="tool-1",
                        ),
                    ]
                ),
                UserMessage(
                    [ToolResultBlock("tool-1", [{"type": "text", "text": "tool output"}])]
                ),
                AssistantMessage([TextBlock("finished")], uuid="checkpoint-run-1"),
                ResultMessage(
                    subtype="success",
                    is_error=False,
                    session_id="session-new",
                    usage={"input_tokens": 10, "output_tokens": 4},
                    total_cost_usd=0.25,
                    num_turns=3,
                    result="final report",
                ),
                AfterResultEvent(),
            ]
            sdk = fake_sdk(messages, prompts)
            with patch.dict(os.environ, env, clear=True):
                signature = pure_sdk_agent._sdk_signature(root)
                with shared_session_lease(
                    context_path,
                    sdk_signature=signature,
                ) as state:
                    state.session_id = "session-old"
                    state.last_run_id = "seed"

                output = io.StringIO()
                with patch.object(pure_sdk_agent, "_sdk_bindings", return_value=sdk), redirect_stdout(output):
                    exit_code = pure_sdk_agent.run(self._args(root))

            self.assertEqual(exit_code, 0)
            self.assertIn("final report", output.getvalue())
            self.assertNotIn("credential-must-not-persist", output.getvalue())
            self.assertEqual(len(FakeOptions.calls), 1)
            options = FakeOptions.calls[0]
            self.assertEqual(
                options,
                {
                    "env": {"CLAUDE_AGENT_SDK_CLIENT_APP": "mako-pure"},
                    "cwd": str(root.resolve()),
                    "tools": {"type": "preset", "preset": "claude_code"},
                    "permission_mode": "bypassPermissions",
                    "system_prompt": {"type": "preset", "preset": "claude_code"},
                    "model": "fixture-model",
                    "resume": "session-old",
                    "mcp_servers": {"mako_artifacts": "fake-artifact-server"},
                },
            )
            forbidden = {
                "allowed_tools",
                "disallowed_tools",
                "hooks",
                "strict_mcp_config",
                "setting_sources",
                "plugins",
                "sandbox",
                "max_turns",
                "max_budget_usd",
                "task_budget",
                "can_use_tool",
                "permission_prompt_tool_name",
                "enable_file_checkpointing",
                "agents",
            }
            self.assertTrue(forbidden.isdisjoint(options))
            self.assertEqual(len(prompts), 1)
            self.assertIn("https://target.invalid/", prompts[0])
            self.assertIn("retrieve the challenge flag", prompts[0])
            self.assertNotIn("validator", prompts[0].lower())
            self.assertNotIn("controller", prompts[0].lower())
            self.assertNotIn("phase", prompts[0].lower())

            run_path = root / "artifacts" / "pure_sdk" / "run-1" / "pure_sdk_run.json"
            record = json.loads(run_path.read_text(encoding="utf-8"))
            self.assertEqual(record["event_types"][-1], "AfterResultEvent")
            self.assertEqual(record["tool_names"], ["Bash"])
            self.assertEqual(record["session_id"], "session-new")
            self.assertEqual(record["num_turns"], 3)
            self.assertEqual(record["terminal_reason"], "completed")
            self.assertEqual(record["checkpoint_message_id"], "checkpoint-run-1")
            self.assertEqual(len(record["artifact_refs"]), 2)
            self.assertNotIn("secret-tool-input", run_path.read_text(encoding="utf-8"))
            self.assertNotIn("credential-must-not-persist", run_path.read_text(encoding="utf-8"))
            self.assertTrue((root / "logs" / "pure_sdk_last_run.json").is_file())

            shared = json.loads(context_path.read_text(encoding="utf-8"))
            self.assertEqual(shared["session_id"], "session-new")
            self.assertEqual(shared["last_run_id"], "run-1")

            evidence_root = root / "artifacts" / "pure_sdk" / "_evidence"
            with ArtifactWorkspace(evidence_root) as workspace:
                receipts = workspace.list_receipts(run_id="run-1", limit=10)
            self.assertEqual(
                {row["receipt"]["source_kind"] for row in receipts},
                {"tool_result", "run_file"},
            )
            tool_receipt = next(
                row for row in receipts if row["receipt"]["source_kind"] == "tool_result"
            )
            self.assertEqual(tool_receipt["receipt"]["source_ref"], "tool-1")
            self.assertEqual(tool_receipt["receipt"]["tool_name"], "Bash")
            self.assertIn("tool output", Path(tool_receipt["object_path"]).read_text())
            evidence_bytes = b"".join(
                path.read_bytes()
                for path in evidence_root.rglob("*")
                if path.is_file()
            )
            self.assertNotIn(b"secret-tool-input", evidence_bytes)

    def test_new_session_omits_resume_and_default_model(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prompts: list[str] = []
            sdk = fake_sdk(
                [
                    ResultMessage(
                        subtype="success",
                        is_error=False,
                        session_id="fresh-session",
                        usage={},
                        total_cost_usd=None,
                        num_turns=1,
                    )
                ],
                prompts,
            )
            with patch.dict(os.environ, {}, clear=True), patch.object(
                pure_sdk_agent, "_sdk_bindings", return_value=sdk
            ):
                exit_code = pure_sdk_agent.run(self._args(root, "--new-session"))

            self.assertEqual(exit_code, 0)
            options = FakeOptions.calls[0]
            self.assertNotIn("resume", options)
            self.assertNotIn("model", options)

    def test_build_options_exposes_followup_fork_flag(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sdk = fake_sdk([], [])
            options = pure_sdk_agent.build_pure_options(
                sdk,
                root,
                "parent-session",
                fork_session=True,
                resume_session_at="checkpoint-parent",
                artifact_server="artifact-server",
            )
        self.assertEqual(options.kwargs["resume"], "parent-session")
        self.assertTrue(options.kwargs["fork_session"])
        self.assertEqual(options.kwargs["resume_session_at"], "checkpoint-parent")
        self.assertEqual(
            options.kwargs["mcp_servers"], {"mako_artifacts": "artifact-server"}
        )
        self.assertNotIn("strict_mcp_config", options.kwargs)
        self.assertNotIn("allowed_tools", options.kwargs)
        self.assertNotIn("hooks", options.kwargs)
        self.assertIs(pure_sdk_agent._build_options, pure_sdk_agent.build_pure_options)
        self.assertIs(pure_sdk_agent._run_sdk_query, pure_sdk_agent.run_sdk_query)

    def test_artifact_tool_results_are_not_recaptured_recursively(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sdk = fake_sdk(
                [
                    AssistantMessage(
                        [
                            ToolUseBlock(
                                "mcp__mako_artifacts__artifact_list",
                                {"limit": 20},
                                id="artifact-tool-1",
                            )
                        ]
                    ),
                    UserMessage(
                        [ToolResultBlock("artifact-tool-1", "artifact listing")]
                    ),
                    ResultMessage(
                        subtype="success",
                        is_error=False,
                        session_id="session-a",
                        usage={},
                        total_cost_usd=None,
                        num_turns=1,
                    ),
                ],
                [],
            )
            with ArtifactWorkspace(root / "evidence") as workspace:
                result = asyncio.run(
                    pure_sdk_agent.run_sdk_query(
                        sdk,
                        "prompt",
                        FakeOptions(),
                        workspace=workspace,
                        run_id="run-1",
                        session_id="session-a",
                        call_id="call-1",
                    )
                )
                receipts = workspace.list_receipts(run_id="run-1")
        self.assertEqual(result["artifact_refs"], [])
        self.assertEqual(receipts, [])

    def test_fresh_and_resumed_runs_form_run_and_session_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first_sdk = fake_sdk(
                [
                    AssistantMessage([TextBlock("first")], uuid="checkpoint-first"),
                    ResultMessage(
                        subtype="success",
                        is_error=False,
                        session_id="session-a",
                        usage={"input_tokens": 3},
                        total_cost_usd=None,
                        num_turns=1,
                    )
                ],
                [],
            )
            second_sdk = fake_sdk(
                [
                    AssistantMessage([TextBlock("second")], uuid="checkpoint-second"),
                    ResultMessage(
                        subtype="success",
                        is_error=False,
                        session_id="session-b",
                        usage={"input_tokens": 5},
                        total_cost_usd=None,
                        num_turns=1,
                    )
                ],
                [],
            )
            with patch.dict(os.environ, {}, clear=True), redirect_stdout(io.StringIO()):
                with patch.object(pure_sdk_agent, "_sdk_bindings", return_value=first_sdk):
                    self.assertEqual(pure_sdk_agent.run(self._args(root, "--new-session")), 0)
                with patch.object(pure_sdk_agent, "_sdk_bindings", return_value=second_sdk):
                    self.assertEqual(
                        pure_sdk_agent.run(self._args(root, "--run-id", "run-2")),
                        0,
                    )

            ledger_path = root / "logs" / "mako_session_ledger.sqlite"
            with SessionLedger(ledger_path) as ledger:
                first_run = ledger.get_run("run-1")
                second_run = ledger.get_run("run-2")
                first_session = ledger.get_session("session-a")
                second_session = ledger.get_session("session-b")
                lineage = ledger.session_lineage("session-b")

            self.assertEqual(first_run["parent_run_id"], "")
            self.assertEqual(first_run["primary_session_id"], "session-a")
            self.assertEqual(first_run["checkpoint_message_id"], "checkpoint-first")
            self.assertEqual(second_run["parent_run_id"], "run-1")
            self.assertEqual(second_run["primary_session_id"], "session-b")
            self.assertEqual(second_run["checkpoint_message_id"], "checkpoint-second")
            self.assertEqual(first_session["parent_session_id"], "")
            self.assertEqual(second_session["parent_session_id"], "session-a")
            self.assertEqual(second_session["fork_reason"], "sdk_session_replacement")
            self.assertEqual([row["session_id"] for row in lineage], ["session-a", "session-b"])

            summary = json.loads(
                (root / "logs" / "pure_sdk_last_run.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary["parent_run_id"], "run-1")
            self.assertTrue(summary["call_id"])
            self.assertEqual(summary["ledger_path"], str(ledger_path.resolve()))

    def test_error_result_returns_nonzero_and_is_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prompts: list[str] = []
            sdk = fake_sdk(
                [
                    AssistantMessage([TextBlock("unable to finish")]),
                    ResultMessage(
                        subtype="error_during_execution",
                        is_error=True,
                        session_id="failed-session",
                        usage={"input_tokens": 2},
                        total_cost_usd=0.01,
                        num_turns=1,
                    ),
                ],
                prompts,
            )
            with patch.dict(os.environ, {}, clear=True), patch.object(
                pure_sdk_agent, "_sdk_bindings", return_value=sdk
            ), redirect_stdout(io.StringIO()):
                exit_code = pure_sdk_agent.run(self._args(root))

            self.assertEqual(exit_code, 1)
            record = json.loads(
                (root / "logs" / "pure_sdk_last_run.json").read_text(encoding="utf-8")
            )
            self.assertFalse(record["success"])
            self.assertTrue(record["is_error"])
            self.assertEqual(record["subtype"], "error_during_execution")

            ledger_path = root / "logs" / "mako_session_ledger.sqlite"
            with SessionLedger(ledger_path) as ledger:
                run_row = ledger.get_run("run-1")
                session_row = ledger.get_session("failed-session")
            with closing(sqlite3.connect(ledger_path)) as conn:
                call_row = conn.execute(
                    "SELECT result_status,usage_json,error_class FROM calls WHERE run_id=?",
                    ("run-1",),
                ).fetchone()
            self.assertEqual(run_row["status"], "failed")
            self.assertEqual(run_row["primary_session_id"], "failed-session")
            self.assertEqual(session_row["origin_run_id"], "run-1")
            self.assertEqual(call_row[0], "error_during_execution")
            self.assertEqual(json.loads(call_row[1]), {"input_tokens": 2})
            self.assertEqual(call_row[2], "error_during_execution")

    def test_sdk_start_failure_still_finishes_run_and_records_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with patch.dict(os.environ, {}, clear=True), patch.object(
                pure_sdk_agent,
                "_sdk_bindings",
                side_effect=RuntimeError("sensitive detail must not persist"),
            ), redirect_stdout(io.StringIO()):
                exit_code = pure_sdk_agent.run(self._args(root))

            self.assertEqual(exit_code, 1)
            ledger_path = root / "logs" / "mako_session_ledger.sqlite"
            with SessionLedger(ledger_path) as ledger:
                run_row = ledger.get_run("run-1")
            with closing(sqlite3.connect(ledger_path)) as conn:
                call_row = conn.execute(
                    "SELECT result_status,error_class FROM calls WHERE run_id=?",
                    ("run-1",),
                ).fetchone()
            self.assertEqual(run_row["status"], "failed")
            self.assertEqual(call_row, ("RuntimeError", "RuntimeError"))
            persisted = (root / "logs" / "pure_sdk_last_run.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("sensitive detail", persisted)

    def test_duplicate_run_id_is_rejected_without_mutating_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sdk = fake_sdk(
                [
                    AssistantMessage([TextBlock("original")], uuid="checkpoint-orig"),
                    ResultMessage(
                        subtype="success",
                        is_error=False,
                        session_id="session-orig",
                        usage={"input_tokens": 3},
                        total_cost_usd=None,
                        num_turns=1,
                    ),
                ],
                [],
            )
            with patch.dict(os.environ, {}, clear=True), redirect_stdout(io.StringIO()):
                with patch.object(
                    pure_sdk_agent, "_sdk_bindings", return_value=sdk
                ):
                    self.assertEqual(pure_sdk_agent.run(self._args(root)), 0)

                ledger_path = root / "logs" / "mako_session_ledger.sqlite"
                with SessionLedger(ledger_path) as ledger:
                    before_run = ledger.get_run("run-1")
                run_summary = (
                    root / "artifacts" / "pure_sdk" / "run-1" / "pure_sdk_run.json"
                ).read_bytes()
                last_summary = (
                    root / "logs" / "pure_sdk_last_run.json"
                ).read_bytes()
                context_before = json.loads(
                    (root / "logs" / "claude_sdk_shared_context.json").read_text()
                )
                with closing(sqlite3.connect(ledger_path)) as conn:
                    calls_before = conn.execute(
                        "SELECT * FROM calls WHERE run_id='run-1' ORDER BY rowid"
                    ).fetchall()

                variants = [
                    [],
                    ["--new-session"],
                    [
                        "--context-file",
                        str(root / "logs" / "other_context.json"),
                    ],
                ]
                for extra in variants:
                    with self.subTest(extra=extra):
                        second_sdk = fake_sdk([], [])
                        with patch.object(
                            pure_sdk_agent, "_sdk_bindings", return_value=second_sdk
                        ) as loader:
                            with self.assertRaisesRegex(
                                ValueError, "run already exists"
                            ):
                                pure_sdk_agent.run(self._args(root, *extra))
                        loader.assert_not_called()

                with SessionLedger(ledger_path) as ledger:
                    self.assertEqual(ledger.get_run("run-1"), before_run)
                with closing(sqlite3.connect(ledger_path)) as conn:
                    calls_after = conn.execute(
                        "SELECT * FROM calls WHERE run_id='run-1' ORDER BY rowid"
                    ).fetchall()
                self.assertEqual(len(calls_before), 1)
                self.assertEqual(calls_after, calls_before)
                self.assertEqual(
                    (
                        root / "artifacts" / "pure_sdk" / "run-1" / "pure_sdk_run.json"
                    ).read_bytes(),
                    run_summary,
                )
                self.assertEqual(
                    (root / "logs" / "pure_sdk_last_run.json").read_bytes(),
                    last_summary,
                )
                context_after = json.loads(
                    (root / "logs" / "claude_sdk_shared_context.json").read_text()
                )
                self.assertEqual(
                    context_after["session_id"], context_before["session_id"]
                )
                self.assertEqual(
                    context_after["last_run_id"], context_before["last_run_id"]
                )

    def test_pure_run_artifact_receipts_track_observed_session(self) -> None:
        for resumed in (False, True):
            with self.subTest(resumed=resumed), tempfile.TemporaryDirectory() as td:
                FakeOptions.calls.clear()
                root = Path(td)
                context_path = root / "logs" / "claude_sdk_shared_context.json"
                explicit_source = root / "explicit_capture.txt"
                explicit_source.write_text("explicit capture", encoding="utf-8")
                handlers: dict[str, object] = {}

                def tool(name, description, schema):
                    def decorate(function):
                        handlers[name] = function
                        return function
                    return decorate

                async def query(*, prompt, options):
                    yield SimpleNamespace(
                        subtype="init", data={"session_id": "actual-session"}
                    )
                    await handlers["artifact_capture"](
                        {"path": str(explicit_source), "note": "explicit"}
                    )
                    yield AssistantMessage(
                        [ToolUseBlock("Read", {"file_path": "/tmp/x"}, id="tool-9")]
                    )
                    yield UserMessage(
                        [ToolResultBlock("tool-9", "observed output")]
                    )
                    yield ResultMessage(
                        subtype="success",
                        is_error=False,
                        session_id="actual-session",
                        usage={},
                        total_cost_usd=None,
                        num_turns=1,
                    )

                sdk = fake_sdk([], [])
                sdk.tool = tool
                sdk.query = query
                with patch.dict(os.environ, {}, clear=True):
                    if resumed:
                        signature = pure_sdk_agent._sdk_signature(root)
                        with shared_session_lease(
                            context_path, sdk_signature=signature
                        ) as state:
                            state.session_id = "resumed-session"
                            state.last_run_id = "seed-run"
                    with patch.object(
                        pure_sdk_agent, "_sdk_bindings", return_value=sdk
                    ), redirect_stdout(io.StringIO()):
                        code = pure_sdk_agent.run(self._args(root))

                self.assertEqual(code, 0)
                options = FakeOptions.calls[0]
                if resumed:
                    self.assertEqual(options["resume"], "resumed-session")
                else:
                    self.assertNotIn("resume", options)
                evidence_root = root / "artifacts" / "pure_sdk" / "_evidence"
                with ArtifactWorkspace(evidence_root) as workspace:
                    receipts = workspace.list_receipts(run_id="run-1", limit=10)
                self.assertEqual(
                    {row["receipt"]["source_kind"] for row in receipts},
                    {"tool_result", "sdk_artifact_tool"},
                )
                for row in receipts:
                    self.assertEqual(
                        row["receipt"]["session_id"], "actual-session"
                    )

    def test_base_exception_after_claim_still_closes_owned_run(self) -> None:
        for exc in (KeyboardInterrupt(), asyncio.CancelledError()):
            with self.subTest(exc=type(exc).__name__), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                with patch.dict(os.environ, {}, clear=True), patch.object(
                    pure_sdk_agent, "_sdk_bindings", side_effect=exc
                ), redirect_stdout(io.StringIO()):
                    with self.assertRaises(type(exc)):
                        pure_sdk_agent.run(self._args(root))

                ledger_path = root / "logs" / "mako_session_ledger.sqlite"
                with SessionLedger(ledger_path) as ledger:
                    run_row = ledger.get_run("run-1")
                self.assertIsNotNone(run_row)
                self.assertEqual(run_row["status"], "failed")
                with closing(sqlite3.connect(ledger_path)) as conn:
                    call_rows = conn.execute(
                        "SELECT result_status,error_class FROM calls WHERE run_id='run-1'"
                    ).fetchall()
                self.assertEqual(len(call_rows), 1)
                self.assertEqual(call_rows[0], ("RuntimeError", "RuntimeError"))

                # A rejected duplicate claim still writes nothing.
                with patch.object(
                    pure_sdk_agent, "_sdk_bindings"
                ) as loader, self.assertRaisesRegex(
                    ValueError, "run already exists"
                ), redirect_stdout(io.StringIO()):
                    pure_sdk_agent.run(self._args(root))
                loader.assert_not_called()
                with SessionLedger(ledger_path) as ledger:
                    self.assertEqual(ledger.get_run("run-1"), run_row)
                with closing(sqlite3.connect(ledger_path)) as conn:
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) FROM calls WHERE run_id='run-1'"
                        ).fetchone()[0],
                        1,
                    )

    def test_setup_failure_after_claim_closes_run_without_keyerror(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            context_path = root / "logs" / "claude_sdk_shared_context.json"
            with patch.dict(os.environ, {}, clear=True):
                signature = pure_sdk_agent._sdk_signature(root)
                with shared_session_lease(
                    context_path, sdk_signature=signature
                ) as state:
                    state.session_id = "resumed-session"
                    state.last_run_id = "prior-run"
                blocker = root / "artifacts" / "pure_sdk" / "run-1"
                blocker.parent.mkdir(parents=True)
                blocker.write_text("not a directory", encoding="utf-8")
                with patch.object(
                    pure_sdk_agent, "_sdk_bindings"
                ) as loader, redirect_stdout(io.StringIO()):
                    with self.assertRaises(FileExistsError):
                        pure_sdk_agent.run(self._args(root))
                loader.assert_not_called()

                ledger_path = root / "logs" / "mako_session_ledger.sqlite"
                with SessionLedger(ledger_path) as ledger:
                    run_row = ledger.get_run("run-1")
                    session_row = ledger.get_session("resumed-session")
                self.assertEqual(run_row["status"], "failed")
                self.assertIsNotNone(session_row)
                with closing(sqlite3.connect(ledger_path)) as conn:
                    call_row = conn.execute(
                        "SELECT session_id,result_status,error_class"
                        " FROM calls WHERE run_id='run-1'"
                    ).fetchone()
                self.assertEqual(
                    call_row,
                    ("resumed-session", "FileExistsError", "FileExistsError"),
                )
                after = json.loads(context_path.read_text(encoding="utf-8"))
                self.assertEqual(after["session_id"], "resumed-session")
                self.assertEqual(after["last_run_id"], "prior-run")


if __name__ == "__main__":
    unittest.main()
