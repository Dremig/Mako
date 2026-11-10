from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from web_agent import followup
from web_agent.artifact_workspace import ArtifactWorkspace
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
    session_id: str = ""
    uuid: str = ""


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
    result: str
    terminal_reason: str = "completed"
    stop_reason: str = ""
    uuid: str = "followup-checkpoint"


class FakeOptions:
    calls: list[FakeOptions] = []

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = dict(kwargs)
        for key, value in kwargs.items():
            setattr(self, key, value)
        type(self).calls.append(self)


def fake_sdk(messages: list[object]) -> SimpleNamespace:
    async def query(*, prompt: str, options: FakeOptions):
        del prompt, options
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


class FakeLedger:
    def __init__(self) -> None:
        self.runs: dict[str, dict[str, object]] = {}
        self.sessions: dict[str, dict[str, object]] = {}
        self.calls: list[dict[str, object]] = []
        self.interventions: list[dict[str, object]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def register_run(self, **values):
        self.runs[str(values["run_id"])] = dict(values)
        return self.runs[str(values["run_id"])]

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        primary_session_id: str = "",
        checkpoint_message_id: str = "",
    ):
        self.runs[run_id]["status"] = status
        self.runs[run_id]["primary_session_id"] = primary_session_id
        self.runs[run_id]["checkpoint_message_id"] = checkpoint_message_id

    def register_session(self, **values):
        self.sessions[str(values["session_id"])] = dict(values)
        return self.sessions[str(values["session_id"])]

    def touch_session(self, session_id: str, *, run_id: str = ""):
        self.sessions[session_id]["last_run_id"] = run_id

    def get_run(self, run_id: str):
        return self.runs.get(run_id)

    def get_session(self, session_id: str):
        return self.sessions.get(session_id)

    def latest_run(self):
        key = next(reversed(self.runs), None) if self.runs else None
        return self.runs.get(key) if key is not None else None

    def record_call(self, **values):
        self.calls.append(dict(values))

    def record_intervention(self, **values):
        intervention_id = f"intervention-{len(self.interventions) + 1}"
        self.interventions.append(
            {"intervention_id": intervention_id, "status": "accepted", **values}
        )
        return intervention_id

    def update_intervention(
        self,
        intervention_id: str,
        *,
        status: str,
        result_run_id: str = "",
        detail: str = "",
    ):
        row = next(
            item for item in self.interventions
            if item["intervention_id"] == intervention_id
        )
        row.update(status=status, result_run_id=result_run_id, detail=detail)


class FollowupTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeOptions.calls.clear()

    def _args(self, root: Path, mode: str, result_run_id: str):
        return followup.parse_args(
            [
                "--root", str(root),
                "--run-id", "source-run",
                "--mode", mode,
                "--message", "continue from the existing evidence",
                "--result-run-id", result_run_id,
            ]
        )

    def _ledger(self, root: Path, *, signature: str | None = None) -> FakeLedger:
        ledger = FakeLedger()
        sig = signature if signature is not None else followup._sdk_signature(root)
        ledger.runs["source-run"] = {
            "run_id": "source-run",
            "primary_session_id": "source-session",
            "target": "https://target.invalid/",
            "objective": "retrieve flag",
            "status": "completed",
            "checkpoint_message_id": "source-checkpoint",
        }
        ledger.sessions["source-session"] = {
            "session_id": "source-session",
            "origin_run_id": "source-run",
            "parent_session_id": "",
            "sdk_signature": sig,
            "status": "active",
        }
        return ledger

    def _result(self, session_id: str, *, success: bool = True) -> ResultMessage:
        return ResultMessage(
            subtype="success" if success else "error_during_execution",
            is_error=not success,
            session_id=session_id,
            usage={"input_tokens": 4, "output_tokens": 2},
            total_cost_usd=0.1,
            num_turns=2,
            result="follow-up complete" if success else "failed",
        )

    def test_resume_continues_source_session_and_closes_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            root = Path(td).resolve()
            ledger = self._ledger(root)
            sdk = fake_sdk([self._result("source-session")])
            with patch.object(followup, "SessionLedger", return_value=ledger), patch.object(
                followup.pure_sdk, "_sdk_bindings", return_value=sdk
            ):
                code = followup.run(self._args(root, "resume", "child-resume"))

            self.assertEqual(code, 0)
            options = FakeOptions.calls[0]
            self.assertEqual(options.resume, "source-session")
            self.assertFalse(bool(getattr(options, "fork_session", False)))
            self.assertEqual(
                options.mcp_servers,
                {"mako_artifacts": "fake-artifact-server"},
            )
            self.assertFalse(hasattr(options, "strict_mcp_config"))
            self.assertFalse(hasattr(options, "allowed_tools"))
            self.assertFalse(hasattr(options, "hooks"))
            self.assertEqual(ledger.runs["child-resume"]["parent_run_id"], "source-run")
            self.assertEqual(ledger.runs["child-resume"]["status"], "completed")
            self.assertEqual(ledger.calls[0]["result_status"], "completed")
            self.assertEqual(ledger.interventions[0]["kind"], "resume")
            self.assertEqual(ledger.interventions[0]["status"], "completed")
            self.assertEqual(ledger.sessions["source-session"]["last_run_id"], "child-resume")
            self.assertTrue(
                (root / "artifacts" / "mako" / "child-resume" / "followup_result.json").is_file()
            )

    def test_fork_creates_session_lineage_and_moves_shared_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            root = Path(td).resolve()
            ledger = self._ledger(root)
            sdk = fake_sdk([self._result("forked-session")])
            with patch.object(followup, "SessionLedger", return_value=ledger), patch.object(
                followup.pure_sdk, "_sdk_bindings", return_value=sdk
            ):
                code = followup.run(self._args(root, "fork", "child-fork"))

            self.assertEqual(code, 0)
            options = FakeOptions.calls[0]
            self.assertEqual(options.resume, "source-session")
            self.assertTrue(options.fork_session)
            self.assertEqual(options.resume_session_at, "source-checkpoint")
            self.assertEqual(
                options.mcp_servers,
                {"mako_artifacts": "fake-artifact-server"},
            )
            forked = ledger.sessions["forked-session"]
            self.assertEqual(forked["parent_session_id"], "source-session")
            self.assertEqual(forked["origin_run_id"], "child-fork")
            self.assertEqual(forked["fork_reason"], "operator_followup")
            self.assertEqual(ledger.runs["child-fork"]["primary_session_id"], "forked-session")
            shared = json.loads(
                (root / "logs" / "claude_sdk_shared_context.json").read_text(encoding="utf-8")
            )
            self.assertEqual(shared["session_id"], "forked-session")
            self.assertEqual(shared["last_run_id"], "child-fork")

    def test_failed_result_closes_child_call_and_intervention(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            root = Path(td).resolve()
            ledger = self._ledger(root)
            sdk = fake_sdk([self._result("source-session", success=False)])
            with patch.object(followup, "SessionLedger", return_value=ledger), patch.object(
                followup.pure_sdk, "_sdk_bindings", return_value=sdk
            ):
                code = followup.run(self._args(root, "inspect", "child-failed"))

            self.assertEqual(code, 1)
            self.assertEqual(ledger.runs["child-failed"]["status"], "failed")
            self.assertEqual(ledger.calls[0]["result_status"], "failed")
            self.assertEqual(ledger.interventions[0]["status"], "failed")
            self.assertEqual(ledger.interventions[0]["kind"], "inspect")

    def test_followup_exposes_artifact_tools_and_captures_results_and_files(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            root = Path(td).resolve()
            produced = root / "artifacts" / "mako" / "artifact-child" / "notes.txt"
            produced.parent.mkdir(parents=True, exist_ok=True)
            produced.write_text("follow-up run file", encoding="utf-8")
            ledger = self._ledger(root)
            sdk = fake_sdk(
                [
                    AssistantMessage(
                        [
                            ToolUseBlock(
                                "Bash",
                                {"command": "input-must-not-persist"},
                                id="follow-tool-1",
                            )
                        ]
                    ),
                    UserMessage([ToolResultBlock("follow-tool-1", "follow tool output")]),
                    self._result("source-session"),
                ]
            )
            with patch.object(followup, "SessionLedger", return_value=ledger), patch.object(
                followup.pure_sdk, "_sdk_bindings", return_value=sdk
            ):
                code = followup.run(self._args(root, "resume", "artifact-child"))

            self.assertEqual(code, 0)
            self.assertEqual(
                FakeOptions.calls[0].mcp_servers,
                {"mako_artifacts": "fake-artifact-server"},
            )
            result_path = produced.parent / "followup_result.json"
            record = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(len(record["artifact_refs"]), 2)

            evidence_root = root / "artifacts" / "mako" / "_evidence"
            with ArtifactWorkspace(evidence_root) as workspace:
                receipts = workspace.list_receipts(run_id="artifact-child", limit=10)
            self.assertEqual(
                {row["receipt"]["source_kind"] for row in receipts},
                {"tool_result", "run_file"},
            )
            tool_receipt = next(
                row for row in receipts if row["receipt"]["source_kind"] == "tool_result"
            )
            self.assertIn("follow tool output", Path(tool_receipt["object_path"]).read_text())
            evidence_bytes = b"".join(
                path.read_bytes()
                for path in evidence_root.rglob("*")
                if path.is_file()
            )
            self.assertNotIn(b"input-must-not-persist", evidence_bytes)

    def test_signature_mismatch_is_rejected_before_sdk_call(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            root = Path(td).resolve()
            ledger = self._ledger(root, signature="different-signature")
            with patch.object(followup, "SessionLedger", return_value=ledger), patch.object(
                followup.pure_sdk, "_sdk_bindings"
            ) as loader:
                code = followup.main(
                    [
                        "--root", str(root), "--run-id", "source-run",
                        "--mode", "resume", "--message", "continue",
                    ]
                )
            self.assertEqual(code, 2)
            loader.assert_not_called()
            self.assertEqual(set(ledger.runs), {"source-run"})

    def test_missing_source_run_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            root = Path(td).resolve()
            ledger = FakeLedger()
            with patch.object(followup, "SessionLedger", return_value=ledger), patch.object(
                followup.pure_sdk, "_sdk_bindings"
            ) as loader:
                code = followup.main(
                    [
                        "--root", str(root), "--run-id", "missing-run",
                        "--mode", "inspect", "--message", "show progress",
                    ]
                )
            self.assertEqual(code, 2)
            loader.assert_not_called()
            self.assertFalse(ledger.interventions)

    def test_omitted_run_id_uses_latest_run(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            root = Path(td).resolve()
            ledger = self._ledger(root)
            sdk = fake_sdk([self._result("source-session")])
            with patch.object(followup, "SessionLedger", return_value=ledger), patch.object(
                followup.pure_sdk, "_sdk_bindings", return_value=sdk
            ):
                code = followup.run(followup.parse_args([
                    "--root", str(root), "--mode", "inspect",
                    "--message", "summarize the current state",
                    "--result-run-id", "latest-child",
                ]))
            self.assertEqual(code, 0)
            self.assertEqual(ledger.runs["latest-child"]["parent_run_id"], "source-run")

    def test_real_ledger_persists_fork_lineage_and_call_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            root = Path(td).resolve()
            ledger_path = root / "logs" / "mako_session_ledger.sqlite"
            signature = followup._sdk_signature(root)
            with followup.SessionLedger(ledger_path) as ledger:
                ledger.register_run(
                    "source-run",
                    target="https://target.invalid/",
                    objective="retrieve flag",
                    mode="pure",
                    workspace_root=str(root),
                )
                ledger.register_session(
                    "source-session",
                    "source-run",
                    sdk_signature=signature,
                )
                ledger.finish_run(
                    "source-run",
                    "completed",
                    primary_session_id="source-session",
                    checkpoint_message_id="source-checkpoint",
                )

            sdk = fake_sdk([
                AssistantMessage([TextBlock("fork complete")], uuid="followup-checkpoint"),
                self._result("real-fork-session"),
            ])
            args = self._args(root, "fork", "real-child")
            args.ledger = ledger_path
            with patch.object(followup.pure_sdk, "_sdk_bindings", return_value=sdk):
                code = followup.run(args)
            self.assertEqual(code, 0)

            with followup.SessionLedger(ledger_path) as ledger:
                child = ledger.get_run("real-child")
                self.assertIsNotNone(child)
                self.assertEqual(child["parent_run_id"], "source-run")
                self.assertEqual(child["primary_session_id"], "real-fork-session")
                self.assertEqual(child["checkpoint_message_id"], "followup-checkpoint")
                lineage = ledger.session_lineage("real-fork-session")
                self.assertEqual(
                    [item["session_id"] for item in lineage],
                    ["source-session", "real-fork-session"],
                )
                interventions = ledger.list_interventions("source-run")
                self.assertEqual(interventions[-1]["status"], "completed")
                self.assertEqual(interventions[-1]["result_run_id"], "real-child")

            with closing(sqlite3.connect(ledger_path)) as conn:
                receipt = conn.execute(
                    "SELECT run_id,session_id,result_status,error_class FROM calls"
                ).fetchone()
            self.assertEqual(
                receipt,
                ("real-child", "real-fork-session", "completed", ""),
            )

    def test_missing_checkpoint_fork_is_rejected_before_any_work(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            root = Path(td).resolve()
            ledger = self._ledger(root)
            ledger.runs["source-run"]["checkpoint_message_id"] = ""
            with patch.object(followup, "SessionLedger", return_value=ledger), patch.object(
                followup.pure_sdk, "_sdk_bindings"
            ) as loader:
                code = followup.main(
                    [
                        "--root", str(root), "--run-id", "source-run",
                        "--mode", "fork", "--message", "branch off",
                        "--result-run-id", "no-checkpoint-child",
                    ]
                )
            self.assertEqual(code, 2)
            loader.assert_not_called()
            self.assertEqual(set(ledger.runs), {"source-run"})
            self.assertFalse(ledger.calls)
            self.assertFalse(ledger.interventions)
            self.assertNotIn("last_run_id", ledger.sessions["source-session"])
            self.assertFalse(
                (root / "artifacts" / "mako" / "no-checkpoint-child").exists()
            )

    def test_inspect_and_resume_without_checkpoint_still_run(self) -> None:
        for mode in ("inspect", "resume"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td, patch.dict(
                os.environ, {}, clear=True
            ):
                root = Path(td).resolve()
                ledger = self._ledger(root)
                ledger.runs["source-run"]["checkpoint_message_id"] = ""
                sdk = fake_sdk([self._result("source-session")])
                with patch.object(
                    followup, "SessionLedger", return_value=ledger
                ), patch.object(
                    followup.pure_sdk, "_sdk_bindings", return_value=sdk
                ):
                    code = followup.run(self._args(root, mode, f"child-{mode}"))
                self.assertEqual(code, 0)
                self.assertEqual(ledger.runs[f"child-{mode}"]["status"], "completed")

    def test_failed_fork_preserves_unrelated_active_pointer(self) -> None:
        for allocated in ("", "failed-child-session"):
            with self.subTest(allocated=allocated), tempfile.TemporaryDirectory() as td, patch.dict(
                os.environ, {}, clear=True
            ):
                root = Path(td).resolve()
                ledger = self._ledger(root)
                context = root / "logs" / "claude_sdk_shared_context.json"
                with shared_session_lease(
                    context, sdk_signature=followup._sdk_signature(root)
                ) as state:
                    state.session_id = "already-active-session"
                    state.last_run_id = "already-active-run"
                sdk = fake_sdk([self._result(allocated, success=False)])
                with patch.object(
                    followup, "SessionLedger", return_value=ledger
                ), patch.object(
                    followup.pure_sdk, "_sdk_bindings", return_value=sdk
                ):
                    code = followup.run(self._args(root, "fork", "failed-fork-child"))

                self.assertEqual(code, 1)
                after = json.loads(context.read_text(encoding="utf-8"))
                self.assertEqual(after["session_id"], "already-active-session")
                self.assertEqual(after["last_run_id"], "already-active-run")
                self.assertEqual(ledger.runs["failed-fork-child"]["status"], "failed")
                self.assertEqual(ledger.calls[0]["result_status"], "failed")
                self.assertEqual(ledger.interventions[0]["status"], "failed")
                if allocated:
                    child = ledger.sessions["failed-child-session"]
                    self.assertEqual(child["parent_session_id"], "source-session")
                    self.assertEqual(child["origin_run_id"], "failed-fork-child")
                    self.assertEqual(child["status"], "failed")
                    self.assertEqual(ledger.calls[0]["session_id"], allocated)
                    self.assertEqual(
                        ledger.runs["failed-fork-child"]["primary_session_id"],
                        allocated,
                    )
                else:
                    self.assertEqual(
                        ledger.calls[0]["session_id"], "source-session"
                    )
                    self.assertEqual(
                        ledger.runs["failed-fork-child"]["primary_session_id"],
                        "source-session",
                    )

    def test_fork_artifact_receipts_use_observed_child_session(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            root = Path(td).resolve()
            ledger = self._ledger(root)
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
                    subtype="init", data={"session_id": "actual-child"}
                )
                await handlers["artifact_capture"](
                    {"path": str(explicit_source), "note": "explicit"}
                )
                yield AssistantMessage(
                    [ToolUseBlock("Read", {"file_path": "/tmp/x"}, id="tool-7")]
                )
                yield UserMessage(
                    [ToolResultBlock("tool-7", "child observation")]
                )
                yield self._result("actual-child")

            sdk = fake_sdk([])
            sdk.tool = tool
            sdk.query = query
            with patch.object(followup, "SessionLedger", return_value=ledger), patch.object(
                followup.pure_sdk, "_sdk_bindings", return_value=sdk
            ):
                code = followup.run(self._args(root, "fork", "child-fork"))

            self.assertEqual(code, 0)
            options = FakeOptions.calls[-1]
            self.assertEqual(options.resume, "source-session")
            self.assertTrue(options.fork_session)
            self.assertEqual(options.resume_session_at, "source-checkpoint")
            evidence_root = root / "artifacts" / "mako" / "_evidence"
            with ArtifactWorkspace(evidence_root) as workspace:
                receipts = workspace.list_receipts(run_id="child-fork", limit=10)
            self.assertEqual(
                {row["receipt"]["source_kind"] for row in receipts},
                {"tool_result", "sdk_artifact_tool"},
            )
            for row in receipts:
                self.assertEqual(row["receipt"]["session_id"], "actual-child")
            self.assertEqual(ledger.calls[0]["session_id"], "actual-child")
            self.assertEqual(
                ledger.runs["child-fork"]["primary_session_id"], "actual-child"
            )


if __name__ == "__main__":
    unittest.main()
