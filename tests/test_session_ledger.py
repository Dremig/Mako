from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from web_agent.session_ledger import SessionLedger


class SessionLedgerTests(unittest.TestCase):
    def test_run_and_session_topology(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state" / "ledger.sqlite"
            with SessionLedger(path) as ledger:
                ledger.register_run(
                    "run-root",
                    target="https://target.invalid",
                    objective="solve",
                    mode="pure_sdk",
                    workspace_root="/workspace/root",
                )
                ledger.register_session(
                    "session-root",
                    "run-root",
                    sdk_signature="sdk-a",
                    transcript_ref="transcripts/root.jsonl",
                )
                ledger.touch_session("session-root", "run-root")
                ledger.register_run(
                    "run-child",
                    parent_run_id="run-root",
                    target="https://target.invalid",
                    objective="follow up",
                    mode="fork",
                    workspace_root="/workspace/child",
                )
                ledger.register_session(
                    "session-child",
                    "run-child",
                    parent_session_id="session-root",
                    sdk_signature="sdk-a",
                    fork_reason="try alternate route",
                )
                ledger.finish_run("run-child", "completed", "session-child")

                root = ledger.get_run("run-root")
                child = ledger.get_run("run-child")
                self.assertEqual(root["primary_session_id"], "session-root")
                self.assertEqual(child["parent_run_id"], "run-root")
                self.assertEqual(child["primary_session_id"], "session-child")
                self.assertEqual(child["status"], "completed")
                self.assertEqual(ledger.latest_run()["run_id"], "run-child")

            self.assertTrue(path.exists())

    def test_register_is_idempotent_and_session_identity_conflicts_fail(self) -> None:
        with tempfile.TemporaryDirectory() as td, SessionLedger(
            Path(td) / "ledger.sqlite"
        ) as ledger:
            run_args = dict(
                target="target",
                objective="objective",
                mode="pure_sdk",
                workspace_root="workspace",
            )
            ledger.register_run("run-1", **run_args)
            ledger.register_run("run-1", **run_args)
            ledger.register_session(
                "session-1", "run-1", sdk_signature="sdk-a"
            )
            ledger.register_session(
                "session-1", "run-1", sdk_signature="sdk-a"
            )

            with self.assertRaisesRegex(ValueError, "parent_session_id"):
                ledger.register_session(
                    "session-1",
                    "run-1",
                    parent_session_id="different-parent",
                    sdk_signature="sdk-a",
                )
            with self.assertRaisesRegex(ValueError, "sdk_signature"):
                ledger.register_session(
                    "session-1", "run-1", sdk_signature="sdk-b"
                )
            with self.assertRaisesRegex(ValueError, "origin_run_id"):
                ledger.register_session(
                    "session-1", "different-run", sdk_signature="sdk-a"
                )

            stored = ledger.get_session("session-1")
            self.assertEqual(stored["parent_session_id"], "")
            self.assertEqual(stored["sdk_signature"], "sdk-a")

    def test_session_lineage_is_root_to_leaf_and_cycles_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td, SessionLedger(
            Path(td) / "ledger.sqlite"
        ) as ledger:
            ledger.register_session("s-root", "r-1", sdk_signature="sdk-a")
            ledger.register_session(
                "s-mid", "r-2", parent_session_id="s-root", sdk_signature="sdk-a"
            )
            ledger.register_session(
                "s-leaf", "r-3", parent_session_id="s-mid", sdk_signature="sdk-a"
            )
            self.assertEqual(
                [row["session_id"] for row in ledger.session_lineage("s-leaf")],
                ["s-root", "s-mid", "s-leaf"],
            )
            self.assertEqual(ledger.session_lineage("missing"), [])
            with self.assertRaisesRegex(ValueError, "cycle"):
                ledger.register_session(
                    "cycle-a",
                    "r-4",
                    parent_session_id="cycle-a",
                    sdk_signature="sdk-a",
                )

    def test_calls_are_immutable_idempotent_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.sqlite"
            with SessionLedger(path) as ledger:
                call_id = ledger.record_call(
                    "run-1",
                    "session-1",
                    call_id="call-1",
                    started_at="2026-01-01T00:00:00Z",
                    ended_at="2026-01-01T00:00:01Z",
                    result_status="completed",
                    usage={"input_tokens": 12, "output_tokens": 4},
                    cost_usd=0.25,
                    num_turns=3,
                    terminal_reason="completed",
                )
                self.assertEqual(call_id, "call-1")
                ledger.record_call(
                    "run-1",
                    "session-1",
                    call_id="call-1",
                    started_at="2026-01-01T00:00:00Z",
                    ended_at="2026-01-01T00:00:01Z",
                    result_status="completed",
                    usage={"input_tokens": 12, "output_tokens": 4},
                    cost_usd=0.25,
                    num_turns=3,
                    terminal_reason="completed",
                )
                with self.assertRaisesRegex(ValueError, "conflicts"):
                    ledger.record_call(
                        "run-1",
                        "session-1",
                        call_id="call-1",
                        started_at="2026-01-01T00:00:00Z",
                        ended_at="2026-01-01T00:00:02Z",
                        result_status="failed",
                        usage={"input_tokens": 12},
                        error_class="TimeoutError",
                    )

            conn = sqlite3.connect(path)
            row = conn.execute("SELECT * FROM calls WHERE call_id='call-1'").fetchone()
            columns = [item[0] for item in conn.execute("SELECT * FROM calls").description]
            conn.close()
            payload = dict(zip(columns, row))
            self.assertEqual(payload["result_status"], "completed")
            self.assertEqual(payload["error_class"], "")
            self.assertEqual(
                json.loads(payload["usage_json"]),
                {"input_tokens": 12, "output_tokens": 4},
            )
            self.assertEqual(payload["cost_usd"], 0.25)
            self.assertEqual(payload["num_turns"], 3)
            self.assertEqual(payload["terminal_reason"], "completed")

    def test_intervention_receipt_lifecycle_hashes_and_truncates_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as td, SessionLedger(
            Path(td) / "ledger.sqlite"
        ) as ledger:
            prompt = "继续检查登录流程" * 30
            iid = ledger.record_intervention(
                "run-source", "session-1", "fork", prompt,
                preview="继续检查[REDACTED]",
            )
            accepted = ledger.list_interventions("run-source")
            self.assertEqual(len(accepted), 1)
            self.assertEqual(accepted[0]["intervention_id"], iid)
            self.assertEqual(accepted[0]["status"], "accepted")
            self.assertEqual(accepted[0]["prompt_preview"], "继续检查[REDACTED]")
            self.assertLessEqual(len(accepted[0]["prompt_preview"]), 200)
            self.assertEqual(
                accepted[0]["prompt_sha256"],
                hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            )
            self.assertNotIn(prompt, json.dumps(accepted, ensure_ascii=False))

            ledger.update_intervention(iid, "applied", result_run_id="run-fork")
            ledger.update_intervention(iid, "completed", detail="follow-up complete")
            completed = ledger.list_interventions("run-source")[0]
            self.assertEqual(completed["status"], "completed")
            self.assertEqual(completed["result_run_id"], "run-fork")
            self.assertEqual(completed["detail"], "follow-up complete")
            with self.assertRaisesRegex(ValueError, "cannot transition"):
                ledger.update_intervention(iid, "applied")

            with self.assertRaises(ValueError):
                ledger.record_intervention("run-source", "session-1", "plan", "x")
            with self.assertRaises(ValueError):
                ledger.update_intervention(iid, "pending")

    def test_schema_contains_no_cognitive_state_tables(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.sqlite"
            with SessionLedger(path):
                pass
            conn = sqlite3.connect(path)
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            conn.close()
            self.assertEqual(tables, {"runs", "sessions", "calls", "interventions"})
            self.assertEqual(mode.lower(), "wal")

    def test_concurrent_writes_on_one_ledger_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as td, SessionLedger(
            Path(td) / "ledger.sqlite"
        ) as ledger:
            errors: list[BaseException] = []

            def writer(index: int) -> None:
                try:
                    ledger.register_run(
                        f"run-{index}",
                        target="target",
                        objective=f"objective-{index}",
                        mode="pure_sdk",
                        workspace_root=f"workspace-{index}",
                    )
                    ledger.register_session(
                        f"session-{index}",
                        f"run-{index}",
                        sdk_signature="sdk-a",
                    )
                    ledger.touch_session(f"session-{index}", f"run-{index}")
                    ledger.record_call(
                        f"run-{index}",
                        f"session-{index}",
                        call_id=f"call-{index}",
                        result_status="completed",
                        usage={"worker": index},
                    )
                except BaseException as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=writer, args=(idx,)) for idx in range(12)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)

            self.assertEqual(errors, [])
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(
                sum(ledger.get_run(f"run-{idx}") is not None for idx in range(12)),
                12,
            )

    def test_exclusive_registration_rejects_duplicate_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as td, SessionLedger(
            Path(td) / "ledger.sqlite"
        ) as ledger:
            run_args = dict(
                target="target",
                objective="objective",
                mode="pure_sdk",
                workspace_root="workspace",
            )
            ledger.register_run("run-1", **run_args)
            ledger.register_run("run-1", **run_args)
            ledger.finish_run(
                "run-1",
                "completed",
                primary_session_id="session-1",
                checkpoint_message_id="checkpoint-1",
            )
            before = ledger.get_run("run-1")
            with self.assertRaisesRegex(ValueError, "run already exists"):
                ledger.register_run("run-1", exclusive=True, **run_args)
            self.assertEqual(ledger.get_run("run-1"), before)

    def test_exclusive_claim_allows_exactly_one_owner_across_ledgers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.sqlite"
            ledger_a = SessionLedger(path)
            ledger_b = SessionLedger(path)
            try:
                barrier = threading.Barrier(2)
                outcomes: list[str] = []

                def claim(ledger: SessionLedger) -> None:
                    try:
                        barrier.wait(timeout=5)
                        ledger.register_run(
                            "shared-run",
                            target="target",
                            objective="objective",
                            mode="pure_sdk",
                            workspace_root="workspace",
                            exclusive=True,
                        )
                        outcomes.append("claimed")
                    except ValueError:
                        outcomes.append("rejected")

                threads = [
                    threading.Thread(target=claim, args=(ledger,))
                    for ledger in (ledger_a, ledger_b)
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=10)

                self.assertEqual(sorted(outcomes), ["claimed", "rejected"])
                self.assertTrue(all(not thread.is_alive() for thread in threads))
                self.assertIsNotNone(ledger_a.get_run("shared-run"))
            finally:
                ledger_a.close()
                ledger_b.close()
            conn = sqlite3.connect(path)
            count = conn.execute(
                "SELECT COUNT(*) FROM runs WHERE run_id='shared-run'"
            ).fetchone()[0]
            conn.close()
            self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
