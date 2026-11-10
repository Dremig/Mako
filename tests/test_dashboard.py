from __future__ import annotations

import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from web_agent.artifact_workspace import ArtifactWorkspace
from web_agent.dashboard import DashboardStore, create_server
from web_agent.session_ledger import SessionLedger


class DashboardStoreTests(unittest.TestCase):
    def _seed(self, root: Path) -> DashboardStore:
        ledger_path = root / "logs" / "mako_session_ledger.sqlite"
        artifact_dir = root / "artifacts" / "mako"
        run_dir = artifact_dir / "run-root"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "pure_sdk_run.json").write_text(
            json.dumps(
                {
                    "run_id": "run-root",
                    "success": True,
                    "assistant_text": "flag{demo}",
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                    "total_cost_usd": 0.25,
                    "num_turns": 2,
                }
            ),
            encoding="utf-8",
        )
        with SessionLedger(ledger_path) as ledger:
            ledger.register_run(
                "run-root",
                target="http://target.invalid/",
                objective="retrieve flag",
                mode="pure",
                workspace_root=str(run_dir),
            )
            ledger.register_session("session-root", "run-root", sdk_signature="sdk-a")
            ledger.touch_session("session-root", "run-root")
            ledger.record_call(
                "run-root",
                "session-root",
                call_id="call-1",
                started_at="2026-01-01T00:00:00Z",
                ended_at="2026-01-01T00:00:02Z",
                result_status="completed",
                usage={"input_tokens": 10, "output_tokens": 5},
                cost_usd=0.25,
                num_turns=2,
                terminal_reason="completed",
            )
            iid = ledger.record_intervention(
                "run-root", "session-root", "resume", "continue"
            )
            ledger.update_intervention(iid, "applied", result_run_id="run-child")
            ledger.register_run(
                "run-child",
                parent_run_id="run-root",
                target="http://target.invalid/",
                objective="retrieve flag",
                mode="followup:resume",
                workspace_root=str(artifact_dir / "run-child"),
            )
            ledger.finish_run(
                "run-root",
                "completed",
                primary_session_id="session-root",
                checkpoint_message_id="checkpoint-1",
            )
        with ArtifactWorkspace(artifact_dir / "_evidence") as workspace:
            workspace.put_bytes(
                b"evidence text",
                run_id="run-root",
                session_id="session-root",
                call_id="call-1",
                tool_name="Bash",
                source_kind="tool_result",
                source_ref="stdout.txt",
            )
        return DashboardStore(root, Path("logs/mako_session_ledger.sqlite"), artifact_dir)

    def test_overview_runs_and_detail_expose_runtime_topology(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = self._seed(Path(td))

            overview = store.overview()
            self.assertEqual(overview["counts"]["runs"], 2)
            self.assertEqual(overview["counts"]["sessions"], 1)
            self.assertEqual(overview["counts"]["calls"], 1)
            self.assertEqual(overview["counts"]["interventions"], 1)
            self.assertEqual(overview["counts"]["artifacts"], 1)
            self.assertEqual(overview["total_turns"], 2)
            self.assertAlmostEqual(overview["total_cost_usd"], 0.25)
            self.assertEqual(overview["usage_totals"]["input_tokens"], 10)
            self.assertEqual(overview["timeline"][0]["call_id"], "call-1")

            runs = store.runs()
            self.assertEqual(runs["latest_run_id"], "run-child")
            root_run = next(row for row in runs["runs"] if row["run_id"] == "run-root")
            self.assertEqual(root_run["artifact_count"], 1)
            self.assertEqual(root_run["call_count"], 1)

            detail = store.run_detail("run-root")
            self.assertIsNotNone(detail)
            assert detail is not None
            self.assertEqual(detail["run"]["primary_session_id"], "session-root")
            self.assertEqual(detail["calls"][0]["usage"]["output_tokens"], 5)
            self.assertEqual(detail["interventions"][0]["result_run_id"], "run-child")
            self.assertEqual(detail["children"][0]["run_id"], "run-child")
            self.assertEqual(detail["session_lineage"][0]["session_id"], "session-root")
            self.assertEqual(detail["artifacts"][0]["tool_name"], "Bash")
            self.assertEqual(detail["record"]["assistant_text"], "flag{demo}")

            graph = store.graph()
            node_types = {node["type"] for node in graph["nodes"]}
            self.assertEqual(node_types, {"origin", "goal", "run", "call", "session", "evidence"})
            node_ids = {node["id"] for node in graph["nodes"]}
            self.assertIn("run:run-root", node_ids)
            self.assertIn("run:run-child", node_ids)
            self.assertIn("call:call-1", node_ids)
            self.assertIn("session:session-root", node_ids)
            self.assertEqual(sum(1 for node in graph["nodes"] if node["type"] == "evidence"), 1)
            edge_pairs = {(edge["source"], edge["target"], edge["kind"]) for edge in graph["edges"]}
            self.assertIn(("run:run-root", "call:call-1", "call"), edge_pairs)
            self.assertIn(("call:call-1", "session:session-root", "session"), edge_pairs)
            self.assertTrue(
                any(edge["kind"] == "intervention" and edge["data"]["kind"] == "resume" for edge in graph["edges"])
            )
            self.assertTrue(any(edge["kind"] == "outcome" for edge in graph["edges"]))
            event_types = {event["type"] for event in graph["events"]}
            self.assertIn("run_registered", event_types)
            self.assertIn("call_started", event_types)
            self.assertIn("call_finished", event_types)
            self.assertIn("intervention_resume", event_types)
            self.assertIn("evidence_captured", event_types)
            self.assertEqual([event["order"] for event in graph["events"]], list(range(1, len(graph["events"]) + 1)))
            self.assertIn("not inferred facts", graph["notice"])

            timeline = store.export("timeline")
            self.assertIn("Mako provenance timeline", timeline)
            self.assertIn("RUN_REGISTERED", timeline)
            self.assertIn("EVIDENCE_CAPTURED", timeline)
            exported = store.export("json")
            self.assertEqual(exported["counts"]["runs"], 2)
            with self.assertRaises(ValueError):
                store.export("yaml")

    def test_run_record_is_not_read_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            root = Path(td)
            outside_dir = Path(outside)
            secret = outside_dir / "pure_sdk_run.json"
            secret.write_text('{"assistant_text":"outside"}', encoding="utf-8")
            ledger_path = root / "logs" / "mako_session_ledger.sqlite"
            artifact_dir = root / "artifacts" / "mako"
            with SessionLedger(ledger_path) as ledger:
                ledger.register_run(
                    "run-outside",
                    target="target",
                    objective="objective",
                    mode="pure",
                    workspace_root=str(outside_dir),
                )
                ledger.finish_run("run-outside", "completed", "session-x")
            store = DashboardStore(root, ledger_path, artifact_dir)
            detail = store.run_detail("run-outside")
            self.assertIsNotNone(detail)
            assert detail is not None
            self.assertEqual(detail["record"], {})

    def test_empty_or_missing_databases_return_empty_views(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = DashboardStore(
                root,
                Path("logs/mako_session_ledger.sqlite"),
                Path("artifacts/mako"),
            )
            self.assertEqual(store.overview()["counts"]["runs"], 0)
            self.assertEqual(store.runs()["runs"], [])
            self.assertIsNone(store.run_detail("missing"))


class DashboardServerTests(unittest.TestCase):
    def test_http_endpoints_serve_dashboard_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = DashboardStore(
                root,
                Path("logs/mako_session_ledger.sqlite"),
                Path("artifacts/mako"),
            )
            server = create_server("127.0.0.1", 0, store)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address[:2]
            try:
                conn = http.client.HTTPConnection(host, port, timeout=5)
                conn.request("GET", "/")
                response = conn.getresponse()
                body = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("Mako Agent Dashboard", body)

                conn.request("GET", "/api/overview")
                response = conn.getresponse()
                payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["counts"]["runs"], 0)

                conn.request("GET", "/api/graph")
                response = conn.getresponse()
                payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["nodes"], [])
                self.assertEqual(payload["edges"], [])

                conn.request("GET", "/api/export?format=timeline")
                response = conn.getresponse()
                body = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                self.assertIn("Mako provenance timeline", body)

                conn.request("GET", "/api/export?format=bogus")
                response = conn.getresponse()
                response.read()
                self.assertEqual(response.status, 400)

                conn.request("GET", "/api/runs/missing")
                response = conn.getresponse()
                response.read()
                self.assertEqual(response.status, 404)
                conn.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
