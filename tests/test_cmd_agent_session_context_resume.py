from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from web_agent.cmd_agent import empty_session_contexts, load_session_contexts_from_run_state


class CmdAgentSessionContextResumeTests(unittest.TestCase):
    def test_load_session_contexts_accepts_matching_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cmd_agent_last_run.json"
            payload = {
                "target": "http://example.local",
                "sdk_signature": "claude-sdk:test-model:test-gateway",
                "session_contexts": {
                    "planner": {"session_id": "session-1"},
                    "summary": {"use_local_msgchain": True},
                },
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_session_contexts_from_run_state(
                path,
                target="http://example.local",
                sdk_signature="claude-sdk:test-model:test-gateway",
            )
        self.assertEqual(loaded["planner"]["session_id"], "session-1")
        self.assertTrue(loaded["summary"]["use_local_msgchain"])
        self.assertEqual(set(loaded.keys()), set(empty_session_contexts().keys()))

    def test_load_session_contexts_rejects_mismatched_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cmd_agent_last_run.json"
            payload = {
                "target": "http://example.local",
                "sdk_signature": "claude-sdk:test-model:test-gateway",
                "session_contexts": {"planner": {"session_id": "session-1"}},
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_session_contexts_from_run_state(
                path,
                target="http://other.local",
                sdk_signature="claude-sdk:test-model:test-gateway",
            )
        self.assertEqual(loaded, empty_session_contexts())


if __name__ == "__main__":
    unittest.main()
