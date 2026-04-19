from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from web_agent.cmd_agent import empty_response_contexts, load_response_contexts_from_run_state


class CmdAgentResponseContextResumeTests(unittest.TestCase):
    def test_load_response_contexts_from_run_state_accepts_matching_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cmd_agent_last_run.json"
            payload = {
                "target": "http://example.local",
                "base_url": "http://gateway.local/v1",
                "model": "gpt-5.4",
                "response_contexts": {
                    "planner": {"previous_response_id": "resp_1"},
                    "summary": {"disable_previous_response_id": True},
                },
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_response_contexts_from_run_state(
                path,
                target="http://example.local",
                base_url="http://gateway.local/v1",
                model="gpt-5.4",
            )
        self.assertEqual(loaded["planner"]["previous_response_id"], "resp_1")
        self.assertTrue(loaded["summary"]["disable_previous_response_id"])
        self.assertEqual(set(loaded.keys()), set(empty_response_contexts().keys()))

    def test_load_response_contexts_from_run_state_rejects_mismatched_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cmd_agent_last_run.json"
            payload = {
                "target": "http://example.local",
                "base_url": "http://gateway.local/v1",
                "model": "gpt-5.4",
                "response_contexts": {
                    "planner": {"previous_response_id": "resp_1"},
                },
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_response_contexts_from_run_state(
                path,
                target="http://other.local",
                base_url="http://gateway.local/v1",
                model="gpt-5.4",
            )
        self.assertEqual(loaded, empty_response_contexts())


if __name__ == "__main__":
    unittest.main()
