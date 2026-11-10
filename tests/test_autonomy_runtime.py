from __future__ import annotations

import unittest

from web_agent.cmd_agent import branch_shift_enforcement, debate_enabled


class AutonomyRuntimeTests(unittest.TestCase):
    def test_debate_is_opt_in_except_collaboration_mode(self) -> None:
        self.assertFalse(debate_enabled("claude", False))
        self.assertTrue(debate_enabled("claude", True))
        self.assertTrue(debate_enabled("claude_collab", False))

    def test_adaptive_soft_branch_shift_is_advisory(self) -> None:
        gain = {
            "severity": "soft",
            "requirements": {"force_branch_shift": True},
        }
        self.assertEqual(branch_shift_enforcement("adaptive", gain, {}), "advisory")

    def test_adaptive_hard_branch_shift_is_enforced(self) -> None:
        monitor = {
            "severity": "hard",
            "requirements": {"force_branch_shift": True},
        }
        self.assertEqual(branch_shift_enforcement("adaptive", {}, monitor), "hard")

    def test_guarded_enforces_any_requested_branch_shift(self) -> None:
        gain = {
            "severity": "soft",
            "requirements": {"force_branch_shift": True},
        }
        self.assertEqual(branch_shift_enforcement("guarded", gain, {}), "hard")

    def test_no_request_has_no_branch_shift(self) -> None:
        self.assertEqual(branch_shift_enforcement("adaptive", {}, {}), "none")


if __name__ == "__main__":
    unittest.main()
