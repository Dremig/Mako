from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from web_agent.solver_shared import (
    cluster_for_failure_reason,
    derive_gain_budget_policy,
    merge_controller_with_gain_policy,
    normalize_failure_reason,
    validate_action,
    MemoryStore,
)


class PolicyControlTests(unittest.TestCase):
    def test_failure_reason_normalization(self) -> None:
        self.assertEqual(normalize_failure_reason(""), "none")
        self.assertEqual(normalize_failure_reason("METHOD_NOT_ALLOWED"), "method_not_allowed")
        self.assertEqual(normalize_failure_reason("weird_new_reason"), "needs_followup")

    def test_failure_reason_cluster_mapping(self) -> None:
        self.assertEqual(cluster_for_failure_reason("missing_required_parameter"), "hypothesis_stale")
        self.assertEqual(cluster_for_failure_reason("timeout_without_signal"), "timeout_spiral")
        self.assertEqual(cluster_for_failure_reason("weird_new_reason"), "none")

    def test_validate_action_blocks_discovery_drift_under_semantic_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="t1")
            memory.upsert_fact("error.semantic.missing_required_parameter", "true", 0.96, 1)
            memory.upsert_fact("endpoint.focus", "/api/login", 0.90, 1)

            ok, reason = validate_action(
                phase="probe",
                expected_phase="probe",
                command="curl -si $TARGET_URL/robots.txt",
                memory=memory,
                history=[],
                controller_reflection={},
            )
            self.assertFalse(ok)
            self.assertIn("Semantic error recovery", reason)

    def test_validate_action_blocks_non_focused_command_under_missing_parameter(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="t1b")
            memory.upsert_fact("error.semantic.missing_required_parameter", "true", 0.96, 1)
            memory.upsert_fact("endpoint.focus", "/api/login", 0.90, 1)

            ok, reason = validate_action(
                phase="probe",
                expected_phase="probe",
                command="curl -si $TARGET_URL/api/profile",
                memory=memory,
                history=[],
                controller_reflection={},
            )
            self.assertFalse(ok)
            self.assertIn("action must focus on /api/login", reason)

    def test_validate_action_blocks_same_family_when_controller_requires_change(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="t2")
            history = [{"command": "curl -si $TARGET_URL/", "returncode": 1, "info_gain": 0}]
            policy = {"requirements": {"change_command_family": True}, "failure_cluster": "low_gain_loop"}

            ok, reason = validate_action(
                phase="probe",
                expected_phase="probe",
                command="curl -si $TARGET_URL/login",
                memory=memory,
                history=history,
                controller_reflection=policy,
            )
            self.assertFalse(ok)
            self.assertIn("command family change", reason)

    def test_validate_action_controller_rule_registry_paths(self) -> None:
        cases = [
            {
                "name": "must_avoid_recon_regression",
                "phase": "recon",
                "policy": {"must_avoid": ["Do not regress to recon when entrypoint/vuln signals already exist."]},
                "history": [],
                "expected_ok": False,
                "reason_contains": "recon regression",
            },
            {
                "name": "cluster_repeat_family_block",
                "phase": "probe",
                "policy": {"failure_cluster": "low_gain_loop"},
                "history": [{"command": "curl -si $TARGET_URL/", "returncode": 0, "info_gain": 1}],
                "expected_ok": False,
                "reason_contains": "repeated command family",
            },
            {
                "name": "unknown_cluster_fallback",
                "phase": "probe",
                "policy": {"failure_cluster": "totally_new_cluster_name"},
                "history": [{"command": "curl -si $TARGET_URL/", "returncode": 0, "info_gain": 1}],
                "expected_ok": True,
                "reason_contains": "",
            },
        ]
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="t3")
            for case in cases:
                with self.subTest(case=case["name"]):
                    ok, reason = validate_action(
                        phase=case["phase"],
                        expected_phase="probe",
                        command="curl -si $TARGET_URL/login",
                        memory=memory,
                        history=case["history"],
                        controller_reflection=case["policy"],
                    )
                    self.assertEqual(ok, case["expected_ok"])
                    if case["reason_contains"]:
                        self.assertIn(case["reason_contains"], reason)
                    else:
                        self.assertEqual(reason, "")

    def test_gain_budget_policy_soft_breach_on_low_gain_streak(self) -> None:
        history = [
            {"command": "curl -si $TARGET_URL/", "info_gain": 1, "returncode": 0},
            {"command": "python3 probe.py", "info_gain": 0, "returncode": 0},
            {"command": "python3 another_probe.py", "info_gain": 1, "returncode": 0},
        ]
        policy = derive_gain_budget_policy(history=history, expected_phase="probe")
        self.assertTrue(policy["breach"])
        self.assertEqual(policy["severity"], "soft")
        self.assertTrue(policy["requirements"]["change_command_family"])
        self.assertTrue(policy["requirements"]["force_plan_refresh"])

    def test_gain_budget_policy_hard_breach_on_window_total(self) -> None:
        history = [
            {"command": f"curl -si $TARGET_URL/{i}", "info_gain": 0, "returncode": 0}
            for i in range(6)
        ]
        policy = derive_gain_budget_policy(history=history, expected_phase="probe")
        self.assertTrue(policy["breach"])
        self.assertEqual(policy["severity"], "hard")
        self.assertTrue(policy["requirements"]["force_branch_shift"])
        self.assertLessEqual(int(policy["timeout_cap_sec"]), 20)

    def test_merge_controller_with_gain_policy_promotes_hard_requirements(self) -> None:
        controller = {
            "failure_cluster": "none",
            "must_do": ["Keep scope focused."],
            "must_avoid": [],
            "requirements": {"require_explicit_success_signal": False},
            "rationale": "base_policy",
        }
        gain_policy = {
            "breach": True,
            "failure_cluster": "low_gain_loop",
            "must_do": ["Force a branch shift."],
            "must_avoid": ["Do not repeat the same low-gain route."],
            "requirements": {
                "change_command_family": True,
                "require_explicit_success_signal": True,
                "force_plan_refresh": True,
                "force_branch_shift": True,
            },
            "rationale": "hard low-gain budget breach",
        }
        merged = merge_controller_with_gain_policy(controller, gain_policy)
        self.assertEqual(merged["failure_cluster"], "low_gain_loop")
        self.assertTrue(merged["requirements"]["change_command_family"])
        self.assertTrue(merged["requirements"]["force_plan_refresh"])
        self.assertIn("Force a branch shift.", merged["must_do"])
        self.assertIn("hard low-gain budget breach", merged["rationale"])


if __name__ == "__main__":
    unittest.main()
