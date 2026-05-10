from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from web_agent.cmd_agent import apply_branch_shift_candidate_override
from web_agent.solver_shared import (
    classify_command_family,
    cluster_for_failure_reason,
    derive_allowed_families_for_branch_shift,
    derive_execution_monitor_policy,
    derive_gain_budget_policy,
    merge_controller_with_gain_policy,
    normalize_failure_reason,
    pathological_repeat_summary,
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

    def test_validate_action_blocks_family_outside_allowed_set(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="t2b")
            ok, reason = validate_action(
                phase="probe",
                expected_phase="probe",
                command="python3 /tmp/http_probe_with_baseline.py --url $TARGET_URL",
                memory=memory,
                history=[],
                controller_reflection={"allowed_families": ["curl", "sqlmap"]},
            )
            self.assertFalse(ok)
            self.assertIn("allowed set", reason)

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

    def test_execution_monitor_policy_same_family_breach(self) -> None:
        policy = derive_execution_monitor_policy(
            enabled=True,
            same_family_streak=4,
            total_calls_since_replan=4,
            last_family="curl",
            same_family_limit=4,
            total_call_limit=10,
            expected_phase="probe",
        )
        self.assertTrue(policy["breach"])
        self.assertEqual(policy["severity"], "hard")
        self.assertTrue(policy["requirements"]["force_plan_refresh"])
        self.assertTrue(policy["requirements"]["force_branch_shift"])
        self.assertIn("curl", " ".join(policy["must_avoid"]))

    def test_execution_monitor_policy_total_call_breach(self) -> None:
        policy = derive_execution_monitor_policy(
            enabled=True,
            same_family_streak=1,
            total_calls_since_replan=10,
            last_family="ffuf",
            same_family_limit=4,
            total_call_limit=10,
            expected_phase="recon",
        )
        self.assertTrue(policy["breach"])
        self.assertEqual(policy["severity"], "soft")
        self.assertTrue(policy["requirements"]["force_plan_refresh"])
        self.assertFalse(policy["requirements"]["force_branch_shift"])

    def test_command_family_is_intent_sensitive_for_python_helpers(self) -> None:
        self.assertEqual(
            classify_command_family("python3 /repo/scripts/http_probe_with_baseline.py --url $TARGET_URL"),
            "python3:http_probe_with_baseline",
        )
        self.assertEqual(
            classify_command_family("python3 /repo/scripts/extract_html_attack_surface.py --html-file page.html"),
            "python3:extract_html_attack_surface",
        )

    def test_branch_shift_allowed_families_avoid_blocked_family(self) -> None:
        allowed = derive_allowed_families_for_branch_shift(
            blocked_family="python3:http_probe_with_baseline",
            available_tools=["curl", "bash", "python3", "sqlmap"],
        )
        self.assertNotIn("python3:http_probe_with_baseline", allowed)
        self.assertIn("curl", allowed)

    def test_branch_shift_allowed_families_avoid_recent_forbidden_families(self) -> None:
        allowed = derive_allowed_families_for_branch_shift(
            blocked_family="python3:http_probe_with_baseline",
            available_tools=["curl", "bash", "python3", "sqlmap"],
            forbidden_families=["curl", "bash"],
        )
        self.assertNotIn("python3:http_probe_with_baseline", allowed)
        self.assertNotIn("curl", allowed)
        self.assertNotIn("bash", allowed)
        self.assertEqual(allowed, ["python3:service_recovery_probe", "sqlmap"])

    def test_branch_shift_candidate_override_rewrites_blocked_family(self) -> None:
        cmd, family, payload = apply_branch_shift_candidate_override(
            raw_cmd="python3 /repo/scripts/http_probe_with_baseline.py --url $TARGET_URL",
            proposed_family="python3:http_probe_with_baseline",
            forced_branch_shift_family="python3:http_probe_with_baseline",
            forced_branch_shift_allowed_families=["curl", "sqlmap"],
            forced_branch_shift_candidates=[
                {"family": "curl", "command": "curl -si $TARGET_URL/", "why": "switch surface"}
            ],
        )
        self.assertEqual(cmd, "curl -si $TARGET_URL/")
        self.assertEqual(family, "curl")
        self.assertIsNotNone(payload)
        self.assertEqual(payload["reason"], "blocked_family")

    def test_branch_shift_candidate_override_keeps_allowed_family(self) -> None:
        cmd, family, payload = apply_branch_shift_candidate_override(
            raw_cmd="curl -si $TARGET_URL/",
            proposed_family="curl",
            forced_branch_shift_family="python3:http_probe_with_baseline",
            forced_branch_shift_allowed_families=["curl", "sqlmap"],
            forced_branch_shift_candidates=[
                {"family": "curl", "command": "curl -si $TARGET_URL/", "why": "switch surface"}
            ],
        )
        self.assertEqual(cmd, "curl -si $TARGET_URL/")
        self.assertEqual(family, "curl")
        self.assertIsNone(payload)

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

    def test_merge_controller_with_execution_monitor_policy_promotes_requirements(self) -> None:
        controller = {
            "failure_cluster": "none",
            "must_do": [],
            "must_avoid": [],
            "requirements": {},
            "rationale": "base_policy",
        }
        monitor_policy = derive_execution_monitor_policy(
            enabled=True,
            same_family_streak=4,
            total_calls_since_replan=4,
            last_family="curl",
            same_family_limit=4,
            total_call_limit=10,
            expected_phase="probe",
        )
        merged = merge_controller_with_gain_policy(controller, monitor_policy)
        self.assertEqual(merged["failure_cluster"], "low_gain_loop")
        self.assertTrue(merged["requirements"]["change_command_family"])
        self.assertTrue(merged["requirements"]["force_branch_shift"])
        self.assertIn("Execution monitor triggered", " ".join(merged["must_do"]))

    def test_pathological_repeat_counts_validator_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="t4")
            history = [
                {
                    "command": "curl -si $TARGET_URL/login",
                    "signal": "blocked-by-validator: repeated command family",
                    "info_gain": 0,
                    "phase": "probe",
                },
                {
                    "command": "curl -si $TARGET_URL/login",
                    "signal": "blocked-by-validator: repeated command family",
                    "info_gain": 0,
                    "phase": "probe",
                },
                {
                    "command": "curl -si $TARGET_URL/login",
                    "signal": "blocked-by-validator: repeated command family",
                    "info_gain": 0,
                    "phase": "probe",
                },
            ]
            summary = pathological_repeat_summary(history, memory)
            self.assertTrue(summary["active"])
            self.assertEqual(summary["reason"], "semantic_repeat_same_surface")


if __name__ == "__main__":
    unittest.main()
