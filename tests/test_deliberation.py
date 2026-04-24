from __future__ import annotations

import unittest

from web_agent.deliberation import choose_final_proposal, force_planner_action_hint, run_counter_solver


class DeliberationTests(unittest.TestCase):
    def test_choose_final_proposal_prefers_corrector_when_fragile(self) -> None:
        recommender = {
            "analysis": "Use bs4 to parse HTML quickly.",
            "decision": "command",
            "phase": "extract",
            "command": "python3 - <<'PY'\nfrom bs4 import BeautifulSoup\nPY",
            "action": {},
            "success_signal": "routes extracted",
            "next_if_fail": "",
        }
        corrector = {
            "verdict": "fragile",
            "issues": ["depends on bs4"],
            "corrected": {
                "analysis": "Use the structured HTML extractor instead of optional dependencies.",
                "decision": "action",
                "phase": "extract",
                "command": "",
                "action": {"name": "extract_html_attack_surface", "args": {}},
                "success_signal": "endpoint.focus appears",
                "next_if_fail": "",
            },
        }
        final, judge = choose_final_proposal(
            recommender=recommender,
            corrector=corrector,
            active_action="extract_html_attack_surface",
        )
        self.assertEqual(final["decision"], "action")
        self.assertEqual(final["action"]["name"], "extract_html_attack_surface")
        self.assertEqual(judge["decision"], "accept_corrected")

    def test_choose_final_proposal_forces_planner_action_when_missing(self) -> None:
        recommender = {
            "analysis": "Fetch current endpoint.",
            "decision": "command",
            "phase": "probe",
            "command": "curl -si $TARGET_URL/",
            "action": {},
            "success_signal": "response collected",
            "next_if_fail": "",
        }
        corrector = {"verdict": "accept", "issues": [], "corrected": recommender}
        final, judge = choose_final_proposal(
            recommender=recommender,
            corrector=corrector,
            active_action="service_recovery_probe",
        )
        self.assertEqual(final["decision"], "action")
        self.assertEqual(final["action"]["name"], "service_recovery_probe")
        self.assertEqual(judge["decision"], "force_planner_action")

    def test_force_planner_action_hint_keeps_existing_action(self) -> None:
        chosen = {
            "analysis": "Use the planner-provided action directly.",
            "decision": "action",
            "phase": "extract",
            "command": "",
            "action": {"name": "extract_html_attack_surface", "args": {}},
            "success_signal": "routes extracted",
            "next_if_fail": "",
        }
        final, judge = force_planner_action_hint(
            chosen=chosen,
            active_action="extract_html_attack_surface",
            base_judge={"decision": "accept_tactical", "reason": "already aligned"},
        )
        self.assertEqual(final["action"]["name"], "extract_html_attack_surface")
        self.assertEqual(judge["decision"], "accept_tactical")

    def test_run_counter_solver_returns_stable_shape_on_failure(self) -> None:
        result = run_counter_solver(
            base_url="http://127.0.0.1:9/v1",
            api_key="x",
            model="gpt-5.4",
            target="http://target.local/",
            objective="obj",
            step=1,
            expected_phase="probe",
            current_plan_text="none",
            memory_summary="none",
            hypotheses_text="none",
            recent_history="none",
            recent_obs="none",
            retrieved_context="none",
            trace_hook=None,
        )
        self.assertIn("main_hypothesis", result)
        self.assertIn("counter_hypothesis", result)
        self.assertIn("evidence_for", result)
        self.assertIn("critical_counterargument", result)
        self.assertIn("cheap_test", result)
        self.assertIn("expected_if_main", result)
        self.assertIn("expected_if_counter", result)
        self.assertIn("decision_rule", result)
        self.assertIn("should_challenge_current_route", result)

    def test_choose_final_proposal_accepts_counter_challenge_when_materially_different(self) -> None:
        recommender = {
            "analysis": "Keep probing baseline endpoint.",
            "decision": "command",
            "phase": "probe",
            "command": "curl -si $TARGET_URL/",
            "action": {},
            "success_signal": "response collected",
            "next_if_fail": "",
        }
        corrected = {
            "analysis": "Run discriminator on an alternate surface.",
            "decision": "command",
            "phase": "recon",
            "command": "curl -si $TARGET_URL/robots.txt",
            "action": {},
            "success_signal": "robots content observed",
            "next_if_fail": "",
        }
        corrector = {"verdict": "accept", "issues": [], "corrected": corrected}
        final, judge = choose_final_proposal(
            recommender=recommender,
            corrector=corrector,
            active_action="",
            counter_solver={"should_challenge_current_route": True},
        )
        self.assertEqual(final["command"], corrected["command"])
        self.assertEqual(judge["decision"], "accept_counter_challenge")


if __name__ == "__main__":
    unittest.main()
