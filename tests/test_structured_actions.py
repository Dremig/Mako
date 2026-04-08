from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from web_agent.solver_shared import MemoryStore, compile_action_command, extract_facts, validate_action_spec


class StructuredActionTests(unittest.TestCase):
    def test_http_probe_with_baseline_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="a1")
            memory.upsert_fact("project.root", "/repo/mako", 1.0, 0)
            memory.upsert_fact("target", "http://127.0.0.1:8080", 1.0, 0)
            spec = validate_action_spec({"name": "http_probe_with_baseline", "args": {}}, memory)
            self.assertEqual(spec["args"]["url"], "http://127.0.0.1:8080")
            self.assertEqual(spec["args"]["baseline_url"], "http://127.0.0.1:8080")
            cmd = compile_action_command(spec, memory)
            self.assertIn("/repo/mako/scripts/http_probe_with_baseline.py", cmd)
            self.assertNotIn("$PROJECT_ROOT", cmd)
            self.assertIn("--url", cmd)
            self.assertIn("--baseline-url", cmd)

    def test_cookiejar_flow_fetch_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="a2")
            memory.upsert_fact("target", "http://target.local/", 1.0, 0)
            memory.upsert_fact("artifact.dir", "/tmp/agent_artifacts", 0.95, 0)
            spec = validate_action_spec({"name": "cookiejar_flow_fetch", "args": {}}, memory)
            self.assertEqual(spec["args"]["base_url"], "http://target.local")
            self.assertEqual(spec["args"]["fetch_url"], "http://target.local")
            self.assertTrue(spec["args"]["cookiejar"].endswith("workflow_cookie.jar"))
            cmd = compile_action_command(spec, memory)
            self.assertIn("cookiejar_flow_fetch.py", cmd)
            self.assertIn("--cookiejar", cmd)
            self.assertIn("--fetch-url", cmd)

    def test_multipart_upload_defaults_from_memory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="a3")
            memory.upsert_fact("target", "http://127.0.0.1:8080", 1.0, 0)
            memory.upsert_fact("artifact.dir", "/tmp/agent_artifacts", 0.95, 0)
            memory.upsert_fact("tomcat.upload_action", "/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=ABC", 0.96, 1)
            memory.upsert_fact("artifact.war_path", "/tmp/agent_artifacts/readfile.war", 0.9, 1)
            memory.upsert_fact("tomcat.creds", "tomcat:s3cret", 0.9, 1)
            spec = validate_action_spec({"name": "multipart_upload_with_known_action", "args": {}}, memory)
            self.assertEqual(
                spec["args"]["action_url"],
                "http://127.0.0.1:8080/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=ABC",
            )
            self.assertEqual(spec["args"]["file"], "/tmp/agent_artifacts/readfile.war")
            self.assertEqual(spec["args"]["username"], "tomcat")
            self.assertEqual(spec["args"]["password"], "s3cret")
            cmd = compile_action_command(spec, memory)
            self.assertIn("multipart_upload_with_known_action.py", cmd)
            self.assertIn("--action-url", cmd)
            self.assertIn("--file", cmd)

    def test_extract_html_attack_surface_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="a4")
            memory.upsert_fact("target", "http://target.local/", 1.0, 0)
            memory.upsert_fact("artifact.dir", "/tmp/agent_artifacts", 0.95, 0)
            spec = validate_action_spec({"name": "extract_html_attack_surface", "args": {}}, memory)
            self.assertEqual(spec["args"]["html_file"], "/tmp/agent_artifacts/root.body")
            self.assertEqual(spec["args"]["base_url"], "http://target.local")
            self.assertTrue(spec["args"]["out"].endswith("html_attack_surface.json"))
            cmd = compile_action_command(spec, memory)
            self.assertIn("extract_html_attack_surface.py", cmd)
            self.assertIn("--html-file", cmd)

    def test_service_recovery_probe_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="a5")
            memory.upsert_fact("target", "http://127.0.0.1:8080", 1.0, 0)
            memory.upsert_fact("artifact.dir", "/tmp/agent_artifacts", 0.95, 0)
            spec = validate_action_spec({"name": "service_recovery_probe", "args": {}}, memory)
            self.assertEqual(spec["args"]["url"], "http://127.0.0.1:8080")
            self.assertEqual(spec["args"]["artifact_dir"], "/tmp/agent_artifacts")
            self.assertEqual(spec["args"]["attempts"], "3")
            self.assertTrue(spec["args"]["out"].endswith("service_recovery_probe.json"))
            cmd = compile_action_command(spec, memory)
            self.assertIn("service_recovery_probe.py", cmd)
            self.assertIn("--url", cmd)

    def test_extract_facts_parses_html_attack_surface_output(self) -> None:
        stdout = (
            '{"candidate_paths":["/api/list","/download/report.pdf"],'
            '"forms":[{"action":"/login","method":"POST","inputs":["username","password"],"hidden":{"csrf":"abc"}}],'
            '"filenames":["report.pdf"],"comments":["debug route maybe /admin"]}'
        )
        facts = extract_facts("python3 scripts/extract_html_attack_surface.py --html-file root.body", stdout, "")
        fact_map = {key: value for key, value, _ in facts}
        self.assertEqual(fact_map["endpoint.focus"], "/api/list")
        self.assertEqual(fact_map["entrypoint.candidate.username"], "form-input")
        self.assertEqual(fact_map["form.hidden.csrf"], "abc")
        self.assertIn("/login", fact_map.values())

    def test_extract_facts_parses_service_recovery_output(self) -> None:
        stdout = (
            '{"classification":"service_not_ready_or_non_http","tcp_connect":true,"ready_http":false,'
            '"empty_http_reply":true,"http_error_kind":"empty_reply","https_error_kind":"SSLError"}'
        )
        facts = extract_facts("python3 scripts/service_recovery_probe.py --url http://127.0.0.1:1", stdout, "")
        fact_map = {key: value for key, value, _ in facts}
        self.assertEqual(fact_map["service.recovery.classification"], "service_not_ready_or_non_http")
        self.assertEqual(fact_map["service.tcp.reachable"], "true")
        self.assertEqual(fact_map["service.http.empty_reply"], "true")
        self.assertEqual(fact_map["service.http.error_kind"], "empty_reply")


if __name__ == "__main__":
    unittest.main()
