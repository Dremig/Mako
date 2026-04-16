from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from web_agent.solver_shared import (
    MemoryStore,
    compile_action_command,
    extract_facts,
    preflight_command_quality,
    validate_action_spec,
)


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
        self.assertEqual(fact_map["endpoint.focus"], "/login")
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

    def test_extract_facts_parses_http_probe_artifacts(self) -> None:
        stdout = (
            '{"baseline":{"status":200,"body_len":10,"elapsed_ms":12},'
            '"probe":{"status":200,"body_len":10,"elapsed_ms":8},'
            '"artifacts":{"artifact_dir":"/tmp/a","body_file":"/tmp/a/root.body","body_html_file":"/tmp/a/root.body.html",'
            '"headers_file":"/tmp/a/root.headers","cookies_file":"/tmp/a/root.cookies.txt"},'
            '"diff":{"status_diff":0,"body_len_diff":0,"elapsed_ms_diff":-4}}'
        )
        facts = extract_facts("python3 scripts/http_probe_with_baseline.py --url http://127.0.0.1:1", stdout, "")
        fact_map = {key: value for key, value, _ in facts}
        self.assertEqual(fact_map["artifact.html_file"], "/tmp/a/root.body.html")
        self.assertEqual(fact_map["artifact.body_file"], "/tmp/a/root.body")
        self.assertEqual(fact_map["artifact.headers_file"], "/tmp/a/root.headers")
        self.assertEqual(fact_map["artifact.cookies_file"], "/tmp/a/root.cookies.txt")

    def test_preflight_autofixes_html_file_extension(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            artifact_dir = Path(td) / "artifacts"
            artifact_dir.mkdir(parents=True, exist_ok=True)
            html_path = artifact_dir / "root.body.html"
            html_path.write_text("<html><body>ok</body></html>", encoding="utf-8")
            repo_root = Path(__file__).resolve().parents[1]
            script_path = repo_root / "scripts" / "extract_html_attack_surface.py"

            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="a6")
            memory.upsert_fact("artifact.dir", str(artifact_dir), 0.95, 0)

            command = (
                f"python3 {script_path} "
                f"--html-file {artifact_dir / 'root.body'} --base-url http://target.local "
                f"--out {artifact_dir / 'html_attack_surface.json'}"
            )
            result = preflight_command_quality(
                command=command,
                action_name="extract_html_attack_surface",
                memory=memory,
                env={},
                cwd=artifact_dir,
            )
            self.assertTrue(result["ok"])
            self.assertTrue(result["autofixed"])
            self.assertIn("root.body.html", result["command"])

    def test_extract_facts_parses_sqli_source_leak_hints(self) -> None:
        stdout = (
            "SELECT rowid FROM users WHERE uname = 'demo' AND pass = 'hash';\n"
            "username = username.replace('admin', '');\n"
            "var username = trim_whitespace(req.body.username);\n"
            "var password = trim_whitespace(req.body.password);\n"
        )
        facts = extract_facts("curl -sS http://target/login", stdout, "")
        fact_map = {key: value for key, value, _ in facts}
        self.assertEqual(fact_map["vuln.signal.sqli"], "true")
        self.assertEqual(fact_map["debug.auth_query.sql_username_password"], "true")
        self.assertEqual(fact_map["dbms"], "sqlite")
        self.assertEqual(fact_map["injection.parameter"], "username")
        self.assertEqual(fact_map["filter.username_strip_admin"], "true")
        self.assertEqual(fact_map["filter.username_whitespace_trim"], "true")
        self.assertEqual(fact_map["filter.password_whitespace_trim"], "true")

    def test_preflight_blocks_python_heredoc_inside_bash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="a7")
            result = preflight_command_quality(
                command="bash -lc 'python3 - <<'\"'\"'PY'\"'\"'\nprint(1)\nPY'",
                action_name="",
                memory=memory,
                env={},
                cwd=Path(td),
            )
            self.assertFalse(result["ok"])
            self.assertIn("fragile python heredoc nested inside bash -lc", result["issues"][0])


if __name__ == "__main__":
    unittest.main()
