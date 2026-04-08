from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from web_agent.logistics import build_logistics_request, perform_logistics_request


class LogisticsTests(unittest.TestCase):
    def test_build_install_request_for_python_dependency(self) -> None:
        request = build_logistics_request(
            {
                "selected": "install_dependency",
                "gap": {"dependency": "beautifulsoup4"},
            },
            {"python3": "/usr/bin/python3"},
        )
        self.assertEqual(request["kind"], "environment_setup")
        self.assertEqual(request["install_strategy"], "pip")
        self.assertIn("python3 -m pip install", request["command"])

    def test_build_install_request_for_cli_tool_uses_system_package_manager(self) -> None:
        request = build_logistics_request(
            {
                "selected": "install_dependency",
                "gap": {"tool": "zsteg", "kind": "missing_tool"},
            },
            {"python3": "/usr/bin/python3"},
        )
        self.assertEqual(request["install_strategy"], "system_package_manager")
        self.assertIn("apt-get", request["command"])

    def test_build_install_request_honors_model_skip(self) -> None:
        request = build_logistics_request(
            {
                "selected": "install_dependency",
                "gap": {"tool": "stegsolve", "kind": "missing_tool"},
            },
            {"python3": "/usr/bin/python3"},
            {"strategy": "skip_install", "reason": "high risk"},
        )
        self.assertEqual(request["install_strategy"], "skip_install")
        self.assertEqual(request["command"], "")

    def test_perform_logistics_request_noop_without_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = perform_logistics_request(
                request={"command": ""},
                run_shell_command=lambda *args, **kwargs: {"returncode": 1, "stdout": "", "stderr": ""},
                env={},
                artifact_dir=Path(td),
                timeout=5,
            )
            self.assertFalse(result["performed"])
            self.assertEqual(result["returncode"], 0)


if __name__ == "__main__":
    unittest.main()
