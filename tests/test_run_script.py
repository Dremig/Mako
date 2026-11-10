from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_web_agent.sh"


class RunWebAgentScriptTests(unittest.TestCase):
    def run_script(self, mode: str | None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_python = Path(tmpdir) / "python"
            fake_python.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$@\"\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            env = {
                **os.environ,
                "PYTHON_BIN": str(fake_python),
                "ARTIFACT_ROOT": "artifacts/test-runtime",
            }
            if mode is None:
                env.pop("MAKO_RUNTIME_MODE", None)
            else:
                env["MAKO_RUNTIME_MODE"] = mode
            return subprocess.run(
                ["bash", str(SCRIPT), "http://target.local/", "objective text", "hint text"],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def test_default_pure_command_uses_sdk_agent_and_only_pure_arguments(self) -> None:
        proc = self.run_script(None)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        args = proc.stdout.splitlines()
        self.assertEqual(args[:3], ["-u", "-m", "web_agent.pure_sdk_agent"])
        self.assertIn("--root", args)
        self.assertIn("--env", args)
        self.assertIn("--target", args)
        self.assertIn("--objective", args)
        self.assertIn("--hint", args)
        self.assertIn("--artifact-dir", args)
        self.assertNotIn("--cmd-timeout", args)
        for flag in ("--index", "--top-k", "--mode", "--alpha", "--disable-rag", "--enable-rag"):
            self.assertNotIn(flag, args)

    def test_governed_command_preserves_cmd_agent_arguments(self) -> None:
        proc = self.run_script("governed")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        args = proc.stdout.splitlines()
        self.assertEqual(args[:3], ["-u", "-m", "web_agent.cmd_agent"])
        for flag in (
            "--root",
            "--env",
            "--target",
            "--objective",
            "--hint",
            "--cmd-timeout",
            "--max-steps",
            "--artifact-dir",
        ):
            self.assertIn(flag, args)
        for flag in ("--index", "--top-k", "--mode", "--alpha", "--disable-rag", "--enable-rag"):
            self.assertNotIn(flag, args)

    def test_invalid_runtime_mode_exits_two(self) -> None:
        proc = self.run_script("unexpected")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Unsupported MAKO_RUNTIME_MODE", proc.stderr)


if __name__ == "__main__":
    unittest.main()
