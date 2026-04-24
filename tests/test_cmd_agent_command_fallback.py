from __future__ import annotations

import unittest
from unittest.mock import patch

from web_agent.cmd_agent import resolve_valid_command


class _DummyMemory:
    def __init__(self) -> None:
        self.events: list[tuple[int, str, str]] = []

    def add_event(self, step: int, kind: str, payload: str) -> None:
        self.events.append((step, kind, payload))


class CmdAgentCommandFallbackTests(unittest.TestCase):
    def test_empty_raw_command_falls_back_to_next_if_fail(self) -> None:
        memory = _DummyMemory()
        with patch("web_agent.cmd_agent.repair_helper_command", side_effect=lambda cmd, _memory: cmd), patch(
            "web_agent.cmd_agent.validate_command",
            side_effect=lambda cmd: cmd.strip() if cmd.strip() else (_ for _ in ()).throw(RuntimeError("Empty command")),
        ):
            cmd = resolve_valid_command(
                raw_cmd="",
                plan={"next_if_fail": "curl -si $TARGET_URL/health"},
                target="http://example.local",
                memory=memory,  # type: ignore[arg-type]
                step=3,
            )
        self.assertEqual(cmd, "curl -si $TARGET_URL/health")

    def test_invalid_primary_command_falls_back_to_default(self) -> None:
        memory = _DummyMemory()

        def _fake_validate(cmd: str) -> str:
            if cmd == "badcmd":
                raise RuntimeError("bad")
            if not cmd.strip():
                raise RuntimeError("empty")
            return cmd

        with patch("web_agent.cmd_agent.repair_helper_command", side_effect=lambda cmd, _memory: cmd), patch(
            "web_agent.cmd_agent.validate_command",
            side_effect=_fake_validate,
        ):
            cmd = resolve_valid_command(
                raw_cmd="badcmd",
                plan={},
                target="http://example.local",
                memory=memory,  # type: ignore[arg-type]
                step=5,
            )
        self.assertEqual(cmd, "curl -si $TARGET_URL/")


if __name__ == "__main__":
    unittest.main()
