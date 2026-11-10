from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from web_agent.shared_session import SharedSessionState, shared_session_lease


class SharedSessionTests(unittest.TestCase):
    def test_state_is_mutable_and_restored_for_matching_signature(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "nested" / "session.json"
            with shared_session_lease(path, sdk_signature="sdk-a") as state:
                self.assertIsInstance(state, SharedSessionState)
                self.assertEqual(state.session_id, "")
                state.session_id = "session-1"
                state.last_run_id = "run-1"

            with shared_session_lease(path, sdk_signature="sdk-a") as restored:
                self.assertEqual(restored.session_id, "session-1")
                self.assertEqual(restored.sdk_signature, "sdk-a")
                self.assertEqual(restored.last_run_id, "run-1")
                self.assertTrue(restored.updated_at)

    def test_signature_mismatch_does_not_restore_session(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "session.json"
            with shared_session_lease(path, sdk_signature="sdk-a") as state:
                state.session_id = "session-a"

            with shared_session_lease(path, sdk_signature="sdk-b") as state:
                self.assertEqual(state.session_id, "")
                self.assertEqual(state.sdk_signature, "sdk-b")
                self.assertEqual(state.updated_at, "")

    def test_reset_forces_empty_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "session.json"
            with shared_session_lease(path, sdk_signature="sdk-a") as state:
                state.session_id = "session-a"

            with shared_session_lease(
                path, sdk_signature="sdk-a", reset=True
            ) as reset_state:
                self.assertEqual(reset_state.session_id, "")
                self.assertEqual(reset_state.updated_at, "")
                self.assertEqual(reset_state.last_run_id, "")

            with shared_session_lease(path, sdk_signature="sdk-a") as later:
                self.assertEqual(later.session_id, "")

    def test_corrupt_json_is_treated_as_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "session.json"
            path.write_text("{not valid json", encoding="utf-8")
            with shared_session_lease(path, sdk_signature="sdk-a") as state:
                self.assertEqual(state.session_id, "")
                state.session_id = "recovered-session"

            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8"))["session_id"],
                "recovered-session",
            )

    def test_atomic_file_contains_only_versioned_public_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "session.json"
            with shared_session_lease(path, sdk_signature="sdk-a") as state:
                state.session_id = "session-a"
                state.last_run_id = "run-a"

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                set(payload),
                {
                    "version",
                    "session_id",
                    "sdk_signature",
                    "updated_at",
                    "last_run_id",
                },
            )
            self.assertEqual(payload["version"], 1)
            self.assertEqual(payload["session_id"], "session-a")
            self.assertEqual(payload["sdk_signature"], "sdk-a")
            self.assertEqual(payload["last_run_id"], "run-a")
            self.assertTrue(payload["updated_at"].endswith("Z"))
            self.assertEqual(list(path.parent.glob(f".{path.name}.*.tmp")), [])

    def test_new_session_is_saved_when_body_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "session.json"
            with self.assertRaisesRegex(RuntimeError, "fixture"):
                with shared_session_lease(path, sdk_signature="sdk-a") as state:
                    state.session_id = "session-from-failed-run"
                    state.last_run_id = "run-failed"
                    raise RuntimeError("fixture")

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["session_id"], "session-from-failed-run")
            self.assertEqual(payload["last_run_id"], "run-failed")

    def test_lease_serializes_threads_for_its_full_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "session.json"
            first_entered = threading.Event()
            release_first = threading.Event()
            second_attempted = threading.Event()
            second_entered = threading.Event()
            order: list[str] = []
            thread_errors: list[BaseException] = []

            def first() -> None:
                try:
                    with shared_session_lease(path, sdk_signature="sdk-a") as state:
                        order.append("first-enter")
                        first_entered.set()
                        release_first.wait(timeout=2)
                        state.session_id = "session-first"
                        order.append("first-exit")
                except BaseException as exc:  # surfaced in the main test thread below
                    thread_errors.append(exc)

            def second() -> None:
                try:
                    first_entered.wait(timeout=2)
                    second_attempted.set()
                    with shared_session_lease(path, sdk_signature="sdk-a") as state:
                        order.append("second-enter")
                        second_entered.set()
                        if state.session_id != "session-first":
                            raise AssertionError("second lease did not observe first lease's write")
                        state.session_id = "session-second"
                except BaseException as exc:  # surfaced in the main test thread below
                    thread_errors.append(exc)

            first_thread = threading.Thread(target=first)
            second_thread = threading.Thread(target=second)
            first_thread.start()
            second_thread.start()
            self.assertTrue(second_attempted.wait(timeout=1))
            time.sleep(0.05)
            self.assertFalse(second_entered.is_set())
            release_first.set()
            first_thread.join(timeout=2)
            second_thread.join(timeout=2)

            self.assertFalse(first_thread.is_alive())
            self.assertFalse(second_thread.is_alive())
            self.assertEqual(thread_errors, [])
            self.assertEqual(order, ["first-enter", "first-exit", "second-enter"])


if __name__ == "__main__":
    unittest.main()
