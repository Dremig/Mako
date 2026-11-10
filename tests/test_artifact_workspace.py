from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from web_agent.artifact_workspace import ArtifactIntegrityError, ArtifactWorkspace


class ArtifactWorkspaceTests(unittest.TestCase):
    def test_content_deduplicates_but_receipts_are_append_only(self) -> None:
        with tempfile.TemporaryDirectory() as td, ArtifactWorkspace(Path(td)) as workspace:
            content = b"same evidence\n"
            first = workspace.put_bytes(
                content,
                run_id="run-1",
                session_id="session-1",
                call_id="call-1",
                tool_name="Bash",
                source_kind="tool_result",
                source_ref="stdout.txt",
                metadata={"exit_code": 0},
            )
            second = workspace.put_bytes(
                content,
                run_id="run-1",
                session_id="session-1",
                call_id="call-2",
                tool_name="Bash",
                source_kind="tool_result",
                source_ref="stdout-again.txt",
            )

            self.assertEqual(first["sha256"], hashlib.sha256(content).hexdigest())
            self.assertEqual(first["artifact_ref"], second["artifact_ref"])
            self.assertNotEqual(first["receipt_id"], second["receipt_id"])
            self.assertEqual(Path(first["object_path"]), Path(second["object_path"]))
            self.assertEqual(Path(first["object_path"]).read_bytes(), content)
            receipts = workspace.list_receipts("run-1")
            self.assertEqual(len(receipts), 2)
            self.assertEqual({row["receipt_id"] for row in receipts}, {
                first["receipt_id"], second["receipt_id"]
            })
            self.assertEqual(first["receipt"]["metadata"], {"exit_code": 0})
            self.assertEqual(first["provenance"]["call_id"], "call-1")

            conn = sqlite3.connect(Path(td) / "artifacts.sqlite")
            self.assertEqual(conn.execute("SELECT count(*) FROM objects").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM receipts").fetchone()[0], 2)
            conn.close()

    def test_resolve_accepts_receipt_sha_and_artifact_ref(self) -> None:
        with tempfile.TemporaryDirectory() as td, ArtifactWorkspace(Path(td)) as workspace:
            stored = workspace.put_bytes(
                b"evidence",
                run_id="run-1",
                source_kind="assistant_output",
            )
            by_receipt = workspace.resolve(stored["receipt_id"])
            by_sha = workspace.resolve(stored["sha256"])
            by_ref = workspace.resolve(stored["artifact_ref"])
            self.assertEqual(by_receipt["sha256"], stored["sha256"])
            self.assertEqual(by_sha["sha256"], stored["sha256"])
            self.assertEqual(by_ref["sha256"], stored["sha256"])
            self.assertIsNone(workspace.resolve("missing"))

    def test_capture_file_streams_content_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "large.txt"
            content = ("abcdef\n" * 200_000).encode()
            source.write_bytes(content)
            with ArtifactWorkspace(root / "workspace") as workspace:
                captured = workspace.capture_file(
                    source,
                    run_id="run-1",
                    session_id="session-1",
                    source_kind="workspace_file",
                )
                self.assertEqual(captured["sha256"], hashlib.sha256(content).hexdigest())
                self.assertEqual(captured["size"], len(content))
                self.assertEqual(captured["media_type"], "text/plain")
                self.assertEqual(captured["provenance"]["source_ref"], str(source.resolve()))
                self.assertEqual(Path(captured["object_path"]).read_bytes(), content)

                link = root / "link.txt"
                try:
                    link.symlink_to(source)
                except (OSError, NotImplementedError):
                    self.skipTest("symlinks are unavailable on this platform")
                with self.assertRaisesRegex(ValueError, "symlink"):
                    workspace.capture_file(
                        link, run_id="run-1", source_kind="workspace_file"
                    )

    def test_tampering_is_detected_on_every_read_path(self) -> None:
        with tempfile.TemporaryDirectory() as td, ArtifactWorkspace(Path(td)) as workspace:
            stored = workspace.put_bytes(
                b"trusted bytes",
                run_id="run-1",
                source_kind="tool_result",
            )
            Path(stored["object_path"]).write_bytes(b"tampered bytes")
            with self.assertRaises(ArtifactIntegrityError):
                workspace.resolve(stored["artifact_ref"])
            with self.assertRaises(ArtifactIntegrityError):
                workspace.peek(stored["receipt_id"])
            with self.assertRaises(ArtifactIntegrityError):
                workspace.list_receipts("run-1")

    def test_peek_supports_ranges_literal_query_and_character_limit(self) -> None:
        with tempfile.TemporaryDirectory() as td, ArtifactWorkspace(Path(td)) as workspace:
            text = "zero\nAlpha needle\ntwo\nNEEDLE again\nfour\n"
            stored = workspace.put_bytes(
                text.encode(),
                run_id="run-1",
                source_kind="tool_result",
                source_ref="output.txt",
            )
            ranged = workspace.peek(stored["artifact_ref"], start_line=1, line_count=2)
            self.assertFalse(ranged["peek"]["binary"])
            self.assertEqual(ranged["peek"]["text"], "Alpha needle\ntwo")
            self.assertEqual(
                [row["line"] for row in ranged["peek"]["lines"]], [1, 2]
            )
            self.assertEqual(ranged["peek"]["total_lines"], 5)
            self.assertTrue(ranged["peek"]["truncated"])

            queried = workspace.peek(stored["receipt_id"], query="needle")
            self.assertEqual(
                [row["text"] for row in queried["peek"]["lines"]],
                ["Alpha needle", "NEEDLE again"],
            )
            limited = workspace.peek(stored["sha256"], max_chars=5)
            self.assertEqual(limited["peek"]["text"], "zero")
            self.assertTrue(limited["peek"]["truncated"])
            self.assertEqual(queried["receipt_id"], stored["receipt_id"])
            self.assertEqual(queried["provenance"]["run_id"], "run-1")

    def test_binary_peek_returns_only_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td, ArtifactWorkspace(Path(td)) as workspace:
            stored = workspace.put_bytes(
                b"\x00\x01\x02secret-binary",
                run_id="run-1",
                source_kind="workspace_file",
            )
            result = workspace.peek(stored["artifact_ref"])
            self.assertEqual(result["media_type"], "application/octet-stream")
            self.assertTrue(result["peek"]["binary"])
            self.assertEqual(result["peek"]["text"], "")
            self.assertEqual(result["peek"]["lines"], [])
            self.assertNotIn("secret-binary", json.dumps(result))

    def test_concurrent_duplicate_captures_create_one_object_many_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as td, ArtifactWorkspace(Path(td)) as workspace:
            errors: list[BaseException] = []
            receipts: list[str] = []
            content = b"concurrent evidence"

            def writer(index: int) -> None:
                try:
                    row = workspace.put_bytes(
                        content,
                        run_id="run-1",
                        call_id=f"call-{index}",
                        source_kind="tool_result",
                    )
                    receipts.append(row["receipt_id"])
                except BaseException as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=writer, args=(idx,)) for idx in range(16)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)

            self.assertEqual(errors, [])
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(len(set(receipts)), 16)
            self.assertEqual(len(workspace.list_receipts("run-1", limit=50)), 16)
            conn = sqlite3.connect(Path(td) / "artifacts.sqlite")
            self.assertEqual(conn.execute("SELECT count(*) FROM objects").fetchone()[0], 1)
            conn.close()

    def test_schema_has_no_cognitive_tables_and_uses_wal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with ArtifactWorkspace(root):
                pass
            conn = sqlite3.connect(root / "artifacts.sqlite")
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            conn.close()
            self.assertEqual(tables, {"objects", "receipts"})
            self.assertEqual(mode.lower(), "wal")
            self.assertTrue({"facts", "claims", "intents"}.isdisjoint(tables))


if __name__ == "__main__":
    unittest.main()
