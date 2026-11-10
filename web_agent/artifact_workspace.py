from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import sqlite3
import stat
import threading
from typing import Any, BinaryIO, Iterator
from uuid import uuid4


class ArtifactIntegrityError(RuntimeError):
    """Stored object bytes no longer match their content address."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any) -> str:
    return str(value or "")


def _hash_stream(handle: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


class ArtifactWorkspace:
    """Content-addressed raw artifact store with append-only provenance receipts."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.objects_root = self.root / "objects"
        self.objects_root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._closed = False
        self._db_path = self.root / "artifacts.sqlite"
        self._conn = sqlite3.connect(
            self._db_path, timeout=5.0, isolation_level=None, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS objects (
                    sha256 TEXT PRIMARY KEY,
                    size INTEGER NOT NULL,
                    media_type TEXT NOT NULL DEFAULT '',
                    object_path TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    session_id TEXT NOT NULL DEFAULT '',
                    call_id TEXT NOT NULL DEFAULT '',
                    tool_name TEXT NOT NULL DEFAULT '',
                    source_kind TEXT NOT NULL,
                    source_ref TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    captured_at TEXT NOT NULL,
                    FOREIGN KEY(sha256) REFERENCES objects(sha256)
                );
                CREATE INDEX IF NOT EXISTS idx_receipts_run
                    ON receipts(run_id, captured_at DESC);
                CREATE INDEX IF NOT EXISTS idx_receipts_sha
                    ON receipts(sha256, captured_at DESC);
                """
            )

    def __enter__(self) -> "ArtifactWorkspace":
        self._ensure_open()
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._conn.close()
                self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("ArtifactWorkspace is closed")

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._ensure_open()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()

    def _relative_object_path(self, sha256: str) -> Path:
        return Path("objects") / sha256[:2] / sha256

    def _full_object_path(self, object_path: str | Path) -> Path:
        candidate = (self.root / Path(object_path)).resolve()
        try:
            candidate.relative_to(self.objects_root)
        except ValueError as exc:
            raise ArtifactIntegrityError("artifact object path escaped the workspace") from exc
        return candidate

    def _detect_media_type(self, sample: bytes, source_ref: str, explicit: str) -> str:
        if explicit.strip():
            return explicit.strip().lower()
        guessed, _encoding = mimetypes.guess_type(source_ref)
        if guessed:
            return guessed.lower()
        if sample.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if sample.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if sample.startswith(b"%PDF-"):
            return "application/pdf"
        if sample.startswith(b"PK\x03\x04"):
            return "application/zip"
        if b"\x00" not in sample:
            try:
                sample.decode("utf-8")
            except UnicodeDecodeError:
                pass
            else:
                return "text/plain"
        return "application/octet-stream"

    def _temporary_path(self, directory: Path) -> Path:
        return directory / f".capture.{os.getpid()}.{threading.get_ident()}.{uuid4().hex}.tmp"

    def _fsync_directory(self, directory: Path) -> None:
        try:
            fd = os.open(directory, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def _install_temporary(self, temporary: Path, destination: Path) -> None:
        try:
            os.link(temporary, destination)
        except FileExistsError:
            pass
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        self._fsync_directory(destination.parent)

    def _verify_path(self, path: Path, expected_sha: str, expected_size: int) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError as exc:
            raise ArtifactIntegrityError("artifact object is missing") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ArtifactIntegrityError("artifact object is not a regular file")
        if info.st_size != expected_size:
            raise ArtifactIntegrityError("artifact object size does not match its receipt")
        with path.open("rb") as handle:
            actual_sha, actual_size = _hash_stream(handle)
        if actual_size != expected_size or actual_sha != expected_sha:
            raise ArtifactIntegrityError("artifact object hash verification failed")

    def _metadata_json(self, metadata: Any) -> str:
        value = {} if metadata is None else metadata
        if not isinstance(value, dict):
            raise TypeError("metadata must be a JSON object")
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def _record(
        self,
        *,
        sha256: str,
        size: int,
        media_type: str,
        run_id: str,
        session_id: str,
        call_id: str,
        tool_name: str,
        source_kind: str,
        source_ref: str,
        metadata: Any,
    ) -> dict[str, Any]:
        run_id = _text(run_id).strip()
        source_kind = _text(source_kind).strip()
        if not run_id:
            raise ValueError("run_id must not be empty")
        if not source_kind:
            raise ValueError("source_kind must not be empty")
        relative = self._relative_object_path(sha256)
        destination = self.root / relative
        self._verify_path(destination, sha256, size)
        receipt_id, captured_at = uuid4().hex, _utc_now()
        metadata_json = self._metadata_json(metadata)
        with self._write_transaction() as conn:
            conn.execute(
                """INSERT INTO objects(sha256,size,media_type,object_path,created_at)
                VALUES (?,?,?,?,?) ON CONFLICT(sha256) DO NOTHING""",
                (sha256, size, media_type, str(relative), captured_at),
            )
            row = conn.execute(
                "SELECT size,object_path FROM objects WHERE sha256=?", (sha256,)
            ).fetchone()
            if row is None or int(row["size"]) != size or row["object_path"] != str(relative):
                raise ArtifactIntegrityError("artifact database identity conflict")
            conn.execute(
                """INSERT INTO receipts
                (receipt_id,sha256,run_id,session_id,call_id,tool_name,source_kind,
                 source_ref,metadata_json,captured_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (receipt_id, sha256, run_id, _text(session_id), _text(call_id),
                 _text(tool_name), source_kind, _text(source_ref), metadata_json,
                 captured_at),
            )
        resolved = self.resolve(receipt_id)
        if resolved is None:  # pragma: no cover - the transaction guarantees it.
            raise RuntimeError("new artifact receipt could not be resolved")
        return resolved

    def put_bytes(
        self,
        data: bytes,
        *,
        run_id: str,
        session_id: str = "",
        call_id: str = "",
        tool_name: str = "",
        source_kind: str,
        source_ref: str = "",
        media_type: str = "",
        metadata: Any = None,
    ) -> dict[str, Any]:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        sha256 = hashlib.sha256(data).hexdigest()
        destination = self.root / self._relative_object_path(sha256)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._temporary_path(destination.parent)
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            self._install_temporary(temporary, destination)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        detected = self._detect_media_type(data[:8192], source_ref, media_type)
        return self._record(
            sha256=sha256, size=len(data), media_type=detected, run_id=run_id,
            session_id=session_id, call_id=call_id, tool_name=tool_name,
            source_kind=source_kind, source_ref=source_ref, metadata=metadata,
        )

    def capture_file(
        self,
        path: Path,
        *,
        run_id: str,
        session_id: str = "",
        call_id: str = "",
        tool_name: str = "",
        source_kind: str,
        source_ref: str = "",
        media_type: str = "",
        metadata: Any = None,
    ) -> dict[str, Any]:
        path = Path(path)
        if path.is_symlink():
            raise ValueError("capture source must not be a symlink")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise ValueError("capture source must be a readable regular file") from exc
        temporary: Path | None = None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("capture source must be a regular file")
            incoming = self.objects_root / "incoming"
            incoming.mkdir(parents=True, exist_ok=True)
            temporary = self._temporary_path(incoming)
            digest, size, sample = hashlib.sha256(), 0, bytearray()
            with os.fdopen(fd, "rb", closefd=False) as source, temporary.open("xb") as out:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
                    if len(sample) < 8192:
                        sample.extend(chunk[: 8192 - len(sample)])
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            sha256 = digest.hexdigest()
            destination = self.root / self._relative_object_path(sha256)
            destination.parent.mkdir(parents=True, exist_ok=True)
            self._install_temporary(temporary, destination)
            temporary = None
        finally:
            os.close(fd)
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
        effective_ref = source_ref or str(path.expanduser().resolve())
        detected = self._detect_media_type(bytes(sample), effective_ref, media_type)
        return self._record(
            sha256=sha256, size=size, media_type=detected, run_id=run_id,
            session_id=session_id, call_id=call_id, tool_name=tool_name,
            source_kind=source_kind, source_ref=effective_ref, metadata=metadata,
        )

    def _format_result(
        self,
        object_row: sqlite3.Row | dict[str, Any],
        receipt_row: sqlite3.Row | dict[str, Any] | None,
    ) -> dict[str, Any]:
        obj = dict(object_row)
        raw_receipt = dict(receipt_row) if receipt_row is not None else {}
        metadata_json = _text(raw_receipt.pop("metadata_json", "{}"))
        try:
            metadata = json.loads(metadata_json)
        except json.JSONDecodeError:
            metadata = {}
        receipt = {**raw_receipt, "metadata": metadata} if raw_receipt else {}
        provenance = {
            key: receipt.get(key, "")
            for key in (
                "receipt_id", "run_id", "session_id", "call_id", "tool_name",
                "source_kind", "source_ref", "captured_at",
            )
        }
        full_path = self._full_object_path(obj["object_path"])
        return {
            "artifact_ref": f"artifact:{obj['sha256']}",
            "ref": f"artifact:{obj['sha256']}",
            "sha256": obj["sha256"],
            "size": int(obj["size"]),
            "media_type": obj["media_type"],
            "object_path": str(full_path),
            "created_at": obj["created_at"],
            "receipt_id": receipt.get("receipt_id", ""),
            "receipt": receipt,
            "provenance": provenance,
        }

    def resolve(self, ref: str) -> dict[str, Any] | None:
        ref = _text(ref).strip()
        if not ref:
            return None
        by_sha = ref.startswith("artifact:")
        value = ref.split(":", 1)[1] if by_sha else ref
        with self._lock:
            self._ensure_open()
            receipt_row = None
            if not by_sha:
                receipt_row = self._conn.execute(
                    "SELECT * FROM receipts WHERE receipt_id=?", (value,)
                ).fetchone()
            if receipt_row is not None:
                sha256 = receipt_row["sha256"]
            else:
                sha256 = value.lower()
                if len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
                    return None
                receipt_row = self._conn.execute(
                    """SELECT * FROM receipts WHERE sha256=?
                    ORDER BY captured_at DESC,rowid DESC LIMIT 1""",
                    (sha256,),
                ).fetchone()
            object_row = self._conn.execute(
                "SELECT * FROM objects WHERE sha256=?", (sha256,)
            ).fetchone()
            if object_row is None:
                return None
            result = self._format_result(object_row, receipt_row)
        self._verify_path(Path(result["object_path"]), result["sha256"], result["size"])
        return result

    def list_receipts(self, run_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._lock:
            self._ensure_open()
            where = "WHERE r.run_id=?" if run_id else ""
            params: tuple[Any, ...] = (run_id, limit) if run_id else (limit,)
            rows = self._conn.execute(
                f"""SELECT
                    o.sha256 AS o_sha256,o.size AS o_size,
                    o.media_type AS o_media_type,o.object_path AS o_object_path,
                    o.created_at AS o_created_at,r.*
                    FROM receipts r JOIN objects o ON o.sha256=r.sha256
                    {where} ORDER BY r.captured_at DESC,r.rowid DESC LIMIT ?""",
                params,
            ).fetchall()
            results: list[dict[str, Any]] = []
            for row in rows:
                data = dict(row)
                obj = {
                    "sha256": data.pop("o_sha256"),
                    "size": data.pop("o_size"),
                    "media_type": data.pop("o_media_type"),
                    "object_path": data.pop("o_object_path"),
                    "created_at": data.pop("o_created_at"),
                }
                results.append(self._format_result(obj, data))
        for result in results:
            self._verify_path(Path(result["object_path"]), result["sha256"], result["size"])
        return results

    def _is_text_media(self, media_type: str) -> bool:
        media_type = media_type.lower().split(";", 1)[0].strip()
        return media_type.startswith("text/") or media_type in {
            "application/json", "application/ld+json", "application/xml",
            "application/javascript", "application/x-javascript", "image/svg+xml",
        }

    def peek(
        self,
        ref: str,
        *,
        start_line: int = 0,
        line_count: int = 80,
        query: str = "",
        max_chars: int = 20000,
    ) -> dict[str, Any]:
        result = self.resolve(ref)
        if result is None:
            return {
                "artifact_ref": "",
                "ref": "",
                "receipt": {},
                "provenance": {},
                "found": False,
            }
        if not self._is_text_media(result["media_type"]):
            return {
                **result,
                "found": True,
                "peek": {
                    "binary": True,
                    "text": "",
                    "lines": [],
                    "total_lines": 0,
                    "truncated": False,
                },
            }
        start_line = max(0, int(start_line))
        line_count = max(0, min(int(line_count), 10000))
        max_chars = max(0, min(int(max_chars), 2_000_000))
        needle = _text(query).casefold()
        selected: list[dict[str, Any]] = []
        rendered: list[str] = []
        used = 0
        truncated = False
        total_lines = 0
        selection_closed = False
        with Path(result["object_path"]).open(
            "r", encoding="utf-8", errors="replace"
        ) as handle:
            for index, raw_line in enumerate(handle):
                total_lines = index + 1
                if index < start_line:
                    continue
                line = raw_line.rstrip("\r\n")
                if needle and needle not in line.casefold():
                    continue
                if selection_closed or len(selected) >= line_count:
                    truncated = True
                    selection_closed = True
                    continue
                remaining = max_chars - used
                if remaining <= 0:
                    truncated = True
                    selection_closed = True
                    continue
                shown = line[:remaining]
                if len(shown) < len(line):
                    truncated = True
                    selection_closed = True
                selected.append({"line": index, "text": shown})
                rendered.append(shown)
                used += len(shown) + 1
        return {
            **result,
            "found": True,
            "peek": {
                "binary": False,
                "start_line": start_line,
                "line_count": len(selected),
                "query": query,
                "total_lines": total_lines,
                "text": "\n".join(rendered),
                "lines": selected,
                "truncated": truncated,
            },
        }
