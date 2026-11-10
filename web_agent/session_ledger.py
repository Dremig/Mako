from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Iterator
from uuid import uuid4


_INTERVENTION_KINDS = {"inspect", "resume", "fork", "recovery"}
_INTERVENTION_STATUSES = {"accepted", "applied", "completed", "failed"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any) -> str:
    return str(value or "")


class SessionLedger:
    """Durable session topology and runtime receipts, never cognitive state."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._closed = False
        self._conn = sqlite3.connect(
            self.path, timeout=5.0, isolation_level=None, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._create_schema()

    def __enter__(self) -> "SessionLedger":
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
            raise RuntimeError("SessionLedger is closed")

    def _create_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                parent_run_id TEXT NOT NULL DEFAULT '',
                target TEXT NOT NULL DEFAULT '',
                objective TEXT NOT NULL DEFAULT '',
                mode TEXT NOT NULL DEFAULT '',
                primary_session_id TEXT NOT NULL DEFAULT '',
                checkpoint_message_id TEXT NOT NULL DEFAULT '',
                workspace_root TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                origin_run_id TEXT NOT NULL DEFAULT '',
                parent_session_id TEXT NOT NULL DEFAULT '',
                sdk_signature TEXT NOT NULL,
                fork_reason TEXT NOT NULL DEFAULT '',
                transcript_ref TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS calls (
                call_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL DEFAULT '',
                session_id TEXT NOT NULL DEFAULT '',
                started_at TEXT NOT NULL,
                ended_at TEXT NOT NULL DEFAULT '',
                result_status TEXT NOT NULL DEFAULT '',
                usage_json TEXT NOT NULL DEFAULT '{}',
                error_class TEXT NOT NULL DEFAULT '',
                cost_usd REAL,
                num_turns INTEGER,
                terminal_reason TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS interventions (
                intervention_id TEXT PRIMARY KEY,
                source_run_id TEXT NOT NULL DEFAULT '',
                result_run_id TEXT NOT NULL DEFAULT '',
                session_id TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL CHECK(kind IN ('inspect','resume','fork','recovery')),
                status TEXT NOT NULL CHECK(status IN ('accepted','applied','completed','failed')),
                prompt_sha256 TEXT NOT NULL,
                prompt_preview TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_sessions_parent ON sessions(parent_session_id);
            CREATE INDEX IF NOT EXISTS idx_calls_run ON calls(run_id, started_at);
            CREATE INDEX IF NOT EXISTS idx_interventions_source
                ON interventions(source_run_id, created_at);
            """
        )
        # Additive local migrations keep ledgers created by earlier Mako builds usable.
        self._ensure_column("runs", "checkpoint_message_id", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("calls", "cost_usd", "REAL")
        self._ensure_column("calls", "num_turns", "INTEGER")
        self._ensure_column("calls", "terminal_reason", "TEXT NOT NULL DEFAULT ''")

    def _ensure_column(self, table: str, name: str, declaration: str) -> None:
        columns = {
            str(row[1]) for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if name not in columns:
            self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

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

    def _fetchone(self, sql: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
        with self._lock:
            self._ensure_open()
            row = self._conn.execute(sql, params).fetchone()
            return dict(row) if row is not None else None

    def register_run(
        self,
        run_id: str,
        *,
        parent_run_id: str = "",
        target: str = "",
        objective: str = "",
        mode: str = "",
        primary_session_id: str = "",
        workspace_root: str = "",
        status: str = "running",
        exclusive: bool = False,
    ) -> None:
        run_id = _text(run_id).strip()
        if not run_id:
            raise ValueError("run_id must not be empty")
        values = {
            "parent_run_id": _text(parent_run_id), "target": _text(target),
            "objective": _text(objective), "mode": _text(mode),
            "primary_session_id": _text(primary_session_id),
            "workspace_root": _text(workspace_root), "status": _text(status),
        }
        now = _utc_now()
        with self._write_transaction() as conn:
            row = conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                conn.execute(
                    """INSERT INTO runs
                    (run_id,parent_run_id,target,objective,mode,primary_session_id,
                     checkpoint_message_id,workspace_root,status,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (run_id, values["parent_run_id"], values["target"],
                     values["objective"], values["mode"], values["primary_session_id"],
                     "", values["workspace_root"], values["status"], now, now),
                )
                return
            if exclusive:
                raise ValueError(f"run already exists: {run_id}")
            existing = dict(row)
            immutable = ("parent_run_id", "target", "objective", "mode", "workspace_root")
            conflicts = [name for name in immutable if existing[name] != values[name]]
            if conflicts:
                raise ValueError(f"run {run_id!r} conflicts on {', '.join(conflicts)}")
            conn.execute(
                """UPDATE runs SET primary_session_id=?,status=?,updated_at=?
                WHERE run_id=?""",
                (values["primary_session_id"] or existing["primary_session_id"],
                 values["status"] or existing["status"], now, run_id),
            )

    def finish_run(
        self,
        run_id: str,
        status: str,
        primary_session_id: str = "",
        checkpoint_message_id: str = "",
    ) -> None:
        with self._write_transaction() as conn:
            row = conn.execute(
                "SELECT primary_session_id,checkpoint_message_id FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown run_id: {run_id}")
            conn.execute(
                """UPDATE runs SET status=?,primary_session_id=?,checkpoint_message_id=?,updated_at=?
                WHERE run_id=?""",
                (_text(status), _text(primary_session_id) or row["primary_session_id"],
                 _text(checkpoint_message_id) or row["checkpoint_message_id"],
                 _utc_now(), run_id),
            )

    def _parent_would_cycle(
        self, conn: sqlite3.Connection, session_id: str, parent_id: str
    ) -> bool:
        seen: set[str] = set()
        current = parent_id
        while current:
            if current == session_id or current in seen:
                return True
            seen.add(current)
            row = conn.execute(
                "SELECT parent_session_id FROM sessions WHERE session_id=?", (current,)
            ).fetchone()
            if row is None:
                return False
            current = _text(row["parent_session_id"])
        return False

    def register_session(
        self,
        session_id: str,
        origin_run_id: str,
        *,
        parent_session_id: str = "",
        sdk_signature: str,
        fork_reason: str = "",
        transcript_ref: str = "",
        status: str = "active",
    ) -> None:
        session_id = _text(session_id).strip()
        parent_session_id = _text(parent_session_id)
        sdk_signature = _text(sdk_signature)
        if not session_id or not sdk_signature:
            raise ValueError("session_id and sdk_signature must not be empty")
        now = _utc_now()
        with self._write_transaction() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id=?", (session_id,)
            ).fetchone()
            if row is None:
                if self._parent_would_cycle(conn, session_id, parent_session_id):
                    raise ValueError("session parent would create a cycle")
                conn.execute(
                    """INSERT INTO sessions
                    (session_id,origin_run_id,parent_session_id,sdk_signature,
                     fork_reason,transcript_ref,status,created_at,last_used_at)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (session_id, _text(origin_run_id), parent_session_id, sdk_signature,
                     _text(fork_reason), _text(transcript_ref), _text(status), now, now),
                )
                return
            existing = dict(row)
            if existing["origin_run_id"] != _text(origin_run_id):
                raise ValueError(f"session {session_id!r} cannot change origin_run_id")
            if existing["parent_session_id"] != parent_session_id:
                raise ValueError(f"session {session_id!r} cannot change parent_session_id")
            if existing["sdk_signature"] != sdk_signature:
                raise ValueError(f"session {session_id!r} cannot change sdk_signature")
            conn.execute(
                """UPDATE sessions SET fork_reason=?,transcript_ref=?,status=?,last_used_at=?
                WHERE session_id=?""",
                (_text(fork_reason) or existing["fork_reason"],
                 _text(transcript_ref) or existing["transcript_ref"],
                 _text(status) or existing["status"], now, session_id),
            )

    def touch_session(self, session_id: str, run_id: str = "") -> None:
        now = _utc_now()
        with self._write_transaction() as conn:
            cur = conn.execute(
                "UPDATE sessions SET last_used_at=? WHERE session_id=?",
                (now, session_id),
            )
            if cur.rowcount == 0:
                raise KeyError(f"unknown session_id: {session_id}")
            if run_id:
                cur = conn.execute(
                    """UPDATE runs SET primary_session_id=?,updated_at=? WHERE run_id=?""",
                    (session_id, now, run_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"unknown run_id: {run_id}")

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        return self._fetchone("SELECT * FROM runs WHERE run_id=?", (run_id,))

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        return self._fetchone("SELECT * FROM sessions WHERE session_id=?", (session_id,))

    def latest_run(self) -> dict[str, Any] | None:
        return self._fetchone(
            "SELECT * FROM runs ORDER BY created_at DESC,rowid DESC LIMIT 1", ()
        )

    def session_lineage(self, session_id: str) -> list[dict[str, Any]]:
        lineage: list[dict[str, Any]] = []
        seen: set[str] = set()
        current = _text(session_id)
        while current:
            if current in seen:
                raise RuntimeError("session lineage contains a cycle")
            seen.add(current)
            row = self.get_session(current)
            if row is None:
                break
            lineage.append(row)
            current = _text(row.get("parent_session_id"))
        return list(reversed(lineage))

    def record_call(
        self,
        run_id: str,
        session_id: str,
        *,
        call_id: str = "",
        started_at: str = "",
        ended_at: str = "",
        result_status: str = "",
        usage: Any = None,
        error_class: str = "",
        cost_usd: float | None = None,
        num_turns: int | None = None,
        terminal_reason: str = "",
    ) -> str:
        call_id = _text(call_id).strip() or uuid4().hex
        usage_json = json.dumps(
            {} if usage is None else usage, ensure_ascii=False,
            sort_keys=True, separators=(",", ":")
        )
        values = {
            "run_id": _text(run_id),
            "session_id": _text(session_id),
            "started_at": _text(started_at) or _utc_now(),
            "ended_at": _text(ended_at),
            "result_status": _text(result_status),
            "usage_json": usage_json,
            "error_class": _text(error_class),
            "cost_usd": None if cost_usd is None else float(cost_usd),
            "num_turns": None if num_turns is None else int(num_turns),
            "terminal_reason": _text(terminal_reason),
        }
        with self._write_transaction() as conn:
            row = conn.execute("SELECT * FROM calls WHERE call_id=?", (call_id,)).fetchone()
            if row is not None:
                existing = dict(row)
                conflicts = [name for name, value in values.items() if existing[name] != value]
                if conflicts:
                    raise ValueError(f"call {call_id!r} conflicts on {', '.join(conflicts)}")
                return call_id
            conn.execute(
                """INSERT INTO calls
                (call_id,run_id,session_id,started_at,ended_at,result_status,
                 usage_json,error_class,cost_usd,num_turns,terminal_reason)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (call_id, *(values[name] for name in (
                    "run_id", "session_id", "started_at", "ended_at",
                    "result_status", "usage_json", "error_class", "cost_usd",
                    "num_turns", "terminal_reason",
                ))),
            )
        return call_id

    def record_intervention(
        self,
        source_run_id: str,
        session_id: str,
        kind: str,
        prompt: str,
        preview: str | None = None,
    ) -> str:
        kind = _text(kind).strip().lower()
        if kind not in _INTERVENTION_KINDS:
            raise ValueError("kind must be inspect, resume, fork, or recovery")
        prompt = _text(prompt)
        prompt_preview = prompt if preview is None else _text(preview)
        iid, now = uuid4().hex, _utc_now()
        with self._write_transaction() as conn:
            conn.execute(
                """INSERT INTO interventions
                (intervention_id,source_run_id,result_run_id,session_id,kind,status,
                 prompt_sha256,prompt_preview,detail,created_at,updated_at)
                VALUES (?,?,'',?,?,'accepted',?,?,'',?,?)""",
                (iid, _text(source_run_id), _text(session_id), kind,
                 hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                 prompt_preview[:200], now, now),
            )
        return iid

    def update_intervention(
        self,
        intervention_id: str,
        status: str,
        result_run_id: str = "",
        detail: str = "",
    ) -> None:
        status = _text(status).strip().lower()
        if status not in _INTERVENTION_STATUSES:
            raise ValueError("status must be accepted, applied, completed, or failed")
        with self._write_transaction() as conn:
            row = conn.execute(
                "SELECT status,result_run_id,detail FROM interventions WHERE intervention_id=?",
                (intervention_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown intervention_id: {intervention_id}")
            current = str(row["status"] or "")
            allowed = {
                "accepted": {"accepted", "applied", "failed"},
                "applied": {"applied", "completed", "failed"},
                "completed": {"completed"},
                "failed": {"failed"},
            }
            if current and status not in allowed.get(current, set()):
                raise ValueError(f"intervention cannot transition from {current} to {status}")
            conn.execute(
                """UPDATE interventions
                SET status=?,result_run_id=?,detail=?,updated_at=? WHERE intervention_id=?""",
                (status, _text(result_run_id) or row["result_run_id"],
                 _text(detail) or row["detail"], _utc_now(), intervention_id),
            )

    def list_interventions(self, source_run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            self._ensure_open()
            rows = self._conn.execute(
                """SELECT * FROM interventions WHERE source_run_id=?
                ORDER BY created_at,rowid""",
                (source_run_id,),
            ).fetchall()
            return [dict(row) for row in rows]
