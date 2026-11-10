from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
from typing import Iterator, TextIO

try:  # POSIX provides the cross-process lock used in production.
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised on non-POSIX hosts.
    _fcntl = None


_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


@dataclass
class SharedSessionState:
    session_id: str = ""
    sdk_signature: str = ""
    updated_at: str = ""
    last_run_id: str = ""


def _process_lock(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PROCESS_LOCKS[key] = lock
        return lock


def _string_field(payload: dict[str, object], name: str) -> str:
    value = payload.get(name, "")
    return value if isinstance(value, str) else ""


def _load_state(path: Path, sdk_signature: str, *, reset: bool) -> SharedSessionState:
    empty = SharedSessionState(sdk_signature=sdk_signature)
    if reset or not path.is_file():
        return empty
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return empty
    if not isinstance(payload, dict):
        return empty
    if payload.get("version") != 1:
        return empty
    if _string_field(payload, "sdk_signature") != sdk_signature:
        return empty
    return SharedSessionState(
        session_id=_string_field(payload, "session_id"),
        sdk_signature=sdk_signature,
        updated_at=_string_field(payload, "updated_at"),
        last_run_id=_string_field(payload, "last_run_id"),
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_write(path: Path, state: SharedSessionState, sdk_signature: str) -> None:
    state.sdk_signature = sdk_signature
    state.updated_at = _utc_now()
    payload = {
        "version": 1,
        "session_id": state.session_id,
        "sdk_signature": state.sdk_signature,
        "updated_at": state.updated_at,
        "last_run_id": state.last_run_id,
    }
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@contextmanager
def shared_session_lease(
    path: Path,
    *,
    sdk_signature: str,
    reset: bool = False,
) -> Iterator[SharedSessionState]:
    """Exclusively lease, update, and persist one shared SDK session.

    A process-local lock guarantees thread serialization on every platform. POSIX
    additionally holds an advisory file lock for the entire context-manager
    lifetime so separate Mako processes cannot resume the same SDK session at once.
    """

    path = Path(path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = Path(f"{path}.lock")
    local_lock = _process_lock(lock_path)

    lock_handle: TextIO | None = None
    file_lock_held = False
    with local_lock:
        try:
            lock_handle = lock_path.open("a+", encoding="utf-8")
            if _fcntl is not None:
                try:
                    _fcntl.flock(lock_handle.fileno(), _fcntl.LOCK_EX)
                    file_lock_held = True
                except (AttributeError, OSError):
                    # Some non-local filesystems do not support flock. The local
                    # lock still provides safe serialization inside this process.
                    file_lock_held = False

            if reset:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            state = _load_state(path, sdk_signature, reset=reset)
            try:
                yield state
            finally:
                # Save even while the with-body is unwinding from an exception: a
                # newly issued session id remains valuable continuation state.
                if state.session_id:
                    _atomic_write(path, state, sdk_signature)
        finally:
            if lock_handle is not None:
                if file_lock_held and _fcntl is not None:
                    try:
                        _fcntl.flock(lock_handle.fileno(), _fcntl.LOCK_UN)
                    except OSError:
                        pass
                lock_handle.close()
