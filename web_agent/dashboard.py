from __future__ import annotations

import argparse
import json
import mimetypes
import sqlite3
import threading
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Sequence


DEFAULT_LEDGER = Path("logs/mako_session_ledger.sqlite")
DEFAULT_ARTIFACT_DIR = Path("artifacts/mako")
STATIC_DIR = Path(__file__).resolve().parent / "dashboard_static"
RUN_RECORD_NAMES = ("pure_sdk_run.json", "followup_result.json")


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any) -> str:
    return str(value or "")


def _resolve_under(root: Path, path: Path) -> Path:
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _is_within(path: Path, *roots: Path) -> bool:
    resolved = path.resolve()
    for root in roots:
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            continue
        return True
    return False


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _connect_readonly(path: Path) -> sqlite3.Connection | None:
    path = path.expanduser().resolve()
    if not path.is_file():
        return None
    uri = "file:" + urllib.parse.quote(str(path)) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _rows(path: Path, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    conn = _connect_readonly(path)
    if conn is None:
        return []
    try:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def _row(path: Path, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    rows = _rows(path, sql, params)
    return rows[0] if rows else None


def _json_object(raw: Any) -> dict[str, Any]:
    try:
        value = json.loads(_text(raw) or "{}")
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _sum_usage(calls: list[dict[str, Any]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for call in calls:
        usage = call.get("usage")
        if not isinstance(usage, dict):
            usage = _json_object(call.get("usage_json"))
        for key, value in usage.items():
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                totals[key] = int(totals.get(key, 0) + value)
    return totals


def _record_subset(record: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "timestamp", "run_id", "parent_run_id", "target", "objective", "hint",
        "model", "resumed", "success", "is_error", "subtype", "error",
        "assistant_text", "result", "usage", "total_cost_usd", "num_turns",
        "terminal_reason", "stop_reason", "event_types", "tool_names",
        "artifact_refs", "artifact_capture_errors", "checkpoint_message_id",
    )
    return {key: record.get(key) for key in keys if key in record}


class DashboardStore:
    """Read-only access to run/session/artifact data for the local dashboard."""

    def __init__(self, root: Path, ledger: Path, artifact_dir: Path) -> None:
        self.root = root.expanduser().resolve()
        self.ledger_path = _resolve_under(self.root, ledger)
        self.artifact_dir = _resolve_under(self.root, artifact_dir)
        self.artifact_db = self.artifact_dir / "_evidence" / "artifacts.sqlite"

    def _artifact_counts(self) -> dict[str, int]:
        rows = _rows(
            self.artifact_db,
            "SELECT run_id,COUNT(*) AS count FROM receipts GROUP BY run_id",
        )
        return {_text(row.get("run_id")): int(row.get("count") or 0) for row in rows}

    def _call_rows(self, run_id: str = "") -> list[dict[str, Any]]:
        where = "WHERE c.run_id=?" if run_id else ""
        params = (run_id,) if run_id else ()
        rows = _rows(
            self.ledger_path,
            f"""SELECT c.*,r.target,r.objective,r.mode,r.status AS run_status
                FROM calls c LEFT JOIN runs r ON r.run_id=c.run_id
                {where} ORDER BY c.started_at,c.rowid""",
            params,
        )
        for row in rows:
            row["usage"] = _json_object(row.pop("usage_json", "{}"))
        return rows

    def _intervention_rows(self, run_id: str = "") -> list[dict[str, Any]]:
        if run_id:
            return _rows(
                self.ledger_path,
                """SELECT * FROM interventions WHERE source_run_id=? OR result_run_id=?
                   ORDER BY created_at,rowid""",
                (run_id, run_id),
            )
        return _rows(
            self.ledger_path,
            "SELECT * FROM interventions ORDER BY created_at,rowid",
        )

    def _artifact_rows(self, run_id: str = "", limit: int = 200) -> list[dict[str, Any]]:
        where = "WHERE r.run_id=?" if run_id else ""
        params: tuple[Any, ...] = (run_id, limit) if run_id else (limit,)
        rows = _rows(
            self.artifact_db,
            f"""SELECT r.receipt_id,r.sha256,r.run_id,r.session_id,r.call_id,
                       r.tool_name,r.source_kind,r.source_ref,r.metadata_json,r.captured_at,
                       o.size,o.media_type
                FROM receipts r JOIN objects o ON o.sha256=r.sha256
                {where} ORDER BY r.captured_at DESC,r.rowid DESC LIMIT ?""",
            params,
        )
        for row in rows:
            row["metadata"] = _json_object(row.pop("metadata_json", "{}"))
            row["artifact_ref"] = f"artifact:{row['sha256']}"
        return rows

    def _run_record(self, run: dict[str, Any]) -> dict[str, Any]:
        candidates: list[Path] = []
        workspace = _text(run.get("workspace_root")).strip()
        if workspace:
            workspace_path = Path(workspace)
            if not workspace_path.is_absolute():
                workspace_path = self.root / workspace_path
            candidates.append(workspace_path.resolve())
        candidates.append((self.artifact_dir / _text(run.get("run_id"))).resolve())
        for directory in candidates:
            if not _is_within(directory, self.root, self.artifact_dir):
                continue
            for name in RUN_RECORD_NAMES:
                record = _read_json(directory / name)
                if record:
                    return _record_subset(record)
        return {}

    def _graph_node(
        self,
        nodes: dict[str, dict[str, Any]],
        node_id: str,
        node_type: str,
        label: str,
        *,
        subtitle: str = "",
        status: str = "",
        timestamp: str = "",
        data: dict[str, Any] | None = None,
    ) -> None:
        nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "subtitle": subtitle,
            "status": status,
            "appears_at": timestamp,
            "data": data or {},
        }

    def _graph_edge(
        self,
        edges: dict[str, dict[str, Any]],
        edge_id: str,
        source: str,
        target: str,
        kind: str,
        *,
        label: str = "",
        status: str = "",
        timestamp: str = "",
        data: dict[str, Any] | None = None,
    ) -> None:
        if not source or not target:
            return
        edges[edge_id] = {
            "id": edge_id,
            "source": source,
            "target": target,
            "kind": kind,
            "label": label,
            "status": status,
            "appears_at": timestamp,
            "data": data or {},
        }

    def _graph_event(
        self,
        events: list[dict[str, Any]],
        event_type: str,
        timestamp: str,
        title: str,
        *,
        target_type: str = "node",
        target_id: str = "",
        run_id: str = "",
        actor: str = "runtime",
        meta: list[str] | None = None,
    ) -> None:
        if not timestamp:
            timestamp = utc_now_z()
        events.append(
            {
                "id": f"event-{len(events) + 1}",
                "type": event_type,
                "timestamp": timestamp,
                "title": title,
                "actor": actor,
                "target_type": target_type,
                "target_id": target_id,
                "run_id": run_id,
                "meta": [item for item in (meta or []) if item],
            }
        )

    def graph(self, artifact_limit: int = 1200) -> dict[str, Any]:
        """Return an objective provenance DAG, not inferred cognitive facts."""
        runs = _rows(self.ledger_path, "SELECT * FROM runs ORDER BY created_at,rowid")
        sessions = _rows(
            self.ledger_path,
            "SELECT * FROM sessions ORDER BY created_at,rowid",
        )
        calls = self._call_rows()
        interventions = self._intervention_rows()
        artifacts = self._artifact_rows(limit=artifact_limit)
        run_records = {
            _text(run.get("run_id")): self._run_record(run)
            for run in runs
            if _text(run.get("run_id"))
        }

        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[str, dict[str, Any]] = {}
        events: list[dict[str, Any]] = []
        run_by_id = {_text(run.get("run_id")): run for run in runs}
        call_by_id = {_text(call.get("call_id")): call for call in calls}
        session_by_id = {_text(row.get("session_id")): row for row in sessions}
        activity_by_run: dict[str, str] = {}
        first_call_by_session: dict[str, str] = {}

        def mark_run_activity(run_id: str, timestamp: str) -> None:
            if not run_id or not timestamp:
                return
            current = activity_by_run.get(run_id)
            if not current or timestamp < current:
                activity_by_run[run_id] = timestamp

        for run in runs:
            mark_run_activity(_text(run.get("run_id")), _text(run.get("created_at")))
        for call in calls:
            mark_run_activity(_text(call.get("run_id")), _text(call.get("started_at")))
            session_id = _text(call.get("session_id"))
            started_at = _text(call.get("started_at"))
            if session_id and started_at:
                current = first_call_by_session.get(session_id)
                if not current or started_at < current:
                    first_call_by_session[session_id] = started_at
        for item in artifacts:
            mark_run_activity(_text(item.get("run_id")), _text(item.get("captured_at")))

        objective_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for run in runs:
            key = (_text(run.get("target")), _text(run.get("objective")))
            objective_groups.setdefault(key, []).append(run)
        group_ids = {
            key: index
            for index, key in enumerate(sorted(objective_groups), start=1)
        }
        run_to_goal: dict[str, str] = {}

        for (target, objective), group_runs in sorted(
            objective_groups.items(), key=lambda item: group_ids[item[0]]
        ):
            group_index = group_ids[(target, objective)]
            origin_id = f"origin:{group_index}"
            goal_id = f"goal:{group_index}"
            starts = sorted(
                activity_by_run.get(_text(run.get("run_id")), _text(run.get("created_at")))
                for run in group_runs
            )
            appears_at = starts[0] if starts else ""
            self._graph_node(
                nodes,
                origin_id,
                "origin",
                target or "No target recorded",
                subtitle="stated target",
                status="origin",
                timestamp=appears_at,
                data={
                    "target": target,
                    "objective": objective,
                    "run_ids": [_text(run.get("run_id")) for run in group_runs],
                },
            )
            self._graph_node(
                nodes,
                goal_id,
                "goal",
                objective or "No objective recorded",
                subtitle="stated objective · not verified proof",
                status="goal",
                timestamp=appears_at,
                data={
                    "target": target,
                    "objective": objective,
                    "run_ids": [_text(run.get("run_id")) for run in group_runs],
                },
            )
            for run in group_runs:
                run_to_goal[_text(run.get("run_id"))] = goal_id

        intervention_links = {
            (
                _text(item.get("source_run_id")),
                _text(item.get("result_run_id")),
            ): item
            for item in interventions
        }
        linked_interventions: set[tuple[str, str]] = set()

        for run in runs:
            run_id = _text(run.get("run_id"))
            if not run_id:
                continue
            node_id = f"run:{run_id}"
            record = run_records.get(run_id) or {}
            self._graph_node(
                nodes,
                node_id,
                "run",
                run_id,
                subtitle=_text(run.get("objective")) or _text(run.get("mode")),
                status=_text(run.get("status")) or "unknown",
                timestamp=activity_by_run.get(run_id, _text(run.get("created_at"))),
                data={**run, "record": {
                    "success": record.get("success"),
                    "is_error": record.get("is_error"),
                    "subtype": record.get("subtype"),
                    "terminal_reason": record.get("terminal_reason"),
                    "num_turns": record.get("num_turns"),
                    "total_cost_usd": record.get("total_cost_usd"),
                }},
            )
            self._graph_event(
                events,
                "run_registered",
                _text(run.get("created_at")),
                run_id,
                target_id=node_id,
                run_id=run_id,
                meta=[_text(run.get("mode")), _text(run.get("objective"))],
            )
            if _text(run.get("updated_at")) and _text(run.get("updated_at")) != _text(run.get("created_at")):
                self._graph_event(
                    events,
                    "run_status",
                    _text(run.get("updated_at")),
                    f"run {run_id} → {_text(run.get('status')) or 'updated'}",
                    target_id=node_id,
                    run_id=run_id,
                    meta=[_text(run.get("status"))],
                )

            parent_id = _text(run.get("parent_run_id"))
            if parent_id and parent_id in run_by_id:
                link = intervention_links.get((parent_id, run_id))
                if link is not None:
                    linked_interventions.add((parent_id, run_id))
                    edge_id = f"intervention:{_text(link.get('intervention_id'))}"
                    self._graph_edge(
                        edges,
                        edge_id,
                        f"run:{parent_id}",
                        node_id,
                        "intervention",
                        label=_text(link.get("kind")) or "follow-up",
                        status=_text(link.get("status")) or _text(run.get("status")),
                        timestamp=_text(link.get("created_at")) or _text(run.get("created_at")),
                        data=link,
                    )
                else:
                    self._graph_edge(
                        edges,
                        f"parent:{parent_id}:{run_id}",
                        f"run:{parent_id}",
                        node_id,
                        "lineage",
                        label="parent run",
                        status=_text(run.get("status")),
                        timestamp=activity_by_run.get(run_id, _text(run.get("created_at"))),
                    )
            else:
                key = (_text(run.get("target")), _text(run.get("objective")))
                group_index = group_ids.get(key)
                if group_index:
                    self._graph_edge(
                        edges,
                        f"origin:{group_index}:{run_id}",
                        f"origin:{group_index}",
                        node_id,
                        "origin",
                        label="starts",
                        status=_text(run.get("status")),
                        timestamp=activity_by_run.get(run_id, _text(run.get("created_at"))),
                    )

            goal_id = run_to_goal.get(run_id)
            finished = _text(run.get("status")) in {"completed", "failed", "error"} or bool(record.get("success"))
            if goal_id and finished:
                outcome_status = _text(run.get("status")) or ("success" if record.get("success") else "reported")
                self._graph_edge(
                    edges,
                    f"goal:{run_id}",
                    node_id,
                    goal_id,
                    "outcome",
                    label="reported outcome",
                    status=outcome_status,
                    timestamp=_text(run.get("updated_at")) or _text(run.get("created_at")),
                    data={"success": record.get("success"), "subtype": record.get("subtype")},
                )

        for item in interventions:
            source = _text(item.get("source_run_id"))
            result = _text(item.get("result_run_id"))
            if not source or not result:
                continue
            if (source, result) not in linked_interventions and source in run_by_id and result in run_by_id:
                edge_id = f"intervention:{_text(item.get('intervention_id'))}"
                self._graph_edge(
                    edges,
                    edge_id,
                    f"run:{source}",
                    f"run:{result}",
                    "intervention",
                    label=_text(item.get("kind")) or "follow-up",
                    status=_text(item.get("status")),
                    timestamp=_text(item.get("created_at")),
                    data=item,
                )
            self._graph_event(
                events,
                f"intervention_{_text(item.get('kind')) or 'recorded'}",
                _text(item.get("created_at")),
                f"{_text(item.get('kind')) or 'follow-up'} → {_text(item.get('status'))}",
                target_type="edge",
                target_id=f"intervention:{_text(item.get('intervention_id'))}",
                run_id=result,
                meta=[_text(item.get("prompt_preview")), source, result],
            )
            if _text(item.get("updated_at")) and _text(item.get("updated_at")) != _text(item.get("created_at")):
                self._graph_event(
                    events,
                    "intervention_status",
                    _text(item.get("updated_at")),
                    f"follow-up {_text(item.get('status'))}",
                    target_type="edge",
                    target_id=f"intervention:{_text(item.get('intervention_id'))}",
                    run_id=result,
                    meta=[_text(item.get("prompt_preview"))],
                )

        session_ids = {
            _text(row.get("session_id"))
            for row in sessions
            if _text(row.get("session_id"))
        }
        session_ids.update(
            _text(call.get("session_id"))
            for call in calls
            if _text(call.get("session_id"))
        )
        for session_id in sorted(session_ids):
            row = session_by_id.get(session_id) or {"session_id": session_id}
            node_id = f"session:{session_id}"
            session_appears_at = min(
                value
                for value in (
                    _text(row.get("created_at")),
                    first_call_by_session.get(session_id, ""),
                )
                if value
            ) if (_text(row.get("created_at")) or first_call_by_session.get(session_id)) else ""
            self._graph_node(
                nodes,
                node_id,
                "session",
                session_id,
                subtitle=_text(row.get("sdk_signature")) or _text(row.get("fork_reason")) or "SDK session",
                status=_text(row.get("status")) or "recorded",
                timestamp=session_appears_at,
                data=row,
            )
            self._graph_event(
                events,
                "session_registered",
                _text(row.get("created_at")),
                session_id,
                target_id=node_id,
                meta=[_text(row.get("origin_run_id")), _text(row.get("fork_reason"))],
            )
            parent_session = _text(row.get("parent_session_id"))
            if parent_session:
                self._graph_edge(
                    edges,
                    f"session-parent:{parent_session}:{session_id}",
                    f"session:{parent_session}",
                    node_id,
                    "session_lineage",
                    label=_text(row.get("fork_reason")) or "forked session",
                    status=_text(row.get("status")),
                    timestamp=_text(row.get("created_at")),
                    data=row,
                )

        for call in calls:
            call_id = _text(call.get("call_id"))
            run_id = _text(call.get("run_id"))
            session_id = _text(call.get("session_id"))
            if not call_id:
                continue
            node_id = f"call:{call_id}"
            usage = call.get("usage") if isinstance(call.get("usage"), dict) else {}
            usage_label = " · ".join(
                f"{key}:{value}" for key, value in list(usage.items())[:3]
            )
            self._graph_node(
                nodes,
                node_id,
                "call",
                call_id,
                subtitle=usage_label or _text(call.get("terminal_reason")) or "Claude SDK call",
                status=_text(call.get("result_status")) or "recorded",
                timestamp=_text(call.get("started_at")),
                data=call,
            )
            self._graph_event(
                events,
                "call_started",
                _text(call.get("started_at")),
                f"SDK call {call_id}",
                target_id=node_id,
                run_id=run_id,
                meta=[_text(call.get("target")), _text(call.get("objective"))],
            )
            if run_id:
                self._graph_edge(
                    edges,
                    f"run-call:{run_id}:{call_id}",
                    f"run:{run_id}",
                    node_id,
                    "call",
                    label="SDK call",
                    status=_text(call.get("result_status")),
                    timestamp=_text(call.get("started_at")),
                    data=call,
                )
            if session_id:
                self._graph_edge(
                    edges,
                    f"call-session:{call_id}:{session_id}",
                    node_id,
                    f"session:{session_id}",
                    "session",
                    label="session",
                    status=_text(call.get("result_status")),
                    timestamp=_text(call.get("started_at")),
                    data=call,
                )
            if _text(call.get("ended_at")):
                self._graph_event(
                    events,
                    "call_finished",
                    _text(call.get("ended_at")),
                    f"call {_text(call.get('result_status')) or 'finished'}",
                    target_id=node_id,
                    run_id=run_id,
                    meta=[
                        f"{call.get('num_turns')} turns" if call.get("num_turns") is not None else "",
                        f"${call.get('cost_usd'):.4f}" if isinstance(call.get("cost_usd"), (int, float)) else "",
                        _text(call.get("terminal_reason")),
                    ],
                )

        evidence_groups: dict[tuple[str, str], dict[str, Any]] = {}
        for item in artifacts:
            run_id = _text(item.get("run_id"))
            call_id = _text(item.get("call_id"))
            source_kind = _text(item.get("source_kind")) or "artifact"
            tool_name = _text(item.get("tool_name")) or "artifact"
            key = (run_id, call_id)
            group = evidence_groups.setdefault(
                key,
                {
                    "run_id": run_id,
                    "call_id": call_id,
                    "count": 0,
                    "total_size": 0,
                    "media_types": set(),
                    "source_kinds": set(),
                    "tool_names": set(),
                    "breakdown": {},
                    "receipts": [],
                    "first_at": _text(item.get("captured_at")),
                    "last_at": _text(item.get("captured_at")),
                },
            )
            group["count"] += 1
            group["source_kinds"].add(source_kind)
            group["tool_names"].add(tool_name)
            breakdown = group["breakdown"].setdefault(
                (source_kind, tool_name),
                {
                    "source_kind": source_kind,
                    "tool_name": tool_name,
                    "count": 0,
                    "total_size": 0,
                    "media_types": set(),
                },
            )
            breakdown["count"] += 1
            if isinstance(item.get("size"), (int, float)):
                size = int(item["size"])
                group["total_size"] += size
                breakdown["total_size"] += size
            if _text(item.get("media_type")):
                group["media_types"].add(_text(item.get("media_type")))
                breakdown["media_types"].add(_text(item.get("media_type")))
            if len(group["receipts"]) < 12:
                group["receipts"].append(item)
            captured = _text(item.get("captured_at"))
            if captured and (not group["first_at"] or captured < group["first_at"]):
                group["first_at"] = captured
            if captured and (not group["last_at"] or captured > group["last_at"]):
                group["last_at"] = captured

        for (run_id, call_id), group in sorted(
            evidence_groups.items(), key=lambda item: (item[1]["first_at"], item[0])
        ):
            group_id = f"evidence:{run_id}:{call_id or 'run'}"
            group_data = dict(group)
            group_data["media_types"] = sorted(group["media_types"])
            group_data["source_kinds"] = sorted(group["source_kinds"])
            group_data["tool_names"] = sorted(group["tool_names"])
            group_data["breakdown"] = [
                {**item, "media_types": sorted(item["media_types"])}
                for item in sorted(
                    group["breakdown"].values(),
                    key=lambda item: (-item["count"], item["source_kind"], item["tool_name"]),
                )
            ]
            self._graph_node(
                nodes,
                group_id,
                "evidence",
                "captured evidence",
                subtitle=f"{group['count']} receipts · {len(group_data['breakdown'])} sources",
                status="captured",
                timestamp=_text(group.get("first_at")),
                data=group_data,
            )
            parent_node = ""
            if call_id and call_id in call_by_id:
                parent_node = f"call:{call_id}"
            elif run_id in run_by_id:
                parent_node = f"run:{run_id}"
            self._graph_edge(
                edges,
                f"evidence-edge:{run_id}:{call_id or 'run'}",
                parent_node,
                group_id,
                "evidence",
                label="captured",
                status="captured",
                timestamp=_text(group.get("first_at")),
                data=group_data,
            )
            top_sources = ", ".join(
                f"{item['tool_name']}×{item['count']}"
                for item in group_data["breakdown"][:3]
            )
            self._graph_event(
                events,
                "evidence_captured",
                _text(group.get("first_at")),
                "captured evidence",
                target_id=group_id,
                run_id=run_id,
                meta=[
                    f"{group['count']} receipts",
                    f"{group['total_size']} bytes",
                    top_sources,
                ],
            )

        ordered_events = sorted(
            enumerate(events),
            key=lambda item: (_text(item[1].get("timestamp")), item[0]),
        )
        for order, (_, event) in enumerate(ordered_events, start=1):
            event["order"] = order
        return {
            "generated_at": utc_now_z(),
            "nodes": list(nodes.values()),
            "edges": list(edges.values()),
            "events": [event for _, event in ordered_events],
            "counts": {
                "nodes": len(nodes),
                "edges": len(edges),
                "events": len(events),
                "runs": len(runs),
                "sessions": len(session_ids),
                "calls": len(calls),
                "evidence_groups": len(evidence_groups),
                "artifact_receipts": len(artifacts),
            },
            "notice": "Derived from runtime receipts and provenance only; nodes are not inferred facts or agent intents.",
        }

    def export(self, export_format: str = "timeline") -> str | dict[str, Any]:
        graph = self.graph()
        if export_format == "json":
            return graph
        if export_format != "timeline":
            raise ValueError("supported formats: timeline, json")
        lines = [
            "# Mako provenance timeline",
            "",
            "Derived from runtime receipts only; entries are not inferred facts or agent intents.",
            "",
        ]
        for event in graph["events"]:
            title = _text(event.get("title"))
            meta = " · ".join(_text(item) for item in event.get("meta") or [])
            lines.append(f"[{_text(event.get('timestamp'))}] {_text(event.get('type')).upper()}")
            lines.append(f"  {title}")
            if meta:
                lines.append(f"  {meta}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def overview(self) -> dict[str, Any]:
        runs = _rows(self.ledger_path, "SELECT * FROM runs ORDER BY created_at,rowid")
        sessions = _rows(self.ledger_path, "SELECT * FROM sessions ORDER BY created_at,rowid")
        calls = self._call_rows()
        interventions = self._intervention_rows()
        artifact_counts = self._artifact_counts()
        status_counts: dict[str, int] = {}
        mode_counts: dict[str, int] = {}
        for run in runs:
            status = _text(run.get("status")) or "unknown"
            mode = _text(run.get("mode")) or "unknown"
            status_counts[status] = status_counts.get(status, 0) + 1
            mode_counts[mode] = mode_counts.get(mode, 0) + 1
        total_cost = sum(
            float(call["cost_usd"])
            for call in calls
            if isinstance(call.get("cost_usd"), (int, float))
        )
        total_turns = sum(
            int(call["num_turns"])
            for call in calls
            if isinstance(call.get("num_turns"), int)
        )
        successful = status_counts.get("completed", 0)
        return {
            "generated_at": utc_now_z(),
            "root": str(self.root),
            "ledger_path": str(self.ledger_path),
            "artifact_dir": str(self.artifact_dir),
            "counts": {
                "runs": len(runs),
                "sessions": len(sessions),
                "calls": len(calls),
                "interventions": len(interventions),
                "artifacts": sum(artifact_counts.values()),
            },
            "status_counts": status_counts,
            "mode_counts": mode_counts,
            "success_rate": (successful / len(runs)) if runs else None,
            "total_cost_usd": total_cost,
            "total_turns": total_turns,
            "usage_totals": _sum_usage(calls),
            "timeline": calls[-200:],
        }

    def runs(self) -> dict[str, Any]:
        artifact_counts = self._artifact_counts()
        rows = _rows(
            self.ledger_path,
            """SELECT r.*,COUNT(c.call_id) AS call_count,
                      COALESCE(SUM(c.cost_usd),0) AS total_cost_usd,
                      COALESCE(SUM(c.num_turns),0) AS total_num_turns,
                      MAX(c.ended_at) AS last_call_at,
                      GROUP_CONCAT(DISTINCT c.result_status) AS call_statuses
               FROM runs r LEFT JOIN calls c ON c.run_id=r.run_id
               GROUP BY r.run_id
               ORDER BY r.created_at DESC,r.rowid DESC""",
        )
        for row in rows:
            row["artifact_count"] = artifact_counts.get(_text(row.get("run_id")), 0)
        latest = rows[0]["run_id"] if rows else ""
        return {"generated_at": utc_now_z(), "latest_run_id": latest, "runs": rows}

    def _session_lineage(self, session_id: str) -> list[dict[str, Any]]:
        lineage: list[dict[str, Any]] = []
        seen: set[str] = set()
        current = session_id
        while current and current not in seen:
            seen.add(current)
            row = _row(
                self.ledger_path,
                "SELECT * FROM sessions WHERE session_id=?",
                (current,),
            )
            if row is None:
                break
            lineage.append(row)
            current = _text(row.get("parent_session_id"))
        return list(reversed(lineage))

    def run_detail(self, run_id: str) -> dict[str, Any] | None:
        run_id = _text(run_id).strip()
        if not run_id:
            return None
        run = _row(
            self.ledger_path,
            "SELECT * FROM runs WHERE run_id=?",
            (run_id,),
        )
        if run is None:
            return None
        session_id = _text(run.get("primary_session_id"))
        calls = self._call_rows(run_id)
        return {
            "generated_at": utc_now_z(),
            "run": run,
            "calls": calls,
            "usage_totals": _sum_usage(calls),
            "interventions": self._intervention_rows(run_id),
            "children": _rows(
                self.ledger_path,
                "SELECT * FROM runs WHERE parent_run_id=? ORDER BY created_at,rowid",
                (run_id,),
            ),
            "session": _row(
                self.ledger_path,
                "SELECT * FROM sessions WHERE session_id=?",
                (session_id,),
            ) if session_id else None,
            "session_lineage": self._session_lineage(session_id),
            "artifacts": self._artifact_rows(run_id),
            "record": self._run_record(run),
        }


def _content_type(path: Path) -> str:
    return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "MakoDashboard/0.1"

    @property
    def store(self) -> DashboardStore:
        return self.server.store  # type: ignore[attr-defined]

    def _send(
        self,
        body: bytes,
        *,
        status: HTTPStatus = HTTPStatus.OK,
        content_type: str = "application/json; charset=utf-8",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, payload: Any, *, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send(
            json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
            status=status,
        )

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self._send_json({"error": message}, status=status)

    def _static_file(self, name: str) -> None:
        if name != "index.html":
            self._send_error(HTTPStatus.NOT_FOUND, "not found")
            return
        path = STATIC_DIR / name
        if not path.is_file() or not _is_within(path, STATIC_DIR):
            self._send_error(HTTPStatus.NOT_FOUND, "not found")
            return
        self._send(
            path.read_bytes(),
            content_type=_content_type(path),
        )

    def _static_asset(self, relpath: str) -> None:
        path = (STATIC_DIR / relpath).resolve()
        if not path.is_file() or not _is_within(path, STATIC_DIR):
            self._send_error(HTTPStatus.NOT_FOUND, "not found")
            return
        content_type = {
            ".js": "text/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".svg": "image/svg+xml",
        }.get(path.suffix.lower())
        if content_type is None:
            self._send_error(HTTPStatus.NOT_FOUND, "not found")
            return
        self._send(
            path.read_bytes(),
            content_type=content_type,
        )

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path in {"/", "/index.html"}:
            self._static_file("index.html")
            return
        if path.startswith("/static/"):
            self._static_asset(urllib.parse.unquote(path[len("/static/"):]))
            return
        if path == "/api/health":
            self._send_json({"ok": True, "generated_at": utc_now_z()})
            return
        if path == "/api/overview":
            self._send_json(self.store.overview())
            return
        if path == "/api/runs":
            self._send_json(self.store.runs())
            return
        if path == "/api/graph":
            self._send_json(self.store.graph())
            return
        if path == "/api/export":
            query = urllib.parse.parse_qs(parsed.query)
            export_format = _text((query.get("format") or ["timeline"])[0])
            try:
                exported = self.store.export(export_format)
            except ValueError as exc:
                self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                return
            if isinstance(exported, dict):
                self._send_json(exported)
            else:
                self._send(
                    exported.encode("utf-8"),
                    content_type="text/plain; charset=utf-8",
                )
            return
        if path.startswith("/api/runs/"):
            run_id = urllib.parse.unquote(path.rsplit("/", 1)[-1])
            detail = self.store.run_detail(run_id)
            if detail is None:
                self._send_error(HTTPStatus.NOT_FOUND, "run not found")
            else:
                self._send_json(detail)
            return
        self._send_error(HTTPStatus.NOT_FOUND, "not found")

    def log_message(self, format: str, *args: Any) -> None:
        print(f"dashboard: {self.address_string()} {format % args}")


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], store: DashboardStore) -> None:
        self.store = store
        super().__init__(address, DashboardHandler)


def create_server(host: str, port: int, store: DashboardStore) -> DashboardServer:
    return DashboardServer((host, port), store)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a read-only local dashboard for Mako agent runs."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    store = DashboardStore(root, args.ledger, args.artifact_dir)
    server = create_server(args.host, args.port, store)
    host, port = server.server_address[:2]
    url = f"http://{host}:{port}/"
    print(f"Mako dashboard: {url}")
    if args.open:
        threading.Timer(0.2, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
