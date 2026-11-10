from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
import re
from typing import Any, Sequence
import uuid

from web_agent.claude_runtime import load_dotenv
from web_agent import pure_sdk_agent as pure_sdk
from web_agent.artifact_tools import (
    ArtifactSessionContext,
    build_artifact_mcp_server,
)
from web_agent.artifact_workspace import ArtifactWorkspace
from web_agent.session_ledger import SessionLedger
from web_agent.shared_session import shared_session_lease


DEFAULT_LEDGER = Path("logs/mako_session_ledger.sqlite")
DEFAULT_CONTEXT_FILE = Path("logs/claude_sdk_shared_context.json")
DEFAULT_ARTIFACT_DIR = Path("artifacts/mako")
FOLLOWUP_MODES = {"inspect", "resume", "fork"}
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class FollowupError(RuntimeError):
    pass


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _resolve(root: Path, path: Path) -> Path:
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _valid_run_id(raw: str, *, field: str) -> str:
    value = str(raw or "").strip()
    if not value or not _RUN_ID_RE.fullmatch(value):
        raise FollowupError(
            f"{field} must contain only letters, digits, dot, underscore, and dash"
        )
    return value


def _result_run_id(ledger: SessionLedger, source_run_id: str, requested: str) -> str:
    if requested.strip():
        candidate = _valid_run_id(requested, field="--result-run-id")
        if ledger.get_run(candidate) is not None:
            raise FollowupError(f"result run already exists: {candidate}")
        return candidate
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for _ in range(8):
        candidate = f"{source_run_id}.followup.{stamp}.{uuid.uuid4().hex[:8]}"
        if ledger.get_run(candidate) is None:
            return candidate
    raise FollowupError("could not allocate a unique follow-up run id")


def _sdk_signature(root: Path) -> str:
    fn = getattr(pure_sdk, "sdk_signature", None) or getattr(
        pure_sdk, "_sdk_signature"
    )
    return str(fn(root))


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    fn = getattr(pure_sdk, "atomic_write_json", None) or getattr(
        pure_sdk, "_atomic_write_json"
    )
    fn(path, payload)


def _redact_record(payload: dict[str, Any]) -> dict[str, Any]:
    redactor = getattr(pure_sdk, "_redact_credentials", None)
    secret_loader = getattr(pure_sdk, "_credential_values", None)
    if callable(redactor) and callable(secret_loader):
        redacted = redactor(payload, secret_loader())
        if isinstance(redacted, dict):
            return redacted
    return payload


def _build_options(
    sdk: Any,
    *,
    root: Path,
    session_id: str,
    fork_session: bool,
    resume_session_at: str = "",
    artifact_server: Any | None = None,
) -> Any:
    builder = getattr(pure_sdk, "build_pure_options", None) or getattr(
        pure_sdk, "_build_options"
    )
    try:
        return builder(
            sdk,
            root=root,
            session_id=session_id,
            fork_session=fork_session,
            resume_session_at=resume_session_at,
            artifact_server=artifact_server,
        )
    except TypeError:
        # Compatibility while the pure entrypoint is being promoted to its public API.
        options = builder(sdk, root=root, session_id=session_id)
        if fork_session:
            setattr(options, "fork_session", True)
        if resume_session_at:
            setattr(options, "resume_session_at", resume_session_at)
        if artifact_server is not None:
            setattr(options, "mcp_servers", {"mako_artifacts": artifact_server})
        return options


async def _run_query(
    sdk: Any,
    prompt: str,
    options: Any,
    *,
    workspace: Any | None = None,
    run_id: str = "",
    session_id: str = "",
    call_id: str = "",
    artifact_context: ArtifactSessionContext | None = None,
) -> dict[str, Any]:
    runner = getattr(pure_sdk, "run_sdk_query", None) or getattr(
        pure_sdk, "_run_sdk_query"
    )
    return await runner(
        sdk=sdk,
        prompt=prompt,
        options=options,
        workspace=workspace,
        run_id=run_id,
        session_id=session_id,
        call_id=call_id,
        artifact_context=artifact_context,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Continue or fork a native Claude Agent SDK session recorded by Mako."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--env", type=Path, default=Path(".env"))
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--context-file", type=Path, default=DEFAULT_CONTEXT_FILE)
    parser.add_argument("--run-id", default="", help="source run id; defaults to latest")
    parser.add_argument("--mode", choices=sorted(FOLLOWUP_MODES), required=True)
    parser.add_argument("--message", required=True)
    parser.add_argument("--result-run-id", default="")
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    load_dotenv(_resolve(root, args.env))
    ledger_path = _resolve(root, args.ledger)
    context_path = _resolve(root, args.context_file)
    artifact_root = _resolve(root, args.artifact_dir)
    requested_source_run_id = str(args.run_id or "").strip()
    mode = str(args.mode).strip().lower()
    message = str(args.message).strip()
    if mode not in FOLLOWUP_MODES:
        raise FollowupError(f"unsupported follow-up mode: {mode}")
    if not message:
        raise FollowupError("--message must not be empty")

    signature = _sdk_signature(root)
    with ArtifactWorkspace(artifact_root / "_evidence") as artifact_workspace, SessionLedger(
        ledger_path
    ) as ledger:
        if requested_source_run_id:
            source_run_id = _valid_run_id(requested_source_run_id, field="--run-id")
            source = ledger.get_run(source_run_id)
        else:
            source = ledger.latest_run()
            source_run_id = str((source or {}).get("run_id", "") or "")
        source = ledger.get_run(source_run_id)
        if source is None:
            detail = source_run_id or "latest"
            raise FollowupError(f"source run not found: {detail}")
        source_session_id = str(source.get("primary_session_id", "") or "").strip()
        if not source_session_id:
            raise FollowupError(f"source run has no primary session: {source_run_id}")
        source_session = ledger.get_session(source_session_id)
        if source_session is None:
            raise FollowupError(f"source session not found: {source_session_id}")
        if str(source_session.get("sdk_signature", "") or "") != signature:
            raise FollowupError("source session SDK signature does not match current runtime")
        source_checkpoint = str(source.get("checkpoint_message_id", "") or "").strip()
        if mode == "fork" and not source_checkpoint:
            raise FollowupError(
                f"source run has no checkpoint to fork from: {source_run_id}"
            )

        result_run_id = _result_run_id(
            ledger, source_run_id, str(args.result_run_id or "")
        )
        result_dir = (artifact_root / result_run_id).resolve()
        result_dir.mkdir(parents=True, exist_ok=True)
        target = str(source.get("target", "") or "")
        objective = str(source.get("objective", "") or "")
        ledger.register_run(
            run_id=result_run_id,
            parent_run_id=source_run_id,
            target=target,
            objective=objective,
            mode=f"followup:{mode}",
            workspace_root=str(result_dir),
            status="running",
            exclusive=True,
        )
        intervention_id = ledger.record_intervention(
            source_run_id=source_run_id,
            session_id=source_session_id,
            kind=mode,
            prompt=message,
            preview=str(_redact_record({"message": message}).get("message", "")),
        )
        ledger.update_intervention(
            intervention_id,
            status="applied",
            result_run_id=result_run_id,
        )

        result: dict[str, Any]
        started_at = utc_now_z()
        call_id = f"call-{uuid.uuid4().hex}"
        effective_session_id = source_session_id
        try:
            sdk_loader = getattr(pure_sdk, "sdk_bindings", None) or getattr(
                pure_sdk, "_sdk_bindings"
            )
            sdk = sdk_loader()
            artifact_context = ArtifactSessionContext(
                session_id="" if mode == "fork" else source_session_id
            )
            artifact_server = build_artifact_mcp_server(
                sdk,
                artifact_workspace,
                project_root=root,
                run_id=result_run_id,
                session_id=source_session_id,
                call_id=call_id,
                artifact_context=artifact_context,
            )
            with shared_session_lease(
                context_path,
                sdk_signature=signature,
                reset=False,
            ) as shared_state:
                options = _build_options(
                    sdk,
                    root=root,
                    session_id=source_session_id,
                    fork_session=mode == "fork",
                    resume_session_at=(source_checkpoint if mode == "fork" else ""),
                    artifact_server=artifact_server,
                )
                result = asyncio.run(
                    _run_query(
                        sdk,
                        message,
                        options,
                        workspace=artifact_workspace,
                        run_id=result_run_id,
                        session_id=source_session_id,
                        call_id=call_id,
                        artifact_context=artifact_context,
                    )
                )
                result_session_id = str(result.get("session_id", "") or "").strip()
                if mode == "fork" and result_session_id:
                    effective_session_id = result_session_id
                else:
                    effective_session_id = source_session_id
                if bool(result.get("success", False)):
                    shared_state.session_id = effective_session_id
                    shared_state.last_run_id = result_run_id
        except Exception as exc:
            result = {
                "success": False,
                "assistant_text": "",
                "session_id": "",
                "subtype": "",
                "is_error": True,
                "usage": {},
                "total_cost_usd": None,
                "num_turns": None,
                "terminal_reason": "",
                "stop_reason": "",
                "event_types": [],
                "tool_names": [],
                "artifact_refs": [],
                "artifact_capture_errors": [],
                "error": type(exc).__name__,
            }

        artifact_refs = [
            str(ref).strip()
            for ref in result.get("artifact_refs", [])
            if str(ref).strip()
        ] if isinstance(result.get("artifact_refs", []), list) else []
        for ref in pure_sdk._capture_run_files(
            artifact_workspace,
            result_dir,
            run_id=result_run_id,
            session_id=effective_session_id,
            call_id=call_id,
            excluded_names={"pure_sdk_run.json", "followup_result.json"},
        ):
            if ref not in artifact_refs:
                artifact_refs.append(ref)
        result["artifact_refs"] = artifact_refs

        completed = bool(result.get("success", False))
        status = "completed" if completed else "failed"
        ended_at = utc_now_z()
        error_class = str(result.get("error", "") or "")
        if not completed and not error_class:
            error_class = str(result.get("subtype", "") or "ResultError")
        ledger.record_call(
            call_id=call_id,
            run_id=result_run_id,
            session_id=effective_session_id,
            started_at=started_at,
            ended_at=ended_at,
            result_status=status,
            usage=(result.get("usage", {}) if isinstance(result.get("usage"), dict) else {}),
            error_class=error_class,
            cost_usd=(
                float(result["total_cost_usd"])
                if isinstance(result.get("total_cost_usd"), (int, float))
                else None
            ),
            num_turns=(
                int(result["num_turns"])
                if isinstance(result.get("num_turns"), int)
                else None
            ),
            terminal_reason=str(result.get("terminal_reason", "") or ""),
        )

        if mode == "fork" and effective_session_id != source_session_id:
            ledger.register_session(
                session_id=effective_session_id,
                origin_run_id=result_run_id,
                parent_session_id=source_session_id,
                sdk_signature=signature,
                fork_reason="operator_followup",
                status="active" if completed else "failed",
            )
        else:
            # inspect and resume are intentionally the same native continuation;
            # their semantic distinction exists only in the intervention ledger.
            ledger.touch_session(source_session_id, run_id=result_run_id)
            effective_session_id = source_session_id

        ledger.finish_run(
            result_run_id,
            status=status,
            primary_session_id=effective_session_id,
            checkpoint_message_id=str(result.get("last_message_uuid", "") or ""),
        )
        ledger.update_intervention(
            intervention_id,
            status=status,
            result_run_id=result_run_id,
            detail=error_class,
        )

    record = _redact_record({
        "timestamp": utc_now_z(),
        "run_id": result_run_id,
        "parent_run_id": source_run_id,
        "mode": mode,
        "source_session_id": source_session_id,
        "session_id": effective_session_id,
        "intervention_id": intervention_id,
        "call_id": call_id,
        "source_checkpoint_message_id": source_checkpoint,
        "checkpoint_message_id": str(result.get("last_message_uuid", "") or ""),
        "status": status,
        "target": target,
        "objective": objective,
        **result,
    })
    _atomic_write_json(result_dir / "followup_result.json", record)
    text = str(record.get("assistant_text", "") or "").strip()
    if text:
        print(text)
    return 0 if bool(result.get("success", False)) else 1


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(parse_args(argv))
    except FollowupError as exc:
        print(f"follow-up rejected: {exc}")
        return 2
    except Exception as exc:
        # Unexpected SDK/ledger errors can contain request data; report type only.
        print(f"follow-up failed: {type(exc).__name__}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
