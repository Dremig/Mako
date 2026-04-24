from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from rag.common import json_completion
from web_agent.solver_shared import strip_noise

STRICT_JSON_RULES = (
    "CRITICAL OUTPUT RULES:\n"
    "Return exactly one valid JSON object only.\n"
    "Do not output markdown, code fences, comments, or any text before/after JSON.\n"
    "Use double quotes for all keys/strings.\n"
)
LOGISTICS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "strategy": {"type": "string"},
        "reason": {"type": "string"},
    },
    "required": ["strategy", "reason"],
}


def _normalize_target(raw: str) -> str:
    val = raw.strip()
    if not val:
        return ""
    # Keep installs predictable and avoid shell metacharacter injection.
    return "".join(ch for ch in val if ch.isalnum() or ch in "._+-=:").strip(" .")


def _looks_like_python_package(name: str, gap_kind: str) -> bool:
    target = name.strip().lower()
    if not target:
        return False
    if gap_kind == "optional_python_dependency":
        return True
    if "." in target:
        return True
    if target.startswith("py") or target.startswith("python-"):
        return True
    return False


def _build_install_command(target: str, *, prefer_python: bool) -> str:
    pkg = shlex.quote(target)
    if prefer_python:
        return f"python3 -m pip install {pkg}"
    return (
        "if command -v brew >/dev/null 2>&1; then "
        f"brew install {pkg}; "
        "elif command -v apt-get >/dev/null 2>&1; then "
        f"apt-get update && apt-get install -y {pkg}; "
        "elif command -v apk >/dev/null 2>&1; then "
        f"apk add --no-cache {pkg}; "
        "elif command -v dnf >/dev/null 2>&1; then "
        f"dnf install -y {pkg}; "
        "elif command -v pacman >/dev/null 2>&1; then "
        f"pacman -Sy --noconfirm {pkg}; "
        "else exit 127; fi"
    )


def run_logistics_decider(
    *,
    base_url: str,
    api_key: str,
    model: str,
    capability: dict[str, Any],
    available_tools: dict[str, str],
    memory_summary: str,
    recent_history: str,
) -> dict[str, Any]:
    gap = capability.get("gap", {}) if isinstance(capability.get("gap"), dict) else {}
    selected = str(capability.get("selected", "")).strip().lower()
    if selected != "install_dependency":
        return {"strategy": "skip_install", "reason": "capability did not request install"}
    target = _normalize_target(str(gap.get("dependency") or gap.get("tool") or ""))
    if not target:
        return {"strategy": "skip_install", "reason": "empty dependency target"}
    prompt = (
        "You are a logistics strategist for a CTF agent.\n"
        "Pick an install strategy with minimal environment impact.\n"
        "Prefer `pip` for Python package needs.\n"
        "Prefer `system_package_manager` for missing command-line tools.\n"
        "Use `skip_install` when install risk is too high.\n"
        f"{STRICT_JSON_RULES}"
        "Return JSON with schema: "
        '{"strategy":"pip|system_package_manager|skip_install","reason":"short reason"}'
    )
    user = (
        f"Capability:\n{capability}\n\n"
        f"Gap:\n{gap}\n\n"
        f"Dependency target: {target}\n"
        f"Available tools: {sorted(list(available_tools.keys()))}\n\n"
        f"Memory summary:\n{memory_summary}\n\n"
        f"Recent history:\n{recent_history}\n"
    )
    try:
        parsed = json_completion(
            base_url=base_url,
            api_key=api_key,
            model=model,
            system_prompt=prompt,
            user_prompt=user,
            json_schema_name="logistics_decision",
            json_schema=LOGISTICS_SCHEMA,
            temperature=0.1,
        )
        if not isinstance(parsed, dict):
            raise RuntimeError("invalid logistics JSON")
        strategy = str(parsed.get("strategy", "")).strip().lower()
        reason = str(parsed.get("reason", "")).strip()
        if strategy not in {"pip", "system_package_manager", "skip_install"}:
            strategy = "skip_install"
        return {"strategy": strategy, "reason": reason[:220]}
    except Exception:
        gap_kind = str(gap.get("kind", "")).strip().lower()
        heuristic = "pip" if _looks_like_python_package(target, gap_kind) else "system_package_manager"
        return {"strategy": heuristic, "reason": "fallback heuristic due to logistics decision failure"}


def build_logistics_request(
    capability: dict[str, Any],
    available_tools: dict[str, str],
    logistics_decision: dict[str, Any] | None = None,
) -> dict[str, Any]:
    gap = capability.get("gap", {}) if isinstance(capability.get("gap"), dict) else {}
    selected = str(capability.get("selected", "")).strip()
    if selected == "write_helper_script":
        return {
            "kind": "helper_generation",
            "goal": "generate_small_helper",
            "install_strategy": "none",
            "command": "",
        }
    if selected == "install_dependency":
        dependency = _normalize_target(str(gap.get("dependency") or gap.get("tool") or ""))
        gap_kind = str(gap.get("kind", "")).strip().lower()
        prefer_python_from_gap = bool(str(gap.get("dependency", "")).strip())
        command = ""
        install_strategy = "none"
        if dependency:
            decided_strategy = str((logistics_decision or {}).get("strategy", "")).strip().lower()
            if decided_strategy not in {"pip", "system_package_manager", "skip_install"}:
                decided_strategy = ""
            if decided_strategy == "skip_install":
                install_strategy = "skip_install"
            elif decided_strategy == "pip":
                install_strategy = "pip"
                command = _build_install_command(dependency, prefer_python=True)
            elif decided_strategy == "system_package_manager":
                install_strategy = "system_package_manager"
                command = _build_install_command(dependency, prefer_python=False)
            else:
                prefer_python = prefer_python_from_gap or _looks_like_python_package(dependency, gap_kind)
                if prefer_python:
                    install_strategy = "pip"
                    command = _build_install_command(dependency, prefer_python=True)
                else:
                    install_strategy = "system_package_manager"
                    command = _build_install_command(dependency, prefer_python=False)
        return {
            "kind": "environment_setup",
            "goal": "install_missing_dependency",
            "dependency": dependency,
            "install_strategy": install_strategy,
            "gap_kind": gap_kind,
            "decision_reason": str((logistics_decision or {}).get("reason", "")).strip()[:220],
            "available_tools": sorted(list(available_tools.keys()))[:30],
            "command": command,
        }
    return {
        "kind": "none",
        "goal": "no_logistics_needed",
        "install_strategy": "none",
        "command": "",
    }


def perform_logistics_request(
    *,
    request: dict[str, Any],
    run_shell_command: Any,
    env: dict[str, str],
    artifact_dir: Path,
    timeout: int,
) -> dict[str, Any]:
    command = str(request.get("command", "")).strip()
    result = {
        "performed": False,
        "returncode": 0,
        "stdout_head": "",
        "stderr_head": "",
        "command": command,
    }
    if not command:
        return result
    proc = run_shell_command(command, timeout=timeout, env=env, cwd=artifact_dir)
    result["performed"] = True
    result["returncode"] = int(proc.get("returncode", 1))
    result["stdout_head"] = strip_noise(str(proc.get("stdout", "")))[:1000]
    result["stderr_head"] = strip_noise(str(proc.get("stderr", "")))[:800]
    return result
