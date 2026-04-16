from __future__ import annotations

import json
from typing import Any, Callable

from rag.common import json_completion
from web_agent.solver_shared import available_action_names

STRICT_JSON_RULES = (
    "CRITICAL OUTPUT RULES:\n"
    "Return exactly one valid JSON object only.\n"
    "Do not output markdown, code fences, comments, or any text before/after JSON.\n"
    "Use double quotes for all keys/strings.\n"
    "If uncertain, keep schema fields with safe defaults instead of adding prose.\n"
)
ACTION_NAMES = set(available_action_names())
PROPOSAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "analysis": {"type": "string"},
        "planner_alignment": {"type": "string"},
        "discussion_response": {"type": "string"},
        "confidence": {"type": "number"},
        "decision": {"type": "string"},
        "phase": {"type": "string"},
        "command": {"type": "string"},
        "action": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string"},
                "args_json": {"type": "string"},
            },
            "required": ["name", "args_json"],
        },
        "success_signal": {"type": "string"},
        "next_if_fail": {"type": "string"},
    },
    "required": ["analysis", "planner_alignment", "discussion_response", "confidence", "decision", "phase", "command", "action", "success_signal", "next_if_fail"],
}
CORRECTOR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "verdict": {"type": "string"},
        "issues": {"type": "array", "items": {"type": "string"}},
        "corrected": PROPOSAL_SCHEMA,
    },
    "required": ["verdict", "issues", "corrected"],
}
COUNTER_SOLVER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "main_hypothesis": {"type": "string"},
        "counter_hypothesis": {"type": "string"},
        "evidence_for": {"type": "array", "items": {"type": "string"}},
        "critical_counterargument": {"type": "string"},
        "cheap_test": {"type": "string"},
        "expected_if_main": {"type": "string"},
        "expected_if_counter": {"type": "string"},
        "decision_rule": {"type": "string"},
        "should_challenge_current_route": {"type": "boolean"},
    },
    "required": [
        "main_hypothesis",
        "counter_hypothesis",
        "evidence_for",
        "critical_counterargument",
        "cheap_test",
        "expected_if_main",
        "expected_if_counter",
        "decision_rule",
        "should_challenge_current_route",
    ],
}


def _fallback_proposal() -> dict[str, Any]:
    return {
        "analysis": "Fallback proposal after repeated JSON parse failures.",
        "planner_alignment": "partial",
        "discussion_response": "Using a minimal fallback because tactical generation failed.",
        "confidence": 0.05,
        "decision": "command",
        "phase": "recon",
        "command": "curl -si $TARGET_URL/robots.txt",
        "action": {},
        "success_signal": "HTTP response with status and body collected",
        "next_if_fail": "curl -si $TARGET_URL/",
    }


def _normalize_proposal_payload(raw: dict[str, Any]) -> dict[str, Any]:
    out = dict(raw)
    action = out.get("action", {})
    if not isinstance(action, dict):
        action = {}
    name = str(action.get("name", "")).strip()
    args: dict[str, Any] = {}
    args_json = str(action.get("args_json", "")).strip()
    if args_json:
        try:
            parsed_args = json.loads(args_json)
            if isinstance(parsed_args, dict):
                args = parsed_args
        except Exception:
            args = {}
    out["action"] = {"name": name, "args": args}
    return out


def _run_json_model(
    *,
    base_url: str,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    json_schema_name: str,
    json_schema: dict[str, Any],
    temperature: float,
) -> dict[str, Any]:
    for attempt in range(1, 4):
        try:
            return json_completion(
                base_url=base_url,
                api_key=api_key,
                model=model,
                system_prompt=system_prompt + "\n" + STRICT_JSON_RULES,
                user_prompt=user_prompt,
                json_schema_name=json_schema_name,
                json_schema=json_schema,
                temperature=temperature,
            )
        except Exception:
            if attempt >= 3:
                return {}
    return {}


def run_recommender(
    *,
    base_url: str,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> dict[str, Any]:
    parsed = _run_json_model(
        base_url=base_url,
        api_key=api_key,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        json_schema_name="deliberation_payload",
        json_schema=PROPOSAL_SCHEMA,
        temperature=0.2,
    )
    if not parsed:
        return _fallback_proposal()
    return _normalize_proposal_payload(parsed)


def run_corrector(
    *,
    base_url: str,
    api_key: str,
    model: str,
    target: str,
    step: int,
    active_title: str,
    active_goal: str,
    active_signal: str,
    active_action: str,
    controller_reflection: dict[str, Any],
    recommender: dict[str, Any],
    available_actions_text: str,
    memory_summary: str,
    recent_history: str,
) -> dict[str, Any]:
    system_prompt = (
        "You are a sabotager-style corrector for a CTF execution agent.\n"
        "Your job is to aggressively find flaws in the recommender proposal, then produce the smallest corrected executable proposal.\n"
        "Do not brainstorm a completely new strategy unless the proposal is clearly misaligned.\n"
        "You may return a corrected command or a corrected structured action.\n"
        "Prefer the planner-suggested structured action when it fits the current subtask.\n"
        "Mark proposals that depend on optional libraries or unverified assumptions as fragile.\n"
        "Return ONLY JSON with schema:\n"
        "{"
        "\"verdict\":\"accept|fragile|misaligned|replace\","
        "\"issues\":[\"short issue\"],"
        "\"corrected\":{"
        "\"analysis\":\"...\","
        "\"confidence\":0.0,"
        "\"decision\":\"command|action|done\","
        "\"phase\":\"recon|probe|exploit|extract|verify|done\","
        "\"command\":\"...\","
        "\"action\":{\"name\":\"\",\"args\":{}},"
        "\"success_signal\":\"...\","
        "\"next_if_fail\":\"...\""
        "}"
        "}"
    )
    user_prompt = (
        f"Step: {step}\n"
        f"Target: {target}\n"
        f"Current subtask: {active_title}\n"
        f"Current goal: {active_goal}\n"
        f"Current success signal: {active_signal}\n"
        f"Current suggested action: {active_action or 'none'}\n"
        f"Controller reflection: {controller_reflection}\n"
        f"Available actions:\n{available_actions_text}\n\n"
        f"Memory summary:\n{memory_summary}\n\n"
        f"Recent history:\n{recent_history}\n\n"
        f"Recommender proposal:\n{recommender}\n"
    )
    parsed = _run_json_model(
        base_url=base_url,
        api_key=api_key,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        json_schema_name="corrector_payload",
        json_schema=CORRECTOR_SCHEMA,
        temperature=0.1,
    )
    verdict = str(parsed.get("verdict", "accept")).strip().lower() or "accept"
    corrected = parsed.get("corrected", recommender)
    if not isinstance(corrected, dict):
        corrected = recommender
    else:
        corrected = _normalize_proposal_payload(corrected)
    issues = parsed.get("issues", [])
    if not isinstance(issues, list):
        issues = []
    return {
        "verdict": verdict,
        "issues": [str(item).strip()[:220] for item in issues if str(item).strip()][:6],
        "corrected": corrected,
    }


def choose_final_proposal(
    *,
    recommender: dict[str, Any],
    corrector: dict[str, Any],
    active_action: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    verdict = str(corrector.get("verdict", "accept")).strip().lower()
    corrected = corrector.get("corrected", recommender)
    if not isinstance(corrected, dict):
        corrected = recommender

    chosen = recommender
    judge = {
        "decision": "accept_recommender",
        "reason": "corrector found no blocking issue",
    }
    if verdict in {"fragile", "misaligned", "replace"}:
        chosen = corrected
        judge = {
            "decision": "accept_corrected",
            "reason": f"corrector verdict={verdict}",
        }
    if active_action and active_action in ACTION_NAMES:
        chosen, judge = force_planner_action_hint(chosen=chosen, active_action=active_action, base_judge=judge)
    return chosen, judge


def force_planner_action_hint(
    *,
    chosen: dict[str, Any],
    active_action: str,
    base_judge: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    judge = dict(base_judge or {"decision": "accept", "reason": "no override"})
    if not active_action or active_action not in ACTION_NAMES:
        return chosen, judge
    payload = chosen.get("action", {})
    action_name = ""
    if isinstance(payload, dict):
        action_name = str(payload.get("name", "")).strip()
    if not action_name and str(chosen.get("decision", "command")).strip().lower() != "done":
        forced = dict(chosen)
        forced["decision"] = "action"
        forced["action"] = {"name": active_action, "args": {}}
        return forced, {
            "decision": "force_planner_action",
            "reason": f"planner suggested structured action {active_action}",
        }
    return chosen, judge


def run_counter_solver(
    *,
    base_url: str,
    api_key: str,
    model: str,
    target: str,
    objective: str,
    step: int,
    expected_phase: str,
    current_plan_text: str,
    memory_summary: str,
    hypotheses_text: str,
    recent_history: str,
    recent_obs: str,
    retrieved_context: str,
    trace_hook: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    system_prompt = (
        "You are a counter-solver for a CTF web agent.\n"
        "Your job is not to solve the task directly. Your job is to attack the current interpretation and design the cheapest falsification test.\n"
        "Find the weakest assumption in the current route, explain the strongest counterargument, and propose one cheap test that separates the main route from a plausible alternative.\n"
        "Do not overfit to one exploit class unless the evidence really forces it.\n"
        "If the current route is still reasonable, say so, but still produce a cheap discriminator test.\n"
        "Return ONLY JSON schema:\n"
        "{"
        "\"main_hypothesis\":\"short statement of what the solver seems to believe\","
        "\"counter_hypothesis\":\"best alternative explanation to test against\","
        "\"evidence_for\":[\"short evidence item\"],"
        "\"critical_counterargument\":\"best reason the current route may be wrong\","
        "\"cheap_test\":\"one cheapest command/action idea to distinguish current route from alternatives\","
        "\"expected_if_main\":\"what result should appear if the main hypothesis is right\","
        "\"expected_if_counter\":\"what result should appear if the counter hypothesis is right\","
        "\"decision_rule\":\"how to update belief from the observed result\","
        "\"should_challenge_current_route\":true"
        "}"
    )
    user_prompt = (
        f"Target: {target}\n"
        f"Objective: {objective}\n"
        f"Step: {step}\n"
        f"Expected phase: {expected_phase}\n"
        f"Current plan:\n{current_plan_text}\n\n"
        f"Persistent memory facts:\n{memory_summary}\n\n"
        f"Hypotheses:\n{hypotheses_text}\n\n"
        f"Recent history:\n{recent_history}\n\n"
        f"Recent observations:\n{recent_obs}\n\n"
        f"Retrieved context:\n{retrieved_context}\n"
    )
    if trace_hook is not None:
        trace_hook({"kind": "counter_prompt", "system_prompt": system_prompt, "user_prompt": user_prompt})
    parsed = _run_json_model(
        base_url=base_url,
        api_key=api_key,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        json_schema_name="counter_solver_payload",
        json_schema=COUNTER_SOLVER_SCHEMA,
        temperature=0.1,
    )
    out = parsed if isinstance(parsed, dict) else {}
    if trace_hook is not None:
        trace_hook({"kind": "counter_response", "parsed": out})
    return {
        "main_hypothesis": str(out.get("main_hypothesis", "")).strip(),
        "counter_hypothesis": str(out.get("counter_hypothesis", "")).strip(),
        "evidence_for": [str(x).strip() for x in out.get("evidence_for", []) if str(x).strip()][:6] if isinstance(out.get("evidence_for", []), list) else [],
        "critical_counterargument": str(out.get("critical_counterargument", "")).strip(),
        "cheap_test": str(out.get("cheap_test", "")).strip(),
        "expected_if_main": str(out.get("expected_if_main", "")).strip(),
        "expected_if_counter": str(out.get("expected_if_counter", "")).strip(),
        "decision_rule": str(out.get("decision_rule", "")).strip(),
        "should_challenge_current_route": bool(out.get("should_challenge_current_route", False)),
    }


def run_tactical_solver(
    *,
    base_url: str,
    api_key: str,
    model: str,
    target: str,
    objective: str,
    step: int,
    max_steps: int,
    expected_phase: str,
    active_title: str,
    active_goal: str,
    active_signal: str,
    active_action: str,
    current_plan_text: str,
    planner_discussion: str,
    planner_open_questions: list[str],
    available_tools_text: str,
    interpreter_notes_text: str,
    planner_context_text: str,
    reflector_notes_text: str,
    memory_summary: str,
    hypotheses_text: str,
    actions_text: str,
    recent_history: str,
    recent_obs: str,
    retrieved_context: str,
    counter_solver_notes: dict[str, Any] | None = None,
    collab_mode: bool = False,
    trace_hook: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if collab_mode:
        system_prompt = (
            "You are the primary tactical operator for a CTF web agent.\n"
            "You own route selection, branching, and retries.\n"
            "Planner/interpreter/reflector notes are optional discussion context, not control constraints.\n"
            "Choose the strongest next executable step based on runtime evidence.\n"
            "Prefer concrete progress over policy compliance text.\n"
            "Use structured actions when they clearly reduce friction; otherwise issue direct shell commands.\n"
            "If runtime evidence exposes SQL queries, auth source code, SELECT/WHERE clauses, or username/password database logic, prioritize SQL injection over NoSQL-style payloads.\n"
            "If input filters strip whitespace or the literal string admin, adapt SQLi payloads to those exact filters rather than switching exploit class.\n"
            "Do not use inline Python heredocs or large embedded scripts inside bash -lc; prefer short curl/bash commands or existing helper scripts.\n"
            "Avoid low-value repeated exploration and static-only targets unless they contain direct clues.\n"
            "Return one concrete next step only.\n"
            "Return ONLY JSON schema:\n"
            "{"
            "\"analysis\":\"1-2 short sentences\","
            "\"planner_alignment\":\"agree|adapt|disagree\","
            "\"discussion_response\":\"short note about what planner/interpreter advice you accept or reject\","
            "\"confidence\":0.0,"
            "\"decision\":\"command|action|done\","
            "\"phase\":\"recon|probe|exploit|extract|verify|done\","
            "\"command\":\"shell command string, may use $TARGET_URL\","
            "\"action\":{\"name\":\"optional structured action name\",\"args\":{\"key\":\"value\"}},"
            "\"success_signal\":\"what confirms progress\","
            "\"next_if_fail\":\"fallback command idea\""
            "}"
        )
    else:
        system_prompt = (
            "You are the tactical execution brain for a CTF web agent.\n"
            "Interpreter, planner, and reflector are advisory discussion layers, not command authorities.\n"
            "Their job is to summarize hypotheses, context, and concerns so that you can solve the current subtask better.\n"
            "Your job is to choose the strongest next executable step for the CURRENT subtask.\n"
            "Think like a skilled human operator collaborating with external notes: read the notes, decide what matters, and act.\n"
            "Prefer one concrete action that materially advances the current subtask over broad speculation.\n"
            "Treat planner/interpreter content as discussion context. You may agree, adapt, or reject local hints when the evidence says they are weak.\n"
            "Minimize route invention, but do not obey stale local hints that conflict with stronger confirmed evidence.\n"
            "If a suggested structured action directly fits the current evidence, prefer it.\n"
            "When a direct helper or structured action exists, prefer it over fragile ad-hoc shell or optional dependencies.\n"
            "When a page exposes a POST form with named fields, probe it with benign/default values before speculative exploit payloads.\n"
            "When baseline HTTP artifacts exist, prefer deterministic extraction of routes/forms/comments before guessing endpoints.\n"
            "Deprioritize static assets such as CSS/JS/images as primary attack targets unless they contain explicit challenge clues.\n"
            "Return one concrete next step only.\n"
            "Return ONLY JSON schema:\n"
            "{"
            "\"analysis\":\"1-2 short sentences\","
            "\"planner_alignment\":\"agree|adapt|disagree\","
            "\"discussion_response\":\"short note about what planner/interpreter advice you accept or reject\","
            "\"confidence\":0.0,"
            "\"decision\":\"command|action|done\","
            "\"phase\":\"recon|probe|exploit|extract|verify|done\","
            "\"command\":\"shell command string, may use $TARGET_URL\","
            "\"action\":{\"name\":\"optional structured action name\",\"args\":{\"key\":\"value\"}},"
            "\"success_signal\":\"what confirms progress\","
            "\"next_if_fail\":\"fallback command idea\""
            "}"
        )
    user_prompt = (
        f"Target: {target}\n"
        f"Objective: {objective}\n"
        f"Step: {step}/{max_steps}\n"
        f"Expected phase: {expected_phase}\n"
        f"Current subtask title: {active_title}\n"
        f"Current subtask goal: {active_goal}\n"
        f"Current subtask success signal: {active_signal}\n"
        f"Current subtask suggested action: {active_action or 'none'}\n"
        f"Current plan:\n{current_plan_text}\n\n"
        f"Planner discussion note:\n{planner_discussion or 'none'}\n\n"
        f"Planner open questions:\n" + ("\n".join(f"- {item}" for item in planner_open_questions) if planner_open_questions else "- none") + "\n\n"
        f"Available tools: {available_tools_text}\n"
        f"Interpreter notes:\n{interpreter_notes_text}\n\n"
        f"Planner context:\n{planner_context_text}\n\n"
        f"Reflector discussion:\n{reflector_notes_text}\n\n"
        f"Persistent memory facts:\n{memory_summary}\n\n"
        f"Hypotheses:\n{hypotheses_text}\n\n"
        f"Structured actions:\n{actions_text}\n\n"
        f"Recent history:\n{recent_history}\n\n"
        f"Recent observations:\n{recent_obs}\n\n"
        f"Counter-solver notes:\n{json.dumps(counter_solver_notes or {}, ensure_ascii=False)}\n\n"
        "If counter-solver notes include a cheap falsification test, prefer executing that discriminator before deeper exploitation unless runtime evidence already falsified it.\n\n"
        f"Retrieved context:\n{retrieved_context}\n"
    )
    if trace_hook is not None:
        trace_hook(
            {
                "kind": "tactical_prompt",
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "collab_mode": collab_mode,
            }
        )
    parsed = _run_json_model(
        base_url=base_url,
        api_key=api_key,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        json_schema_name="tactical_payload",
        json_schema=PROPOSAL_SCHEMA,
        temperature=0.15,
    )
    chosen = _normalize_proposal_payload(parsed) if parsed else _fallback_proposal()
    if trace_hook is not None:
        trace_hook(
            {
                "kind": "tactical_response",
                "parsed": parsed if isinstance(parsed, dict) else {},
                "chosen": chosen,
                "collab_mode": collab_mode,
            }
        )
    return chosen, {"decision": "accept_tactical", "reason": "single-pass codex tactical solver"}
