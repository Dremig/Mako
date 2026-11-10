---
name: mako-ctf-runtime
description: Use when working inside this repository on the Mako CTF agent loop, especially for solver behavior, done semantics, reflection, planner/runtime coordination, and benchmark debugging.
---

# Mako CTF Runtime

Use this skill when editing or debugging the local CTF agent runtime in this repository.

## Runtime routing

- `scripts/run_web_agent.sh` defaults to `web_agent.pure_sdk_agent`.
- Pure mode is one unrestricted Claude Agent SDK loop with a shared resumable session. Mako does not own its plan, tool calls, phases, or completion decision.
- `scripts/followup.sh` sends inspect/resume/fork messages directly to recorded SDK sessions; it must not translate them into planner tasks.
- `web_agent/session_ledger.py` may store topology and runtime receipts, but must never become a facts/claims/intents authority.
- `web_agent/artifact_workspace.py` may preserve immutable bytes and provenance receipts, but must never infer claims, score routes, or inject artifact content into prompts automatically.
- Artifact retrieval is model-pull: Claude may use `artifact_capture`, `artifact_list`, and `artifact_peek` when useful.
- `MAKO_RUNTIME_MODE=governed` selects the older interpreter/planner/validator runtime in `web_agent.cmd_agent`.
- Apply the control rules below only to governed mode. For pure mode, debug SDK configuration, session continuity, Claude settings/MCP/tool discovery, and the target environment without reintroducing Mako policy gates.

## Governed-runtime rules

1. `done` means challenge completion, not subtask completion.
- Never treat "homepage fetched", "baseline stable", or "one subtask finished" as challenge solved.
- A `done` decision must be backed by flag-like evidence or an explicitly confirmed `goal:flag` state.
- Pending `probe` / `exploit` / `extract` / `verify` subtasks are a warning sign that `done` is probably wrong.

2. Prefer evidence-first runtime control.
- Keep planner/interpreter/reflector advisory unless the check is a hard runtime invariant.
- Hard invariants are things like:
  - no unsafe `done`
  - no clearly duplicate low-gain loops
  - no missing required action artifacts
  - no invalid command shape

3. Distinguish exact duplicates from semantic repeats.
- Exact duplicate: same normalized command string.
- Semantic repeat: same surface, same command family, low gain, different wording.
- The runtime should cut semantic repeats before they consume long budgets.

4. Artifact state must match planner intent.
- If a plan expects HTML parsing, ensure the HTML artifact really exists.
- If a helper script depends on a saved file, prefer repairing the artifact path or regenerating the artifact over replanning into the same broken action.

## Web CTF Frontend-Observation-First Protocol

Use this protocol for general web challenges without overfitting to one transport channel.

1. Observe frontend thoroughly before exploit assumptions.
- Collect and persist:
  - full HTML (not only snippets)
  - inline/external JS behavior relevant to requests and control flow
  - forms, hidden fields, and client-side validation/transforms
  - navigation/state transitions (redirect, cookies, local/session storage cues)
- Do not begin payload loops until this observation snapshot exists in artifacts/logs.

2. Build complete request semantics from observed behavior.
- From the observed frontend, extract request semantics as a set:
  - endpoint/path
  - method
  - parameter locations (query/body/path/cookie/header)
  - encoding/serialization rules
- Avoid pre-committing to a single carrier (header/body/query) before evidence.

3. Run smallest falsification checks before deep exploitation.
- For each candidate control point, run one minimal A/B experiment with one variable changed.
- Compare status, redirect chain, response markers, and state changes.
- If no measurable difference appears, switch evidence type rather than micro-mutating payloads.

4. Enforce low-gain branch shifts with evidence diversity.
- If the same surface loops with low gain, force one of:
  - frontend observation -> request replay
  - request replay -> state verification on protected resource
  - same endpoint retries -> alternate confirmed control point
- Do not allow repeated retries that only restyle the same hypothesis.

5. Required checkpoints before exploit escalation.
- `checkpoint.frontend_snapshot=true`:
  core frontend artifacts and logic are captured.
- `checkpoint.request_semantics=true`:
  controllable request structure is mapped from evidence.
- `checkpoint.control_diff=true`:
  at least one variable change yields a measurable server-side difference or is falsified.

6. Minimal progression order.
- baseline fetch
- full frontend observation
- request semantics extraction
- minimal controllability checks
- exploit payloads
- protected-resource verification

## Debugging checklist

When a run looks bad, classify it quickly:

1. Premature completion
- `done=true` with empty flag
- final report claims solved without exploit or extraction

2. Artifact drift
- repeated `preflight_block`
- missing file paths such as `root.body`, `root.html`, cookie jars, or helper outputs

3. Low-gain loop
- repeated `no_new_signal`, `redundant_recon`, or `repeated_low_gain_pattern`
- same phase and same surface over multiple steps

4. Adapter/platform fault
- missing target URL
- wrong scheme/port
- container startup failure

## Preferred fixes

1. Preserve the pure SDK boundary: do not add planner, validator, tool hooks, turn caps, or command interception to `pure_sdk_agent.py`.
2. For governed-mode failures, tighten hard runtime invariants before changing prompts.
3. Keep governed changes local and testable in:
- `web_agent/cmd_agent.py`
- `web_agent/solver_shared.py`
- `web_agent/deliberation.py`
- `web_agent/planner.py`

4. After behavior changes, run targeted regressions first.
- Compile touched Python files.
- Run focused tests for deliberation/policy/structured actions.
- Then rerun a small benchmark slice before a full batch.

## Repository-specific expectation

For this repo, the main failure modes are usually:
- solver/runtime semantics, not raw model availability
- poor convergence, not just insufficient time
- planner/runtime mismatch, not lack of prompts alone

Default stance:
- pure mode: trust the SDK loop and preserve shared context
- governed mode: fix control semantics first
- then rerun representative benchmark cases
