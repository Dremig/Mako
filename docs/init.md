# Init: Iteration Baseline

## Why this exists
This file captures the practical starting point after removing `sync/`.
It records the key ideas that matter for the current agent iteration.

## Most important takeaways from previous sync notes

1. State management is the real core, not RAG itself.
- RAG helps recall knowledge.
- Stability comes from explicit state: phase, facts, hypotheses, reflection constraints, and action history.

2. The architecture should stay split into interpreter + planner + deliberation + shared runtime.
- Interpreter provides priors and route ordering.
- Planner turns priors into explicit subtasks.
- Recommender/corrector/judge execute one subtask at a time.
- Capability management resolves what is missing before execution.
- Logistics is the support branch that performs environment setup, helper generation, and tool supplementation.
- Shared memory is the control surface across steps.

3. Reflection must be a mechanism, not just prompt text.
- Failures need structured reasons.
- Reflection outputs must be persisted.
- Reflection should modify plan state, not just nudge the next command.
- Next-step solver must consume the active subtask from the planner.

4. Hypothesis lifecycle is mandatory.
- Candidate / confirmed / rejected / stale should be explicit.
- Strategy drift happens when hypotheses are implicit.

5. Execution reliability is a first-class problem.
- Strategy can be correct while shell execution fails.
- Structured actions and validator/executor layers are needed for critical chains.
- Capability acquisition should be tracked separately from challenge progress.
- Installing dependencies is the highest-impact option and should lose to reuse/helper generation unless it clearly wins.
- Install targets should stay dynamic. We constrain install timing and accounting, not a hardcoded package list.

6. Information gain should gate actions.
- Avoid repeating commands with low new evidence.
- Force action-family changes after repeated low-gain or timeout loops.

7. Entry-point extraction must remain conservative.
- False parameters pollute memory and break downstream planning.
- Precision-first extraction is safer than wide noisy extraction.

## Current direction in this repo
- Keep `rag/` focused on retrieval utilities.
- Keep `web_agent/` focused on interpreter, planner, deliberation, capability management, validation, reflection, and runtime memory.
- Continue moving from free-form shell toward typed structured actions for high-value flows.

## Current architecture snapshot

```text
task_interpreter
  -> planner
  -> recommender / corrector / judge
  -> capability
  -> logistics
  -> executor
  -> fact extraction / hypothesis update / reflection
  -> plan patch
  -> planner
```

- `planner` owns the explicit subtask list.
- `reflector` changes plan state, not just next-command wording.
- `capability` decides what support is missing.
- `logistics` performs the support work without consuming challenge-step budget.

## Immediate guardrails
- Preserve reason/cluster canonical mapping.
- Keep controller validation rules modular and testable.
- Prefer module-based execution entrypoints (`python -m ...`) for import stability.

## Current structured-action baseline
- `http_probe_with_baseline`
- `extract_html_attack_surface`
- `cookiejar_flow_fetch`
- `service_recovery_probe`
- `multipart_upload_with_known_action`
- `build_jsp_war`
- `tomcat_manager_read_file`
