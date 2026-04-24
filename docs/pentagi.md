# Pentagi Notes

## Purpose
This file is reserved for PentAGI-driven design input and integration notes.

## What to track here
- Flow-level orchestration ideas we want to absorb.
- Provider/tool-call reliability patterns.
- Structured execution contracts (action schemas, validators, executors).
- Runtime observability and state models useful for `web_agent/`.
- Any migration decisions from experimental code to stable modules.

## Initial integration goals
1. Align failure semantics between reasoning and execution layers.
2. Expand structured actions for brittle exploit chains.
3. Keep deterministic parsing for deterministic artifacts (tokens, forms, upload actions).
4. Define promotion rules from free-form probing to programmatic flow execution.

## Implemented in this iteration

### Runtime architecture now in repo
- `task_interpreter.py`: priors and opener bias
- `planner.py`: explicit subtasks and plan patch application
- `deliberation.py`: tactical action selection (`codex tactical solver` by default, legacy recommender/corrector/judge retained as fallback)
- `capability.py`: decide whether to reuse, write helper, install, or replan
- `logistics.py`: perform support work outside challenge-step accounting
- `reflector.py`: policy reflection that constrains and patches planning
- `solver_shared.py`: runtime memory, validators, structured actions, execution reflection

### Current responsibility split
- `interpreter + planner`: produce route hypotheses, summaries, and discussion context for the current subtask
- `codex tactical solver`: is the primary local solver and owns the concrete method for the current subtask (`command` / structured `action` / helper-first move)
- `runtime guard`: owns preflight, validator, execution, artifact persistence, and final validation

This is intentionally closer to the common human + Codex CTF workflow:
- semantic reasoning stays outside the command loop as advisory context
- the concrete next move is delegated to Codex

### Advisory-not-command rule
- planner/interpreter/reflector should discuss, not command
- their outputs are useful because they summarize and hypothesize
- they should not suppress Codex's local judgment with overly hard subtask constraints

Operationally, this means:
- planner suggestions are treated as `discussion cards`
- Codex may agree, adapt, or reject local hints
- runtime validation in Codex mode should keep only hard safety/budget bottoms, not semantic over-control

### Structured actions expanded
- `http_probe_with_baseline`
- `extract_html_attack_surface`
- `cookiejar_flow_fetch`
- `service_recovery_probe`
- `multipart_upload_with_known_action`

### New helper scripts
- `scripts/http_probe_with_baseline.py`
- `scripts/extract_html_attack_surface.py`
- `scripts/cookiejar_flow_fetch.py`
- `scripts/service_recovery_probe.py`
- `scripts/multipart_upload_with_known_action.py`

### Integration status
- Added to `web_agent/solver_shared.py` action schemas.
- Added defaults derived from runtime memory (`target`, `artifact.dir`, `tomcat.upload_action`, `tomcat.creds`, `artifact.war_path`).
- Kept free-form shell as fallback, but high-value execution paths now have deterministic action wrappers.
- Structured-action JSON outputs are now parsed back into runtime memory facts, so action results can drive follow-up planning instead of remaining opaque stdout.
- Added a capability-resolution layer (`web_agent/capability.py`) before execution. It scores `reuse_existing_action`, `write_helper_script`, `install_dependency`, and `replan`.
- Added a separate logistics layer (`web_agent/logistics.py`) that receives support tasks from capability resolution and performs environment setup/tool supplementation without consuming challenge steps.
- Logistics install strategy is model-driven with hard fallback (`pip`, `system_package_manager`, or `skip_install`) and dynamic install targets.

## NYU Bench findings

### Cases exercised
1. `homeworkme` (`removed/2022/CSAW-Finals/web/homeworkme`)
2. `dinoauth` (`removed/2023/CSAW-Finals/web/dinoauth`)
3. `United` (`removed/2021/CSAW-Finals/web/United`)

### Observed outcomes
- `homeworkme`: agent completed 4 steps and produced a report, but stopped at generic path probing. It fetched `/`, then enumerated guessed endpoints such as `/login`, `/graphql`, `/admin`, and `/api`, all of which returned `404`.
- `dinoauth`: agent completed 4 steps and produced a report, but only established that the exposed port accepted TCP and returned empty HTTP responses on `/`. It did not transition into service-readiness checks, alternate route discovery, or container-log inspection.
- `United`: image build failed before agent execution. `npm install` could not build `sqlite3@5.0.2` on `node:14-alpine` for `linux/arm64` because no prebuilt binary was available and the Dockerfile did not install `make` or a compiler toolchain.

### Current gaps vs PentAGI-style execution
- We still over-index on generic endpoint guessing after landing-page fetches. The runtime needs a deterministic parser step for inline JavaScript, DOM-derived routes, and file/resource extraction.
- We do not yet have a recovery branch for "service reachable but not speaking expected HTTP". PentAGI-style flows would escalate into readiness checks, alternate ports, container logs, or protocol validation instead of repeating curl.
- Challenge bring-up is not normalized. We need a benchmark harness that can detect build/runtime incompatibilities and classify them as environment failures instead of mixing them with agent failures.
- The old loop was interpreter -> solver -> reflector. We now need planner-owned subtasks, with reflector producing plan patches instead of only command-level constraints.

### Concrete next moves
1. Promote `extract_html_attack_surface` into the default follow-up after successful landing-page fetches so endpoint discovery stops relying on guessed routes.
2. Promote `service_recovery_probe` into the recovery branch for empty reply / handshake / protocol mismatch failures.
3. Add benchmark-case classification to the harness:
   - `build_failure`
   - `service_not_ready`
   - `agent_exhausted_steps`
   - `flag_found`
4. Keep capability acquisition conservative: prefer action reuse, then stdlib helper generation, and only then environment-changing installs.

## NYU Web smoke rerun (2026-04-11)

### Run setup
- Harness: `AAAgentBench` branch `wjm/mako`
- Platform: `nyu` (test split)
- Solver: `mako`
- Timeout per case: `900s`
- Mako config: `--mako-max-steps 40 --mako-cmd-timeout 120`

### Cases and outcomes
1. `2021q-web-poem_collection`: `solved` in `695.69s`
2. `2021q-web-no_pass_needed`: `timeout` at `900s`

Result records:
- `artifacts/aaagentbench/nyu/mako/2021q-web-poem_collection.json`
- `artifacts/aaagentbench/nyu/mako/2021q-web-no_pass_needed.json`

### Intended-exploit check for `poem_collection`
- This solve is consistent with the intended path (LFI / path traversal).
- Challenge-local evidence:
  - `README.md` declares it as LFI.
  - `src/poems/index.php` reads `$_GET["poem"]` via `file_get_contents(...)` without path sanitization.
  - `solve.sh` uses `?poem=../flag.txt` directly.

### What this rerun proves (and does not prove)
- Proves:
  - End-to-end pipeline is stable for at least one intended NYU Web case (`prepare -> solve -> validate -> cleanup`).
  - Recent reliability work did not regress the successful path for simple LFI exploitation.
- Does not prove:
  - Single-case success cannot isolate which reliability feature contributed most (`HTTP retries`, `planner/deliberation fallback`, `preflight quality gate`).
  - We still need multi-case A/B metrics to claim broad reliability gains.

### Next validation pass
1. Keep the same two targets and run with/without preflight gate for A/B comparison.
2. Track per-run counters: `error rate`, `timeout rate`, `invalid command block count`, `autofix count`, `steps to first actionable exploit`.
3. Add one more low-complexity Web case (`2021q-web-gatekeeping`) to reduce single-target bias.

## Convergence diagnosis: taxonomy-to-control gap

We already have rich error taxonomy in memory, but slow convergence shows the taxonomy is not yet acting as a hard control loop.

### Why convergence is still slow even with good classification coverage
1. Late trigger:
   - Many labels are produced after expensive execution (`validator + retries + command timeout`) instead of before costly steps.
2. Weak action mapping:
   - Error labels are descriptive, but not always mapped to deterministic next actions.
   - Example target behavior should be explicit: `service_unready -> readiness macro`, `validation_block -> command rewrite macro`.
3. Soft constraints only:
   - Labels are written to memory but often treated as hints; planner/solver can still pick near-identical low-yield actions.
4. No budget coupling:
   - Error types are not consistently tied to retry caps, per-step timeout, or forced phase transition thresholds.

### Design target: state-transition contract
Use error taxonomy as a strict transition table, not only reflection metadata.

`(error_type, phase) -> {next_phase, allowed_actions, must_do, must_avoid, timeout_sec, retry_cap}`

This contract should be enforced before next action selection so repeated low-gain loops are cut off early.

### Minimum implementation checklist
1. Add a transition registry in solver shared policy:
   - canonical key: `(failure_cluster, current_phase)`.
2. On each failed/low-gain step, resolve transition first, then gate planner/deliberation choices.
3. Enforce hard `retry_cap` per `(cluster, subtask)` pair.
4. Enforce dynamic timeout policy:
   - infra/transient failures use shorter command timeout + quick retry.
   - strategy failures force branch shift instead of same-action retry.
5. Add low-gain circuit breaker:
   - `N` consecutive `info_gain == 0` triggers mandatory branch switch/replan.

### Metrics to validate that taxonomy is actually controlling behavior
1. `classification_coverage`:
   - fraction of failed steps mapped to a transition rule.
2. `repeat_after_classification`:
   - rate of same-action-family retries after a strategy-class failure.
3. `time_to_branch_shift`:
   - median wall-clock time from classified failure to next distinct strategy family.
4. `timeout_without_transition`:
   - number of run-level timeouts where no transition rule fired in the final `K` steps.
