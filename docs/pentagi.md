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
- `deliberation.py`: recommender / corrector / judge
- `capability.py`: decide whether to reuse, write helper, install, or replan
- `logistics.py`: perform support work outside challenge-step accounting
- `reflector.py`: policy reflection that constrains and patches planning
- `solver_shared.py`: runtime memory, validators, structured actions, execution reflection

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
