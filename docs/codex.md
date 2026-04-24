# Codex As Backend

## Purpose
This document answers one concrete question for this repo:

Can we keep the current CTF control architecture and move the model/runtime foundation to Codex-style OpenAI primitives?

Short answer: yes, but "use Codex as the backend" can mean three different things with very different rewrite costs.

## What official docs confirm

The current OpenAI direction is to build agentic workflows on the `Responses API`, not on legacy `chat/completions`.

Official references:
- Responses migration guide: <https://developers.openai.com/api/docs/guides/migrate-to-responses>
- Function calling: <https://developers.openai.com/api/docs/guides/function-calling>
- Structured outputs: <https://developers.openai.com/api/docs/guides/structured-outputs>
- Background mode: <https://developers.openai.com/api/docs/guides/background>
- Agents SDK running agents: <https://developers.openai.com/api/docs/guides/agents/running-agents>
- Agents SDK results/state: <https://developers.openai.com/api/docs/guides/agents/results>
- GPT-5.3-Codex model page: <https://developers.openai.com/api/docs/models/gpt-5.3-codex>

Key facts from those docs:
- `Responses API` is recommended for new projects and is the agentic primitive OpenAI wants developers to build on.
- Responses supports built-in tools, multi-turn continuation, better reasoning-model behavior, and stateful chaining.
- Function calling uses JSON Schema and supports strict mode.
- Structured outputs in Responses use `text.format` with JSON schema, not `response_format`.
- Background mode is the official mechanism for long-running tasks that may take minutes.
- Agents SDK runs an explicit loop: model call -> inspect output -> execute tools -> continue -> stop on final answer.
- Agents SDK exposes reusable state surfaces such as local history, sessions, response IDs, interruptions, and resumable state.
- Current Codex-class models support function calling and structured outputs. GPT-5.3-Codex also exposes `reasoning_effort`.

## Model choice note

Official model guidance and "Codex as backend" are not exactly the same decision.

OpenAI's current general model guidance says to start with `gpt-5.4` for complex reasoning and coding workloads.
Official references:
- Models overview: <https://developers.openai.com/api/docs/models>
- Model comparison: <https://developers.openai.com/api/docs/models/compare>

For this repo, the practical interpretation is:
- if you want the strongest general backend, benchmark `gpt-5.4` first
- if you want a coding-agent-optimized backend aligned with Codex-style environments, benchmark `gpt-5.3-codex` or the current Codex-class model line

So "move to Codex backend" should be understood as:
- adopt `Responses API` primitives first
- then choose between `gpt-5.4` and a Codex-class model empirically on your CTF benchmark

## What "Codex as backend" can mean

### Option A: Codex model only
Use a Codex-class model such as `gpt-5.3-codex` as the reasoning model, but keep your own runtime loop.

What stays:
- `task_interpreter`
- `planner`
- `recommender/corrector/judge`
- `MemoryStore`
- validators
- structured actions
- RAG

What changes:
- model endpoint wrapper
- structured output enforcement
- tool-call schema generation
- timeout/continuation handling

Rewrite cost: medium

This is the lowest-risk path and the one most compatible with the current repo.

### Option B: Responses API as the new runtime substrate
Keep your CTF policy layer, but move the model interaction layer from ad hoc chat completion calls to a Responses-native interface.

What stays:
- the repo still owns CTF-specific planning, memory, validators, and action execution

What changes:
- `rag/common.py` becomes a Responses client instead of a `chat/completions` wrapper
- JSON-only prompting is replaced by strict structured outputs where possible
- shell/structured actions are exposed as function tools
- long-running turns use `background=true` when appropriate
- continuation can use `previous_response_id` or your own local replay strategy

Rewrite cost: medium to high

This is the recommended target architecture.

### Option C: Agents SDK / Codex-native orchestration
Re-express interpreter, planner, solver, and possibly corrector as SDK agents with handoffs, sessions, interruptions, and tool routing.

What stays:
- high-level CTF ideas
- some tool implementations
- some schema and validation logic

What changes:
- the execution loop ownership moves from `cmd_agent.py` to the SDK runner
- state boundaries and continuation surfaces change
- planner/solver separation may need to be redesigned around agent runs and handoffs

Rewrite cost: high

This is not the right first migration. It is a second-phase architecture move after Option B is stable.

## Current repo assessment

Right now the repo is not "far from Codex". It is already Codex-shaped in several ways:
- `web_agent/cmd_agent.py` is already an explicit local agent loop.
- `web_agent/deliberation.py` already has a recommender/corrector/judge split.
- `web_agent/solver_shared.py` already has typed actions, validators, reflection, and runtime memory.
- Most model access is centralized through `rag/common.py:221`.

The main mismatch is not architecture shape. The mismatch is runtime primitive choice.

Current state:
- the repo uses `/chat/completions`
- JSON correctness is enforced mostly by prompt wording plus parse/retry
- tool calling is simulated in your own prompts and executors
- state continuity is stored locally in SQLite and replayed manually

Codex-native state:
- Responses-native typed items
- strict structured outputs
- first-class function tools
- optional background execution for long turns
- optional server-managed continuation

Conclusion:
- this is not a total rewrite if the goal is "Codex as backend"
- it is a total rewrite only if the goal is "let OpenAI Agents SDK own the whole loop"

## Recommended target architecture

The practical target is:

`your CTF control plane` + `Responses API / Codex-class model` + `your local executors`

In concrete terms:
- Keep `Interpreter + Planner + Shared Memory + Validator + Corrector + RAG`.
- Replace free-form model IO with Responses-native structured IO.
- Represent `structured actions` and selected shell operations as tools/functions.
- Keep execution, memory persistence, benchmark integration, and artifact handling local.

This keeps the CTF-specific moat in your codebase instead of delegating it to a generic SDK loop.

## Strategy vs tactics split

The right migration target for this repo is not "let Codex replace the planner".

The more accurate split is:
- planner/interpreter own `what to pursue`
- Codex owns `how to execute the current subtask`

That means:
- keep `task_interpreter.py` and `planner.py` as the route-selection layer
- keep memory, validator, preflight, execution, artifacts, and benchmark glue as the runtime guard layer
- replace the old multi-hop tactical chain (`recommender -> corrector -> judge`) with a single Codex tactical step that produces the next executable action for the active subtask

This matches the common human + Codex CTF workflow:
- human/strategy layer decides the route
- Codex/tactics layer decides the concrete command, helper, payload, or structured action

In repo terms, the desired contract is:

`planner decides route` -> `codex tactical solver decides next move` -> `runtime guard validates and executes`

The practical benefit is that tactical quality improves without giving up the repo's CTF-specific planning logic.

## Advisory relationship

The next refinement is important:

- planner/interpreter/reflector should not behave like command authorities
- Codex should be the primary solver
- semantic layers should behave like external discussants

That means the upper layers do not "order" the next move. They provide:
- route hypotheses
- confirmed evidence summaries
- open questions
- anti-drift notes
- suggested structured actions when strongly justified

Codex then decides whether to:
- agree
- adapt
- reject a weak local hint

The intended relationship is:

`semantic discussion layers -> Codex primary solver -> runtime guard`

not:

`planner command -> Codex execution`

In practical terms, planner output should be interpreted as advisory context, not as a hard local target selector.

## Codex Collaboration Mode (Implemented)

To support a closer "human + Codex collaborative solving" style, this repo now supports:

- `--solver-mode codex_collab`

Behavioral intent:

- Codex is the primary tactical decision-maker for each step.
- interpreter / reflector are bypassed as control layers in this mode.
- planner is treated as optional advisory context rather than hard command authority.
- validator hard-gates are relaxed in this mode to reduce framework-induced dead loops.
- a counter-solver / falsifier runs before the tactical step and attacks the current route.

The mode still keeps your local runtime moat:

- memory persistence
- tool execution
- artifact capture
- benchmark integration
- safety-oriented command validation

## Experimental Falsifier Loop (Implemented)

`codex_collab` now includes a lightweight adversarial reasoning layer before each tactical move.

Intent:

- do not replace Codex with framework-side exploit classification
- make Codex explicitly state what it believes
- force an adversarial alternative and a cheap discriminator test
- reduce long wrong-route streaks instead of pretending to prevent all reasoning mistakes

Current falsifier outputs:

- `main_hypothesis`
- `counter_hypothesis`
- `evidence_for`
- `critical_counterargument`
- `cheap_test`
- `expected_if_main`
- `expected_if_counter`
- `decision_rule`
- `should_challenge_current_route`

This is intentionally different from a normal `corrector`.

- `corrector` attacks command quality
- `falsifier` attacks the current explanation and proposes the cheapest distinguishing experiment

Practical effect:

- the tactical solver sees both the current route and the adversarial discriminator
- the tactical solver is instructed to prefer the cheap falsification test before deeper exploit chains when appropriate

This keeps Codex-first control while adding an internal self-critique loop.

## Dialogue Trace (Implemented)

For post-run auditing of "what was sent to Codex and what Codex returned", each run now writes:

- `artifacts/.../<run_id>/codex_dialogue.jsonl`

Each JSONL line contains:

- timestamp
- step
- kind (`tactical_prompt`, `tactical_response`, `preflight_soft_bypass`, ...)
- kind (`counter_prompt`, `counter_response`, `tactical_prompt`, `tactical_response`, `preflight_soft_bypass`, ...)
- solver mode
- payload (prompts and parsed tactical response)

## Stream-Only Responses Mode (Implemented)

Some OpenAI-compatible gateways only support `Responses API` with `stream=true`.

This repo now supports:

- `OPENAI_RESPONSES_FORCE_STREAM=true`

When enabled:

- Responses text calls go directly through the streaming path
- the runtime avoids an initial non-streaming request that would fail on stream-only gateways

This is useful for internal OpenAI-compatible endpoints that implement `/v1/responses` but reject non-streaming calls.

## Stateful Responses Continuation (Implemented)

To preserve Codex runtime context across steps, the agent now carries `previous_response_id` per role:

- planner
- counter solver
- tactical solver
- recommender
- corrector
- final run summarizer

Implementation notes:

- `rag/common.py` now supports `response_context` and updates it with the latest response id.
- stream and non-stream Responses paths both attempt to extract and persist response ids.
- `web_agent/cmd_agent.py` keeps per-role context dictionaries and logs updates into:
  - memory events `response_context.<role>`
  - `codex_dialogue.jsonl` as `kind=response_context`

Effect:

- the runtime no longer starts every tactical turn from a cold model context
- Codex can accumulate local working context over sequential steps while still using your planner/validator memory plane

Counter-session stabilization:

- `counter_solver` keeps a separate Responses session from `tactical_solver`.
- it now supports periodic reset with `OPENAI_COUNTER_SESSION_RESET_STEPS` (or `--counter-session-reset-steps`).
- default is `8`; set `0` to disable resets.
- each reset is logged as `response_context_reset` in `codex_dialogue.jsonl`.

## Recommended migration path

### Phase 1: Replace the model transport, not the architecture

Goal:
- make Codex-class models usable without rewriting `web_agent`

Changes:
- add a Responses client in [rag/common.py](/Users/Dremig/stduy/research/ctf-agent/mako/rag/common.py:1)
- keep `chat_completion(...)` as a compatibility wrapper at first
- add a new primitive such as:
  - `responses_text(...)`
  - `responses_json(...)`
  - `responses_tool_loop(...)`

Why:
- all major call sites currently route through `rag/common.py`
- this lets the repo adopt Codex-class models with the smallest blast radius

### Phase 2: Eliminate prompt-only JSON contracts

Target files:
- [web_agent/deliberation.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/deliberation.py:1)
- [web_agent/reflector.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/reflector.py:1)
- [web_agent/planner.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/planner.py:1)
- [web_agent/task_interpreter.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/task_interpreter.py:1)

Replace:
- "return exactly one valid JSON object" prompting

With:
- Responses `text.format = { type: "json_schema", ... , strict: true }`

Why:
- your current pipeline burns time on malformed JSON, re-prompts, and repair attempts
- strict schema is the clearest place where moving to Responses gives immediate value

### Phase 2.5: Collapse tactical deliberation into one Codex step

Goal:
- keep planner ownership of subtask selection
- remove tactical quality loss from multi-hop proposal correction

Changes:
- keep `planner.py` and `task_interpreter.py`
- add a single tactical interface in `web_agent/deliberation.py`
- make `cmd_agent.py` call that tactical interface directly for the current subtask
- keep the legacy `recommender/corrector/judge` path only as fallback

Why:
- the repo's weak point is not high-level route selection
- the weak point is that concrete next-step commands degrade when passed through several tactical sublayers
- Codex is strongest when it directly chooses the next concrete action under a planner-owned objective

### Phase 2.6: Convert planner output into discussion cards

Goal:
- stop treating planner subtasks as command authority
- make planner outputs explicitly useful to Codex rather than restrictive

Changes:
- planner subtasks carry:
  - `discussion`
  - `open_questions`
- tactical prompts treat interpreter/planner/reflector content as advisory discussion
- Codex returns not only the next step but also whether it agrees with the advisory context

Why:
- semantic layers are good at summarizing and hypothesizing
- they are not the true "solver"
- turning them into hard controllers suppresses Codex's local judgment and produces low-value moves

### Phase 3: Convert structured actions into function tools

Target file:
- [web_agent/solver_shared.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/solver_shared.py:1)

Map each action schema into a Responses function tool:
- `http_probe_with_baseline`
- `extract_html_attack_surface`
- `cookiejar_flow_fetch`
- `service_recovery_probe`
- `multipart_upload_with_known_action`
- `build_jsp_war`
- `tomcat_manager_read_file`

Execution model:
- model emits a tool call
- your local runtime executes the tool
- tool output is returned to the same response loop

Why:
- this removes a large amount of "model emits pseudo-command, runtime reparses it" friction
- it aligns your strongest existing abstraction with the primitive the platform already supports

### Phase 4: Keep shell as a privileged fallback tool

Do not expose unrestricted shell first.

Recommended split:
- normal path: typed tools only
- fallback path: `shell_command` tool guarded by validator + preflight + allow/deny policy

Reason:
- Codex-class models are good at tool use, but shell remains the highest-risk and highest-variance action surface
- your current validators are valuable and should remain in the loop

### Phase 5: Add long-turn execution mode

Use background Responses mode selectively for:
- planner refresh
- difficult exploit chain synthesis
- report generation
- high-latency retries that may exceed request time limits

Do not use background mode for:
- cheap, interactive micro-steps
- flows that need immediate local approval before tool execution

### Phase 6: Evaluate whether Agents SDK is still worth it

Only after Phase 1-5.

At that point, decide whether these should become SDK agents:
- interpreter
- planner
- solver
- reflector

My current recommendation:
- do not migrate to Agents SDK first
- first migrate to Responses-native structured IO and tool calls

## Concrete code impact

### Files that likely need direct refactor
- [rag/common.py](/Users/Dremig/stduy/research/ctf-agent/mako/rag/common.py:1)
- [web_agent/deliberation.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/deliberation.py:1)
- [web_agent/planner.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/planner.py:1)
- [web_agent/reflector.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/reflector.py:1)
- [web_agent/task_interpreter.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/task_interpreter.py:1)
- [web_agent/cmd_agent.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/cmd_agent.py:1)

### Files that can mostly stay
- [web_agent/capability.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/capability.py:1)
- [web_agent/logistics.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/logistics.py:1)
- most of [web_agent/solver_shared.py](/Users/Dremig/stduy/research/ctf-agent/mako/web_agent/solver_shared.py:1)

### What is reusable with minimal change
- `MemoryStore`
- failure taxonomy and reflection normalization
- structured action definitions
- execution preflight
- local artifact handling
- benchmark integration

## Recommended first implementation slice

If the goal is to start migration without destabilizing the repo, the first slice should be:

1. Add `responses_json(...)` to `rag/common.py`.
2. Migrate `deliberation.py` to strict schema output.
3. Migrate `reflector.py` and `planner.py` next.
4. Keep `cmd_agent.py` loop ownership local.
5. Delay Agents SDK adoption.

This gives the highest leverage with the smallest architectural risk.

## Non-goals for phase one

Do not do these first:
- rewrite the whole loop around Agents SDK sessions and handoffs
- expose unrestricted shell as the primary tool
- remove local SQLite memory
- remove your validator/preflight layer

Those are exactly the pieces that make this repo CTF-specific rather than a generic coding agent wrapper.

## Final recommendation

Yes, you can build on a Codex foundation.

But the right interpretation is:
- use `Responses API + Codex-class model` as the backend substrate
- keep your own CTF orchestration and execution control plane

So the real migration is not:
- "replace my system with Codex"

It is:
- "replace prompt-level chat completion plumbing with Codex-native Responses primitives"

That is still a significant refactor, but it is not a ground-up rewrite.
