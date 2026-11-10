# Claude Agent SDK Runtime

Mako has two Claude Agent SDK paths. The default is a pure SDK agent; the older governed runtime remains available for comparison.

## Default pure runtime

`web_agent/pure_sdk_agent.py` starts one native Claude Code agent loop and does not place Mako between Claude and its tools. Its SDK options intentionally specify only:

- the Claude Code default tool preset;
- the Claude Code default system prompt;
- `bypassPermissions`;
- the project root as the working directory;
- the optional model override and a client identifier;
- a prior shared session ID when one exists.

Mako does not supply allow/deny lists, hooks, MCP configuration, filesystem setting sources, plugins, a sandbox, an agent-turn limit, planner output, phase state, command validation, or its own executor. Because filesystem setting sources are left at SDK defaults, Claude can discover user/project/local settings, Skills, plugins, MCP servers, and an existing CLI login.

“Pure” means no Mako policy layer. Claude Code and an organization or endpoint may still apply their own managed rules, critical-path behavior, or permission semantics even under `bypassPermissions`.

## Shared context

Pure runs share `logs/claude_sdk_shared_context.json`. The file contains only a version, non-secret SDK signature, session ID, timestamp, and last run ID. A process/thread lease is held for the complete query so two Mako processes cannot resume and mutate the same session concurrently.

When endpoint, model, config directory, and project root match, the next invocation passes the saved ID through the SDK's `resume` option. The SDK transcript therefore carries prior prompts, tool calls, tool results, responses, and compaction state across runs. `--new-session` atomically clears the previous association before starting a fresh session.

Sessions preserve conversation history, not filesystem snapshots. Files created by the agent remain ordinary workspace files.

## Session Tree Ledger

`logs/mako_session_ledger.sqlite` indexes run and session lineage without duplicating the SDK transcript. It contains only:

- run identity, parent run, target/objective, workspace, status, primary session, and end-of-run message checkpoint;
- session identity, parent session, origin run, SDK signature, fork reason, and transcript reference;
- immutable SDK call receipts with usage, cost, turn count, terminal reason, and error class;
- operator intervention receipts with lifecycle status, message hash, and a bounded preview.

There are deliberately no fact, claim, intent, lane, route, hypothesis, or scheduler tables. The SDK transcript remains the conversation authority; the ledger only answers continuity and audit questions.

## Native follow-up lane

`scripts/followup.sh` sends an operator message directly to a recorded SDK session. If `--run-id` is omitted, it uses the latest run.

```bash
./scripts/followup.sh --mode inspect --message "Explain the evidence collected so far"
./scripts/followup.sh --mode resume --message "Continue until the objective is complete"
./scripts/followup.sh --run-id <run> --mode fork --message "Try the alternate route"
```

`inspect` and `resume` both append to the same native session; their distinction is an operator receipt. `fork` passes both the source session and that run's recorded assistant-message checkpoint to the SDK, producing a new child session. This prevents a later continuation from silently moving the historical fork point.

The shared-session lease covers the complete follow-up call. A successful follow-up becomes the active shared pointer; each attempt, including failures, closes its child run, call receipt, and intervention receipt.

## Artifact Workspace

`artifacts/mako/_evidence` is a content-addressed store, not a facts database. Object bytes are keyed by SHA-256 and installed atomically; duplicate content reuses the object while retaining distinct append-only receipts. Each receipt identifies the producing run, session, SDK call, tool, source kind, source reference, timestamp, and optional non-cognitive metadata.

Pure and follow-up message streams capture SDK `ToolResultBlock` content without persisting the corresponding tool input. Files written under a run's artifact directory are captured after the SDK call. Symlinks and non-regular files are ignored or rejected, and stored objects are size/hash checked on every read. The workspace schema contains only `objects` and `receipts`.

The programmatic `mako_artifacts` SDK MCP server adds `artifact_capture`, `artifact_list`, and `artifact_peek`. It is merged with Claude's normal MCP/tool environment without strict MCP mode, hooks, or allow/deny rules. `artifact_peek` returns a bounded text window or literal match; binary objects return metadata only. Errors expose only their type.

Artifact MCP results are excluded from passive recapture to prevent recursive evidence objects. Run summaries retain exact receipt IDs so provenance is not lost when several receipts point to the same content hash. The model chooses whether to call these tools; Mako does not automatically inject artifacts or infer claims from them.

## Governed runtime

`web_agent/cmd_agent.py` is retained behind `MAKO_RUNTIME_MODE=governed`. It uses the tool-free adapter in `web_agent/claude_runtime.py`, per-role sessions, local schema validation, planner/reflection state, Mako command validation, and the local executor. It receives no framework-selected external knowledge context. The autonomy and JSON-compatibility controls in `.env.example` apply to this path, not to pure mode.

## Configuration

Install the pinned SDK before running either path:

```bash
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt
```

Pure mode can use an existing Claude CLI login. `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`, `ANTHROPIC_MODEL`, and `CLAUDE_CONFIG_DIR` are inherited when present. Governed mode requires an explicit credential and model. The authoritative governed and retrieval options are in `.env.example`.

## Run records

Pure summaries contain final text, event type names, tool names, artifact receipt IDs, session ID, checkpoint ID, usage, cost, turn count, and terminal status. They deliberately omit tool inputs and SDK stderr, and environment credential values are redacted before persistence. The full conversation and tool context remain in the SDK session transcript.

## Verification boundary

Unit tests use deterministic SDK message streams to verify exact pure options, absence of Mako controls, complete stream consumption, shared-session locking/resume/reset, session topology, receipt immutability, checkpointed forks, content deduplication, tamper detection, bounded peeks, MCP handlers, redaction, and failure exit codes. A local Anthropic-format smoke test has exercised the artifact-enabled pure runtime and a historical-checkpoint fork through the installed SDK. It does not prove compatibility with a particular live gateway or model.

References: [Python SDK reference](https://code.claude.com/docs/en/agent-sdk/python), [sessions](https://code.claude.com/docs/en/agent-sdk/sessions), and [permissions](https://code.claude.com/docs/en/agent-sdk/permissions).
