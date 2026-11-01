// Package vtcode implements the adapter for VT Code (`vtcode`,
// github.com/vinhnx/VTCode), a Rust terminal coding agent. See
// [models.ToolVTCode] and docs/vtcode-adapter.md (the Phase 0 research
// record). Grounded 2026-10-21 against vtcode-core 0.180.2 sessions run by
// the operator on WSL Ubuntu and on Windows 11.
//
// # Storage shape
//
// VT Code keeps two stores per session:
//
//   - The per-WORKSPACE "unified session store" — the single source of
//     truth (`vtcode session-store --help`):
//
//     <workspace>/.vtcode/sessions/<session-id>/events.jsonl   (append-only)
//     <workspace>/.vtcode/sessions/<session-id>/manifest.json  (created_at, counts)
//     <workspace>/.vtcode/sessions/<session-id>/index/turns.json
//     <workspace>/.vtcode/logs/trajectory.jsonl (+ rotated trajectory-<ts>.jsonl)
//
//   - The per-USER global archive, one JSON per session, rewritten at
//     session end:
//
//     Linux:   ~/.local/state/vtcode/sessions/<session-id>.json  (XDG state)
//     Windows: %APPDATA%\vinhnx\vtcode\state\sessions\<session-id>.json
//     macOS:   not grounded (no host) — no root is emitted.
//
// The session id (`session-<workspace label>-<UTC ts>_<n>-<pid>` for the
// TUI and `vtcode exec`; `auto-task-<unix seconds>` for the autonomous
// `--auto` / `--full-auto` run, which writes no archive) is the session
// directory name, events.jsonl's thread.started thread_id, the archive
// file stem, and what `vtcode --resume <id>` accepts. Its trailing number
// is the vtcode pid (grounded against the hook probe's $PPID): a live
// session (manifest status not "completed", log on this OS's own
// filesystem) emits a SessionProcessSeed, and ResolveTerminalSession binds
// a terminal's vtcode process to the session dir whose id carries its pid.
//
// Watch roots are the archive directories of every cross-mount home plus
// every workspace store named by an archive's `metadata.workspace_path`
// (a construction-time snapshot). Two shapes are session files:
// events.jsonl (tailed live) and the archive JSON (a trigger that re-parses
// the archived workspace's events.jsonl in full, so a workspace first used
// after the daemon started is still captured when its session ends). Both
// emit rows whose SourceFile is the events.jsonl and whose ids are
// identical, so they dedupe on (source_file, source_event_id).
//
// # Events
//
// events.jsonl lines are `{"schema_version":"0.18.0","event":{...}}`
// (VT Code's exec-events ThreadEvent). The adapter consumes:
//
//   - thread.started   → session_start (timestamp from manifest.json)
//   - turn.started     → user_prompt when context.origin == "user" (the
//     goal text); origin "continuation" is a harness follow-up, not a prompt
//   - item.completed agent_message → assistant_message
//   - item.completed tool_invocation + tool_output (paired on tool_call_id)
//     → one action; arguments/status/outcome from the invocation,
//     output/exit_code from the output, DurationMs from the call's first
//     item.* timestamp to the output's completion
//   - turn.completed / turn.failed / turn.blocked → the turn's token row;
//     turn.failed also → turn_aborted
//   - thread.completed → session_end (subtype as target; stop_reason and a
//     non-zero total_cost_usd in the metadata)
//   - permission.resolved → permission_request (allow; DurationMs = the
//     approval wait) or permission_denied
//   - interjected → only its image_count, as image attachments on the next
//     user prompt (the text is raw composer input incl. /model, /exit)
//
// Skipped: permission.requested, harness items (snapshot / latency /
// blocked-handoff bookkeeping), reasoning items (stage "diagnosis" — the
// harness's own failure diagnosis, not model reasoning).
//
// apply_patch arrives as `{"input": "*** Begin Patch ..."}`; its
// RawToolInput is the bare patch (the codex convention) so internal/loc's
// Begin-Patch shape counts it.
//
// Phantom calls: some providers stream a call header that never receives
// arguments; VT Code closes it at turn end as failed/cancelled ("Tool call
// ended when the turn finished before it could execute."). An invocation
// with no arguments and outcome "cancelled" ran nothing and emits no row
// (18 of 36 calls in the WSL session, 54 of 106 on Windows). `vtcode exec`
// closes the same headers as status "failed", outcome "error" with no
// output; an argument-less failed invocation that never got an output is a
// phantom too.
//
// # Token capture
//
// One usage object per TURN on the turn's terminal event: {input_tokens,
// cached_input_tokens, cache_creation_tokens, output_tokens}. It is the sum
// of the turn's LLM requests — verified exactly against the per-request
// trajectory `prompt_cache_metrics` records — and thread.completed's usage
// is the sum of the turns (ignored). A blocked turn writes turn.failed AND
// turn.blocked with the same usage, so one row is emitted per turn id
// (SourceEventID/MessageID/TurnID all keyed on it).
//
// input_tokens is GROSS (OpenAI/OpenRouter prompt_tokens convention:
// trajectory shows input_tokens == prompt_tokens and total == prompt +
// completion), so InputTokens = input_tokens − cached_input_tokens,
// CacheReadTokens = cached_input_tokens, CacheCreationTokens =
// cache_creation_tokens (0 on every OpenRouter turn observed; whether an
// Anthropic-provider input_tokens also includes cache creation is NOT
// grounded). output_tokens maps to OutputTokens; no reasoning split exists,
// so ReasoningTokens stays 0 and nothing is double-billed.
//
// Model: events.jsonl names none. The served model per turn comes from
// the workspace trajectory (`prompt_cache_metrics`, else
// `history_projection_metrics`, matched on run_id == session id and
// turn_id), falling back to the archive's metadata.model — the model at
// session START, stale after a `/model` switch (the Windows session's
// archive says xiaomi/mimo-v2.6-pro while every request was served by
// minimax/minimax-m3.1-flash:free). Model ids are OpenRouter route ids
// kept verbatim: the cost engine prices `:free` ids at $0 and strips the
// provider prefix itself.
//
// Per-request data: each trajectory `prompt_cache_metrics` record is one
// successful request (usage + elapsed_ms + ts). The turn row's GenMs is
// the sum of its requests' elapsed_ms (basis native) when — and only when
// — the requests sum exactly to the turn's usage; every request also
// becomes one implicit-cache Tier-2 observation (OpenAI-compatible
// providers only). Token COUNTS stay one row per turn: per-request rows
// could double-count against a turn row emitted when the (independently
// rotated) trajectory was incomplete — see onTurnEnd.
//
// Reasoning: the model's own reasoning lives only in the archive's
// `messages` (operator ruling 4, 2026-10-21) and is joined onto the first
// tool call of the issuing Assistant message by tool_call_id (or onto a
// text-only message by its text) as PrecedingReasoning, scrubbed, 500
// bytes.
//
// Tool version: no store records the build per session, so every session
// is stamped with the install-level `last_seen_version` of the
// update-check cache beside the archive dir (operator ruling 1).
//
// # Settings, subagents, surface
//
// Effort: the archive's metadata.reasoning_effort (a session setting, e.g.
// "medium" / "none") → ActionMetadata.EffortLevel on user prompts.
// Subagents: items carry context.actor_id (the session id for the primary
// agent); an item from any other actor is IsSidechain. No subagent run was
// observed live; an item from thread.started's thread_id is primary too.
//
// Surface: an `auto-task-*` session is cli / vtcode-auto (only the
// --auto / --full-auto run writes that id). `session-*` is shared by the
// TUI and `vtcode exec` and is not stamped (archive metadata.primary_agent
// "auto" + no `progress` key marked every exec run observed and "build"
// every TUI run — a candidate discriminator, not adopted on 4 samples).
//
// Archive-only sessions: when the archived workspace's events.jsonl is gone
// (a deleted scratch workspace), the archive's `messages` alone yield
// session start/end, prompts, assistant text, tool calls with outcomes and
// reasoning — no tokens, no turn ids, synthesized row times
// (parseArchiveOnly). The transcript reader (ReadTranscript /
// ReadTranscriptFull) uses events.jsonl and falls back the same way.
//
// # Security / off-limits
//
// Never read: the config dir's `auth/` (OAuth / provider credentials) and
// config.toml, any vtcode.toml (provider overrides and custom providers
// can carry key material), the OS-keyring / encrypted-file secret store
// (`vtcode secret`), `.vtcode/checkpoints/` (file snapshots),
// `.vtcode/context/tool_outputs/`, `.vtcode/terminals/`,
// `.vtcode/history/`, `.vtcode/tasks/` (blocker hand-offs whose
// `-forensics/events.jsonl` copies are deliberately not session files),
// the archive's `transcript` and `progress`, the `debug-*.log` files beside
// the archives, and any `.env` / provider key. Read: the archive's
// metadata, started_at / ended_at and messages, and the update-check
// cache's last_seen_version. All prompt, tool input, tool output,
// reasoning and error text passes through the injected scrub.Scrubber.
package vtcode
