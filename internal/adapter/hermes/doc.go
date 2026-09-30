// Package hermes implements the Adapter interface for Nous Research's
// Hermes Agent (https://github.com/NousResearch/hermes-agent), an
// open-source autonomous AI agent written in Python with 70+ built-in
// tools across ~28 toolsets, full MCP client+server support, persistent
// SOUL.md / MEMORY.md, and 18+ LLM providers (Anthropic, OpenAI,
// OpenRouter, Nous Portal, Gemini, Nvidia, …).
//
// Hermes stores all session data in a single SQLite file at
// ~/.hermes/state.db (Linux/macOS/WSL2) or %LOCALAPPDATA%\hermes\state.db
// (Windows native), WAL mode enabled, schema version 14 at the time of
// this adapter's first capture (2026-06-05). The plan in
// docs/hermes-adapter-plan.md §3 documents the schema; the live reality
// check in §17.1 of the same doc captures the deltas vs. the originally-
// researched v11 shape (sessions.cwd column exists, messages.active
// filter required, tool_calls wrapper carries call_id+response_item_id+
// type extras, tool-result content is structured JSON, model strings
// carry OpenRouter-style :suffix tails).
//
// Capture strategy is **hooks-primary + SQLite backfill** (same hybrid
// model as the cursor adapter):
//
//   - Primary (real-time): a Python plugin at
//     ~/.hermes/plugins/superbased-observer/ registers callbacks via
//     ctx.register_hook("post_tool_call", …) / "post_api_request" /
//     "on_session_start" / "on_session_end" / "subagent_start" /
//     "subagent_stop" and fires `observer hook post-tool` as a
//     subprocess with the structured event JSON on stdin. Same wire
//     pattern as the Claude Code / cursor hooks. 0.5s subprocess
//     timeout; exceptions swallowed so observer being down never
//     blocks Hermes.
//   - Backfill (historical): this adapter's ParseSessionFile opens
//     state.db read-only via modernc.org/sqlite, tracks the last-seen
//     messages.id offset, and emits ToolEvents + TokenEvents for any
//     newly-landed rows. Used for sessions that predate plugin install
//     and for `observer backfill --hermes`.
//
// Token capture is Tier 2 (approximate) on both paths today:
//   - Hook path: post_api_request carries a usage{input_tokens,
//     output_tokens} dict per API call — richer than post_llm_call,
//     which has no usage payload at all (confirmed against the live
//     hermes_cli/hooks.py _DEFAULT_PAYLOADS dict, schema v14).
//   - SQLite path: session-level aggregates from the sessions table
//     (input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
//     reasoning_tokens). Per-message granularity is also available via
//     messages.token_count but is less precise.
//   - SQLite path, auxiliary calls: newer Hermes schemas (v30 at
//     v2026.9.24) record auxiliary LLM calls (vision, compression,
//     title_generation, background_review, ...) ONLY in
//     session_model_usage rows with a non-empty task, never in the
//     sessions aggregate, and fire them through the distinct
//     post_auxiliary_call plugin event rather than post_api_request.
//     One TokenEvent per such row (auxTokenEvent), emitted whatever the
//     hook coverage; a store without the table emits none.
//
// Reasoning emission (B3, 2026-07-31): messages.reasoning /
// reasoning_content mint NO action row. The chain-of-thought is threaded
// onto the next event the batch emits as PrecedingReasoning — the
// message's first tool call, else its assistant-text row — under
// grok-style semantics: consumed-once, last-wins, discarded at a
// role='user' turn boundary, and never crossing a session id (one
// state.db interleaves every session). The 200-char preview convention
// the retired `hermes.reasoning` row used is applied at the flush site,
// scrubbed there. Capture is deliberately NOT hook-gated (the retired
// row was): threading adds no row, so there is no hook/SQLite duplicate
// to suppress. See reasoningThread in parse.go.
//
// Tier 1 (accurate) proxy routing is a v2 follow-up — Hermes accepts a
// custom inference.base_url per provider in ~/.hermes/config.yaml, so
// pointing it at the observer proxy would work, but the wiring is
// deferred per docs/plans/hermes-adapter-implementation-plan-2026-06-05.md.
//
// See:
//   - docs/hermes-adapter-plan.md — the research note + reality check.
//   - docs/plans/hermes-adapter-implementation-plan-2026-06-05.md —
//     the per-file build order.
//   - testdata/hermes/ — schema-v14 fixtures.
package hermes
