// Package devin implements a SQLite-store adapter for Cognition's Devin
// CLI (binary `devin`, the local CLI released ~2026-04 — distinct from
// cloud Devin). Live-verified against build 3000.1.27 on WSL + Windows
// 2026-07-09.
//
// # Storage
//
// Devin persists every session in a single SQLite store:
//
//   - Linux/macOS: ~/.local/share/devin/cli/sessions.db
//   - Windows:     %APPDATA%\devin\cli\sessions.db  (AppData\Roaming)
//
// The watch root is the enclosing `cli` directory, discovered across
// every cross-mount-resolved home so a WSL2 observer reaches a
// Windows-side store (and vice-versa).
//
// Devin Desktop (the renamed Windsurf VS Code fork) writes the SAME
// store — verified live 2026-09-03 on Windows, where its
// %APPDATA%\Devin\cli\sessions.db is the same case-insensitive
// directory as the Windows root above, with an identical schema
// (refinery version 16). No desktop-specific root exists or is watched;
// the lanes are told apart per session in surface.go. See
// docs/devin-adapter.md §"Devin Desktop".
//
// # Store shape (live-verified 2026-07-09)
//
//   - sessions(id, working_directory, backend_type, model, agent_mode,
//     created_at, last_activity_at, title, main_chain_id, …) — session
//     ids are adjective-noun slugs (e.g. `cobalt-fruit`); `main_chain_id`
//     is the node_id of the ACTIVE conversation's leaf; `working_directory`
//     is the RAW OS path (a `C:\…` string on Windows-side sessions).
//   - message_nodes(row_id, session_id, node_id, parent_node_id,
//     chat_message JSON, created_at, metadata) — a TREE keyed by
//     (session_id, node_id) with parent pointers. Regenerated turns fork
//     the tree, so the same logical turn can appear on more than one
//     branch; only the path from `main_chain_id` up to the root is the
//     canonical conversation. `row_id` is the monotonic incremental
//     watermark.
//
// Each message_nodes.chat_message is a JSON object: {message_id, role
// (system|user|assistant|tool), content (string), tool_calls[] (assistant
// only: {id,name,arguments,index,kind}), thinking ({thinking}) , tool_call_id
// (tool role), metadata}. metadata.metrics carries the per-message token
// bundle {input_tokens, output_tokens, cache_read_tokens,
// cache_creation_tokens, ttft_ms, total_time_ms} and metadata.generation_model
// the per-turn model. tool-role nodes carry the paired result plus a
// metadata.extensions["chisel/tool_result_meta"].success flag.
//
// # Token capture
//
// Contrary to an early handover note ("no local tokens; only ACU/credit
// columns"), the WSL capture recorded real per-message token counts in
// metadata.metrics. This adapter emits one approximate TokenEvent per
// assistant node that carries metrics, keyed by the node's message_id.
// The backend is "Windsurf" and models look like `swe-1-6-slow`.
// cache_read_tokens IS populated (grounded 2026-09-03 on the desktop
// capture; the July CLI capture had it null throughout) and input_tokens
// is NET of it — input + cache_read equals the node's own
// num_tokens_preceding — so neither needs adjusting.
// cache_creation_tokens is still null in every captured row.
// Devin exposes no base-URL override, so there is no proxy tier — tokens
// come only from this store.
//
// # Not captured
//
// Devin's `.devin/hooks.v1.json` is explicitly Claude-Code-compatible but
// UNWIRED in the shipped CLI, so this package has no hook receiver.
// Subagents spawned by the `run_subagent` tool surface as a
// spawn_subagent action, but the subagent's own inner tool calls are not
// separately represented in message_nodes as a sidechain in the captured
// store. Rendered transcript exports at cli/transcripts/<id>.json
// (ATIF-v1.7) are a convenience export, not the canonical store; this
// adapter reads the always-present message_nodes tree instead.
package devin
