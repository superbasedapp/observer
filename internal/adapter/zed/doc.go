// Package zed implements an adapter for Zed's own NATIVE coding agent
// (zed.dev). Grounded live 2026-09-06 against the operator's own
// prompt-kit run; the Claude-ACP-in-Zed integration path did not persist
// a usable local store, so this adapter targets the built-in agent's own
// SQLite store instead.
//
// # Store
//
// One SQLite database per Zed install, opened read-only and
// WAL-tolerant, under a per-OS application-data directory (note this is
// NOT uniform across OSes — unlike e.g. Kilo Code, Zed follows each
// platform's own convention):
//
//	Windows: %LOCALAPPDATA%\Zed\threads\threads.db
//	macOS:   ~/Library/Application Support/Zed/threads/threads.db
//	Linux:   ~/.local/share/zed/threads/threads.db  (XDG_DATA_HOME, NOT ~/.config)
//
// Schema (verified live):
//
//	CREATE TABLE threads (
//	  id TEXT PRIMARY KEY, summary TEXT, updated_at TEXT NOT NULL,
//	  data_type TEXT NOT NULL, data BLOB NOT NULL, parent_id TEXT,
//	  folder_paths TEXT, folder_paths_order TEXT, created_at TEXT
//	);
//
// One `threads` row is one session. `data_type` is "zstd" in every live
// row observed; `data` is a zstd-compressed JSON blob (magic 28 B5 2F
// FD) holding the FULL thread. A `data_type` this adapter doesn't
// recognize is skipped with a warning rather than guessed. The row is
// REWRITTEN WHOLE on every turn (freebuff-desktop's rewrite-in-place
// pattern, not an append), so `updated_at` (TEXT, RFC3339Nano) is the
// watermark: ParseSessionFile re-reads every row whose `updated_at` is
// at or after the persisted cursor, decompresses+decodes it, and
// re-emits the WHOLE thread. Deterministic SourceEventIDs make the
// re-emission a store-level no-op for already-seen rows.
//
// # Decompressed JSON shape (schema "version": "0.3.0")
//
// Top-level fields this adapter reads: `title`, `messages`, `model`
// ({provider, model}), `request_token_usage` (map[user-message-id]usage),
// `cumulative_token_usage` (thread-level running total — read for
// context only, never itself emitted as a row: it would double-count
// every `request_token_usage` entry), `initial_project_snapshot`
// ({worktree_snapshots: [{worktree_path, git_state}]}). `messages` is an
// EXTERNALLY-TAGGED enum: each element is a one-key object,
// `{"User":{...}}` or `{"Agent":{...}}`.
//
//   - A User message carries `content: [{"Text": "..."}], id`.
//   - An Agent message carries `content` blocks — `{"Text":...}`,
//     `{"ToolUse":{id,name,raw_input,input,is_input_complete,
//     thought_signature}}`, `{"Thinking":{text,signature}}` observed live;
//     any other block kind is skipped, never guessed — plus a
//     `tool_results` map keyed by the ToolUse call id
//     ({tool_use_id, tool_name, is_error, content:[{"Text":...}], output}).
//
// 7 grounded native tool names, the COMPLETE surface a live multi-call
// session exercised: read_file, write_file, edit_file, list_directory,
// find_path, terminal, delete_path.
//
// # Timestamps
//
// The payload carries NO per-message timestamp anywhere — only the
// thread-level `updated_at` (and `initial_project_snapshot.timestamp`
// for session start). Per-block Timestamps are therefore SYNTHESIZED
// from a session-start base plus a one-second-per-message-index
// increment (the freebuff CLI-layout precedent, adapter.go
// parseChatDirTime/emitMessage) — never taken as literal wall-clock
// times. Documented as a known limitation, not silently faked precision.
//
// # Tokens
//
// `request_token_usage[msgID]` is per-turn (`input_tokens`,
// `output_tokens`, `cache_read_input_tokens`). Unlike most adapters
// here, `input_tokens` is ALREADY NET of `cache_read_input_tokens` (a
// grounded example: input 455 against cache_read 9728) — no netting
// arithmetic applies; InputTokens is carried straight through. The
// SourceEventID is keyed on the request/user-message id, so it is also
// the TokenEvent MessageID.
//
// # Model / pricing
//
// The one grounded capture reports `model.provider`="zed.dev" /
// `model.model`="gpt-5.6-luna" — Zed's own managed model gateway (a
// closed, non-mainstream backend). No pricing entry exists for it in
// the cost engine; token rows land with EstimatedCostUSD=0 and resolve
// as unknown cost rather than a fabricated price. This is honest, not a
// bug — add a pricing entry only once a real published rate is
// grounded.
//
// # Surface
//
// Every session is stamped models.SurfaceIDE / "zed": Zed is itself the
// editor, and its built-in agent has no separate CLI/TUI launch surface
// for `observer zed` to start. Capture-only — no proxy route, no hook,
// no MCP registration.
//
// # Sub-agent / fork lineage (best-effort, ungrounded against a live capture)
//
// The `threads.parent_id` DB column and the JSON's own `subagent_context`
// field both exist for forked/child threads, per the schema and the
// vendor's own naming, but no live capture in hand exercises either
// (`subagent_context` reads null in the one grounded session). When
// EITHER is non-empty, every row emitted for that thread is marked
// IsSidechain — a defensive best-effort, not a verified behavior.
//
// # Off-limits (never read)
//
// Zed's `settings.json`, `keymap.json`, and any credential/auth store
// are never opened. This adapter reads ONLY `threads/threads.db` (plus
// its `-wal` / `-shm` siblings, claimed the same way every other
// WAL-SQLite adapter here does).
//
// See docs/zed-adapter.md for the operator-facing reference.
package zed
