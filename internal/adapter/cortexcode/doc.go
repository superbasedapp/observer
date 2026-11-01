// Package cortexcode implements the capture adapter for Snowflake Cortex
// Code, the standalone `cortex` CLI (a Node single-executable; v1.2.18
// grounded 2026-10-21 on WSL Ubuntu and native Windows 11). Distinct from
// the JetBrains ACP pointer investigated alongside poolside
// (docs/poolside-adapter.md), which persisted no capturable store: the CLI
// writes a resumable, plaintext conversation store.
//
// # Storage shape
//
// Cortex keeps its data home at `$CORTEX_HOME`, else
// `$SNOWFLAKE_HOME/cortex`, else `~/.snowflake/cortex` (the same layout on
// Linux, macOS and Windows: `%USERPROFILE%\.snowflake\cortex`). Every
// session is TWO files in one flat directory:
//
//	conversations/<session-uuid>.history.jsonl   append-only message log
//	conversations/<session-uuid>.json            session metadata, rewritten whole
//	conversations/.last-session                  bare id of the latest session
//
// The uuid is the id `cortex --resume <id>` accepts and the
// `session_id` field of the metadata file; it is the ONE canonical
// session id this adapter emits. A subagent run is its own
// `<agent-id>.json` / `.history.jsonl` pair whose metadata names its
// parent in `parent_session_id` (read off the v1.2.18 bundle's orphan
// sweep; not yet observed live). Backup copies are named
// `<id>.back.<n>.json` and are rejected by IsSessionFile (the stem carries
// a dot).
//
// The history log is one JSON object per line with `role` user|assistant
// and an Anthropic-shaped `content` block array:
//
//   - user records carry `text` blocks (`is_user_prompt` true for the
//     operator's typed prompt, `internalOnly` true for the harness's own
//     system-reminder / hook-output injections) and `tool_result` blocks
//     (`{name, tool_use_id, content[], status, metrics{duration_ms}}`).
//     A user record is RE-APPENDED as a growing snapshot under the same
//     `id` (once more with `server_message_id` after the server sync, and
//     again each time the harness folds another block into it); a later
//     typed prompt can even arrive INSIDE an earlier record's snapshot
//     under its own block `message_id`. Identity is therefore taken per
//     BLOCK (prompt block `message_id`, tool_result `tool_use_id`), never
//     per line, and the store's (source_file, source_event_id) dedup makes
//     every re-appearance a no-op.
//   - assistant records carry `thinking` (`{thinking:{text,signature}}`),
//     `text` and `tool_use` (`{tool_use:{tool_use_id,name,input}}`)
//     blocks plus `model`, `thinking_effort`, `assistant_sent_time` and
//     `created_on` (epoch ms). Each assistant record is written once.
//
// The metadata file carries `working_directory`, `git_root`,
// `git_branch`, `created_at`, `last_updated`, `session_type`
// (`main` live) and the SESSION-CUMULATIVE per-model `token_usage` map.
//
// # Token capture (Tier 2, session-level)
//
// The history log carries NO per-message usage. The only token source is
// the metadata file's `token_usage[<model>]` =
// `{inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens}`,
// accumulated by the client from each response's `usage`. `inputTokens`
// is GROSS of BOTH cache columns: on both live sessions
// `inputTokens - cacheReadTokens - cacheWriteTokens` came to exactly 12
// (the per-request `uncached_tokens` the bundle also accumulates), so the
// adapter nets both (§4.4c) and emits ONE TokenEvent per (session, model)
// with a fixed SourceEventID — the store's ON CONFLICT MAX-upgrade keeps
// it monotonic as the file is rewritten (§8.2). Thinking tokens are not
// split out (Anthropic folds them into output), so ReasoningTokens stays
// zero (§8.4). Only cumulative cache totals exist, so no Tier-2
// cachetrack observation is possible (§8.6). Inference is billed by
// Snowflake in credits; the cost engine prices the model id at the API
// list price, an estimate rather than the invoice.
//
// # Capture choices recorded per the checklist
//
//   - Subagents (§7.1): SessionLineage. A child run is its own session
//     pair (`session_type` "subagent"); its metadata's `parent_session_id`
//     becomes a lineage row with ThreadSource "subagent". A `--fork-session`
//     / `/fork` copy names its source in `forked_from` (ForkedFromID,
//     ThreadSource "user"). Both are bundle-read; no live child or fork
//     exists yet. The `task` / `spawn_teammate` calls are spawn_subagent.
//     Double-count note (bundle-read, not live-verified): the only
//     `setTokenUsage` call site found writes a PROCESS-global per-model
//     accumulator into the main connection's session on quit, so a parent's
//     `token_usage` likely already includes in-process subagent spend, and
//     a second session started in the same process may inherit the first
//     one's totals. No child file with its own `token_usage` was seen.
//   - Effort (§7.2): `thinking_effort` on each assistant record (live:
//     "low"; the CLI's --effort flag accepts minimal..max) is wired to
//     ActionMetadata.EffortLevel on that record's events.
//   - Attachments (§7.3): structural-unknown — no image/file block was
//     observed live, so nothing is emitted rather than guessed.
//   - Output composition (§8.5): ContentBytes from write `content` and
//     edit `new_string`.
//   - Interrupts: the internalOnly `[Request interrupted by user]` block
//     becomes one turn_aborted row.
//   - Surface / tool version / process seed (cocolog.go): read from the
//     vendor log `logs/coco.log` by a key-only reader (ts, logger, pid,
//     session_id, terminal_launcher_source; `msg` decoded only for four
//     allow-listed logger/prefix pairs and never kept). Version = the
//     install directory named in the run's `coco.utils.bundle` line,
//     falling back to the install-level `cortex-version.txt`; surface =
//     launcher source (cli / vscode / desktop) or ACP mode; seed = the pid
//     of the session's latest unexited run on a native mount. The same
//     index backs ResolveTerminalSession (terminal_identity.go).
//   - Account (ruling 2026-10-21): `thread.accountHost` is the Snowflake
//     ACCOUNT host; every message-bound event gets one account-level
//     ToolAccountObservation (scope account:snowflake_host).
//   - Transcript (transcript.go): ReadTranscript / ReadTranscriptFull
//     re-read history.jsonl with the same per-block dedup.
//
// # Off-limits (never read)
//
// `~/.snowflake/connections.toml` and `config.toml` (Snowflake connection
// credentials), `cortex/cache/credential_cache/` (cached auth tokens),
// `cortex/connection_cache.json` (account / user / org identifiers),
// `cortex/permissions.json`, `cortex/settings.json`, `cortex/cortex.json`,
// `cortex/history` (raw prompt history), `cortex/stats/usage.json` (a
// token duplicate), `cortex/thread_goals.sqlite`, `cortex/logs/coco_errors.log`
// and `cortex/.ctx/`. `cortex/logs/coco.log` is read only through the
// key-only reader above. Inside the metadata file the adapter decodes only
// the fields named above: `connection_name`, `session_accounts` and
// `permission_cache` are never decoded.
package cortexcode
