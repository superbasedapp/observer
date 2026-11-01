// Package dirac implements the Adapter interface for the Dirac CLI
// (`dirac`, npm package `dirac-cli`, Apache-2.0), a fork of Cline.
// Distinct from internal/adapter/cline (the Cline VS Code extension,
// `api_conversation_history.json` arrays in VS Code globalStorage) and
// internal/adapter/clinecli (the Cline 3.x CLI, `~/.cline/data` SQLite +
// messages.json): Dirac keeps the Cline task-directory idea but persists
// every task as an append-only OPERATION LOG, so neither sibling's parser
// can read it and this package is not a §2.1 retag of either.
//
// Store (grounded 2026-10-21 against dirac-cli 0.5.22 on Windows 11 and
// WSL Ubuntu; home = $DIRAC_DIR or `~/.dirac` on every OS, data dir =
// $DIRAC_DATA_DIR or `<home>/data`):
//
//	<data>/tasks/<taskId>/
//	├── api_conversation_history.jsonl            ← CLAIMED: op log (append_message | append_user_content | reset)
//	├── api_conversation_history.jsonl.archive.N  ← read: the op log rotated out at 8 MiB (N = its last op offset)
//	├── api_conversation_history.baseline.jsonl   ← not read: materialized state at the last rotation
//	├── ui_messages.jsonl (+ .baseline.jsonl)     ← read: presentation op log; ONLY api_status (token split, request start) and tool-card timing
//	├── task_metadata.json                        ← read: model_usage + environment_history
//	└── subagents/<runId>/transcript.md           ← not read (sub-agent markdown; see docs)
//	<data>/state/taskHistory.json                 ← read: per-task cwdOnTaskInitialization (the only cwd)
//	<data>/logs/dirac-cli.log                     ← read (tail, four fact shapes): pid, install id, package dir, channel
//
// The session id is the task directory name (a Unix-millis task id, e.g.
// `1792563515376`), which is exactly what `dirac --taskId <id>` resumes.
//
// Parsing streams the live op log from the byte cursor; a parse from 0
// first replays the rotated archives. Rotation is a RENAME, so a cursor
// past EOF means a new file (CursorSemanticsFor declares
// RewindsOnTruncate). Every event's SourceFile is the live log and every
// SourceEventID is content-derived (tool_use id, provider response id,
// message ts), so a `reset` that re-lists earlier messages dedups.
//
// Tokens: one row per assistant message carrying `metrics`. Dirac's
// metrics.tokens.cached is cache READS + cache WRITES summed, and carries
// no reasoning count, so the per-request split is taken from the
// matching ui_messages `api_status` record (exact tokensIn/tokensOut/
// cached match, ordered walk); without a match the metrics are booked
// with cached as reads. Input is NET (Dirac's own normalizers subtract
// cache; verified against taskHistory totals). Reasoning is stamped only
// where the provider's relation to output is grounded (reasoningShapes):
// OpenAI-family output INCLUDES reasoning and is netted, Gemini output
// excludes it.
//
// Dirac has no assistant `text` blocks on the grounded providers: every
// user-facing message is a `respond` tool call, classified per operation
// into the synthesized raw names respond.complete / respond.question /
// respond.progress / respond.plan.
//
// Beyond the claimed op log the adapter derives: the per-request generation
// span (api_status start to assistant persist), per-tool duration (tool
// cards), plan/act mode (modelInfo.mode), a context_compacted row for a
// shrinking `reset`, the (pid, session) process seed and an account-level
// install id from the vendor log, surface/version fallbacks for a task with
// no task_metadata.json, and a handoff ReadTranscript that replays the op log.
//
// NEVER reads: `<data>/secrets.json` (provider API keys + the ChatGPT
// subscription OAuth tokens), `<data>/globalState.json` (provider
// settings incl. base URLs), `<data>/settings/`,
// `<data>/cache/`, `<data>/workspaces/`, a task's `tool_context*.jsonl`,
// `api_conversation_provider_state.json`, `context_history.json`, or the
// home's Agents/Hooks/Rules/Workflows directories. Sibling files are
// read through readCapped, which refuses symlinks.
//
// See docs/dirac-adapter.md and testdata/dirac/README.md.
package dirac
