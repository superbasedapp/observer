// Package qoder implements the adapter for Qoder (closed source; PAT auth
// against api.qoder.com) across ALL THREE of the vendor's surfaces:
//
//   - the terminal binary `qoder`/`qodercli`,
//   - the Qoder IDE, a VS Code fork (vscodehost product token "qoder"),
//   - Qoder Work, a separate desktop app that DRIVES qodercli.
//
// They are ONE tool id, not three. The IDE and Work both execute the same
// qodercli engine, write into the same `~/.qoder/projects` store, and —
// decisively — share its SESSION-ID space: a Qoder Work
// chat_session_messages.session_id IS the `<uuid>.jsonl` basename in the
// CLI store, and its `tools[].id` IS the transcript's `tool_use` block id,
// byte for byte. Splitting them into separate tool ids would fragment one
// conversation across identities that never merge. The distinction they
// DO deserve is a capture SURFACE, which is what surface.go emits. See
// docs/qoder-adapter.md "§2.1 decision" for the full reasoning table.
//
// The CN edition under ~/.qoder-cn/ IS a separate tool and out of scope.
//
// # Storage shape
//
// Qoder persists one Claude-Code-shaped JSONL transcript per session at
//
//	~/.qoder/projects/<dash-sanitized-cwd>/<uuid>.jsonl            ← CLI
//	~/.qoder/projects/<dash-sanitized-cwd>/transcript/<task-id>.jsonl ← IDE
//
// with an encrypted per-session store beside it
// (<uuid>/state.json and <uuid>/compression-v2/state.json) and a verbose
// run log at
//
//	~/.qoder/logs/sessions/<dash-sanitized-cwd>/<sid>/segments/<ts>-<rand>-p<pid>.jsonl
//
// Qoder Work keeps its own desktop store, read by work.go:
//
//	%APPDATA%\com.qoder.app.stable\main.sqlite                     ← Windows (grounded)
//	~/Library/Application Support/com.qoder.app.stable/main.sqlite ← macOS (UNVERIFIED)
//	~/.config/com.qoder.app.stable/main.sqlite                     ← Linux (UNVERIFIED)
//
// The IDE and CLI transcripts share a record shape and therefore a
// parser; they differ only in the surface they stamp (the IDE's session
// ids carry a `.session.execution` suffix and its files sit one level
// deeper, under `transcript/`). The Work store is a different shape
// entirely: a per-message SQLite projection whose cursor is a Unix-
// millisecond watermark, not a byte offset.
//
// Each transcript line is one record carrying the Claude-Code envelope
// (uuid / parentUuid / sessionId / timestamp / cwd / version / gitBranch /
// isSidechain), plus a per-record body. The record `type` is one of:
//
//   - user       — a prompt (message.content is a bare STRING) or tool
//     results (message.content is an ARRAY of tool_result blocks, with a
//     structured toolUseResult sibling)
//   - assistant  — a model turn; message.content is an ARRAY of Anthropic
//     content blocks (text and/or tool_use); message.id is the upstream
//     `chatcmpl-…` id
//   - runtime-config / file-history-snapshot / last-prompt — informational
//     records the adapter skips
//
// Qoder uses the Claude-Code tool vocabulary verbatim (Write / Bash /
// Read / Edit / Grep / Glob …), so the action map mirrors the claudecode
// adapter's.
//
// # Token capture (honest gaps)
//
// There is NO usable local token capture. The transcript records carry NO
// token fields at all. The run-log segments DO carry Anthropic-NET token
// names (input_tokens / output_tokens / cache_read_input_tokens /
// cache_creation_input_tokens on model.response.completed records) — but
// every field was ZERO in live capture (v1.0.40, 2026-07-09): qoder
// resolves usage server-side and never writes real counts locally, and it
// exposes no base-URL knob to route through the observer proxy. The adapter
// parses those segment records so that IF a future build writes non-zero
// counts they flow through as TokenEvents, guarded by a zero-usage check so
// no phantom rows land today. TokenTier is effectively NONE.
//
// # Model
//
// The concrete model string is ALSO server-side only — message.model,
// runtime-config.model, and every segment `model` field were EMPTY in live
// capture. The adapter leaves Model empty rather than fabricating one.
//
// # Project root
//
// The directory name dash-sanitizes the cwd, but every transcript record
// carries the RAW OS path in its `cwd` field (and the run-log's
// session.config.loaded carries `project_root`). The adapter resolves the
// project root from that field through crossmount.TranslateForeignPath (so
// a Windows `C:\...` session parsed by a WSL2 observer maps to `/mnt/c/...`)
// followed by git.Resolve — the lossy dir slug is never used for path
// resolution.
//
// # Sub-agents
//
// The per-record `isSidechain` flag is carried onto every emitted event.
// It was false throughout the live capture and no `subagents/` directory
// was present; sub-agent traces (were they to appear) surface inline in the
// same transcript with isSidechain:true, mirroring the Claude-Code model.
//
// # Capture surface
//
// Every parse stamps models.SessionSurface through
// ParseResult.SessionSurfaces, resolved by surface.go's ONE layout table
// (never a tool-name branch):
//
//	CLI transcript / run-log segment → cli     / qoder
//	IDE transcript                   → ide     / qoder
//	Qoder Work main.sqlite           → desktop / qoder-work   (HOSTED)
//
// Only the Work stamp is HOSTED. A Work-driven run truthfully
// self-reports `entrypoint:"cli"` in its own transcript — it genuinely IS
// a qodercli process — so the desktop origin is a fact only the hosting
// app's store holds, and store.SetSessionSurface lets it REPLACE the
// self-report. The Work parser cannot see the transcript store, so a
// stamp may arrive before the session row exists; it therefore re-emits
// stamps for anything touched inside workFreshnessWindow and sets
// ParseResult.RetrySuggested while any stamped session is still in
// flight (adapter.ParseResult §4.7).
//
// # Ownership (Qoder Work)
//
// The qodercli transcript is the RICHER record — split tool_use /
// tool_result pairs, per-record cwd + gitBranch, isSidechain, the
// upstream message id — so it OWNS the conversation rows. For a Work
// session WITH a transcript twin the Work parser contributes only the
// hosted surface stamp. A twin-less Work session (the aborted-run shape:
// the CLI created its project dir but never wrote a transcript) is the
// only record of that conversation, and there work.go emits it in full.
// This mirrors internal/adapter/kirocrew's rule; the twin check is a
// filesystem stat over the transcript roots, never a cross-store read.
//
// # Security / off-limits
//
// The adapter reads only the `projects/<slug>/**/*.jsonl` transcripts,
// the `logs/sessions/.../segments/*.jsonl` run logs, and exactly three
// tables of Qoder Work's main.sqlite (chat_sessions, chat_session_messages
// and — for documentation only — chat_session_context_usage). It NEVER
// reads the encrypted per-session `state.json` blobs,
// `~/.qoder/settings.json` (provider config), `~/.qoder/.auth/` (the
// `user` token blob and the `machine_id` telemetry fingerprint), nor —
// in the Work store — `byok_model_credentials`, `mcp_oauth_credentials`
// or `account_profiles`, whose names appear in no query in this package.
// The IDE's `state.vscdb` / `SharedClientCache/.../local.db` are outside
// every watch root. All raw text (prompts, tool inputs, tool outputs,
// error bodies) passes through the injected scrub.Scrubber before it
// leaves the adapter.
//
// Note: qoder writes a stable machine-id fingerprint at
// ~/.qoder/.auth/machine_id used for its own telemetry; the adapter neither
// reads nor emits it.
package qoder
