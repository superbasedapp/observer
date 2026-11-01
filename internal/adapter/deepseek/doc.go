// Package deepseek parses DeepSeek Harness session logs.
//
// DeepSeek Harness (npm package "@deepseek-ai/dsh") is launched web-only:
// `npx @deepseek-ai/dsh web` serves a local GUI at http://127.0.0.1:3080.
// There is no separate terminal/TUI mode this adapter targets, and this
// package deliberately covers usage capture ONLY — no proxy launcher, no
// terminal/remote integration, no hooks registration, no MCP-specific
// work. See internal/integration's "deepseek" Capability row for the
// honest, table-driven statement of what IS and is NOT wired.
//
// # Storage layout
//
// Identical on WSL (~/.dsh) and native Windows (%USERPROFILE%\.dsh, seen
// from WSL at /mnt/c/Users/<user>/.dsh):
//
//	~/.dsh/sessions/<cwd-slug>/session-<uuid>/session.v4.jsonl.zstd  (current builds)
//	~/.dsh/sessions/<cwd-slug>/session-<uuid>/session.jsonl.zstd     (older builds)
//
// Both basenames are accepted through the closed sessionLogForms table
// (session.jsonl.zstd and session.v<N>.jsonl.zstd for any decimal N). When
// one session directory holds more than one log, only the highest version
// is parsed (the unversioned name ranks below every explicit version) and
// every lower one yields no events, so a session is never ingested twice
// under two source files. See supersedingSibling.
//
// <cwd-slug> is the session's working directory with path separators
// replaced by `-` and a leading+trailing `--`, e.g.
// `--home-marmutapp-parking-game--` for /home/marmutapp/parking-game.
//
// The .zstd file is REWRITTEN WHOLE on every flush (full recompress, not
// an append), unlike every other JSONL-based adapter in this codebase.
// ParseSessionFile therefore re-decodes and re-parses the entire file on
// every call rather than streaming from a byte offset — see the doc
// comment on ParseSessionFile for how this maps onto the shared
// adapter.ParseResult.NewOffset cursor contract (the same
// whole-file-rescan approach internal/adapter/cursor uses for its
// store.db shape).
//
// Off-limits: ~/.dsh/.credentials.yaml and ~/.dsh/settings.yaml are
// NEVER read by this package — they hold API keys / harness settings,
// not session activity.
//
// # Windows sessions are backfill-only
//
// DrvFs inotify does not fire for writes made by a Windows-side `dsh`
// process, so a WSL2 observer only sees Windows sessions on the next
// `observer backfill` sweep, never live. defaultRoots() still lists the
// Windows-side tree (via crossmount.AllHomes(), which already enumerates
// cross-mount Windows homes) so backfill can find it; this is stated
// honestly rather than silently dropped.
//
// # Record shape
//
// The first line of every session log (either basename) is a HEADER with a distinct
// shape (no seq/time/data envelope):
//
//	{"type":"session","version":0,"id":"session-<uuid>","createdAt":<unix-ms>,
//	 "cwd":"<project root>","delegationDepth":0,"agentPreset":"standard"}
//
// The header's own `id` is the ONE canonical session id (§4.5a) — used
// for every ToolEvent/TokenEvent this file produces. `cwd` is the ONLY
// statement of the project root anywhere in the file.
//
// Every subsequent line is an envelope of the shape
// {"type":"<str>","seq":<int>,"time":<unix-ms>,"data":{...}} (a handful
// of streaming-delta lines use seq0/time0 instead — see below, these are
// skipped). `time`/`createdAt` are Unix MILLISECONDS throughout.
//
// Consumed event types:
//
//   - user/message — a genuine user-authored prompt IFF
//     data.source.kind=="user". DeepSeek Harness also emits harness-
//     injected context (sandbox/approval-policy snapshots, etc.) through
//     the identical user/message envelope shape with
//     data.source.kind=="plugin" (observed plugin id
//     "@deepseek-ai/dsh-system-prompt") — these must NOT be classified as
//     ActionUserPrompt or they corrupt every user_prompt-boundary-
//     dependent surface (internal/predict's turns-per-message ladder,
//     same class of bug muse's subagent_start/user_prompt split guards
//     against). Any source.kind other than "user" is skipped.
//   - assistant/message — the assistant's reply AND the token/model
//     source. data.message.content[] carries text blocks and tool-call
//     blocks (each {id,name,arguments} where arguments is a JSON STRING
//     needing a second unmarshal); data.message.source.{provider,model}
//     resolves the model; data.usage is a SIBLING of data.message (not
//     nested inside it) — {inputTokens,outputTokens,cacheReadTokens?}.
//   - tool/call — data.{turn,step,callId,name,arguments} (arguments a
//     JSON string), the per-call companion event to the tool-call block
//     already seen inside the preceding assistant/message. Used only to
//     confirm/backfill target extraction; the ToolEvent itself is
//     created from the assistant/message tool-call block so its
//     MessageID and ordering stay tied to the reply that issued it.
//   - tool/result — data.message.content[] entries of type "tool-result"
//     with toolCallId + nested content[].text; stamps the paired
//     ToolEvent's output.
//   - turn/start / turn/end — data.turn (+ data.reason.kind on end, e.g.
//     "completed"). No usage aggregate here — usage lives ONLY on
//     assistant/message.
//   - step/start / step/end — data.{turn,step}, informational only.
//   - session header — cwd → project root.
//
// Skipped entirely (streaming/ephemeral, superseded by the final
// consolidated record; identifiable by seq0/time0 instead of seq/time):
// assistant/chunk, text-chunks, text-delta, tool-call-chunks,
// tool-call-delta.
//
// Skipped entirely (session/config informational, no normalized-action
// counterpart): permission/preset, sandbox/mode, approval/policy,
// session/title, session/title-llm-request, request/header,
// request/context, agent/inbox/spliced.
//
// # Token semantics
//
// Usage is PER STEP (per model call), not cumulative. inputTokens is
// already NET of cacheReadTokens — confirmed against live capture where
// one row showed inputTokens (4011) SMALLER than cacheReadTokens (7680),
// which is only possible if input excludes the cached prefix. Do NOT
// subtract cacheReadTokens again (contrast with internal/adapter/muse and
// internal/adapter/codex, which correct a GROSS input). No cache-write
// field is emitted by this source, and no per-call cost field either —
// EstimatedCostUSD is left for the cost engine (internal/intelligence/cost
// already carries exact-match pricing for
// "deepseek/deepseek-v4-flash"/"deepseek/deepseek-v4-pro", the OpenRouter
// slugs this source's assistant/message.data.message.source.model field
// states verbatim).
//
// # Known gaps (honest, not speculative)
//
//   - Sub-agent rollup is UNGROUNDED. The available sample (178 lines,
//     one straightforward single-turn session) contains no real
//     sub-agent invocation — a `subagent`/`subagent_fork` grep hit only
//     matched JSON-schema parameter-type strings ("type":"array" etc.),
//     not real events. The header's delegationDepth:0 field HINTS that a
//     sub-agent session may write its own independent top-level
//     session.jsonl.zstd (in which case it is captured automatically as
//     an ordinary session, no special code needed) rather than nesting
//     under the parent the way muse nests subagent/<uuid>/ — but this is
//     NOT confirmed. No rollup logic is implemented; this is a
//     documented gap, not an oversight.
//   - turn/end reason kinds other than "completed" were never observed.
//     Defensively, any non-"completed" reason is treated as an aborted
//     turn (mirrors muse's emitTurnTerminal), but this branch is
//     unexercised by live data.
package deepseek
