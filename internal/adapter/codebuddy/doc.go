// Package codebuddy implements the adapter for Tencent CodeBuddy Code
// (npm `@tencent-ai/codebuddy-code`; binaries `codebuddy`, `cbc`,
// `codebuddy-code`), Tencent Cloud's terminal coding agent.
//
// # Storage shape (grounded 2026-10-21, v2.171.0, WSL + Windows)
//
// CodeBuddy keeps one JSONL transcript per session under a per-project
// slug directory, with the SAME layout on Linux, macOS and native
// Windows (`%USERPROFILE%\.codebuddy`):
//
//	~/.codebuddy/projects/<slug>/<session-id>.jsonl                  ← parsed
//	~/.codebuddy/projects/<slug>/<session-id>/subagents/agent-*.jsonl ← not claimed (v1)
//	~/.codebuddy/projects/<slug>/<session-id>/tool-results/…          ← not read
//
// CODEBUDDY_CONFIG_DIR relocates the whole data home (vendor bundle:
// `process.env.CODEBUDDY_CONFIG_DIR || join(homedir(), ".codebuddy")`).
// The slug drops the leading separator and lowercases a drive letter
// (`home-<u>-proj`, `c-Users-<u>-proj`); it is lossy and never decoded —
// every message line carries the raw `cwd`.
//
// The file stem IS the session id: every line's `sessionId` repeats it
// and `codebuddy --resume=<id>` accepts it (both operator sessions).
//
// # Record shapes
//
// The transcript is Claude-Code-shaped in LAYOUT but not in CONTENT:
// each line is a serialized @openai/agents-core `AgentInputItem` (the
// vendor depends on agents-core 0.5.2) plus CodeBuddy envelope fields.
//
//   - `session-meta` (line 1 of an interactive run, re-appended when
//     metadata changes; a headless `-p` run writes none, so its first
//     record of any kind opens the session instead):
//     `{type,id,sessionId,timestamp,meta:{"codebuddy.ai/mainAgent":"ptc"}}`
//     → one session_start marker. GROUNDED.
//   - `message` (role user / assistant) with `content` parts
//     `input_text` / `output_text`, `status`, `providerData`
//     {skipRun, agent, conversationRequestId, error}, `cwd`, `parentId`,
//     epoch-MILLISECOND `timestamp`. GROUNDED.
//   - `file-history-snapshot`, `ai-title`, a `summary` whose
//     providerData.source is "initial-user-message" → skipped. GROUNDED.
//   - `function_call` {callId,name,arguments(JSON string)},
//     `function_call_result` {callId,name,status,output{type,text},
//     providerData.toolResult} → GROUNDED SHAPES: the 2026-10-21 hook probe
//     drove the real CLI with a loopback MOCK model, so the record shapes
//     are real CLI output while the model text, token numbers (10 in / 5
//     out) and call ids are mock values. Only Read / Bash / Edit were
//     exercised.
//   - `hosted_tool_call`, `reasoning`, input_image / input_file parts,
//     `_fromSubAgent`, and a `summary` with source "pre-compact" /
//     "periodic" or a provider `compaction` item (→ context_compacted) →
//     UNVERIFIED: agents-core schema plus the vendor bundle, never seen in
//     a capture.
//
// User records with providerData.skipRun:true are local slash-command
// bookkeeping (`<command-name>/model</command-name>`,
// `<local-command-stdout>…`) never sent to a model; they are not
// prompts. An assistant record carrying providerData.error (the grounded
// auth failure) becomes an ActionAPIError row, Success=false. An assistant
// record with providerData.hookStatus "blocked" (GROUNDED) is a
// UserPromptSubmit hook blocking the turn; the blocked prompt itself is not
// persisted, and the record becomes an ActionPermissionDenied row.
//
// # Tokens (Tier 2, JSONL) — shape live, numbers unproven
//
// Usage rides providerData.usage (the agents-core Usage instance) on EVERY
// item of a model response (live: each function_call and the assistant
// message), with providerData.rawUsage holding the provider's own object.
// The parser follows the vendor bundle's own
// rules: input is GROSS of cache reads (netted), output INCLUDES
// reasoning (netted, reasoning carried separately), cache writes carried
// through un-subtracted. One row per providerData.messageId (the
// generation id, MAX-merged across its items); TurnID =
// providerData.conversationRequestId. The envelope SHAPES are live but the
// probe's numbers were mock values, so the netting rules are backed by the
// vendor bundle, not by observed provider numbers. Tier-2 cache observation
// is fed from the same rows. GenMs comes from the diagnostic log's native
// model-call duration (see below), never from transcript timestamps.
//
// # The diagnostic log (a line filter, never a file reader)
//
// `<data home>/logs/<date>/<workspace>__<hash>.log` is the only place the
// CLI version, the owning pid and the per-call generation duration are
// written. logs.go extracts exactly those fields (process start line,
// session-scoped pid lines, agent.model_call.completed telemetry), keeps
// nothing else and returns no line; the log can hold prompt text, paths and
// post-login auth notes. The facts feed SessionToolVersions (falling back to
// the installed package.json), a cli surface stamp, SessionProcessSeeds and
// the adapter.TerminalSessionResolver. See docs/codebuddy-adapter.md.
//
// # Sub-agents
//
// The spawn (`Agent`) is ActionSpawnSubagent. A sub-agent writes its own
// transcript under `<session-id>/subagents/`, AND the vendor forwards its
// items into the main session stream marked `_fromSubAgent`. Whether
// those forwarded items are persisted in the parent file is unknown, so
// v1 claims only the parent file and flags any line carrying
// `_fromSubAgent:true` as a sidechain. The subagents/ files are left
// unclaimed until a real capture settles the double-count question.
//
// # Files this adapter deliberately does NOT read
//
//   - `~/.codebuddy/history.jsonl` — cross-project raw prompt log.
//   - `~/.codebuddy/settings.json` (model, trustedDirectories, hooks,
//     env — may hold provider keys), `~/.codebuddy.json` /
//     `~/.codebuddy/mcp.json` / `.mcp.json` (MCP config, may embed
//     credentials), `models.json`.
//   - `~/.codebuddy/local_storage/` (gzip+base64 cached product/account
//     state), `channels/remote-control-host-id`, `user-state.json`,
//     `web-ui-port.json`, `sessions/`, `shell-snapshots/`,
//     `diagnostics/`, `traces/` (per-process agent traces with host
//     names), `plugins/`. `logs/` is read only through the field filter
//     above.
//   - Any credential store the CLI keeps after `/login` (the operator
//     never logged in, so none exists on the grounding hosts).
//
// # Security
//
// Every string that leaves the adapter passes through the injected
// scrub.Scrubber.
package codebuddy
