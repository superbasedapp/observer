// Package dimcode implements a SQLite-store adapter for DimCode (binaries
// `dim` and `dimcode`, npm `dimcode`, a terminal AI coding agent built on
// the Vercel AI SDK). Live-verified against dimcode 0.5.21 on WSL Ubuntu and
// Windows 11 on 2026-10-21.
//
// # Storage
//
// Every session of every surface (TUI, `dim exec`, web UI, ACP, remote) is
// persisted in ONE WAL SQLite store, byte-for-byte the same layout on every
// OS, rooted at the DimCode home (default ~/.dimcode, override
// $DIMCODE_HOME) plus a fixed `v2` generation directory:
//
//   - Linux/macOS: ~/.dimcode/v2/dimcode.sqlite
//   - Windows:     %USERPROFILE%\.dimcode\v2\dimcode.sqlite
//
// The watch root is the `v2` directory, discovered across every
// cross-mount-resolved home so a WSL2 observer reaches a Windows-side store
// (and vice versa). The -wal/-shm siblings are watched too and mapped back to
// the main .sqlite; a foreign-mount source is mirrored locally before open
// because modernc.org/sqlite hits SQLITE_IOERR against a DrvFs path DimCode
// holds open in WAL mode.
//
// # Store shape (live-verified 2026-10-21)
//
//   - sessions(sessionId, cwd, title, status, createdAt, updatedAt, …).
//     sessionId is `sess_<epoch-ms>_<base36>` for a top-level session and
//     `subagent_<epoch-ms>_<base36>` for a sub-agent's own session (live,
//     2026-10-21): globally unique, and exactly what `dim --session <id>` /
//     `dim exec resume <id>` accept, so it is the canonical SessionID
//     verbatim (no store scoping needed). cwd is the RAW
//     OS path (a C:\… string on a Windows-side session). updatedAt does NOT
//     track activity (it stayed at session-start while the run kept going);
//     messages.updatedAt does.
//   - session_states(sessionId, selectedProviderId, selectedModelId, settings,
//     …). The model the session currently has selected; settings is a JSON
//     object that carries reasoningEffort when the user set one and a
//     `metadata` bag (lastUsedGitBranch; on a sub-agent's session
//     __subagentOrigin + parentSessionId). permissionSettings.humanApprovalMode
//     (never | auto) is the approval posture; currentMode is `agent`.
//   - messages(messageId, sessionId, role, parts, toolMetadata, metadata,
//     orderKey, createdAt, updatedAt). role is user | assistant | tool_result.
//     parts is a JSON ARRAY of Anthropic-shaped blocks: {type:"text"},
//     {type:"thinking"} (with startTime/endTime), {type:"tool_use", id, name,
//     input, startTime} and, on a role=tool_result message, {type:
//     "tool_result", tool_use_id, content, structuredContent, is_error}.
//     metadata.runId ties every message of one user prompt (a "run") together;
//     orderKey (`<hex-ms>-<seq>`) is the stable chronological order.
//   - usage_run_stats(runId, sessionId, providerId, modelId, status,
//     startedAt, endedAt, durationMs, inputTokens, outputTokens, totalTokens,
//     cacheReadTokens, cacheWriteTokens, cost, …). ONE row per run (one user
//     prompt fanning out to N model calls), written when the run ends.
//   - usage_ledger(ledgerId, sessionId, runId, providerId, modelId, usage,
//     cost, createdAt). `usage_<runId>` mirrors the run; any other ledgerId
//     (observed: `plugin_ledger_<uuid>`, the session-title generation call)
//     is a SEPARATE billable model call that usage_run_stats does not include.
//   - session_relations(sourceSessionId, targetSessionId, relationType,
//     typeData). relationType is `subagent` (source = parent, target = child;
//     typeData carries parentRunId/parentToolCallId/subagentType) or `branch`
//     (a user fork; source = original, target = copy). The subagent row is
//     LIVE-grounded (2026-10-21); the branch row is read from the vendor's
//     code only.
//   - messages with role=user are not all prompts: the vendor stores its own
//     runtime bookkeeping (run terminal status, provider-retry recovery,
//     background-task notifications, ...) as role=user rows tagged
//     metadata._dimTranscript.kind. See harness.go: only untagged / user_input
//     / user-owned rows are user_prompt; the rest map through an ordered rule
//     table to api_error / turn_aborted / prompt_context.
//
// # Token capture
//
// DimCode records NO per-call tokens, only per-RUN totals, so this adapter
// emits one TokenEvent per run (SourceEventID `run:<runId>`, timestamp =
// endedAt) plus one per standalone ledger call (`ledger:<ledgerId>`). The
// run's `lastCall` sub-object in the mirror ledger row is NOT emitted: it is
// the final call of a run whose total already contains it.
//
// promptTokens/inputTokens is GROSS. DimCode's own mapUsage() normalizes every
// provider's usage into `promptTokens = reported prompt + separately-reported
// cache read/write` and `totalTokens = prompt + completion` (cache is never
// added on top), and the live rows agree (total 149457 = 147551 + 1906 while
// cacheRead 41504 is a subset of the prompt). Observer's TokenEvent contract
// is NET non-cached input, so InputTokens = prompt − cacheRead − cacheWrite
// (clamped ≥ 0). completionTokens already includes reasoning tokens (no
// separate reasoning key exists in the usage JSON), so ReasoningTokens stays
// 0 and reasoning bills at the output rate through OutputTokens (§8.4).
//
// Cost: usage_run_stats.cost is DimCode's own pricing; it is carried as
// EstimatedCostUSD only when its quality is "exact" (the vendor's enum is
// exact | base_tokens | missing_price, and every live run was missing_price
// for a :free OpenRouter model). The cost engine prices the rest from tokens.
//
// Cache observation (§8.6): not emitted. Cache tokens exist only as run-level
// totals, never per call, so a Tier-2 accumulator would have to invent
// per-turn deltas.
//
// # Actions
//
// Tool calls come from assistant tool_use blocks, paired with their
// tool_result by (runId, tool_use_id): success = !is_error && toolMetadata
// status success && exitCode (when present) == 0; DurationMs is exec's
// structuredContent.wallTimeMs only (the tool_use→result gap includes the
// human approval wait, so it is never used). A call with no result yet is
// emitted OutcomePending and later resolved through an ActionOutcomeUpdate.
//
// Sub-agent decision (§7.1): mechanism 2, SessionLineage, plus sidechain. A
// spawned sub-agent is its own `subagent_…` session linked by a
// session_relations row (or by its own settings.metadata.parentSessionId), so
// the child keeps its own rows, is linked to the parent via
// ParentThreadID/ThreadSource "subagent", has every action and token row
// flagged IsSidechain, and carries ActionMetadata.IsSubagent + ParentSessionID;
// the parent's `agent` tool_use is classified spawn_subagent and is not itself
// a sidechain row. A `branch` relation lands as ForkedFromID.
// A fork copies the source's messages under new ids, so a forked session
// repeats its history; that is the vendor's store shape, not deduplicated here.
//
// Effort / approval mode (§7.2): session_states.settings.reasoningEffort,
// permissionSettings.humanApprovalMode and currentMode, when present, are
// stamped on every event as ActionMetadata.EffortLevel / PermissionMode /
// CollaborationMode. They are session-level CURRENT settings, not per-turn
// history, and no grounding session set an effort (absent ⇒ no stamp). The git
// branch (settings.metadata.lastUsedGitBranch) is stamped as GitBranch.
//
// Tool version: the store records none, so every session is stamped with the
// installed build (version.go: highest <home>/.dimcode/binaries/dimcode-*/<ver>
// directory, else the npm package.json), first-wins-unless-empty.
//
// Session handoff: ReadTranscript / ReadTranscriptFull (transcript.go) re-read
// one session from the same store.
//
// # Not captured / off-limits
//
// The providers table and ~/.dimcode/v2/providers.json hold provider
// credentials and base URLs and are NEVER read; neither are auth.json,
// permissions.json, mcp.json, hooks.json, web-plugin.json, file_checkpoints or
// blob_data. User attachments are not captured (the attachments column was
// empty in every row, so its shape is ungrounded). See docs/dimcode-adapter.md.
package dimcode
