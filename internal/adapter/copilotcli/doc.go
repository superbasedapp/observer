// Package copilotcli ingests GitHub Copilot CLI session data.
//
// Copilot CLI is GitHub's agentic terminal tool, npm-installed as
// `@github/copilot` (binary `copilot`). It is distinct from the
// VS Code Copilot Chat extension (which is covered by
// internal/adapter/copilot under models.ToolCopilot). Both products
// share GitHub branding but have separate on-disk layouts and event
// schemas; this adapter exists because conflating them would
// corrupt per-tool dashboard slicing.
//
// On-disk layout (per OS user home, cross-mount via crossmount.AllHomes):
//
//	<home>/.copilot/
//	├── session-state/<session-uuid>/
//	│   ├── events.jsonl        ← per-session event stream (primary data)
//	│   ├── workspace.yaml      ← session metadata (cwd / git_root / branch)
//	│   ├── session.db          ← per-session SQLite (todos + inbox; skip)
//	│   └── …                   ← checkpoints/ rewind-snapshots/ files/ research/
//	└── logs/
//	    └── process-<ts>-<pid>.log  ← global per-PID log (token-capture source)
//
// Token-capture (four-tier graceful degradation, see
// docs/copilot-cli-adapter-plan.md §3 + §11):
//
//   - Tier 1 (accurate, source='otel'): when Copilot CLI runs at
//     --log-level debug, the per-process log captures every
//     upstream-API response as `[DEBUG] response (Request-ID 00000-…):`
//     plus a pretty-printed JSON with the full `usage` object
//     (prompt_tokens,
//     completion_tokens, prompt_tokens_details.cached_tokens,
//     completion_tokens_details.reasoning_tokens). Joined to
//     events.jsonl assistant.message rows via the Request-ID
//     (matches assistant.message.requestId). When present, supersedes
//     Tier 0 and Tier 3 for the same session via the store-layer
//     dedup paths.
//
//   - Tier 2 (approximate, source='log_delta'): even at default INFO
//     level the log captures `CompactionProcessor: Utilization X%
//     (CTX/128000 tokens)` snapshots before every API call. The raw
//     CTX value is the gross prompt size at request time. Captures
//     InputTokens only; OutputTokens is filled by the matching Tier 3
//     row via MessageID = Request-ID.
//
//   - Tier 3 (output-only, source='jsonl'): events.jsonl exposes
//     assistant.message.outputTokens unconditionally with
//     MessageID = requestId. Always active.
//
//   - Tier 0 (session aggregate, source='session_summary'):
//     events.jsonl `session.shutdown.data.modelMetrics` carries
//     per-model cumulative usage delta for the work span since the
//     most recent `session.resume` — inputTokens, outputTokens,
//     cacheReadTokens, cacheWriteTokens, reasoningTokens. Each
//     shutdown is its own delta block (verified empirically: summing
//     all shutdowns in a session matches Tier 3 totals). Captured to
//     fill the input/cache/reasoning gap for users not running in
//     debug mode — without Tier 0, ~90% of cost would silently
//     disappear off the dashboard. OutputTokens is left zero to
//     avoid double-counting with Tier 3 per-message rows. When Tier 1
//     rows exist for the same session, the store-layer dedup drops
//     Tier 0 rows (Tier 1 has finer per-request granularity).
//
//   - Compaction (source='jsonl', per-event MessageID):
//     events.jsonl `session.compaction_complete.data.compactionTokensUsed`
//     carries the input/output/cache_read for each compaction call.
//     Verified empirically these are NOT included in
//     `session.shutdown.data.modelMetrics` — sum of modelMetrics
//     outputs across all shutdowns matches Tier 3 (assistant.message)
//     outputs within 0.2%, while compactionTokensUsed.output is
//     additive on top. Two observed schema variants: older
//     `{input, output, cachedInput}` (38/39 events in the sampled
//     log) and newer `{inputTokens, outputTokens, cacheReadTokens,
//     cacheWriteTokens, model}` (1/39 in the sampled log). The
//     adapter resolves either shape via field-fallback. Model is
//     taken from the payload when present, else falls back to
//     st.model (the session's active model). MessageID is the
//     payload's requestId when present (joins to Tier 1 otel rows
//     for the same compaction call via the v1.6.3 T1 dedup), else
//     "compaction:<env.ID>".
//
// token_usage rows are upserted ON CONFLICT(source_file,
// source_event_id) so a later Tier-1 log scan enriches an earlier
// events.jsonl row without double-counting. Same-session cross-tier
// dedup is handled at the store layer (see
// store.InsertTokenEvents).
//
// # Capture surface
//
// `workspace.yaml`'s `client_name` line is the ONE grounded
// discriminator for which client drove a session — surface.go resolves
// it into a models.SessionSurface stamp (`JetBrains.<Product>` →
// ide/jetbrains-<product>; `github/cli` → cli/copilot-cli; anything
// else → no stamp). It is read through the SAME
// resolveProjectFromWorkspaceYAML that already resolves the project
// root, from both the events.jsonl and the process-log lanes, so there
// is one reader of that file and one owner of the mapping. Nothing in
// the event stream itself distinguishes the lanes:
// `session.start.data.producer` is "copilot-agent" and `copilotVersion`
// is just the CLI build in both cases. See surface.go's file doc for
// the honesty rules, and testdata/copilotcli/README.md for the
// grounding capture.
package copilotcli
