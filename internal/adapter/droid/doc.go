// Package droid implements the adapter for Factory AI's agentic CLI
// ("droid", binary `droid`; "Factory AI" is the company, "droid" the
// product — see [models.ToolDroid]).
//
// # Storage shape
//
// droid persists one append-only JSONL transcript per session plus a
// sibling settings sidecar:
//
//	~/.factory/sessions/<dash-encoded-cwd>/<uuid>.jsonl
//	~/.factory/sessions/<dash-encoded-cwd>/<uuid>.settings.json
//	~/.factory/sessions/<dash-encoded-cwd>/<uuid>.settings.json.bak
//
// The same relative layout is used on Windows (%USERPROFILE%\.factory) —
// there is no %APPDATA%/%LOCALAPPDATA% split, mirroring kilo-code's
// XDG-everywhere choice.
//
// Every JSONL line is a complete, typed JSON object. The observed
// `type` vocabulary is:
//
//   - session_start        — always line 1: id / title / owner / version /
//     cwd / hostId.
//   - message              — `message.role` user|assistant with Anthropic-
//     shaped `message.content[]` blocks (text, thinking, tool_use,
//     tool_result). Assistant messages carry `message.modelId`; under the
//     OpenAI BYOK path they also carry openaiMessageId / openaiPhase /
//     openaiEncryptedContent / openaiReasoningId / reasoningEffort.
//   - agent_turn_outcome   — turnId / reason (completed|error|…) /
//     resultKind. One per assistant-turn boundary. Carries NO timestamp.
//   - compaction_state     — summaryText / summaryTokens / summaryKind /
//     anchorMessage / removedCount + a `systemInfo` snapshot of live
//     pwd/ls/git status/git log command+output pairs.
//   - todo_state           — droid's TodoWrite mirror; `todos.todos` is a
//     single flattened markdown STRING, not a structured array.
//
// # Message visibility
//
// `message.visibility` discriminates three kinds of user-role record:
//
//   - absent      — a real user prompt        → [models.ActionUserPrompt]
//   - "llm_only"  — droid's per-turn context injection (system-reminder
//     blocks listing available tools / skills / the current date). The
//     body IS content, so it maps to [models.ActionSystemPrompt], and the
//     SourceEventID is a content hash so the identical block repeated on
//     every turn collapses to one row per distinct payload.
//   - "user_only" — a host notice never sent to the model ("No active
//     subscription found.")  → [models.ActionNotification]. The most
//     recent notice is also reused as the ErrorMessage of a subsequent
//     failed agent_turn_outcome, which itself carries no message.
//
// tool_result blocks arrive inside user-role messages (Anthropic shape)
// and are matched back to their tool_use by `tool_use_id`.
//
// # Cursor discipline
//
// The byte cursor advances past every fully terminated line, with two
// deliberate deferrals: a partially written trailing line, and the
// record of a tool_use whose tool_result has not landed yet. The second
// exists because store's action ON CONFLICT clause updates neither
// `success` nor `error_message` — an optimistic row shipped between the
// two records could never be corrected — so the pair MUST resolve in one
// parse window. Bounded by adapter.MaxDeferTailBytes +
// adapter.PendingResultGrace so an interrupted call cannot stall
// ingestion; see adapter.DeferUnpairedTail.
//
// A resumed parse (fromOffset > 0) first replays [0, fromOffset) with
// emission suppressed to rebuild the running model id, the last
// user_only host notice and the last record timestamp — the codex
// prefetchSessionContext shape. See replayPrefix.
//
// # Token capture
//
// droid has NO per-message usage envelope anywhere in the JSONL — tokens
// are SESSION-LEVEL cumulative only, in the sidecar `<uuid>.settings.json`:
//
//	tokenUsage           — this session alone
//	inclusiveTokenUsage  — this session + childInclusiveTokenUsageBySessionId
//	lastCallTokenUsage   — the most recent single API call only
//
// The adapter emits ONE [models.TokenEvent] per session from the
// self-only `tokenUsage` block under the stable SourceEventID
// `tokens:<session-id>`, exactly like the goose adapter's session-level
// accumulators. Re-reading a grown sidecar re-emits the same id with
// larger counts, and store.InsertTokenEvents' ON CONFLICT MAX-upgrade
// absorbs it — no adapter-side dedup is needed. `inclusiveTokenUsage` is
// deliberately NOT used: mission/child sessions get their own transcript
// + sidecar pair, so rolling them up here would double-count them.
//
// `lastCallTokenUsage` is deliberately NOT emitted either — it is a
// subset of the cumulative block and emitting both would double-count.
//
// KNOWN CLASS LIMITATION — day attribution. store.InsertTokenEvents'
// ON CONFLICT clause upgrades counts / model / cost / ids but NOT
// `timestamp`, so the single cumulative row stays stamped at the moment
// it was first inserted. A session left open across a day boundary
// books all its tokens on day one. This is shared by every
// session-level-token adapter — goose (`tokens:<session-id>` +
// sessions.updated_at) and crush (`tokens:<session id>`) key their rows
// identically and freeze the same way. Splitting into per-snapshot ids
// would fix the date but break the MAX-upgrade, since the snapshots are
// cumulative and N rows would sum far above the session's real usage.
// droid matches the goose precedent rather than inventing a divergent
// scheme; real per-turn attribution needs a per-message usage envelope
// droid does not write.
//
// GROSS-vs-NET: droid's persisted `inputTokens` is already NET of
// `cacheReadTokens` and is NOT re-netted here. Evidence:
// `inputTokens(3131) < cacheReadTokens(23040)` on the Linux BYOK fixture
// and `inputTokens(303) < cacheReadTokens(16896)` on the Windows one —
// GROSS would require input ≥ cacheRead. droid appears to normalize
// client-side even under an OpenAI-shaped BYOK call, where the provider's
// own wire `prompt_tokens` is GROSS. CAVEAT: this is confirmed for the
// BYOK path only (both data points are the same custom-model pairing);
// the Factory-hosted built-in-model path is unconfirmed. See
// docs/droid-adapter.md "Tokens and limitations".
//
// Tier: `source='jsonl'`, `reliability='approximate'` — the counts are
// droid's own bookkeeping, not a raw provider usage envelope.
// `factoryCredits` (a droid-specific consumption unit) is out of
// TokenBundle scope and not consumed. ToolEvent.ContentBytes is left
// unset: droid's tool schemas were not grounded well enough in Phase 0 to
// compute authored-code bytes honestly.
//
// # Model strings
//
// Model ids are recorded VERBATIM (`claude-opus-5`,
// `custom:GPT-5.4-Mini-[OpenAI-BYOK]-0`). The `custom:` ids are
// operator-defined BYOK aliases whose underlying model and price are
// unknowable from the transcript, so they are never rewritten onto a
// pricing-table key — a wrong price is worse than no price.
//
// # Project root
//
// The `<dash-encoded-cwd>` directory name is LOSSY (a real path component
// containing a dash is indistinguishable from a separator), so it is
// never decoded. The authoritative project root is the inline `cwd` on
// the session_start event, which is read from line 1 of the transcript on
// EVERY parse — including resumed parses that start past it. The cwd goes
// through crossmount.TranslateForeignPath BEFORE git.Resolve so a Windows
// `C:\...` session read by a WSL2 observer maps to `/mnt/c/...` instead of
// being treated as a relative path and prefixed with the observer's own
// cwd.
//
// # Security
//
// WatchPaths is scoped to `~/.factory/sessions` ONLY, never the parent
// `~/.factory`. The adapter never reads:
//
//   - ~/.factory/settings.json      — global config; embeds plaintext
//     customModels[].apiKey
//   - ~/.factory/auth.v2.file, auth.v2.key, auth.json, certs/, cache/certs/
//   - ~/.factory/history.json       — raw prompt/command history (the droid
//     analogue of cline-cli's excluded user_input_history.jsonl)
//   - ~/.factory/cache/session-discovery-index.json — regeneratable cache
//   - ~/.factory/logs/              — droid's own application log
//   - <uuid>.settings.json.bak      — the PRIOR settings snapshot; its
//     token counts are by definition stale and re-emitting them under the
//     same session id would fight the MAX-upgrade
//
// `<uuid>.settings.json` is a DERIVED path — whatever sits at that name
// is read without the watcher having claimed it — so readSidecar
// os.Lstats it first and refuses symlinks, treating one exactly like a
// missing sidecar. Without that guard a symlink planted at the sidecar
// name would redirect the read at any of the files above.
//
// All prompt text, assistant text, tool inputs, tool outputs and error
// bodies pass through the injected scrub.Scrubber before leaving the
// adapter. compaction_state's embedded `systemInfo` git/directory
// command OUTPUT pairs are dropped entirely rather than stored.
package droid
