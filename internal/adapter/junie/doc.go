// Package junie parses JetBrains Junie session logs.
//
// # The tool — three surfaces, one store
//
// "Junie" now names three distinct surfaces, all sharing the same
// `${JUNIE_HOME:-~/.junie}/sessions` store (2026-09-03 grounding, plan
// ticket U2):
//
//   - The IDE plugin — a TUI embedded inside JetBrains IDEs (IntelliJ
//     IDEA, PyCharm, etc.). This is what Phase-0 grounding captured (two
//     real `hello world`-scale sessions on the operator's own WSL2
//     Ubuntu install, 2026-08-16). JetBrains has since merged the Junie
//     plugin into AI Assistant (`com.intellij.ml.llm`); the doc's
//     original "not a standalone CLI" framing predates the standalone
//     CLI below and is now stale.
//   - A standalone `junie` CLI (junie.jetbrains.com/docs/junie-cli.html):
//     install via `curl -fsSL https://junie.jetbrains.com/install.sh |
//     bash` (macOS/Linux), `npm i -g @jetbrains/junie`,
//     `brew install jetbrains/junie/junie`, or the Windows
//     `install.ps1`. Auth is one of four modes: JetBrains account,
//     `JUNIE_API_KEY` (usage-billed), BYOK (OpenAI/Anthropic/Google/
//     xAI/OpenRouter/GitHub Copilot), or a custom endpoint
//     (LiteLLM/Ollama/LM Studio). `~/.junie/allowlist.json` holds
//     approved commands for this surface.
//   - `/local` — a CLI subcommand that runs a local ~20 GB Qwen3.6-27B
//     model instead of a remote provider.
//
// As of 2026-09-07 this adapter DOES distinguish two of the three
// surfaces: a live standalone CLI session has now been captured
// alongside a same-prompt IDE run, and diffing the two `events.jsonl`
// files surfaced two positive structural markers (see "Capture
// surface" below and surface.go for the full grounding), so a session
// is now self-stamped `cli`/`junie-cli` or `ide`/`jetbrains` per the
// codebase's honesty rule (a grounded positive discriminator, never an
// absence, drives the stamp). The gap that remains is the third
// surface, `/local`, and the pre-AI-Assistant-merge plain-plugin lane
// (2026-08-16 vintage): neither carries either positive marker, so a
// session from either one still gets no `surface`/`surface_host`
// value at all — honestly, not a regression (see "Known gaps" below).
//
// # JUNIE_HOME
//
// All three surfaces resolve their session store from
// `${JUNIE_HOME:-~/.junie}/sessions` — a decompiled-jar finding (the
// 2026-09-02 IDE audit's IDE-17 row), not documented on the CLI's own
// page. When set, `defaultRoots` puts `$JUNIE_HOME/sessions` FIRST in
// WatchPaths (absolutized via `absHomeEnv`, same convention as
// clinecli's `CLINE_DIR` and qwencode's `QWEN_HOME`), deduped against
// the per-cross-mount-home `~/.junie/sessions` defaults that are still
// emitted alongside it. A relocated store carries no `.junie` path
// segment at all, so `matchesShape`'s shape predicate falls back to
// "exactly two levels below one of the adapter's watch roots" (see
// adapter.go) when the literal `/.junie/sessions/` substring isn't
// present.
//
// # Storage layout
//
//	${JUNIE_HOME:-~/.junie}/
//	    settings.json                       model/provider config (fields
//	                                         read; credentials NEVER READ)
//	    secure_credentials.json              auth material     NEVER READ
//	    allowlist.json                       CLI approved-command list
//	                                                            NEVER READ
//	    trust/                               per-project trust decisions
//	                                                            NEVER READ
//	    sessions/
//	        index.jsonl                      one line per session:
//	                                         sessionId/createdAt/updatedAt/
//	                                         projectDir/taskName — used ONLY
//	                                         as a project-root fallback
//	        <session-id>/
//	            events.jsonl                 THE session log — the only
//	                                         file this adapter parses
//	            state.json                   UI-resume snapshot   not parsed
//	            transcript.md                human-readable render, mode
//	                                         600 on real sessions, not parsed
//	            task-<task-id>/.matterhorn/…  internal scratch dirs, not
//	                                         parsed
//
// The Windows path (`%USERPROFILE%\.junie`, mirroring the Unix
// `~/.junie` shape 1:1) is CONFIRMED as of 2026-09-03: an IntelliJ
// IDEA 2026.2 run on Windows 11 wrote
// `C:\Users\<user>\.junie\sessions\<session-id>\events.jsonl`, exactly
// the Unix shape, NOT the `%APPDATA%\JetBrains\<Product>` convention
// every other JetBrains-plugin adapter in this codebase uses. The
// fixture is testdata/junie/jetbrains-mcp/.
//
// The session id lives in the enclosing DIRECTORY name, not inside the
// file — sessionIDFromPath recovers it from the path
// (`…/sessions/<session-id>/events.jsonl`) rather than from any record
// field, since no record states its own session id. Both
// sessionIDFromPath and the index.jsonl fallback (indexProjectDir)
// resolve purely relative to the session log's OWN directory tree
// (`filepath.Dir`/`filepath.Base` off the file's path), never off a
// hardcoded `.junie` segment — so both already work unmodified under a
// JUNIE_HOME-relocated store.
//
// # Off-limits files
//
// This adapter reads `events.jsonl` (per session) and, as a fallback only,
// the sibling `index.jsonl`. It NEVER opens:
//
//   - `~/.junie/secure_credentials.json` — auth material.
//   - `~/.junie/allowlist.json` — the CLI's approved-command list; not
//     needed for session capture and not read by this adapter.
//   - `~/.junie/trust/` — per-project trust grants.
//   - `~/.junie/settings.json`'s credential fields (its model/provider
//     fields would be harmless to read, but this adapter does not read the
//     file at all — Junie's model id is instead read per-call off
//     `LlmResponseMetadataEvent.modelUsage[].model`, which is more precise
//     since a session can switch models mid-task).
//   - `<session>/state.json`, `<session>/transcript.md`,
//     `<session>/task-*/.matterhorn/…` — UI/scratch state, none of it
//     needed; `transcript.md` in particular is mode 600 on a real
//     install, matching the sensitivity of the events log it's rendered
//     from. `state.json` additionally carries the operator's ENTIRE
//     PROCESS ENVIRONMENT under its blob's `env` key. It does hold one
//     tempting field — `lastAgentParameters.ide_name` ("IDEA") — and
//     that is exactly why the capture-surface note below refuses to
//     read it.
//
// The same rule applies inside `events.jsonl`:
// `EnvironmentVariablesUpdatedEvent` carries the same environment, and
// its `env` field is NOT DECLARED on agentEventRaw at all, so no code
// path can decode, persist or emit it. That is a structural guarantee,
// not a filter.
//
// # Capture surface: self-stamped since 2026-09-07
//
// Junie's store still carries no explicit client/host/transport field
// on any observed record shape and none in index.jsonl — but on
// 2026-09-07 the operator captured a live standalone CLI session
// (`junie --session-id session-260907-002452-gk1t`) alongside a
// same-prompt IntelliJ IDEA 2026.2 AI-Assistant run
// (`session-260907-002018-1eui`), and diffing the two events.jsonl
// files surfaced two POSITIVE structural markers (surface.go carries
// the full grounding):
//
//   - IDE: the session's first UserPromptEvent carries an
//     extraAttachments entry of kind
//     "TaskRequestMcpServersAttachment" whose mcpServers[].env[] names
//     an IJ_MCP_AUTH_TOKEN key, naming the MCP server the IDE spawns
//     for Junie to call over MCP. The attachment kind alone is NOT
//     enough — the CLI lane also runs MCP clients once the operator
//     configures one, so the auth-token key name is what makes this
//     IDE-specific (see surface.go's hasIDEMCPAttachment). Present on
//     both real IDE-hosted captures (2026-09-03 jetbrains-mcp,
//     2026-09-07 IDE run); absent on the CLI run and on the older
//     2026-08-16 plain-plugin fixture (predates the AI-Assistant
//     merge).
//   - CLI: a top-level SessionCostTrajectorySnapshotEvent record — the
//     CLI's own end-of-task cost breakdown, emitted once right before
//     TaskState. Present on the 2026-09-07 CLI run; absent from BOTH
//     completed IDE fixtures (2026-09-03 AND 2026-08-16 both reach
//     TaskState:"COMPLETED" without ever emitting it), so this is a
//     genuine CLI-only feature, not an artifact of an incomplete
//     session.
//
// This adapter now emits a self-reported (Hosted=false)
// `cli`/`junie-cli` or `ide`/`jetbrains` models.SessionSurface when one
// of those markers is found; a session with neither marker (the
// pre-merge plain-plugin shape, or a truncated capture) still gets no
// stamp — honesty, not a regression. `state.json`'s `ide_name` remains
// rejected on the off-limits grounds above (and would still be
// ungrounded for the CLI lane), and the mere presence of `idea/…` MCP
// tools remains circumstantial on its own — the discriminator used here
// is the ATTACHMENT that hands Junie the MCP server, not the tool
// names it later calls through it.
//
// The IDE self-stamp can never fight JetBrains AI Assistant's own
// `aia-task-history/<task>.agentsession` record, which
// internal/surfaceenrich resolves into a Hosted=true `ide` /
// `jetbrains-<product>` stamp: store.setHostedSessionSurface lets a
// hosted stamp REPLACE a differing self-report outright, so the
// enricher's more specific product token always wins once its pointer
// resolves. This adapter's generic "jetbrains" host token exists only
// to cover the window (or the install) where that pointer never
// arrives.
//
// # Record shape
//
// `events.jsonl` is an append-only, event-sourced stream — not a chat
// transcript. Every line is one JSON object discriminated by a top-level
// `kind`:
//
//	UserPromptEvent                  the operator's verbatim prompt
//	TaskStartedEvent                 a task (turn) begins
//	SessionA2uxEvent                 the workhorse — see below
//	UserMessagesCommittedToHistory   correlates prompt ids already
//	                                 captured by UserPromptEvent; no new
//	                                 information, skipped silently
//	TaskState                        session-level state changes
//	                                 ("COMPLETED" observed); SKIPPED (see
//	                                 "Why TaskState is skipped" below)
//
// A `SessionA2uxEvent` wraps the real inner discriminated union one level
// down, at `event.agentEvent.kind` — NOT at the envelope's own top level:
//
//	{"kind":"SessionA2uxEvent","timestampMs":...,
//	 "event":{"state":"IN_PROGRESS","agentEvent":{"kind":"TerminalBlockUpdatedEvent", …}}}
//
// `event.state` ("IN_PROGRESS"/"COMPLETED") is a SIBLING of `agentEvent`,
// tracking the enclosing task's run state, not the block's own status.
// Only on a `ResultBlockUpdatedEvent` envelope, a `completion` object
// appears as a SIBLING OF `event` (not nested inside it):
// `{"event":{...},"completion":{"startedAtMs":...,"endedAtMs":...,"taskCostUsd":...}}`.
//
// 13 distinct `agentEvent.kind` values were observed in the 2026-08-16
// Phase-0 capture and 3 more (`McpBlockUpdatedEvent`,
// `ViewFilesBlockUpdatedEvent`, `ToolBlockUpdatedEvent`) in the
// 2026-09-03 IDE-hosted capture; 8 have a normalized-action counterpart
// and are acted on (see records.go's kind constants and mcpblocks.go's).
// The rest — `AgentCurrentStatusUpdatedEvent`,
// `EnvironmentVariablesUpdatedEvent`, `TipSuggestionCreatedEvent`,
// `AgentTaskNameUpdatedEvent`, `ContextWindowReportEvent`,
// `AgentPatchCreatedEvent`, `NextPromptSuggestionEvent` — are scheduler /
// UI / diagnostic bookkeeping with no counterpart and are skipped
// silently, as is `ToolBlockUpdatedEvent` (see mcpblocks.go for why).
//
// # Two tool lanes: built-in executors vs the host's MCP server
//
// WHO HOSTS the run decides which tool records it emits. Junie's own
// CLI and the plain plugin execute shell/file work themselves and emit
// `TerminalBlockUpdatedEvent`/`FileChangesBlockUpdatedEvent`. Run as the
// `junie` ACP agent inside JetBrains AI Assistant (IntelliJ IDEA
// 2026.2), the IDE serves its OWN tools over MCP and the run emits
// `McpBlockUpdatedEvent` instead — 42 of them, and ZERO of the other
// two, in the 2026-09-03 capture. Both lanes land through the same
// stepId collapse; see mcpblocks.go for the tool-name table and the
// `details`-mirrors-`input` / `cancelRequest`-is-not-a-cancellation
// findings.
//
// # Block collapse by stepId, and the rebroadcast-after-completion finding
//
// Terminal, FileChanges, Result, Mcp and ViewFiles blocks each carry a
// stable `stepId`
// that recurs across the block's own lifecycle: an `IN_PROGRESS`
// occurrence, then a terminal-status (`COMPLETED`/`FAILED`) occurrence.
// Once the ENCLOSING TASK finishes (`event.state` reaches `COMPLETED`),
// every block belonging to it is re-broadcast ONE MORE TIME, byte-for-byte
// identical except for a several-hundred-millisecond timestamp jitter —
// confirmed against all 6 stepId chains in the Phase-0 fixture — and
// again against all 8 MCP chains + 2 ViewFiles chains + the Result
// chain in testdata/junie/jetbrains-mcp/ —
// (`testdata/junie/session-260816-220304-lrfz/events.jsonl`), e.g. the
// Terminal block keyed `62c01dad-eff2-4fcc-bde3-332dde2a43c5` at lines
// 41 -> 45 -> 69 -> 208 (its terminal-status occurrence at line 69 reports
// FAILED). The parser's `stepIdx` map updates the existing ToolEvent row
// in place on every later occurrence of the same stepId, so the
// rebroadcast produces no duplicate row.
//
// # Why TaskState is skipped
//
// An earlier draft of this adapter mapped `TaskState:"COMPLETED"` to a
// session-end marker. That was wrong on two counts: TaskState carries no
// task id of its own (a session can run several tasks/turns in sequence),
// and it fires essentially simultaneously with the matching
// `ResultBlockUpdatedEvent`, which this adapter already turns into an
// `ActionTaskComplete` row per task. Emitting a second, taskless
// session-end row alongside that would be redundant and, on a multi-task
// session, actively misleading (which task ended?). TaskState is now
// skipped entirely — there is no dispatch case for it.
//
// # Why there is no pending.go
//
// Muse's parser defers an unpaired tail record across parse calls via a
// byte-offset rewind (pending.go), because a Muse tool-call record only
// becomes actionable once its LATER result record arrives, and the two
// can straddle a poll boundary.
//
// Junie's block records don't have that shape: every occurrence of a
// stepId — the IN_PROGRESS creation, the terminal-status update, and the
// completion rebroadcast — is a SELF-SUFFICIENT single-line record that
// already carries everything needed (command/output/status/details) to
// stand on its own. Nothing here is ever incomplete pending a later line.
//
// Two duplicate-suppression cases follow from that:
//
//   - IN-WINDOW duplicates (the same stepId recurring within one
//     ParseSessionFile call) are handled in memory via `parseState.stepIdx`,
//     which updates the existing `res.ToolEvents[idx]` row in place.
//   - CROSS-WINDOW duplicates (a stepId whose earlier occurrence was
//     emitted by a PRIOR parse call, e.g. the terminal-status update
//     arriving in a later poll tick than the IN_PROGRESS creation) are
//     handled by simply appending a new row with the SAME
//     SourceEventID — relying on the store's own
//     `ON CONFLICT(source_file, source_event_id) DO UPDATE` self-heal
//     (internal/store's insertActionSQL): `success` flips 1->0 only when
//     the new row also carries a non-empty `error_message` (which a
//     FAILED terminal-status update always does), `duration_ms` only
//     updates 0->nonzero, and `raw_tool_output`/`content_bytes` merge by
//     taking the longer/larger value — exactly the direction every later
//     occurrence of a Junie block moves in (IN_PROGRESS has the least
//     information, the terminal update has more, the rebroadcast is
//     identical to the terminal update). No separate deferral mechanism is
//     needed.
//
// # Tokens: NET input, provider-stated cost
//
// `LlmResponseMetadataEvent.modelUsage[]` carries one entry per model
// invoked to produce a turn. `inputTokens` is already NET of
// `cacheInputTokens` (both observed rows in the Phase-0 capture carried
// `cacheInputTokens: 0`, and JetBrains documents the field as the cache
// portion already reflected in, not additional to, the billed input) — no
// gross-vs-net subtraction is applied, unlike several other adapters in
// this codebase. `cost` is a genuine per-call dollar figure the log
// states directly, unlike Muse (which states none): it is carried
// straight through to `TokenEvent.EstimatedCostUSD`. Reliability is
// `models.ReliabilityAccurate` — the same tag cowork/openclaw/cursor use
// for provider-stated-exact counts — not `ReliabilityApproximate`.
//
// `completion.taskCostUsd` is a separate, TASK-level total (the sum of
// every modelUsage[].cost billed across the whole task); it is NOT added
// to any per-call Cost and is not currently surfaced on any emitted event.
// Only `completion.startedAtMs`/`endedAtMs` feed the Result action's
// DurationMs.
//
// # Project root resolution
//
// Unlike Muse (which states its workspace_root once, on essentially the
// first line, via a dedicated `runtime.session.metadata` record), Junie's
// `CurrentDirectoryUpdatedEvent` was observed roughly a quarter of the way
// into the fixture, and a resumed parse (fromOffset > 0) would never see
// it if the parser only read forward. ParseSessionFile therefore ALWAYS
// re-scans from byte 0 (readHeader / scanHeader, bounded to
// headerScanLines) on every call, mirroring Muse's own "always re-read the
// header" convention, before seeking to fromOffset for the real parse
// pass. When no such event is found within the bound (an interrupted
// session with no terminal/file-change block, for instance), the sibling
// `index.jsonl` is consulted by session id as a fallback
// (indexProjectDir). The same bounded scan also resolves the IDE
// capture-surface marker (see "Capture surface" above and surface.go)
// so a resumed parse doesn't miss it either.
//
// # Known gaps
//
//   - Only 6 of 13 observed `agentEvent.kind` values have a normalized
//     action; the rest are scheduler/UI bookkeeping (see above).
//   - `UserMessagesCommittedToHistory` and `TaskState` are both skipped —
//     see their sections above.
//   - No proxy route, no MCP entry, no verified interactive-resume/inject
//     contract exists yet for Junie (see
//     internal/integration/integration.go's Capability row); this is a
//     local-capture-only adapter today. That registry row (Binary/Names/
//     Launch) is owned by a separate, concurrent install-gap track — not
//     this package.
//   - The CLI/IDE surface discriminator (see "Capture surface" above)
//     covers only two of the three surfaces named in "The tool — three
//     surfaces, one store": a plain-plugin session (pre-AI-Assistant
//     merge) and a `/local` session still get no stamp, since neither
//     positive marker has been grounded against a live `/local`
//     capture, and the plain-plugin lane predates both markers by
//     construction.
//   - The Windows storage path (`%USERPROFILE%\.junie`) is an unverified
//     assumption (see "Storage layout" above).
package junie
