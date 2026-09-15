// Package kirocli implements the SuperBased Observer adapter for AWS's
// Kiro CLI (`kiro-cli`, the rebranded Amazon Q Developer CLI;
// models.ToolKiroCLI).
//
// # Mode-dependent multi-layout store
//
// Kiro persists a session in ONE of three layouts depending on how the
// run was invoked (layouts 1 + 2 live-verified 2026-07-09 on WSL Ubuntu
// + Windows 11; layout 3 is BUNDLE-DERIVED — see below). A single
// package parses all three, dispatching on the file shape at
// IsSessionFile / ParseSessionFile time — the same
// one-package/multi-layout pattern antigravity uses for its `.pb`
// desktop store vs its plaintext-protobuf `.db` CLI store.
//
//	Layout 1 — interactive flat bundles.
//	  ~/.kiro/sessions/cli/<uuid>.json   full session state; when the
//	                                     turn accounting has been
//	                                     flushed it carries
//	                                     session_state.conversation_metadata
//	                                     .user_turn_metadatas[] with
//	                                     input/output_token_count,
//	                                     context_usage_percentage and
//	                                     metering_usage credits. A live
//	                                     or killed session's .json may
//	                                     LACK user_turn_metadatas and
//	                                     carry only the envelope keys —
//	                                     both shapes are tolerated.
//	  ~/.kiro/sessions/cli/<uuid>.jsonl  the append-only message stream
//	                                     ({"kind":"Prompt"|"AssistantMessage",
//	                                     "data":{message_id,content:[{kind:
//	                                     "text",data}],meta:{timestamp}}}).
//	  ~/.kiro/sessions/cli/<uuid>.history  raw input lines (ignored).
//	  ~/.kiro/sessions/cli/<uuid>.lock     lock sentinel (ignored).
//	  The .kiro/sessions/cli path is identical on every OS (Windows uses
//	  C:\Users\<u>\.kiro\sessions\cli, NOT %LOCALAPPDATA%).
//
//	Layout 2 — non-interactive SQLite.
//	  ~/.local/share/kiro-cli/data.sqlite3           (Linux/macOS)
//	  %LOCALAPPDATA%\Kiro-Cli\data.sqlite3           (Windows)
//	  table conversations_v2(key TEXT = RAW cwd string,
//	                         conversation_id TEXT,
//	                         value TEXT = full JSON conversation,
//	                         created_at INTEGER ms, updated_at INTEGER ms).
//	  The `value` JSON carries history[] of user/assistant turns plus
//	  env_context.env_state.current_working_directory. On Windows the
//	  `key` is a raw `C:\...` string — the KEY itself is crossmount-
//	  translated. The sqlite `conversations` (v1) and `history` tables
//	  are legacy shell-history — never read for chat.
//
//	Layout 3 — Kiro IDE (AWS's VS Code fork, agent extension
//	kiro.kiro-agent). The SIBLING subtree of the CLI's `cli/` bundles,
//	under the SAME `~/.kiro/sessions` parent on every OS:
//	  ~/.kiro/sessions/<bucket>/<sessionId>/session.json
//	                                         zod schema `hV`: schemaVersion,
//	                                         id, title, agentMode,
//	                                         workspacePaths[], rootPaths[],
//	                                         createdAt, lastModifiedAt,
//	                                         modelId?, effortLevel?, ...
//	  ~/.kiro/sessions/<bucket>/<sessionId>/messages.jsonl
//	                                         {id, timestamp(ISO), payload:{type}}
//	                                         with type ∈ session_start | user |
//	                                         assistant(Say/Reasoning/Print/
//	                                         Summary) | tool_call | tool_result |
//	                                         turn_start | turn_end |
//	                                         session_metadata | session_event |
//	                                         sub_agent_start | tombstone.
//	  ~/.kiro/sessions/<bucket>/<sessionId>/snapshots/**   never read
//	  ~/.kiro/sessions/<bucket>/<sessionId>/sub-executions/<execId>.jsonl
//	                                         NOT a trigger — skipped silently
//	                                         (record shape unverified; the
//	                                         parent messages.jsonl fires on its
//	                                         own writes anyway).
//	  <bucket> is sha256(normalized workspaceFolders).hex[:16], or the
//	  literal `global` (a window with no folder). The literal `cli` is
//	  layout 1 and is never an IDE bucket.
//
//	  GROUNDING: layout 3 is BUNDLE-DERIVED (kiro.kiro-agent 1.0.776 read
//	  verbatim 2026-09-02) — no logged-in Kiro IDE session existed on the
//	  capture box (AWS Builder ID gate). The record union, the field
//	  names and the bucket formula are read out of the extension's own
//	  zod schemas; the fixtures under testdata/kirocli/ide/ are
//	  synthesised from them, NOT captured live. One logged-in session is
//	  the outstanding verification (docs/kiro-cli-adapter.md, "Operator
//	  verification checklist").
//
// # Watch-root breadth: snapshots/ and sub-executions/ are cheap rejects
//
// The watch root is the PARENT `~/.kiro/sessions`, not
// `~/.kiro/sessions/cli`, because one prefix root has to cover both
// file-backed layouts (see roots.go). The watcher's addRecursive adds
// every directory under a root, so the IDE subtree's `snapshots/**` and
// `sub-executions/` directories are watched too, and every write into
// them raises an fsnotify event that classifyLayout immediately rejects
// (it accepts only `<sid>/messages.jsonl` — see adapter.go's exclusion
// comment and the ide_test.go matrix rows that pin it).
//
// This is deliberate and accepted, not an oversight. There is no
// adapter-declared ignore/exclude hook in internal/watcher today (the
// only optional adapter interface is CursorSemantics), and adding a
// watcher API for one adapter's subdirectory would be a cross-cutting
// change for a cost that is two string comparisons per event. The real
// cost is the inotify watch descriptors those directories consume on
// Linux, which scales with snapshot count per session; if an operator
// ever hits `inotify_add_watch: no space left on device` on a heavy
// Kiro IDE install, THAT is the signal to build a general
// adapter-declared exclusion mechanism — for every adapter, not a
// kirocli special case.
//
// # One tool id, two surfaces
//
// Kiro IDE sessions are tagged models.ToolKiroCLI ("kiro-cli") like
// every other layout — deliberately. The tool id encodes the CAPABILITY
// SHAPE (SigV4 CodeWhisperer wire ⇒ no proxy lane, no Tier-1 tokens,
// same cost model), and that is identical for the IDE. What differs is
// the CLIENT, which rides the surface columns instead:
// ParseResult.SessionSurfaces stamps `cli`/`kiro-cli` for layouts 1 + 2
// and `ide`/`kiro` for layout 3, through the single layoutSurfaces
// table (one row per layout — CLAUDE.md #3/#5). A separate tool id
// would fork the registry row, the cost engine and the parity matrix
// for a difference the surface columns already carry.
//
// # Token honesty
//
// Kiro CLI authenticates to SigV4 CodeWhisperer endpoints, so the
// proxy CANNOT intercept its traffic — there is NO Tier-1 capture. The
// flat bundle's user_turn_metadatas carry input/output_token_count but
// they were observed to be 0 for every captured turn; the adapter emits
// those counts honestly (0 included) tagged unreliable rather than
// fabricating a value. The SQLite request_metadata carries token fields
// (total_tokens / uncached_input_tokens / output_tokens /
// cache_read_input_tokens / cache_write_input_tokens) but they were all
// null in every capture — no token event is emitted when they are null.
// The metering_usage "credit" values are kiro credits, NOT tokens and
// NOT US dollars; they are deliberately NOT stored (mapping them onto a
// TokenBundle or a USD cost column would be a fabrication).
//
// The Kiro IDE layout persists NO token counts AT ALL — the only usage
// signal on disk is session_metadata{key:"contextUsage"} carrying a
// `usagePercentage`, which is a context-window fraction, not a token
// count and not convertible into one. parseIDESession therefore emits
// ZERO TokenEvents. That is the honest state of the store, not a
// parsing gap; a token row synthesised from a percentage would be a
// fabrication of exactly the kind the metering_usage credits are
// refused for above.
//
// # Security
//
// The adapter enumerates ONLY conversations_v2 in the SQLite store. The
// auth_kv table (`kirocli:social:token`), the state table
// (`telemetry-cognito-credentials`, `telemetry-cognito-identity-id`,
// `api.codewhisperer.profile`, …) and the `.history` files are NEVER
// read. In the IDE subtree only `messages.jsonl` and its sibling
// `session.json` are opened: the `snapshots/**` file copies (verbatim
// workspace source, potentially secrets) and the two `node:sqlite`
// memory stores (`memories`, `memory_scopes`) are never touched.
package kirocli
