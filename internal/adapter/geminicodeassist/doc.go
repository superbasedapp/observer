// Package geminicodeassist is an UNREGISTERED skeleton adapter for the
// Chat Mode half of Google's Gemini Code Assist VS Code extension
// (`google.geminicodeassist`).
//
// It exists so the roots, the file-shape predicate, the off-limits table
// and the fixture recipe are written down BEFORE the login-gated
// grounding session that will confirm the record shapes. It is deliberately
// wired into nothing (see "Not registered" below), so it has zero runtime
// effect on any install.
//
// # Provenance and confidence
//
// Everything below is grounded in a read of the shipped extension bundle
// `google.geminicodeassist` 2.98.0 on 2026-09-02
// (docs/audits/ide-session-tracking-audit-2026-09-02.md §3.7). It is a
// STATIC read: no signed-in session ever produced a byte of this data on
// the measurement host — `globalStorage/google.geminicodeassist` was
// absent entirely. Confidence marks in this file are carried forward
// verbatim from that audit and MUST NOT be upgraded without a live
// capture:
//
//	[STATIC-GROUNDED]  the string literally appears in the bundle (a
//	                   directory name, a memento key, a JSON field name)
//	[UNVERIFIED]       neither observed nor stated — this package's own
//	                   placeholder, to be replaced at grounding time
//
// # Two modes, one of them already captured
//
// Gemini Code Assist ships two distinct agents inside one extension:
//
//   - Agent Mode bundles `@google/gemini-cli-core` (`GeminiClient`,
//     `Scheduler`, `Config`) with `USER_SETTINGS_DIR = join(homedir(),
//     ".gemini")`, `TMP_DIR_NAME = "tmp"`, `CHATS_DIR = "chats"`,
//     `SESSION_FILE_PREFIX = "session-"`, so `Storage.getProjectTempDir()`
//     resolves to `~/.gemini/tmp/<projectId>/chats/session-<ISO>-<sid8>.jsonl`
//     [STATIC-GROUNDED]. That is byte-for-byte the store
//     internal/adapter/gemini already parses, so Agent Mode is CAPTURED
//     today and is tagged `gemini-cli`. It is explicitly OUT OF SCOPE
//     here, and this package must never claim a path under `~/.gemini`.
//
//   - Chat Mode is the sidebar chat, and is NOT captured anywhere. It is
//     the only subject of this package.
//
// # Chat Mode candidate stores
//
// Three, all under the host editor's VS Code user-data tree:
//
//	<globalStorage>/state.vscdb                                 memento DB
//	<globalStorage>/google.geminicodeassist/metrics_to_send/    token spool
//	<globalStorage>/google.geminicodeassist/chat_checkpoint_files/
//
// Taken in turn:
//
//   - The memento. Chat threads are persisted through the VS Code
//     `globalState` memento under key `geminiCodeAssist.chatThreads`
//     [STATIC-GROUNDED], which VS Code stores as one `ItemTable` row keyed
//     `google.geminicodeassist` inside the shared `state.vscdb` SQLite
//     file [STATIC-GROUNDED — that is how every VS Code memento is
//     stored]. The JSON shape of a thread — its id, its message array,
//     any timestamps — is UNVERIFIED and login-gated: the extension will
//     not create a thread without a signed-in Google account.
//
//   - The metrics spool. `sendMetricsFromDisk` drains
//     `metrics_to_send/<uuid>.tmp` → `<uuid>.json` [STATIC-GROUNDED].
//     Records carry event names `CHAT_STREAMING_OFFERED_START` and
//     `CHAT_STREAMING_OFFERED_CHUNK` and a `usageMetadata` object whose
//     four field names — `promptTokenCount`, `candidatesTokenCount`,
//     `totalTokenCount`, `cachedContentTokenCount` — are read verbatim
//     out of the bundle [STATIC-GROUNDED]. The ENCLOSING envelope is
//     [UNVERIFIED]: whether the file holds one object, an array of
//     events, or an object with an events array, and at what nesting
//     depth `usageMetadata` sits, was never observed. parseSpool is
//     written to tolerate all of those.
//     The spool is also TRANSIENT by design: a file is written,
//     uploaded, and DELETED. Capture off it is therefore best-effort
//     even once grounded, and a fixture copy has to be taken
//     immediately after a prompt, before the next upload tick drains it
//     (testdata/geminicodeassist/README.md).
//
//   - The checkpoints. `chat_checkpoint_files/` [STATIC-GROUNDED as a
//     directory name] holds per-chat checkpoint files whose contents,
//     naming and relationship to a thread id are all [UNVERIFIED].
//
// `agent/src/persistence/gcs.js` in the same bundle is a SERVER-side
// Google Cloud Storage task store, not a local one — nothing to watch.
//
// # Off-limits
//
// Never opened by this package, at any point, grounded or not:
//
//   - `~/.gemini/oauth_creds.json` and `~/.gemini/google_accounts.json` —
//     OAuth material and account identity.
//   - Any file under `<globalStorage>/google.geminicodeassist/` whose name
//     contains `auth`, `credential`, `token`, `secret` or `account`; the
//     two directory roots declared in roots.go are the ONLY subtrees this
//     package watches, and neither is an auth store.
//   - The OS keyring / Windows Credential Manager entries the extension
//     uses for its refresh token.
//   - `<globalStorage>/state.vscdb`'s other `ItemTable` rows: even once a
//     reader exists it must select the single `google.geminicodeassist`
//     key, never scan the table (other extensions' rows routinely carry
//     secrets).
//
// The skeleton opens no SQLite database at all — see ParseSessionFile.
//
// # Token tier, once grounded
//
// The spool's `usageMetadata` is the only token signal any Chat Mode
// store is known to carry. Gemini's `promptTokenCount` is GROSS: it
// INCLUDES `cachedContentTokenCount`. The cost engine's TokenBundle.Input
// contract is NET non-cached, so the netting arithmetic must mirror
// internal/adapter/gemini/parser.go::tokenEventFor exactly —
//
//	CacheReadTokens = cachedContentTokenCount
//	InputTokens     = max(0, promptTokenCount - cachedContentTokenCount)
//	OutputTokens    = candidatesTokenCount
//
// — or the cached portion is double-billed. `totalTokenCount` is a
// derived sum and is deliberately not stored. Nothing in the bundle
// exposes a thoughts/reasoning count, so ReasoningTokens stays 0.
//
// Reliability is models.ReliabilityUnreliable, matching
// internal/adapter/kirocli's treatment of counts it cannot vouch for.
// Source stays models.TokenSourceJSONL — the numbers are vendor-reported
// off a JSON file on disk, so tagging them models.TokenSourceEstimated
// would be dishonest in the other direction; what is unreliable is our
// reading of the envelope, not the vendor's arithmetic.
//
// # Not registered
//
// This package is NOT wired into anything. It is absent from
// internal/adapter/defaults, absent from config.Default().EnabledAdapters,
// has no models.Tool* constant (the tool id lives here as ToolName until
// registration) and no internal/integration capability row. The watcher
// never constructs it, so it watches nothing and parses nothing on a real
// install. This is the skeleton-package convention of
// docs/plans/uncaptured-surfaces-wiring-plan-2026-09-03.md §4 note 1.
//
// Wiring checklist for the LATER commit that registers it, after the P3
// step-in (docs/plans/uncaptured-surfaces-login-schedule-2026-09-03.md §1)
// has produced a real fixture under testdata/geminicodeassist/:
//
//  1. Add `models.ToolGeminiCodeAssist = "gemini-code-assist"` in
//     internal/models/models.go and switch ToolName here to reference it.
//  2. Register the adapter in internal/adapter/defaults/defaults.go and
//     confirm TestRegistryRootsNonOverlapping still passes (see roots.go
//     for the state.vscdb ownership decision that keeps it passing).
//  3. Add `"gemini-code-assist"` to config.Default().EnabledAdapters and
//     refresh the adoptadapters goldens.
//  4. Add the internal/integration capability row (Proxy / Routability /
//     Hook / MCP / Native / TokenTier) and bump RegistryVersion.
//  5. Decide adapter.CursorSemantics. The metrics spool looks like a
//     CursorNoActions file (token records only) and state.vscdb like a
//     CursorWatermark one, but that interface's own doc requires
//     evidence from a live DB before either is declared — so the
//     skeleton declares neither and keeps byte-offset semantics.
//  6. Replace every [UNVERIFIED] mark in this package with the grounded
//     shape, and add docs/gemini-code-assist-adapter.md + a row in
//     docs/adapters.md and docs/README.md.
package geminicodeassist
