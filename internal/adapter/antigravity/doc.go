// Package antigravity parses session data from Google's Antigravity
// family — the desktop Antigravity IDE (a VS Code fork), the `agy`
// Antigravity CLI, and whichever of the family's other surfaces turn
// out to share those two stores. Since Google's 2026-06-18 retirement
// of Gemini CLI + Gemini Code Assist for individual / AI Pro / AI Ultra
// tiers, Antigravity is the successor family and the Google surface
// that matters for individual developers (the gemini-cli row is
// DEPRECATED on that event; Standard/Enterprise GCA is unaffected).
//
// # Stores and layouts
//
//	~/.gemini/antigravity/brain/<uuid>/.system_generated/logs/transcript.jsonl
//	    LayoutDesktopTranscript — the desktop IDE's PLAINTEXT per-step
//	    trace, a first-class session file since 2026-09-03 (transcript.go).
//	    Source of truth for a desktop conversation: user prompts,
//	    assistant text, one action row per tool result (run_command /
//	    read_file / write_file / edit_file / search_files, native tool
//	    names in raw_tool_name), the model DISPLAY name from the
//	    <USER_SETTINGS_CHANGE> block, project root from the tool calls'
//	    Cwd, surface stamp ide/antigravity. NO tokens — the file carries
//	    no usage and the adapter emits none rather than estimate.
//	~/.gemini/antigravity/conversations/<uuid>.db
//	    LayoutDesktopDB — an agy-backed conversation in the DESKTOP tree:
//	    the VS Code extension Google.google-antigravity bundles its own
//	    agy and writes a plaintext-protobuf SQLite with the CLI's exact
//	    schema (live-grounded 2026-09-03). Read by clidb.go: REAL
//	    per-generation tokens + API model id (gen_metadata), project from
//	    trajectory_metadata_blob → ~/.gemini/config/projects/<id>.json,
//	    surface from trajectory_meta.source (table: 17 = agy CLI →
//	    cli/antigravity-cli, 1 = VS Code extension → ide/vscode, other →
//	    the tree default ide/antigravity + raw value in
//	    ActionMetadata.CaptureSource + a warning), text + actions from
//	    the sibling brain/ transcript. The standalone IDE build wrote NO
//	    .db the same day — "has .db" currently distinguishes agy-backed
//	    clients from the IDE itself.
//	~/.gemini/antigravity/conversations/<uuid>.pb
//	    LayoutDesktop — the same conversation, OSCrypt-encrypted protobuf.
//	    Kept for the pre-2026-06-06 builds whose sidecar was
//	    overview.txt and for any host where decrypt still works; when a
//	    transcript.jsonl exists and this adapter watches brain/, the .pb
//	    reader DEFERS to it (parseSessionFile's ownership guard) so one
//	    conversation is never ingested from two files. The Windows cipher
//	    is unknown (audit IDE-12, parked) — decrypt is no longer needed
//	    for capture, only for tokens.
//	~/.gemini/antigravity-cli/conversations/<uuid>.db
//	    LayoutCLIDB — the agy CLI's plaintext-protobuf SQLite store with
//	    real per-generation tokens + model (clidb.go, same reader as
//	    LayoutDesktopDB), text + actions from the CLI's own
//	    brain/<uuid>/…/transcript.jsonl, surface from
//	    trajectory_meta.source (17 → cli/antigravity-cli).
//	~/.gemini/antigravity-acp/conversations/<uuid>.db
//	    LayoutCLIDB too — a THIRD tree the agy backend writes when driven
//	    by the JetBrains AI Assistant "antigravity-acp" ACP agent (grounded
//	    2026-09-04: identical schema, trajectory_meta.source=0, cascade_id
//	    == the conversation uuid == the ACP pointer sid). Captured as
//	    ToolAntigravityCLI; the source=0 self-stamp is the honest zero and
//	    the JetBrains enricher (jetbrainshost.acpAgents) supplies the real
//	    ide/jetbrains-idea host. The real run's brain/ is empty → token-only.
//	~/.gemini/antigravity-cli/conversations/<uuid>.pb
//	    LayoutCLI — the older agy store, decrypt/gRPC-bridge gated.
//
// # Ownership per conversation uuid (both trees)
//
//	.db                        tokens + model id + surface (its own rows) AND
//	                           text + actions synthesized from the transcript
//	brain/…/transcript.jsonl   text + actions (always parsed when it is a
//	                           session file, i.e. in the desktop tree)
//	conversations/<uuid>.pb    out-ranked by either of the above → emits nothing
//
// The .db and the transcript both synthesize the text + action rows and
// key them IDENTICALLY — SourceFile = the transcript path, SourceEventID
// = "antigravity-transcript:<uuid>:step:<n>:<kind>", the .db's model id
// and trajectory_meta.source read by BOTH (agyDBEnrichmentFor) — so
// whichever is parsed first wins and the other is a UNIQUE(source_file,
// source_event_id) no-op, in either arrival order: the live extension
// run births the .db ~270 ms before the transcript, but a client whose
// .db appears AFTER the transcript was ingested (Antigravity 2.0, a
// future IDE build, a conversation reopened in the extension) must not
// re-list the conversation either. Only the .pb defers
// (conversationOwner). The CLI tree's transcript is never a session
// file, so a CLI conversation is synthesized once, by its .db.
//
// Rows older builds persisted under OTHER source_files — the .pb
// augmentation ("antigravity-cli-transcript:…" under the .pb) and the
// text-only .db augmentation (same ids under the .db) — are suppressed
// by Target through legacyTextCoverage on every parse, for user_prompt /
// assistant text. KNOWN UPGRADE DUPLICATE, tool rows only: on a host
// where .pb decrypt or the gRPC bridge worked, structured.* tool rows
// (read_file / edit_file / run_command under the .pb) are re-listed
// once by the transcript under its own source_file — Target coverage
// cannot pair them (different path normalizations). One-time cleanup
// after upgrading such a host:
//
//	DELETE FROM actions WHERE source_file LIKE '%/.gemini/antigravity/conversations/%.pb'
//	  AND raw_tool_name IN ('structured.file_view','structured.artifact_write','structured.run_command')
//	  AND session_id IN (SELECT session_id FROM actions WHERE source_event_id LIKE 'antigravity-transcript:%:tool');
//
// # Usage fields in gen_metadata (1.17.2.X) and what they mean
//
// Re-read 2026-09-03 against 20 real Gemini generations: field 1 is
// CONSTANT per conversation (1071 / 1318), fields 2 + 5 sum to the
// growing prompt (5 absent on cache-miss generations, where 2 carries
// the whole prompt), field 3 = 9 + 10. That is the Anthropic-style
// split Antigravity normalizes every provider onto — 1 = uncached
// un-written suffix, 2 = prefix newly WRITTEN to cache, 5 = prefix READ
// from cache — so the decoder's map (1=input, 2=cacheCreation,
// 5=cacheRead, 9=reasoning, 10=output) is not mislabelled; it is NOT
// Gemini's own usage_metadata numbering (1 prompt / 2 candidates /
// 3 cached / 4 total / 10 thoughts). COST GAP — RESOLVED 2026-09-03
// (cost engine, not this package): the Gemini pricing rows carried no
// CacheCreation rate, so engine.go priced the field-2 portion — most of
// every Gemini prompt here — at $0, understating Antigravity/Gemini
// cost by roughly the whole prompt. Grounded against
// ai.google.dev/gemini-api/docs/pricing (2026-09-03): Google's card has
// Input / Output / "Context caching" (= the READ rate, 10% of input
// line-wide) / storage-per-hour and NO cache-creation line, for either
// implicit or explicit caching — a Gemini cache write IS an ordinary
// input token. The fix is a per-provider rule table in the cost engine
// (`cacheWriteRules` in internal/intelligence/cost/pricing.go): a
// family whose rate card has no write term derives CacheCreation from
// its own Input rate (and LongContextCacheCreation from
// LongContextInput) at lookup time, so every Gemini row — baked,
// config-overridden, or family-fallback — prices field 2 correctly
// without restating the fact per row. The decoder's mapping here was
// never the problem and is unchanged. See docs/cache-tracking.md
// "Provider cache-billing shapes".
//
// Two adapter identities share the code: New() = "antigravity" watches
// the desktop roots (conversations/ AND brain/), NewCLI() =
// "antigravity-cli" watches the CLI root. Both cross-mount-resolve
// $HOME (WSL2 ↔ Windows).
//
// # Family coverage (docs/audits/antigravity-family-surfaces-2026-09-03.md)
//
// Google ships nine surfaces on one harness. What this package is
// VERIFIED to cover versus what is UNVERIFIED:
//
//   - Antigravity IDE (standalone, v2.5.5 at the time of writing): the
//     desktop transcript path above — GROUNDED live 2026-09-03 (that
//     build wrote .pb + transcript, no .db → no tokens).
//   - Antigravity CLI `agy` (v1.1.23): the CLI-tree .db path — GROUNDED
//     2026-06-26 and RE-GROUNDED 2026-09-03 (schema unchanged,
//     trajectory_meta.source = 17). No `agy login` exists: the first
//     interactive run opens a browser OAuth flow (OS keyring); BYOK =
//     GEMINI_API_KEY + modelProvider:"gemini" in
//     ~/.gemini/antigravity-cli/settings.json; base-URL override
//     GOOGLE_GEMINI_BASE_URL (semantics unverified); no OTel export.
//   - VS Code extension `Google.google-antigravity`: VERIFIED 2026-09-03
//     — bundles its own ~/.gemini/bin/agy.exe and writes into the
//     DESKTOP tree (brain/<uuid>/… transcript + siblings AND
//     conversations/<uuid>.db with trajectory_meta.source = 1); no VS
//     Code globalStorage dir is created. Covered by LayoutDesktopDB with
//     real tokens and the ide/vscode stamp.
//   - Antigravity 2.0 (v2.12.0, the editor-less orchestration dashboard):
//     INFERRED to share ~/.gemini/antigravity with the IDE; unconfirmed.
//     If it does, its sessions carry the tree-default ide/antigravity
//     stamp (transcript-only) or whatever trajectory_meta.source it
//     writes (.db) — an unmapped value warns and lands in
//     ActionMetadata.CaptureSource.
//   - Visual Studio 2026 / JetBrains (JetBrains AI > Agents) / Zed /
//     Xcode integrations: storage and backend bundling UNDOCUMENTED —
//     nothing here claims them.
//   - Python SDK (`google-antigravity`): ships its own runtime; most
//     likely a separate surface with no local session log. Not covered.
//
// # Surface attribution
//
// The agy .db carries a real discriminator — trajectory_meta.source, a
// numeric enum that differs by the client driving the backend —
// resolved through clidb.go's agySourceSurface table (17 = agy CLI →
// cli/antigravity-cli, 1 = VS Code extension → ide/vscode; both
// live-grounded 2026-09-03). An unmapped value falls back to the TREE
// default (desktop tree → ide/antigravity; CLI tree → no stamp, the
// honest zero) with the raw value kept in ActionMetadata.CaptureSource
// on the user_prompt rows and a parse warning. The transcript-only
// path (standalone IDE) has no in-file discriminator, so the STORE
// SHAPE is the evidence (the checklist's cursor / kiro rule): brain/
// under ~/.gemini/antigravity is the IDE's own tree → ide/antigravity
// through a one-row table keyed on layout.
//
// # What is never read or persisted
//
// antigravity_state.pbtxt's installation_uuid (an install identifier),
// its last_selected_agent_model (an opaque MODEL_PLACEHOLDER_* enum —
// not a model name), agyhub_summaries_proto.pb, the transcript's
// siblings transcript_full.jsonl / chunks/ / steps/<n>/output.txt /
// .user_uploaded/ / scratch/, implicit/*.pb, and the CLI's
// settings.json / keyring material.
//
// # Cursoring
//
// .pb: file-size based — the IDE rewrites the whole file per turn.
// transcript.jsonl: whole-file re-parse on every size change (append-
// only is unverified from a single snapshot; the status field implies
// in-flight steps can be finalised in place); every SourceEventID is
// keyed on step_index so the store's UNIQUE(source_file,
// source_event_id) index drops the repeats, and a step whose status is
// not DONE emits nothing so a partial line never becomes the row that
// sticks. .db (+ -wal / -shm sidecars, claimed like cline-cli's): a
// WATERMARK cursor = max mtime (unix ms) of the .db and its -wal — WAL
// mode absorbs whole turns without growing the main file, so a size
// cursor would never re-fire; CursorSemanticsFor declares
// CursorWatermark so the watcher's size gate stays off.
//
// Watch-root cost (follow-up): brain/ is a recursive root, and each
// conversation adds ~8-10 inotify watches (.system_generated/{logs,
// logs/chunks/*, steps/<n>}, .user_uploaded, scratch). The watcher has
// no per-root ignore API and a per-conversation root set would miss a
// brand-new conversation until the next root refresh, so the recursive
// root stays; a watcher-level ignore glob is the clean fix.
//
// # Older desktop history (still true where decrypt works)
//
// The .pb path decrypts before parsing (internal/platform/oscrypt:
// macOS Keychain, Linux libsecret, Windows DPAPI, WSL2-via-PowerShell),
// wire-walks the undocumented protobuf with content heuristics
// (internal/platform/protowire), and extracts a per-message model —
// Antigravity agents run against Gemini, Claude or GPT-OSS at the
// user's choice, so that field is load-bearing for cost. state.vscdb
// (+ .backup) provides the trajectorySummaries index for title +
// workspace URI (absent on some installs — IDE-12). When local decrypt
// fails and [observer.antigravity] network_recovery = "local", the
// running language_server's gRPC ConvertTrajectoryToMarkdown /
// GetCascadeTrajectory endpoints are the fallback.
package antigravity
