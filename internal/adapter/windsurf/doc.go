// Package windsurf is the UNREGISTERED skeleton adapter for Cascade, the
// in-IDE agent of Windsurf (Cognition's VS Code fork, marketed as "Devin
// Desktop"; the extension inside the app is published as `codeium.windsurf`
// v0.2.0, bundled — not installed from a marketplace).
//
// It exists so the watch roots, the file-shape predicate and the fixture
// recipe are written down and test-pinned BEFORE a live capture exists. It
// emits NO rows: ParseSessionFile returns an empty adapter.ParseResult with
// one Warning naming testdata/windsurf/README.md. See the "Not registered"
// section below — nothing in a shipped install ever calls this code.
//
// # The surface
//
// Cascade is a distinct producer from Devin-in-Windsurf. Windsurf bundles
// `resources\app\extensions\windsurf\devin\bin\devin.exe` — that binary IS
// the Devin CLI (Enterprise bundle), and the sessions it writes are already
// captured by internal/adapter/devin. This package must never claim them.
// Cascade itself is driven by the bundled Codeium/Exafunction language
// server (`language_server_windows_x64.exe`, Connect/gRPC, protobuf package
// `exa.language_server_pb` / `exa.auto_cascade_common_pb`), which is where
// the conversation state actually lives.
//
// # Candidate stores, with confidence marks
//
// Two candidates are declared as watch roots. NEITHER has been observed
// holding a byte on any host — Windsurf 2.3.15 is installed on the
// development box but has never been launched, and both `~/.codeium` and
// `%APPDATA%\Windsurf` are ABSENT there.
//
//	(1) <home>/.codeium/windsurf/cascade/            [MEDIUM]
//
// Vendor docs (docs.windsurf.com/windsurf/cascade/memories) plus community
// reports place Cascade conversation history in `~/.codeium/windsurf/cascade`
// (Windows `%USERPROFILE%\.codeium\windsurf\cascade`). The FILE FORMAT is
// undocumented — not JSON, not JSONL, not SQLite, nothing is claimed here.
// Confidence is MEDIUM and not higher because a read-only grep of the
// shipped extension bundle (2026-09-03, see "Bundle findings") does NOT
// corroborate the `cascade` directory segment: the string never appears as a
// path literal there. The dir may be written by the language server rather
// than the extension, or the docs may describe an older layout.
//
// The `.codeium/<channel>` parent IS bundle-grounded [HIGH]:
// WindsurfExtensionMetadata.codeiumDirPathSegments returns
// `[".codeium", isWindsurfInsiders() ? "windsurf-insiders" :
// isWindsurfNext() ? "windsurf-next" : "windsurf"]`, so all three release
// channels are declared as roots. The `cascade` leaf under each is the
// MEDIUM half of the claim, not the `.codeium/<channel>` half.
//
//	(2) <...>/Windsurf/User/globalStorage/state.vscdb    [STATIC/UNVERIFIED]
//
// The 2026-09-02 IDE audit (IDE-26) reported a memento key
// `windsurf.workspaceCascadeMap` in Windsurf's own VS Code state database.
// The bundle read confirms the key exists and — importantly — narrows what
// it is worth:
//
//   - `STATE_IDS.WORKSPACE_CASCADE_MAP = "windsurf.workspaceCascadeMap"`,
//     read/written through `context.globalState` (a VS Code memento), so on
//     disk it is a FIELD inside the `codeium.windsurf` globalState blob in
//     `ItemTable`, not a top-level `ItemTable` key [UNVERIFIED — VS Code
//     convention, never read off a live DB].
//   - its value is a plain `{workspaceFolderUri: cascadeId}` map, and
//     `getCascadeIdForCurrentWorkspace()` DELETES the entry immediately
//     after reading it (`setWorkspaceCascadeMap(uri, undefined)`) [HIGH,
//     bundle-verbatim]. It is a one-shot handoff of "which cascade belongs
//     to the workspace being opened", NOT a durable conversation index.
//
// So state.vscdb is expected to yield at most a transient workspace↔cascade
// id correlation, and no conversation content at all. It is watched anyway
// because that correlation is the only bridge from a cascade id to a project
// root that has been located so far, and because the step-in diff needs the
// file on the list to be captured.
//
// # Bundle findings (read-only, 2026-09-03, extension.js of Windsurf 2.3.15)
//
//   - `--database_dir` is composed at runtime as
//     `<home>/.codeium/<channel>/database/9c0694567290725d9dcba14ade58e297`
//     and passed to the language server ALONGSIDE `--enable_index_service`
//     and `--enable_local_search`. That reads as a CODE-INDEX / local-search
//     store, not a conversation store — the audit's "runtime-composed
//     `database_dir` (embedded SQLite / `codeium_%s_%s.pb`)" note should not
//     be read as "this is where transcripts live". No `codeium_%s_%s.pb`
//     format string exists in the extension bundle at all. [STATIC —
//     inferred from adjacent flags; the directory has never been seen.]
//   - Memories are served over the language-server API
//     (`exa.language_server_pb.GetCascadeMemoriesResponse` /
//     `GetUserMemoriesResponse`, message `CortexMemory`), so a
//     `~/.codeium/windsurf/memories/` directory is a projection of that API,
//     not the primary store. Either way it is OFF LIMITS (below).
//   - `.jsonl` appears ZERO times in the bundle. Any assumption that Cascade
//     history is JSONL is unfounded; IsSessionFile is extension-agnostic for
//     exactly this reason.
//
// # Off limits — never read, never parsed, never watched
//
//   - `<home>/.codeium/<channel>/memories/` — Cascade auto-memories. Not
//     sessions; user-authored context that has no landing place in the
//     models schema.
//   - `<home>/.codeium/<channel>/config.json` and any sibling that carries
//     credentials — Cascade auth is a Codeium API key.
//   - any `*.token`, `*.key`, keyring/credential store, or
//     `mcp_config.json` (MCP server definitions routinely embed API keys in
//     their `env` blocks).
//   - the Devin lane: `<home>/.devin/`, `%APPDATA%\devin\config.json`, and
//     the bundled `devin.exe` store. Owned by internal/adapter/devin.
//
// The roots this package declares (`.../cascade`, and the single
// `state.vscdb` FILE) cannot reach any of these by construction: none is a
// child of a declared root.
//
// # Not registered — and what registering it will take
//
// This package is deliberately absent from internal/adapter/defaults, from
// `config.Default().EnabledAdapters`, and from the internal/integration
// capability registry. A zero-capability registry row would claim nothing
// and cost a maintenance edge, so the row lands in the SAME commit that
// registers the adapter, never before (plan
// docs/plans/uncaptured-surfaces-wiring-plan-2026-09-03.md §4 note 1).
//
// The tool id therefore lives here as ToolName rather than in
// internal/models: on registration it MOVES to `models.ToolWindsurf =
// "windsurf"` and this constant is deleted, so no second spelling of the id
// can drift into existence in the meantime.
//
// Wiring checklist for that later commit (after testdata/windsurf/ holds a
// real capture):
//
//  1. models.ToolWindsurf const; delete ToolName here and re-point Name().
//  2. internal/adapter/defaults: construct and register windsurf.New().
//  3. config.Default().EnabledAdapters += "windsurf" (+ the adoptadapters
//     goldens that mirror that list).
//  4. internal/integration: one Capability row (Proxy / Routability / Hook /
//     MCP / Native / TokenTier), grounded — zero value where nothing is
//     known, never fabricated — plus the RegistryVersion bump.
//  5. Decide the cursor semantics per shape and implement
//     adapter.CursorSemantics if either shape is not a byte offset: the
//     state.vscdb reader will want CursorWatermark (the cursor precedent,
//     internal/adapter/cursor/statedb.go), and a shape that carries only
//     correlation and no activity wants CursorNoActions — but only with the
//     live-DB evidence that interface's doc demands.
//  6. docs/adapters.md row, docs/README.md index, a docs/windsurf-adapter.md
//     operator reference, and the CLAUDE.md adapter roll-call.
//
// # Watch-root shape
//
// The state.vscdb root is the FILE, not its globalStorage parent — exactly
// the cursor precedent (internal/adapter/cursor/scan.go::defaultRoots).
// cline, kilo-code and copilot legitimately watch
// `<Windsurf>/User/globalStorage/<ext>/...` for extensions installed inside
// the Windsurf host (internal/platform/vscodehost lists Windsurf as a
// product), and the watcher's root dispatch requires cross-adapter roots to
// be pairwise non-prefix (tests/…/defaults_test.go::
// TestRegistryRootsNonOverlapping). A file root keeps this package's root
// disjoint from all of them, and the `-wal`/`-shm` sidecars fall outside it
// by construction (adapter.HasPathPrefix only extends a prefix at a path
// separator), which is also why they are not session files here: SQLite
// reads them itself.
//
// There is no environment-variable override for either root. The bundle
// composes `--codeium_dir` from the hard-coded segments above and the vendor
// documents no knob, so declaring one would be an invention.
package windsurf
