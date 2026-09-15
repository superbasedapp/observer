// Package cursor implements the Adapter interface for Cursor (hook-based
// capture; no native structured logs). See spec §4.3. Implemented in Phase 3.
//
// Because each hook event arrives in its own short-lived process, the
// afterAgentThought reasoning is carried to its successor through a tiny
// on-disk stash rather than in-memory parser state — see pending.go. It
// never becomes a row of its own. See
// docs/plans/b3-reasoning-convergence-plan-2026-07-31.md §1.
//
// There is no docs/cursor-*.md feature doc: this file is the package
// reference (docs/README.md says so).
//
// # Store shapes and the surface table
//
// The watcher path recognises three on-disk shapes, and that shape is
// the ONLY grounded discriminator Cursor offers for which client wrote
// a session — nothing in a transcript, a store.db or state.vscdb
// carries an `entrypoint` / `originator` / `source` field. The shape
// enum (storeLayout) is therefore the single dispatch key for BOTH
// parsing and surface attribution; the mapping lives in exactly one
// table, surfaceByLayout (surface.go):
//
//	layout          on-disk shape                                       surface
//	--------------  --------------------------------------------------  --------------------
//	layoutTranscript .cursor/projects/<slug>/agent-transcripts/<c>/<c>.jsonl  ide / cursor
//	layoutStateDB    <...>/Cursor/User/globalStorage/state.vscdb              ide / cursor
//	layoutStoreDB    .cursor/chats/<ws-hash>/<conv>/store.db                  cli / cursor-agent
//
// The first two are written by the Cursor IDE (the VS Code fork); the
// third by the `cursor-agent` CLI. layoutUnknown gets no stamp — an
// unrecognized shape is not evidence of a client. Stamps ride
// adapter.ParseResult.SessionSurfaces (one per session id per parse)
// and land node-local on sessions.surface / sessions.surface_host via
// Store.SetSessionSurface. The hook path (internal/hook/cursor.go)
// stamps nothing.
//
// # Surface precedence: the CLI store.db wins
//
// The table above is a first approximation, because the three shapes are
// not equally strong evidence. A store.db is written by exactly ONE
// client — the CLI. A transcript, or a `composerData:` row in the shared
// state.vscdb, can exist for a conversation that `cursor-agent` ran.
//
// Store.SetSessionSurface is FIRST-WINS-UNLESS-EMPTY (the first grounded
// stamp sticks; later stamps only fill empty fields), so if the IDE
// stamp were emitted unconditionally, a CLI run whose transcript the
// watcher happened to parse before its store.db would be recorded as
// `ide/cursor` forever — decided by parse ORDER, not by evidence.
//
// So the resolution happens at EMISSION: before stamping a transcript or
// state.vscdb conversation, resolveSurface (surface.go) checks whether
// that conversation has its own `.cursor/chats/*/<conv>/store.db` and, if
// so, stamps `cli/cursor-agent` instead. layoutStoreDB always stamps
// `cli/cursor-agent` and is never overridden — it is the strong evidence,
// so re-deriving it would be circular. The layouts eligible for the
// upgrade are one table, cliStoreOverridable.
//
// The store.db half of the sibling lookup is cursorAgentStoreExists
// (statedb.go), factored out of cursorSiblingExists precisely so this
// half of the question can be asked on its own.
//
// # state.vscdb document shapes (v14 / v15)
//
// state.vscdb is undocumented and its JSON documents have drifted
// across Cursor releases. Two shape facts, both grounded against a live
// operator store on 2026-09-02 (23 composerData + 293 bubbleId rows),
// are load-bearing — declaring either one narrowly made EVERY document
// fail json.Unmarshal, which is how the reader came to emit zero rows
// off a store holding hundreds (audit IDE-02):
//
//   - `composerData.modelConfig` is an OBJECT on `_v` 14/15 —
//     {"modelName":"default","maxMode":false} and, on some rows,
//     with "selectedModels":[{"modelId":…,"parameters":[]}] — where
//     older builds wrote an ARRAY of {"modelName":…}. modelConfigDoc
//     accepts object, array or null; `modelName` is the primary source
//     and `selectedModels[0].modelId` only a fallback for an empty one.
//   - `bubbleId.createdAt` is an ISO-8601 STRING
//     ("2026-08-30T11:04:07.318Z") on current builds and Unix
//     milliseconds as a NUMBER on older ones. flexTime accepts both
//     (plus a quoted epoch), and an unusable value degrades to the file
//     mtime — the same fallback as an absent createdAt.
//
// `composerData.name` is JSON null on some rows; Go decodes that to the
// zero string, so those sessions surface with an empty name rather than
// being dropped. The live capture also carries a non-UUID composerId,
// "empty-state-draft" (Cursor's own key; its exact meaning is not
// documented by the vendor and was not reverse-engineered). It is
// treated exactly like any other conversation id — it has no sibling
// transcript or store.db, so it passes the coverage gate and registers
// a session row of its own, which is the pre-existing behaviour this
// ticket deliberately left alone. Callers grouping by session id should
// simply expect one id that is not a UUID.
//
// Both tolerant decoders are TOTAL: an unrecognized future shape yields
// a missing field, never an error, so one more drift cannot again drop
// whole documents.
//
// # Known limitation: immutable=1 hides un-checkpointed writes
//
// parseStateDBFile opens the file with `mode=ro&immutable=1`. That is
// deliberate — state.vscdb is Cursor's live, shared, frequently-written
// store and observer must never take a lock on it — but immutable=1
// tells SQLite to ignore the -wal sidecar entirely. Rows Cursor has
// written but not yet checkpointed into the main database file are
// therefore INVISIBLE to this reader until Cursor checkpoints (which it
// does on its own schedule, and always by the time it exits). The
// practical effect is added latency on very recent empty-window
// conversations, not lost data: SQLite checkpoints the WAL back into
// the main file on its own (at the latest when the last connection
// closes, i.e. when Cursor exits), and the MAX(rowid) watermark then
// picks the rows up on a later poll. Changing the DSN is a separate
// decision with its own locking risk and is NOT made here.
package cursor
