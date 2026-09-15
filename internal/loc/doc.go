// Package loc counts lines of CODE (as opposed to comments, blank lines
// and pure-whitespace reflows) authored by an AI agent or by a human,
// from the before/after text an editing tool already recorded.
//
// It is a PURE package in the sense of CLAUDE.md module-boundary rule #1:
// no database/sql, no net/http, no fsnotify, and no imports of
// internal/adapter or internal/store. All I/O is injected by its callers —
// the store seam (internal/store/loc.go) for live ingest and backfill, and
// the dashboard/CLI for reads. Its purity is pinned by imports_test.go.
//
// The three layers, in the order a caller uses them:
//
//  1. Language classification. Language reports the normalized language
//     and the Category bucket (code / docs / config / generated /
//     vendored / unknown) for a path, from loc's OWN extension and
//     denylist tables — deliberately NOT internal/codeintel's, which
//     drops testdata/bin/build/target by basename and carries no docs or
//     config bucket (see docs/plans/lines-of-code-tracking-plan-2026-09-07.md §0).
//
//  2. Line classification. ClassifyLines runs a table-driven lexer for
//     the language over a text FRAGMENT and labels every line
//     code / comment / blank / unknown, reporting a Confidence. Edits are
//     fragments, so boundary cases (a block comment opened but never
//     closed, one closed but never opened, a partial first or last line)
//     degrade to ClassUnknown, never silently to ClassBlank.
//
//  3. Diff + count. Diff aligns two line sequences in two passes —
//     whitespace-normalized pairing first, then Myers on the residue —
//     and Count folds the resulting hunks plus both sides' line classes
//     into a Stats bucket set through an explicit class-transition table.
//
// Extract sits on top of all three: it walks a table-driven shape ladder
// over the already-scrubbed actions.raw_tool_input of one edit/write
// action and returns one FileStats per file the action touched.
//
// Privacy: loc never returns, stores or logs file content. FileStats
// carries counts, a path (which its caller hashes), and an InputDigest
// over the normalized per-file patch text used for deduplication.
package loc
