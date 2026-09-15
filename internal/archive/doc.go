// Package archive is the pure-logic layer of the corpus archival arc
// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md).
//
// It owns three things and no I/O whatsoever:
//
//   - The ROW TYPES that cross the hot-store ⇄ archive-store boundary. Both
//     sides speak these, so neither side's schema types leak into the other
//     (CLAUDE.md "one seam per integration point; no type leakage past it").
//   - The VERIFICATION math: a per-table digest (an exact row count plus an
//     order-independent checksum) and [Verify], which compares the digest of
//     the hot rows against the digest read back OUT of the archive file. This
//     is the gate that stands between a copy and a delete — see [Verify].
//   - The CANDIDATE PLAN: which cold units this pass should move, in what
//     order, and how many ([SelectCandidates]). Bounded by construction —
//     one capped batch per retention pass, never loop-until-done.
//
// This package must never import database/sql, net/http, or fsnotify: the SQL
// for the HOT tables lives in internal/store, the SQL for the archive file
// lives in internal/archivestore, and internal/archivesvc composes the two.
// Pinned by imports_test.go.
package archive
