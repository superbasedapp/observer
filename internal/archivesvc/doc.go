// Package archivesvc composes the two halves of a corpus archive move
// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §3.1
// "Module boundary").
//
// It owns no SQL of its own. The hot codeintel_* tables stay owned by
// internal/store; the archive_* tables stay owned by internal/archivestore;
// the verification math and the row types stay in the pure internal/archive.
// This package holds only the ORDER those pieces must run in, and the refusal
// to skip a step:
//
//	pre-clear cold → copy hot→cold (digesting the hot rows in the same pass)
//	              → read the cold copy BACK → verify → delete hot + mark.
//
// That order is the safety property. Every failure mode leaves the hot rows
// intact, and the only step that destroys anything runs after the copy has
// been proven readable.
package archivesvc
