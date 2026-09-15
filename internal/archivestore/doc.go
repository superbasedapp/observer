// Package archivestore is the ONE owner of the cold-storage database,
// ~/.observer/archive.db (docs/plans/observer-corpus-archival-lazyload-design-
// 2026-08-26.md §3.1).
//
// It is a wholly separate SQLite file with its own *sql.DB, its own pragmas,
// its own lock, and its own migration lineage — deliberately NOT an ATTACH
// onto the hot connection. An attached cold database would put cold data back
// on hot query plans and hot lock contention, which is precisely the "the
// corpus is carried on every operation" failure the whole arc exists to end.
// A slow archive read cannot block a hot write, and vice versa.
//
// It is also not opened through internal/db.Open: that helper runs the AGENT
// migration lineage, which must never touch this file. The shape mirrored here
// instead is internal/edge/wal — the existing precedent for a sibling SQLite
// file with its own Open, its own DSN-pinned pragmas, and its own migrations
// sub-package.
//
// Privacy: this file never enters the org-push wire. That is true by
// construction (internal/store/orgpush.go has no path to a second database
// handle) and pinned belt-and-braces by the forbidden-name sentinel in
// tests/invariant/privacy_test.go.
package archivestore
