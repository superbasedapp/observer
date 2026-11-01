// Package templatecache shares one migrated SQLite template database between
// test binaries. It is test support: nothing a shipped binary runs may import
// it (TestPackageIsTestSupportOnly), and it is reached only through the two
// fixture packages that own a lineage's template, internal/db/dbtemplate
// (node) and internal/orgserver/db/dbtest (org server), plus the org
// server's own in-package tests.
//
// Why it exists: each fixture package used to build its template once per
// test BINARY. Under `go test -race` a full org-server migration replay costs
// about 35 s, and a run of about 150 binaries paid it about 150 times for
// byte-identical results. This package pays it once per migration set per
// machine: the first binary builds the template under a file lock and every
// later binary, in the same run or a later one, reads the finished file.
//
// # Key
//
// A template is stored as $TMPDIR/sbo-dbtemplates/<lineage>-<key>.db, where
// key is a SHA-256 over a format version, the lineage name, the SQL driver
// and its module version, the dialect, the name and bytes of every embedded
// migration file, and the bytes of every non-test .go file of the lineage's
// migration runner (its db package, internal/migplan and the fixture
// package's build function, read from the module tree above the test's
// working directory). A binary therefore never reads a template built from a
// different migration set or by different runner code: either change is a
// different key and a fresh build. When the module tree cannot be found the
// template is built privately, never shared. The fixture packages keep their
// equivalence tests (a template copy has exactly the schema a from-scratch
// migration produces). To discard every shared template by hand:
// rm -rf "${TMPDIR:-/tmp}/sbo-dbtemplates".
//
// # Concurrency and safety
//
// The build runs under an exclusive lock on <lineage>-<key>.lock and writes a
// temporary file in the same directory that is renamed into place only once
// it is complete, so a reader never sees a half-written template. The lock is
// an efficiency device, not a correctness one: two binaries that build the
// same key without it produce the same bytes and the rename is atomic. Any
// failure of the shared path (a directory that is not a private one owned by
// this user, a lock that cannot be taken within lockWait) falls back to a
// build in a process-private directory, which is the old behaviour.
//
// The directory holds one file per key. Files of the same lineage not used for
// pruneAge are removed when a new template is built, so a laptop that moves
// between branches does not collect templates without bound.
//
// The opt-out stays where it was: OBSERVER_DBTEST_SQLITE_TEMPLATE=0 makes the
// fixture packages skip templates altogether, so this package is never
// reached.
package templatecache
