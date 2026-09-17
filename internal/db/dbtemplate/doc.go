// Package dbtemplate is a TEST-ONLY drop-in for [db.Open] that pays the agent
// migration chain once per test binary instead of once per test.
//
// Why it exists: [db.Open] applies every migration in
// internal/db/migrations (125 files as of 2026-09-17) on every call. That is
// correct for a process which opens its database once, and quadratic-ish pain
// for a suite where every test wants a pristine schema. Measured on this
// repo's dashboard package, a full migration replay costs ~3.28s/op under
// `go test -race` against ~49ms/op for copying a pre-migrated file — ~66x —
// and internal/store pays it 477 times through one helper, cmd/observer ~196
// times. Those are the packages that hit CI's `-timeout 40m` per-binary cliff
// on 2026-09-16.
//
// The mechanism is the one the org-server lineage already uses
// (internal/orgserver/db/dbtest): build a fully migrated database ONCE, then
// hand each caller a byte copy of it. [db.Open]'s migration runner fast-paths
// when schema_meta.version is already at head (internal/db/db.go::runMigrations),
// so the copy opens with no migration work and NO production-code change.
//
// # Test-only
//
// Nothing outside a _test.go file may import this package. That is not a
// convention: TestPackageIsTestOnly walks the module and fails if any
// non-test file imports it. The API deliberately does not take a
// [testing.TB], so this package does not import "testing" — the guard test,
// not the type system, is what keeps it out of production.
//
// # Opt-out
//
// Set OBSERVER_DBTEST_SQLITE_TEMPLATE=0 on the command line to restore
// from-scratch migration for every call in the run:
//
//	OBSERVER_DBTEST_SQLITE_TEMPLATE=0 go test ./internal/store/
//
// The value is read once at package-init time, so a suspected template
// artefact can be excluded in one run, and a test cannot silently move the
// switch with t.Setenv (the same discipline as [db.AllowRealDBInTestEnv]).
// The same variable disables the org-server SQLite template in
// internal/orgserver/db/dbtest.
package dbtemplate
