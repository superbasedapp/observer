package db

import (
	"context"
	"database/sql"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger"
)

// MigrationDeferral decides, for a database whose schema is behind this
// binary's migrations, whether Open applies them now (false) or leaves the
// schema as it is (true). path is the database file, applied the schema
// version on disk, latest this binary's newest migration, and pending the
// steps Open would run, ascending. pending can hold only steps at or below
// applied (late steps, T-979), so a notice should name them rather than
// compare the two versions.
//
// Lane FIX-UPGRADE U3 (D-590): after a package-manager upgrade the CLI is a
// new binary while the running daemon is still the old one. A read-only
// command (status, doctor, components status) used to migrate the database
// underneath that daemon. The CLI installs a deferral that answers true
// while another observer process holds the database (its lockfile), so
// only the daemon that owns the database migrates it, at its next start.
type MigrationDeferral func(path string, applied, latest int, pending []int) bool

// migrationDeferral is the process-wide deferral; nil applies migrations
// (the default for every caller that does not install one, including tests
// and the daemon).
var migrationDeferral atomic.Pointer[MigrationDeferral]

// SetMigrationDeferral installs (or, with nil, removes) the process-wide
// MigrationDeferral. cmd/observer installs it once per process, before the
// first Open.
func SetMigrationDeferral(d MigrationDeferral) {
	if d == nil {
		migrationDeferral.Store(nil)
		return
	}
	migrationDeferral.Store(&d)
}

// deferMigrations reports whether Open should skip runMigrations for path.
// It plans lock-free; any read error (a fresh file with no schema_meta)
// means "migrate", because nothing can be using a database that has no
// schema yet. Only a plan that RUNS a step consults the deferral: recording
// the ledger of a pre-ledger database (adopt-only bookkeeping) changes no
// schema, so it never waits for the daemon. A step pending below the
// recorded version (a late step) defers exactly like one above it.
func deferMigrations(ctx context.Context, database *sql.DB, path string) bool {
	p := migrationDeferral.Load()
	if p == nil || path == "" || path == ":memory:" {
		return false
	}
	entries, err := readMigrationEntries()
	if err != nil || len(entries) == 0 {
		return false
	}
	latest := entries[len(entries)-1].version
	embedded, _ := lineageIndex(entries)
	plan, err := sqliteledger.Plan(ctx, database, embedded, lateSteps)
	if err != nil {
		return false
	}
	pending := plan.RunVersions()
	if len(pending) == 0 {
		return false
	}
	applied, err := currentVersion(ctx, database)
	if err != nil {
		return false
	}
	return (*p)(path, applied, latest, pending)
}

// LatestSchemaVersion is the newest migration this binary carries.
func LatestSchemaVersion() int {
	entries, err := readMigrationEntries()
	if err != nil || len(entries) == 0 {
		return 0
	}
	return entries[len(entries)-1].version
}
