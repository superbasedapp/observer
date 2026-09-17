package dashboard

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// This file exists for one reason: `go test -race` on this package was
// timing out at the 40-minute per-binary budget (CI run 30698650697 on
// v1.28.0 — `FAIL internal/intelligence/dashboard 2400.066s`), and the
// cost was not test logic. No single test is even 2.1% of the total.
// The dominant term is a fixed per-test setup: every test that needs a
// database calls db.Open on a fresh path, and db.Open applies the whole
// agent migration chain from scratch. Measured in isolation that is
// 3.28s/op under -race against 49ms/op for copying a pre-migrated file
// — ~66x — and this package pays it 171 times.
//
// openTestDB is a drop-in for db.Open that seeds from a template built
// once per test binary. The mechanism used to live here; it now lives in
// internal/db/dbtemplate so that internal/store (477 fixtures through one
// helper) and cmd/observer (~196 direct call sites) get the same win from
// the same code. This file is the thin local alias plus the guard tests
// that pin the property for THIS package.
//
// Analysis: docs/plans/dashboard-race-budget-2026-08-01.md.

// openTestDB opens a test database at opts.Path, seeding it from the
// pre-migrated template when the path is new. See dbtemplate.Open for the
// behaviour-preservation rules (live-DB guard first, existing files never
// touched, every failure falls back to a plain db.Open).
func openTestDB(ctx context.Context, opts db.Options) (*sql.DB, error) {
	return dbtemplate.Open(ctx, opts)
}

// TestOpenTestDBSeedsFromTemplate pins the property this file exists for.
//
// Every other test here would still pass if the template were never copied —
// they would just each pay full migration cost under -race again, and the
// package would drift back to the 40-minute CI cliff with nothing red. The
// template's own correctness is pinned in internal/db/dbtemplate; what is
// local to this package is that its 195 fixtures actually go through it.
func TestOpenTestDBSeedsFromTemplate(t *testing.T) {
	if !dbtemplate.Enabled() {
		t.Skip(dbtemplate.DisableEnv + "=0: the template is disabled for this run")
	}
	database, seeded, err := dbtemplate.OpenSeeded(context.Background(),
		db.Options{Path: filepath.Join(t.TempDir(), "seed-probe.db")})
	if err != nil {
		t.Fatalf("open fresh path: %v", err)
	}
	defer database.Close()
	if !seeded {
		t.Fatal("a brand-new path was NOT seeded from the template — every test in this package is paying full migration cost again")
	}
}
