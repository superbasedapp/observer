package db

import (
	"context"
	"path/filepath"
	"testing"
)

// TestOpenDefersMigrationsWhenTheDeferralSaysSo is U3's red/green at the
// db seam: with a deferral installed that answers true, Open leaves a
// schema that is behind exactly where it was, and the deferral sees the
// applied and latest versions. A current schema never consults it.
func TestOpenDefersMigrationsWhenTheDeferralSaysSo(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "observer.db")
	d, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	latest := LatestSchemaVersion()
	if v, _ := Version(ctx, d); v != latest {
		t.Fatalf("fresh Open: version %d, want %d", v, latest)
	}
	// Pretend the file is one release behind (the daemon that owns it has
	// not migrated yet). A late step at the head whose column is present is
	// adopted, never run (lateSteps: the wave fork's 197), so rewinding past
	// only that step leaves nothing to defer; rewind one step further then.
	behind := latest - 1
	for _, s := range lateSteps {
		if s.Version == latest {
			behind = latest - 2
		}
	}
	if _, err := d.ExecContext(ctx, `UPDATE schema_meta SET value = ? WHERE key = 'version'`, behind); err != nil {
		t.Fatal(err)
	}
	_ = d.Close()

	var gotApplied, gotLatest, calls int
	SetMigrationDeferral(func(_ string, applied, l int, _ []int) bool {
		calls++
		gotApplied, gotLatest = applied, l
		return true
	})
	t.Cleanup(func() { SetMigrationDeferral(nil) })
	d2, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if v, _ := Version(ctx, d2); v != behind {
		t.Fatalf("deferred Open migrated: version %d, want %d", v, behind)
	}
	if calls != 1 || gotApplied != behind || gotLatest != latest {
		t.Fatalf("deferral saw (%d, %d) in %d calls, want (%d, %d) once", gotApplied, gotLatest, calls, behind, latest)
	}

	// A current schema never asks.
	path2 := filepath.Join(t.TempDir(), "current.db")
	SetMigrationDeferral(nil)
	d3, err := Open(ctx, Options{Path: path2})
	if err != nil {
		t.Fatal(err)
	}
	_ = d3.Close()
	calls = 0
	SetMigrationDeferral(func(string, int, int, []int) bool { calls++; return true })
	d4, err := Open(ctx, Options{Path: path2})
	if err != nil {
		t.Fatal(err)
	}
	_ = d4.Close()
	if calls != 0 {
		t.Fatal("a current schema consulted the deferral")
	}
}
