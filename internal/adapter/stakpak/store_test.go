package stakpak

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

func TestIsForeignMountPathAndMirror(t *testing.T) {
	orig := allHomesFunc
	defer func() { allHomesFunc = orig }()

	foreignHome := t.TempDir()
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: filepath.Join("home", "native"), OS: crossmount.OSLinux, Origin: "native"},
			{Path: foreignHome, OS: crossmount.OSWindows, Origin: "wsl-mnt:c"},
		}
	}

	native := filepath.Join("home", "native", ".stakpak", "data", "local.db")
	if isForeignMountPath(native) {
		t.Errorf("native path %q classified foreign", native)
	}
	srcDB := filepath.Join(foreignHome, ".stakpak", "data", "local.db")
	if !isForeignMountPath(srcDB) {
		t.Fatalf("foreign path %q not classified foreign", srcDB)
	}

	// Staging itself (a filtered mirror, never a byte copy) is pinned by
	// TestForeignMirrorKeepsOnlyAllowListedTables (RB1 sweep finding A2).
}

func TestNativePathIsNotMirrored(t *testing.T) {
	orig := allHomesFunc
	defer func() { allHomesFunc = orig }()
	allHomesFunc = func() []crossmount.HomeRoot { return nil }
	got, err := stageMirrorIfForeign(fixtureDB)
	if err != nil || got != fixtureDB {
		t.Fatalf("native path should pass through, got %q %v", got, err)
	}
}

func TestMaxCheckpointRowIDAndSchemaTolerance(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if v, err := maxCheckpointRowID(ctx, db); err != nil || v != 0 {
		t.Errorf("no checkpoints table: got %d, %v; want 0, nil", v, err)
	}
	if m, err := loadSessionMeta(ctx, db); err != nil || len(m) != 0 {
		t.Errorf("no sessions table: got %v, %v", m, err)
	}
	called := false
	if err := scanCheckpointsAfter(ctx, db, 0, func(checkpointRow) bool { called = true; return true }); err != nil || called {
		t.Errorf("no checkpoints table: scan err=%v called=%v", err, called)
	}
}

func TestScanCheckpointsParentLen(t *testing.T) {
	ctx := context.Background()
	rows := map[string]checkpointRow{}
	db, err := openReadOnlyDB(fixtureDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := scanCheckpointsAfter(ctx, db, 0, func(r checkpointRow) bool {
		rows[r.ID] = r
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 16 {
		t.Fatalf("checkpoints = %d, want 16", len(rows))
	}
	root := rows["00000000-0000-4000-8000-000000000002"]
	if root.HasParent || root.ParentLen != 0 {
		t.Errorf("root checkpoint should have no parent: %+v", root)
	}
	// Windows checkpoint 0003 follows a 1-message root.
	second := rows["00000000-0000-4000-8000-000000000003"]
	if !second.HasParent || second.ParentLen != 1 {
		t.Errorf("second checkpoint parent len = %+v, want 1", second)
	}
	// Early stop.
	n := 0
	if err := scanCheckpointsAfter(ctx, db, 0, func(checkpointRow) bool { n++; return false }); err != nil || n != 1 {
		t.Errorf("early stop visited %d rows, err=%v", n, err)
	}
}
