package mirrorbase

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyWALWithoutWALClearsWALHeaderBytes(t *testing.T) {
	db := make([]byte, 4096)
	copy(db, "SQLite format 3\x00")
	db[16], db[17] = 0x10, 0x00
	db[18], db[19] = 2, 2
	got, err := applyWAL(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got[18] != 1 || got[19] != 1 {
		t.Errorf("format bytes = %d,%d, want 1,1", got[18], got[19])
	}
	for _, junk := range [][]byte{[]byte("short"), make([]byte, 64)} {
		if _, err := applyWAL(db, junk); err != nil {
			t.Errorf("invalid WAL %q should be ignored, got %v", junk[:5], err)
		}
	}
}

// TestApplyWALStopsAtCorruptCommit: a torn or corrupt last frame drops
// only the transaction it commits; earlier committed transactions apply.
func TestApplyWALStopsAtCorruptCommit(t *testing.T) {
	dir := t.TempDir()
	SetBaseForProcess(filepath.Join(dir, "cache"))
	t.Cleanup(func() { SetBaseForProcess("") })
	src := filepath.Join(dir, "store.db")
	w := seedVendorStore(t, src)
	mustExec(t, w, `INSERT INTO session VALUES ('s3', 3)`)

	wal, err := os.ReadFile(src + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	wal[len(wal)-1] ^= 0xff // corrupt the final (commit) frame's page
	if err := os.WriteFile(src+"-wal", wal, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Stage(context.Background(), src, testSpec)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if n := countRows(t, got, "session"); n != 2 {
		t.Errorf("session rows = %d, want 2 (s3's commit frame is corrupt)", n)
	}
}

func TestApplyWALRejectsUnknownVersion(t *testing.T) {
	wal := make([]byte, walHeaderSize)
	wal[0], wal[1], wal[2], wal[3] = 0x37, 0x7f, 0x06, 0x82
	wal[7] = 9
	if _, err := applyWAL(make([]byte, 4096), wal); err == nil {
		t.Fatal("unknown WAL version accepted")
	}
}
