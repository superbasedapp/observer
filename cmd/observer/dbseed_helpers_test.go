package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// seedNodeDB puts the pre-migrated template database at path, for a test
// node whose config names path as db_path and whose code under test opens
// it through the production db.Open (a hook receiver, a CLI env, a
// subprocess). Without it every such node paid the whole migration chain on
// its first open: that chain was 80-90% of the time of the hook-gate
// matrices, which build a node per case.
//
// The seeded file is exactly what the first db.Open would have left behind
// (an empty, fully migrated database), and db.Open still runs on it, so it
// still applies any step the template lacks. A path that already exists is
// left alone, and with the template switched off
// (OBSERVER_DBTEST_SQLITE_TEMPLATE=0) or unbuildable nothing is written and
// the code under test migrates from scratch as before.
func seedNodeDB(t *testing.T, path string) {
	t.Helper()
	if !dbtemplate.Enabled() {
		return
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			return
		}
	}
	image, err := dbtemplate.Bytes()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
}
