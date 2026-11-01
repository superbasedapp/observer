//go:build !windows

package fsatomic

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSyncDirFlushesOnPOSIX pins the POSIX half of the build-tag split
// (WINNODE item 1): the directory flush is real here. It opens the directory
// (so a missing one is an error naming the step) and syncs it.
func TestSyncDirFlushesOnPOSIX(t *testing.T) {
	dir := t.TempDir()
	if err := syncDir(dir); err != nil {
		t.Fatalf("syncDir(existing) = %v, want nil", err)
	}
	err := syncDir(filepath.Join(dir, "missing"))
	if err == nil || !strings.Contains(err.Error(), "open dir for fsync") {
		t.Fatalf("syncDir(missing) = %v, want the open-dir error (the POSIX flush must still run)", err)
	}
}
