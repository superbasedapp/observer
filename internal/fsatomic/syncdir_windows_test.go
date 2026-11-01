//go:build windows

package fsatomic

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestWindowsSyncDirIsANoop pins the Windows half of the build-tag split
// (WINNODE item 1): a directory handle cannot be flushed there, so syncDir
// never opens one and never fails, even for a directory that is gone.
func TestWindowsSyncDirIsANoop(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{dir, filepath.Join(dir, "missing")} {
		if err := syncDir(d); err != nil {
			t.Fatalf("syncDir(%s) = %v, want nil on Windows", d, err)
		}
	}
}

// TestWindowsWriteFileFsync is the v1.36.0 demo failure: every Fsync write
// (the org policy cache, the governance sidecar, the relay PDP cache) failed
// after its rename. Each option combination the callers use must succeed and
// leave exactly the written content and no temp file.
func TestWindowsWriteFileFsync(t *testing.T) {
	for _, opts := range []Options{
		{Fsync: true},
		{Fsync: true, TempPattern: ".policy-resource-*.tmp"},
		{Fsync: true, OwnerOnly: true},
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "cache", "node.governance.json")
		for _, want := range [][]byte{[]byte(`{"version":1}`), []byte(`{"version":2}`)} {
			if err := WriteFile(path, want, opts); err != nil {
				t.Fatalf("WriteFile(%+v): %v", opts, err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("read back = %q (%v), want %q", got, err, want)
			}
		}
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil || len(entries) != 1 {
			t.Fatalf("directory entries = %d (%v), want 1", len(entries), err)
		}
	}
}
