package fsatomic

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileFsyncSucceeds pins that an Fsync write lands on every OS. On
// Windows the directory flush used to fail with "Access is denied", so every
// crash-consistent write (reporter, sidecar, update rollback, config
// snapshot) failed on a native Windows node.
func TestWriteFileFsyncSucceeds(t *testing.T) {
	for _, fsync := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "sub", "state.json")
		want := []byte(`{"ok":true}`)
		if err := WriteFile(path, want, Options{Fsync: fsync}); err != nil {
			t.Fatalf("WriteFile(Fsync=%v): %v", fsync, err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("content = %q, want %q", got, want)
		}
		// A rewrite over the existing file also succeeds.
		if err := WriteFile(path, []byte("2"), Options{Fsync: fsync}); err != nil {
			t.Fatalf("rewrite (Fsync=%v): %v", fsync, err)
		}
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("directory holds %d entries, want 1 (no temp left)", len(entries))
		}
	}
}
