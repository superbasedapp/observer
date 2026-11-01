package gitview

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestHostGitRefusedStamp: a root at or under a directory carrying
// HostGitRefusedStamp is refused before git starts (lane SBX-P3C audit
// fixes, D4); an unstamped sibling is not.
func TestHostGitRefusedStamp(t *testing.T) {
	dir := t.TempDir()
	copyDir := filepath.Join(dir, "copy")
	sub := filepath.Join(copyDir, "src", "pkg")
	other := filepath.Join(dir, "other")
	for _, d := range []string{sub, other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(copyDir, HostGitRefusedStamp), []byte("refused\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{copyDir, sub} {
		if got, ok := HostGitRefused(root); !ok || got != copyDir {
			t.Fatalf("%s: %q %v", root, got, ok)
		}
		if _, _, err := RunReadOnly(context.Background(), root, 1<<10, "status"); !errors.Is(err, ErrHostGitRefused) {
			t.Fatalf("%s: git ran: %v", root, err)
		}
	}
	if _, ok := HostGitRefused(other); ok {
		t.Fatal("an unstamped directory is refused")
	}
}
