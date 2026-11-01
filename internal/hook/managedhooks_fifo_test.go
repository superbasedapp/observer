//go:build unix

package hook

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestReadManagedHooksFileRefusesAFIFO pins orchestrator follow-up H3: the
// administrator hooks file is read through one non-blocking, no-follow
// descriptor (regularfile.ReadNoFollow), so a FIFO at the path is refused
// at once instead of hanging `observer init`, the daemon's hook registration
// or the cursor.hooks doctor row. The old reader (os.Lstat, then a blocking
// os.Open) hung on a FIFO swapped in between the two calls. A symlink at the
// path is refused as before.
func TestReadManagedHooksFileRefusesAFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "hooks.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan ManagedHooks, 1)
	go func() { done <- readManagedHooksFile(fifo) }()
	select {
	case m := <-done:
		if !m.Found || !strings.Contains(m.Untrusted, "is not a regular file") || len(m.events) != 0 {
			t.Fatalf("FIFO: %+v, want a found file refused as not regular", m)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("readManagedHooksFile blocked on a FIFO")
	}

	doc, _, _ := ManagedHooksDocument("cursor", "", "linux")
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if m := readManagedHooksFile(link); !m.Found || !strings.Contains(m.Untrusted, "is not a regular file") || len(m.events) != 0 {
		t.Fatalf("symlink: %+v, want a found file refused as not regular", m)
	}
}
