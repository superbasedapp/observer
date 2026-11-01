//go:build !windows

package diag

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestVendorPolicyFIFONeverBlocks: a FIFO at a cache path, or a symlink to
// one, is refused at once; the managed-integrity collector and the doctor
// must never hang on it (R-188 F7 reader).
func TestVendorPolicyFIFONeverBlocks(t *testing.T) {
	for _, viaLink := range []bool{false, true} {
		home := t.TempDir()
		cache := filepath.Join(home, ".factory", "org-managed-settings.cache.json")
		if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
			t.Fatal(err)
		}
		fifo := cache
		if viaLink {
			fifo = filepath.Join(home, ".factory", "pipe")
		}
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
		if viaLink {
			if err := os.Symlink(fifo, cache); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan []VendorPolicyFinding, 1)
		go func() { done <- VendorPolicyFindings(home, nil) }()
		select {
		case got := <-done:
			if len(got) != 0 {
				t.Fatalf("link %v: a FIFO was judged: %+v", viaLink, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("link %v: reading a FIFO cache blocked", viaLink)
		}
	}
}
