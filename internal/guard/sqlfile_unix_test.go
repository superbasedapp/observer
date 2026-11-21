//go:build unix

package guard

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReadSQLFileBoundedFIFO pins DB-4: a FIFO with no writer neither
// blocks the read nor is judged.
func TestReadSQLFileBoundedFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "swapped.sql")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan bool, 1)
	go func() {
		_, ok := readSQLFileBounded(p)
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Error("a FIFO was reported as a readable SQL file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}
