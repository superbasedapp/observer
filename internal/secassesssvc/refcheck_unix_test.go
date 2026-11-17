//go:build unix

package secassesssvc

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// TestRefCheckerFIFO: a FIFO named by the agent is refused at the Lstat, and
// the open flags themselves never block on one (the swap between the Lstat and
// the open that O_NONBLOCK exists for).
func TestRefCheckerFIFO(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	c := newChecker(t, root, time.Time{}, nil)
	done := make(chan secassess.LookupStatus, 1)
	go func() {
		_, _, st := c.Lines("pipe", 1, 1)
		done <- st
	}()
	select {
	case st := <-done:
		if st != secassess.LookupMissing {
			t.Fatalf("a FIFO read as %v", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reference walk blocked on a FIFO")
	}
	// The raced case: the open itself, as the checker does it, returns at once
	// and the handle is then seen not to be a regular file.
	opened := make(chan error, 1)
	go func() {
		r, err := os.OpenRoot(root)
		if err != nil {
			opened <- err
			return
		}
		defer func() { _ = r.Close() }()
		fh, err := r.OpenFile("pipe", openFlags, 0)
		if err != nil {
			opened <- err
			return
		}
		defer func() { _ = fh.Close() }()
		st, err := fh.Stat()
		if err == nil && st.Mode().IsRegular() {
			err = os.ErrInvalid
		}
		opened <- err
	}()
	select {
	case err := <-opened:
		if err != nil {
			t.Fatalf("opening a FIFO non-blocking: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("open(2) of a FIFO blocked: O_NONBLOCK is not set")
	}
}
