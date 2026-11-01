//go:build unix && !solaris

package regularfile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReadNoFollowDescriptorRefusesAFIFO pins the descriptor half of
// ReadNoFollow (orchestrator follow-up H3): a FIFO that took the path after
// the Lstat still opens at once through openNoFollow (O_NONBLOCK) and the
// descriptor stat refuses it, and ReadNoFollow itself refuses a FIFO at the
// path promptly.
func TestReadNoFollowDescriptorRefusesAFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "hooks.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	type result struct{ err error }
	done := make(chan result, 2)
	go func() {
		f, err := openNoFollow(fifo, nil)
		if err != nil {
			done <- result{err}
			return
		}
		defer func() { _ = f.Close() }()
		_, _, err = readOpen(f, fifo, 64)
		done <- result{err}
	}()
	go func() {
		_, _, err := ReadNoFollow(fifo, 64)
		done <- result{err}
	}()
	for i := 0; i < 2; i++ {
		select {
		case r := <-done:
			if !errors.Is(r.err, ErrNotRegular) {
				t.Errorf("FIFO: %v, want ErrNotRegular", r.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the read blocked on a FIFO")
		}
	}
}

// TestOpenNoFollowRefusesALink: the no-follow open itself fails on a
// symlink at the leaf, so a link swapped in after the Lstat is not read.
func TestOpenNoFollowRefusesALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if f, err := openNoFollow(link, nil); err == nil {
		_ = f.Close()
		t.Fatal("openNoFollow opened a symlink")
	}
}
