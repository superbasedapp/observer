//go:build !windows

package hook

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestOwnGateRegisteredRefusesAFIFO pins audit follow-up 4: the probe reads
// the hooks file through regularfile.Read, so a FIFO planted at the path is
// refused at once (absent, the call is judged) instead of hanging the
// replay. The old readSettingsFile (os.Stat, then os.ReadFile) blocked on
// it forever.
func TestOwnGateRegisteredRefusesAFIFO(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".copilot", "hooks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "superbased-observer.json"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan bool, 1)
	go func() {
		done <- OwnGateRegistered(Options{HomeDir: home, BinaryPath: "/usr/local/bin/observer"})("copilot-cli", "PreToolUse")
	}()
	select {
	case got := <-done:
		if got {
			t.Fatal("a FIFO read as registered")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the probe blocked on a FIFO")
	}
}
