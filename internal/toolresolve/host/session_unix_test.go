//go:build unix

package host

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestDetachSessionSetsSetsid (tracker F-031): the capture shell runs in a
// session of its own, so an interactive login shell can never take the
// observer's terminal and stop its process group; and a timeout cancels
// the whole group.
func TestDetachSessionSetsSetsid(t *testing.T) {
	cmd := exec.Command("true")
	detachSession(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
		t.Fatalf("SysProcAttr = %+v, want Setsid", cmd.SysProcAttr)
	}
	if cmd.Cancel == nil {
		t.Fatal("no Cancel: a timeout would kill the shell alone")
	}
}

// TestCaptureTimeoutKillsTheShellsDescendants (fix round 1 of lane FU1): a
// shell whose rc file starts a long-lived child and then hangs is timed
// out, and the child dies with it (the whole process group is killed).
func TestCaptureTimeoutKillsTheShellsDescendants(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	shell := writeFakeShell(t, "bash", "sleep 60 &\necho $! > "+pidFile+"\nsleep 60")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := runLoginShell(ctx, []string{shell, "-lc", "true"}, os.Environ()); err == nil {
		t.Fatal("a hung shell did not time out")
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("the child never started: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the shell's child %d outlived the capture timeout", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
