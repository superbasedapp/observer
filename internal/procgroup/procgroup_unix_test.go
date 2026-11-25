//go:build !windows

package procgroup

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestSetKeepsExistingAttrs: Set turns on Setpgid without dropping a
// SysProcAttr the caller already filled in.
func TestSetKeepsExistingAttrs(t *testing.T) {
	cmd := exec.Command("true")
	Set(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatalf("Set on a bare command: SysProcAttr = %+v", cmd.SysProcAttr)
	}
	cmd = exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	Set(cmd)
	if !cmd.SysProcAttr.Setpgid || !cmd.SysProcAttr.Setsid {
		t.Fatalf("Set dropped an existing attribute: %+v", cmd.SysProcAttr)
	}
}

// TestTerminateNilIsNoop: Terminate tolerates a nil command and a command
// that never started.
func TestTerminateNilIsNoop(t *testing.T) {
	Terminate(nil, time.Second)
	Terminate(exec.Command("true"), time.Second)
}

// TestTerminateEndsTheGroup: a child started in its own group is ended by
// Terminate, well inside the grace period's KILL fallback.
func TestTerminateEndsTheGroup(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	Set(cmd)
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	Terminate(cmd, 2*time.Second)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("sleep 60 exited cleanly; want it signalled")
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the child was still running 30s after Terminate")
	}
}
