//go:build !windows

package procgroup

import (
	"os/exec"
	"syscall"
	"time"
)

// Set puts the child in its OWN process group, so a deadline can kill the
// whole tree (a child that spawns helpers must not outlive its run). Call
// it before cmd.Start.
func Set(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// Terminate sends SIGTERM to the child's whole process group, waits the
// grace period, then SIGKILLs whatever is left. It is safe to call more than
// once and on an already-exited child.
func Terminate(cmd *exec.Cmd, grace time.Duration) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pgid := -cmd.Process.Pid
	if err := syscall.Kill(pgid, syscall.SIGTERM); err != nil {
		// No group (Setpgid failed) — fall back to the process itself.
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	deadline := time.After(grace)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline:
			if err := syscall.Kill(pgid, syscall.SIGKILL); err != nil {
				_ = cmd.Process.Kill()
			}
			return
		case <-tick.C:
			// Signal 0 probes liveness without delivering anything.
			if err := syscall.Kill(pgid, 0); err != nil {
				return
			}
		}
	}
}
