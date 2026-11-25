//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// killProcGroup sends SIGKILL to the harness's process group. Called from
// cmd.Cancel on context cancellation/timeout. The runner launches each
// harness in its own process group (procgroup.Set) so the signal reaches the
// whole group (plan §3.2 step 2): a hung grandchild (codex app-server) can't
// outlive the cell.
func killProcGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	// Negative pid targets the process group (Setpgid made pgid == pid).
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
