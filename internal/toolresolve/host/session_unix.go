//go:build unix

package host

import (
	"os/exec"
	"syscall"
)

// detachSession runs the capture shell in a session of its own (tracker
// F-031). `bash -lic` is an interactive shell: started in the observer's own
// process group under a terminal it takes that terminal's foreground group,
// and the observer (a daemon or CLI started as a background job of an
// interactive terminal, or a test binary under `timeout`) is then stopped by
// SIGTTOU or SIGTTIN with its whole group. A new session has no controlling
// terminal, so the shell cannot take one.
//
// The shell leads its new session's process group, so a timeout kills that
// whole group (fix round 1 of lane FU1): a slow rc file's descendants (an
// auto-updater, a backgrounded helper) never outlive the capture. WaitDelay
// still bounds the wait for a pipe one of them held.
func detachSession(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// The group id is the shell's pid (it called setsid); kill the
		// group, and the shell itself should the group be gone already.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
