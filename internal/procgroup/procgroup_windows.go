//go:build windows

package procgroup

import (
	"os/exec"
	"time"
)

// Set is a no-op on Windows: there is no POSIX process group. The child is
// still killed on the deadline by Terminate.
func Set(_ *exec.Cmd) {}

// Terminate kills the child process. Windows has no process-group signal
// equivalent, so a grandchild the child spawned is NOT reaped here: an
// honest platform limitation rather than a silent claim of parity.
func Terminate(cmd *exec.Cmd, _ time.Duration) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
