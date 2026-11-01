//go:build unix

package host

import (
	"os"
	"syscall"
)

// newSessionAttr starts the helper's grandchild in a new session, outside
// the run's process group.
func newSessionAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }

// trampolineDieEnv makes a trampoline start of this test binary say its
// first status word and then die without another, as a trampoline killed
// by a task cap would.
const trampolineDieEnv = "EXTRUN_TRAMPOLINE_DIE"

// dieAfterStarted is the trampolineDieEnv behaviour, run first in TestMain.
func dieAfterStarted() {
	if os.Getenv(trampolineDieEnv) != "1" || !isTrampolineStart(os.Args, os.Getenv) {
		return
	}
	if f := os.NewFile(trampolineStatusFD, "extrun-status"); f != nil {
		_, _ = f.Write(encodeStatus(trampolineStatus{Ev: evStarted}))
	}
	os.Exit(2)
}
