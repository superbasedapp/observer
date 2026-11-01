//go:build unix && !linux

package host

import (
	"fmt"
	"os/exec"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// trampolineSupported: the per-process caps are set before exec through
// the trampoline here too.
const trampolineSupported = true

// platformCaps is what macOS and the other Unix systems hold: wall time and
// output caps for the whole group, CPU (RLIMIT_CPU, best effort: per
// process) and file size (RLIMIT_FSIZE) set before exec by the trampoline.
// Memory and child caps are not enforced (RLIMIT_DATA does not bound the
// allocator here, and there is no /proc to count from).
func platformCaps() map[extrun.Cap]extrun.CapState {
	return map[extrun.Cap]extrun.CapState{
		extrun.CapWall:     extrun.CapEnforced,
		extrun.CapStdout:   extrun.CapEnforced,
		extrun.CapStderr:   extrun.CapEnforced,
		extrun.CapCPU:      extrun.CapBestEffort,
		extrun.CapFileSize: extrun.CapEnforced,
	}
}

// childrenApplied: the child cap is not held here.
func childrenApplied(trampolineStatus) extrun.CapApplied { return extrun.CapApplied{} }

// bsdGroup cannot count its members.
type bsdGroup struct {
	unixGroup
}

func (bsdGroup) count() (int, bool) { return 0, false }

// attach returns the group; no cap is applied here.
func attach(cmd *exec.Cmd, _ extrun.Limits) (procGroup, error) {
	if cmd.Process.Pid <= 0 {
		return nil, fmt.Errorf("extrun/host: no process id")
	}
	return bsdGroup{unixGroup{pid: cmd.Process.Pid, proc: cmd.Process}}, nil
}
