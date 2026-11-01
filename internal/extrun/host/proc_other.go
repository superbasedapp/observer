//go:build !unix && !windows

package host

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// platformCaps on a system with neither process groups nor job objects: the
// output caps hold, wall time only for the program itself (best effort),
// memory and child caps not at all.
func platformCaps() map[extrun.Cap]extrun.CapState {
	return map[extrun.Cap]extrun.CapState{
		extrun.CapWall:   extrun.CapBestEffort,
		extrun.CapStdout: extrun.CapEnforced,
		extrun.CapStderr: extrun.CapEnforced,
	}
}

func prepareCmd(*exec.Cmd) {}

// trampolineSupported: there is no trampoline here.
const trampolineSupported = false

// selfPath is never used here (no trampoline).
func selfPath(bool) (string, error) { return os.Executable() }

// appliedCaps: nothing beyond the platform's plan is held here.
func appliedCaps(extrun.Limits, trampolineStatus, bool) map[extrun.Cap]extrun.CapApplied {
	return nil
}

// soloGroup can only kill the program itself.
type soloGroup struct {
	p *os.Process
}

func (g soloGroup) kill()                      { _ = g.p.Kill() }
func (soloGroup) count() (int, bool)           { return 0, false }
func (soloGroup) close()                       {}
func signalOf(*os.ProcessState) (string, bool) { return "", false }

func attach(cmd *exec.Cmd, _ extrun.Limits) (procGroup, error) {
	if cmd.Process == nil {
		return nil, fmt.Errorf("extrun/host: no process")
	}
	return soloGroup{p: cmd.Process}, nil
}
