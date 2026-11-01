//go:build !unix && !windows

package host

import (
	"os/exec"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// containmentFacts: no group and no job here; the program runs alone.
func (e *Executor) containmentFacts(extrun.Plan, bool) extrun.ContainmentFacts {
	return extrun.ContainmentFacts{}
}

func (e *Executor) setupRung(extrun.Rung, extrun.Plan, bool) (rungSetup, error) {
	return rungSetup{}, nil
}

func (e *Executor) groupFor(l *launch, p extrun.Plan) (procGroup, error) {
	return attach(l.cmd, p.Limits)
}

func abortStart(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
}

func (e *Executor) survivors(*launch) int { return 0 }

func bootTicks() uint64 { return 0 }
