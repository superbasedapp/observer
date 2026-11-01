//go:build windows

package host

import (
	"os/exec"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// containmentFacts: every run on Windows is held by its job object.
func (e *Executor) containmentFacts(extrun.Plan, bool) extrun.ContainmentFacts {
	return extrun.ContainmentFacts{JobObject: true}
}

// setupRung: the job object needs no launcher and no trampoline.
func (e *Executor) setupRung(extrun.Rung, extrun.Plan, bool) (rungSetup, error) {
	return rungSetup{}, nil
}

// groupFor puts the suspended program in its job and resumes it.
func (e *Executor) groupFor(l *launch, p extrun.Plan) (procGroup, error) {
	return attach(l.cmd, p.Limits)
}

// abortStart kills a start that never reached the program and reaps it.
func abortStart(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
}

// bootTicks: not used here.
func bootTicks() uint64 { return 0 }

// survivors counts the processes still in the run's job after the final
// TerminateJobObject (termination is asynchronous, so it waits up to a
// second for the count to drop). The job is the identity here: every
// process the program started is in it, since breakaway is never allowed.
func (e *Executor) survivors(l *launch) int {
	g, ok := l.grp.(*jobGroup)
	if !ok {
		return 0
	}
	deadline := time.Now().Add(time.Second)
	for {
		n, ok := g.active()
		if !ok || n == 0 || time.Now().After(deadline) {
			return n
		}
		time.Sleep(20 * time.Millisecond)
	}
}
