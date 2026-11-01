//go:build unix && !linux

package host

import (
	"errors"
	"os"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// containmentFacts: macOS and the BSDs have process groups only (no cgroup,
// no isolation provider yet), so every run is labelled not contained.
func (e *Executor) containmentFacts(p extrun.Plan, _ bool) extrun.ContainmentFacts {
	return extrun.ContainmentFacts{PIDNamespace: p.PIDNamespace, ProcessGroup: true}
}

// setupRung: every rung starts the program through the exec-mode
// trampoline; there is no subreaper sweep here.
func (e *Executor) setupRung(extrun.Rung, extrun.Plan, bool) (rungSetup, error) {
	return rungSetup{mode: modeExec}, nil
}

// groupFor returns the run's process group.
func (e *Executor) groupFor(l *launch, p extrun.Plan) (procGroup, error) {
	return attach(l.cmd, p.Limits)
}

// survivors: there is no /proc to look survivors up in.
func (e *Executor) survivors(*launch) int { return 0 }

// bootTicks: not used here.
func bootTicks() uint64 { return 0 }

// supervise: there is no child subreaper here.
func supervise(_ trampolinePayload, _ *os.File, _ func(trampolineStatus), fail func(string, error, int) int) int {
	return fail("supervise", errors.New("no child subreaper on this OS"), trampExitStart)
}
