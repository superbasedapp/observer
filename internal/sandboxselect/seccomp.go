package sandboxselect

import (
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// seccomp.go resolves what one run's agent got from the syscall filter
// (tracker F-002, lane FU4): the per-run evidence terminal_run.seccomp and
// the posture bucket. It reads the layers' grounded Iso.Seccomp field and
// [terminal.sandbox].seccomp, never a backend id.

// seccompFacts is what the table reads about a run's layers.
type seccompFacts struct {
	keyOn bool
	// observer: a layer loads Observer's profile on request.
	observer bool
	// engine: a layer applies its container engine's default profile.
	engine bool
}

// seccompRunRows is the decision table, walked top down; the first row
// whose condition holds names the state. The last row always holds.
var seccompRunRows = []struct {
	state vocab.SeccompRun
	when  func(f seccompFacts) bool
}{
	{vocab.SeccompRunObserverDefault, func(f seccompFacts) bool { return f.keyOn && f.observer }},
	{vocab.SeccompRunEngineDefault, func(f seccompFacts) bool { return f.engine }},
	{vocab.SeccompRunOff, func(f seccompFacts) bool { return f.observer }},
	{vocab.SeccompRunNotApplicable, func(f seccompFacts) bool { return f.keyOn }},
	{vocab.SeccompRunNone, func(seccompFacts) bool { return true }},
}

// SeccompRunState is the state a run on layers records, with keyOn the
// value of [terminal.sandbox].seccomp at launch. It is recorded when the run
// is created, before the read-back: observer_default means the filter was
// planned and is enforced, and a run whose read-back refuses ends with that
// refusal (fail closed) rather than lowering this value (audit FU4-A4).
func SeccompRunState(keyOn bool, layers []sandboxbackend.Capability) vocab.SeccompRun {
	f := seccompFacts{keyOn: keyOn}
	for _, l := range layers {
		f.observer = f.observer || l.FiltersWithObserverProfile()
		f.engine = f.engine || l.Iso.Seccomp == vocab.SeccompEngineDefault
	}
	for _, r := range seccompRunRows {
		if r.when(f) {
			return r.state
		}
	}
	return vocab.SeccompRunNone
}

// seccompLabels are the launch line's words for the states a user turned
// [terminal.sandbox].seccomp on for (audit N2-A9: a row the key cannot
// reach is named, never silently unfiltered). The other states print
// nothing, so a launch with the key off reads as it did before.
var seccompLabels = map[vocab.SeccompRun]string{
	vocab.SeccompRunObserverDefault:    "seccomp filter observer_default",
	vocab.SeccompRunObserverSeizePIDNS: "seccomp filter observer_seize_pidns (strace allowed: PTRACE_SEIZE lifted, the sandbox has its own process list)",
	vocab.SeccompRunObserverSeizeYama:  "seccomp filter observer_seize_yama (strace allowed: PTRACE_SEIZE lifted, Yama limits it to the run's own child processes)",
	vocab.SeccompRunNotApplicable:      "seccomp not applicable on this backend (Observer's filter does not run there and no engine filter is grounded); this run is not filtered by Observer",
}

// SeccompLabel is the launch line's seccomp part for state ("" for none).
func SeccompLabel(state vocab.SeccompRun) string { return seccompLabels[state] }
