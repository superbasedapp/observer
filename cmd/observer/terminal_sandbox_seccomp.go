//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxseccomp"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_seccomp.go is the daemon side of the seccomp filter of
// the bwrap and process_lite rows (gap G16, lane N2): the one place a
// launch resolves [terminal.sandbox].seccomp into a profile id. The program
// itself is built where it is loaded (the host helper for bwrap, the exec
// step for process_lite), from that id; sandbox_seccomp_linux.go loads and
// reads it back.
//
// The strace opt-in (lane ptrace, PT-96): [terminal.sandbox]
// .seccomp_allow_seize picks a profile with PTRACE_SEIZE lifted when a
// containment ground holds at launch (sandboxseccomp.DecideSeize). The
// decision is made once, when the run is created (withSeccompRun), and
// recorded on the run; the argv is composed from that record
// (sandboxSeccompProfile's recorded argument), so the run row and the
// filter it runs under can never disagree.

// readYamaScope reads Yama's ptrace scope (a variable so tests can set the
// host's answer). It reads a /proc file and changes nothing.
var readYamaScope = func() (int, bool) {
	b, err := os.ReadFile(sandboxseccomp.YamaScopePath)
	if err != nil {
		return 0, false
	}
	return sandboxseccomp.ParseYamaScope(string(b))
}

// seizeFacts is the containment table's input for a run on layers: the
// opt-in, whether a layer declares a pid namespace of its own (the
// registry's grounded field, never a backend name), and Yama read now.
func seizeFacts(cfg config.TerminalSandboxConfig, layers []sandboxbackend.Capability) sandboxseccomp.SeizeFacts {
	f := sandboxseccomp.SeizeFacts{OptIn: cfg.SeccompAllowSeize}
	for _, l := range layers {
		f.OwnPIDNamespace = f.OwnPIDNamespace || l.Iso.OwnPIDNamespace
	}
	f.YamaScope, f.YamaKnown = readYamaScope()
	return f
}

// sandboxSeccompProfile is the profile a launch on row is planned with: ""
// when [terminal.sandbox].seccomp is off (the default, D7) or the row does
// not load Observer's profile (its grounded Iso.Seccomp field, never its
// name). Otherwise it is the profile the run recorded (recorded, the run's
// terminal_run.seccomp state) when that names a profile lifting
// PTRACE_SEIZE and the opt-in is still on, else observer_default; either is
// checked to build on this host now, so a launch that could not be filtered
// is refused here and never runs unfiltered.
func sandboxSeccompProfile(cfg config.TerminalSandboxConfig, row sandboxbackend.Capability, recorded string) (string, error) {
	if !cfg.Seccomp || !row.FiltersWithObserverProfile() {
		return "", nil
	}
	id := sandboxseccomp.ProfileObserverDefault
	if cfg.SeccompAllowSeize && vocab.SeccompRun(recorded).LiftsSeize() {
		id = sandboxseccomp.ProfileID(recorded)
	}
	return seccompProfileFor(runtime.GOOS, runtime.GOARCH, id)
}

// seccompProfileFor is sandboxSeccompProfile's check on a given host.
func seccompProfileFor(goos, goarch string, id sandboxseccomp.ProfileID) (string, error) {
	if goos != "linux" {
		return "", fmt.Errorf("terminal_sandbox: [terminal.sandbox].seccomp is on, but the seccomp filter is Linux only (this host is %s); the launch is refused, never run unfiltered", goos)
	}
	if _, err := sandboxseccomp.Build(id, goarch); err != nil {
		return "", fmt.Errorf("terminal_sandbox: [terminal.sandbox].seccomp is on, but the filter cannot be built on this host: %w; the launch is refused, never run unfiltered", err)
	}
	return string(id), nil
}

// withSeccompRun stamps what the syscall filter gives a created run on its
// isolation evidence (tracker F-002, lane FU4; terminal_run.seccomp,
// migration 232): resolved from the layers' grounded Iso.Seccomp field and
// [terminal.sandbox].seccomp by sandboxselect.SeccompRunState, never from a
// backend name. A run with no layers (no stack recorded) is left unrecorded.
// With the key on and no layer that filters, the state is not_applicable
// and the launch line says so (audit N2-A9), so the run is never silently
// unfiltered. A run that gets Observer's profile then takes the strace
// opt-in's decision (lane ptrace): the seize profile of the ground that
// held, or observer_default and, when the opt-in is on, the reason on the
// run's note.
func (r *sandboxRuntime) withSeccompRun(res termsvc.CreateResult, err error) (termsvc.CreateResult, error) {
	if err != nil || len(res.Isolation.Stack) == 0 {
		return res, err
	}
	layers := seccompLayers(res.Isolation.Stack)
	state := sandboxselect.SeccompRunState(r.cfg.Seccomp, layers)
	if state == vocab.SeccompRunObserverDefault {
		d := sandboxseccomp.DecideSeize(seizeFacts(r.cfg, layers))
		state = vocab.SeccompRun(d.Profile)
		if d.Refusal != "" {
			res.Note += "; " + d.Refusal
		}
	}
	res.Isolation.Seccomp = string(state)
	return res, nil
}

// seccompLayers looks a run's stack up in the registry; an id the registry
// does not know contributes no layer (it filters nothing Observer knows of).
func seccompLayers(stack []string) []sandboxbackend.Capability {
	out := make([]sandboxbackend.Capability, 0, len(stack))
	for _, id := range stack {
		if row, ok := sandboxbackend.Get(id); ok {
			out = append(out, row)
		}
	}
	return out
}

// sandboxCLISeccompLabel is the CLI launch line's seccomp part: "" for the
// key-off states (the line reads as before), else ", " and the state's
// words.
func sandboxCLISeccompLabel(state string) string {
	l := sandboxselect.SeccompLabel(vocab.SeccompRun(state))
	if l == "" {
		return ""
	}
	return ", " + l
}

// sandboxCLISeizeRefusal is the CLI launch's line when the strace opt-in is
// on but PTRACE_SEIZE stays denied for this run (no containment ground): ""
// otherwise. It reads the run's recorded state and stack, so it speaks only
// for a run that got observer_default with the opt-in on.
func sandboxCLISeizeRefusal(cfg config.TerminalSandboxConfig, state string, stack []string) string {
	if !cfg.SeccompAllowSeize || vocab.SeccompRun(state) != vocab.SeccompRunObserverDefault {
		return ""
	}
	return sandboxseccomp.DecideSeize(seizeFacts(cfg, seccompLayers(stack))).Refusal
}

// sandboxSeizeRows decides the strace switch for every offered row that
// loads Observer's filter, from the row's grounded pid-namespace field and
// the Yama reading given (the dashboard route and `observer sandbox status`
// share it).
func sandboxSeizeRows(yamaScope int, yamaKnown bool) []dashapi.SandboxSeizeRow {
	out := []dashapi.SandboxSeizeRow{}
	for _, row := range sandboxbackend.Offered() {
		if !row.FiltersWithObserverProfile() {
			continue
		}
		d := sandboxseccomp.DecideSeize(sandboxseccomp.SeizeFacts{
			OptIn: true, OwnPIDNamespace: row.Iso.OwnPIDNamespace, YamaScope: yamaScope, YamaKnown: yamaKnown,
		})
		out = append(out, dashapi.SandboxSeizeRow{
			Backend: row.ID, Label: row.Label,
			Lifted: d.Ground != "", Ground: string(d.Ground), Reason: d.Refusal,
		})
	}
	return out
}

// sandboxSeizeHostNow is the strace switch's answer on this host now.
func sandboxSeizeHostNow() dashapi.SandboxSeizeHost {
	scope, known := readYamaScope()
	return dashapi.SandboxSeizeHost{YamaScope: scope, YamaKnown: known, Rows: sandboxSeizeRows(scope, known)}
}

// sandboxSeizeHostSeam is the dashboard's Options.SandboxSeize.
func sandboxSeizeHostSeam() func() dashapi.SandboxSeizeHost { return sandboxSeizeHostNow }
