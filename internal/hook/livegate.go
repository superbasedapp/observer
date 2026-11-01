package hook

import (
	"sort"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// # The live-check gate on hook writers (surface-gap DEC-12)
//
// A writer that is built but waits on a live check refuses here, before it
// reads or writes anything, whoever calls it (`observer init`, the
// dashboard, `observer start`). One gate, two sources of "waiting":
//
//   - a registry row's hook writer (integration.HookSpec.LiveGate, read
//     through integration.HookLiveGate);
//   - a cross-OS registration target this package defines with no registry
//     row of its own (the Windows to WSL twins and the Wave 7 IDE targets,
//     liveGateRows), which waits until EVERY live check its row lists has
//     passed.
//
// Register refuses both with one SkipLiveGated result
// (liveGateRefusal); a gated writer may also call liveGateRefusal itself
// (register_cortex.go). The callers skip gated targets on their own too
// (autoRegisterLiveGate, the dashboard hooks cell), so this is the backstop
// that keeps a forgotten caller from writing. Installed never lists a gated
// cross-OS target (nor spends the detection on it); InstalledLiveGated lists
// the detected ones for the doctor. Unregister is never gated. The one
// wording is integration.LiveGate.Text: "built, waiting on live check <id>".

// SkipLiveGated: the target's writer is built but switched off until its
// live check passes. No Observer hook exists on the target, so it reads like
// SkipNotApplicable for enforcement (CoveredElsewhere is false).
const SkipLiveGated SkipKind = "live_gated"

// runLiveGatedHookWriters lets this package's tests run a gated writer's
// real logic. Production code never sets it: switching a writer on is a
// registry change (clearing HookSpec.LiveGate) or deleting a liveGateRows
// row, never a flag.
var runLiveGatedHookWriters = false

// hookLiveGateFor is the registry lookup (a variable so tests can gate a
// synthetic target).
var hookLiveGateFor = integration.HookLiveGate

// liveGateRefusal returns the refusal for tool when its hook writer waits on
// a live check (its registry row's, or its cross-OS target row's), and
// ok=false when the writer may run.
func (r *Registry) liveGateRefusal(tool string) (RegistrationResult, bool) {
	if runLiveGatedHookWriters {
		return RegistrationResult{}, false
	}
	g := hookLiveGateFor(tool)
	if !g.Waiting() {
		id, gated := LiveCheckGate(tool)
		if !gated {
			return RegistrationResult{}, false
		}
		g = integration.LiveGate(id)
	}
	if g.Finding() != "" {
		// The check ran and found the host does not run the hook (FU-195):
		// switched off for that finding, not waiting.
		return RegistrationResult{
			Tool: tool, DryRun: r.opts.DryRun, Skipped: true, SkipKind: SkipLiveGated,
			SkipReason: "not written: " + g.Text() + " (the writer stays switched off)",
			SkipAdvice: "nothing to do; Observer does not write a gate the host would not run (--force does not lift this)",
		}, true
	}
	return RegistrationResult{
		Tool: tool, DryRun: r.opts.DryRun, Skipped: true, SkipKind: SkipLiveGated,
		SkipReason: "not written: " + g.Text() + " (the writer is switched off until that check passes)",
		SkipAdvice: "nothing to do now; a later release switches the writer on once the live check passes (--force does not lift this)",
	}, true
}

// liveGateRow is one gated cross-OS target and every live check it waits
// on: the target stays off until all of them have passed (the row is
// deleted then).
type liveGateRow struct {
	target     string
	liveChecks []string
}

// liveGatesMu guards the test seam that injects a row.
var (
	liveGatesMu sync.RWMutex
	liveGates   = buildLiveGates()
)

// liveGateRows is the table the cross-OS gate is built from. Each family of
// gated targets contributes its rows from the table that defines its
// writers.
var liveGateRows = gatedTargetRows()

// gatedTargetRows collects every family's gated targets.
func gatedTargetRows() []liveGateRow {
	return append(append(wslTwinGateRows(), ideTargetGateRows()...), xcodeTargetGateRows()...)
}

func buildLiveGates() map[string]string {
	m := make(map[string]string, len(liveGateRows))
	for _, row := range liveGateRows {
		m[row.target] = joinLiveChecks(row.liveChecks)
	}
	return m
}

// joinLiveChecks spells a row's checks as one gate value ("WSL-4", or
// "WSL-4 and FU-87"), so the shared wording names every check still owed.
func joinLiveChecks(ids []string) string {
	return strings.Join(ids, " and ")
}

// LiveGate is one gated cross-OS registration target and the live check (or
// checks) it waits on.
type LiveGate struct {
	// Target is the registration target ("claude-code-wsl").
	Target string
	// LiveCheck is the pending-tracker id of the live check, or several
	// joined with " and " ("WSL-4 and FU-87") when every one must pass.
	LiveCheck string
}

// Note is the operator text for the gate: LiveGateNote of its live check.
func (g LiveGate) Note() string { return LiveGateNote(g.LiveCheck) }

// LiveCheckGate reports whether cross-OS target is switched off behind a
// live check, and which (all of them, joined).
func LiveCheckGate(target string) (liveCheck string, gated bool) {
	liveGatesMu.RLock()
	defer liveGatesMu.RUnlock()
	id, ok := liveGates[target]
	return id, ok
}

// LiveGatedTargets returns every gated cross-OS target, sorted by target.
func LiveGatedTargets() []LiveGate {
	liveGatesMu.RLock()
	defer liveGatesMu.RUnlock()
	out := make([]LiveGate, 0, len(liveGates))
	for t, id := range liveGates {
		out = append(out, LiveGate{Target: t, LiveCheck: id})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// LiveGateNote is the one wording every surface uses for a gated writer
// (integration.LiveGate.Text).
func LiveGateNote(liveCheck string) string {
	return integration.LiveGate(liveCheck).Text()
}

// InstalledLiveGated returns the cross-OS targets whose home is detected on
// this host but which are switched off behind a live check, in detection
// order. The doctor reports each with LiveGateNote.
func (r *Registry) InstalledLiveGated() []LiveGate {
	var out []LiveGate
	for _, t := range r.installedAll(true) {
		if id, ok := LiveCheckGate(t); ok {
			out = append(out, LiveGate{Target: t, LiveCheck: id})
		}
	}
	return out
}

// setLiveGateForTest adds (or with liveCheck "" removes) a gate row for the
// duration of a test.
func setLiveGateForTest(t interface{ Cleanup(func()) }, target, liveCheck string) {
	liveGatesMu.Lock()
	prev, had := liveGates[target]
	if liveCheck == "" {
		delete(liveGates, target)
	} else {
		liveGates[target] = liveCheck
	}
	liveGatesMu.Unlock()
	t.Cleanup(func() {
		liveGatesMu.Lock()
		defer liveGatesMu.Unlock()
		if had {
			liveGates[target] = prev
		} else {
			delete(liveGates, target)
		}
	})
}

// splitLiveGated partitions targets into the ones that may run and the
// gated cross-OS ones, keeping each side in input order.
func splitLiveGated(targets []string) (open []string, gated []LiveGate) {
	for _, t := range targets {
		if id, ok := LiveCheckGate(t); ok {
			gated = append(gated, LiveGate{Target: t, LiveCheck: id})
			continue
		}
		open = append(open, t)
	}
	return open, gated
}
