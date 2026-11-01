package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// hook_components.go is the hook-runtime half of the L2 adapter gate
// (modular packaging P5, lane MP-ADP; ledger MODPKG-14 residual 3). An
// inactive adapter's hooks are never registered (init and the start-time
// auto-register skip it), but an entry can outlive the removal: a hand edit
// of [components], a removal applied with skip teardown, an org policy that
// blocks the adapter, or a binary built without the adapter (L1). Such a
// leftover hook still runs `observer hook <tool> <event>`. Without this gate
// it would keep ingesting the tool's events, so the adapter would not be
// inert.
//
// The rule is one decision (hookComponentDecision, table-driven): an
// inactive adapter's hook answers the host with the universal allow and
// records nothing (no row, no hook-events.jsonl receipt), EXCEPT on a hook whose plan fails closed (a wired gate
// while guard enforcement is on): there the guard keeps deciding, exactly as
// before, because inactive components never weaken enforcement (the same
// fail-safe direction as ledger MODPKG-11). A tool id the catalog does not
// know resolves active (fail open to today's behaviour).

// hookComponentTimeout bounds the component-state read on the hook path
// (the enrolment / grant / policy read of a managed node). A read that does
// not finish resolves ungoverned, so the local selection decides.
const hookComponentTimeout = time.Second

// hookComponentVerdict is what the hook runtime does for one invocation.
type hookComponentVerdict int

const (
	// hookRunAsBefore dispatches the invocation as today.
	hookRunAsBefore hookComponentVerdict = iota
	// hookAllowInert answers the dialect's allow and records nothing.
	hookAllowInert
)

// hookComponentRows is the ordered decision table, walked top-down.
var hookComponentRows = []struct {
	name           string
	adapterActive  bool
	planFailsClose bool
	verdict        hookComponentVerdict
}{
	{name: "active adapter runs as before", adapterActive: true, planFailsClose: false, verdict: hookRunAsBefore},
	{name: "active adapter, enforced gate, runs as before", adapterActive: true, planFailsClose: true, verdict: hookRunAsBefore},
	{name: "inactive adapter, enforced gate: guard keeps deciding", adapterActive: false, planFailsClose: true, verdict: hookRunAsBefore},
	{name: "inactive adapter: allow, record nothing", adapterActive: false, planFailsClose: false, verdict: hookAllowInert},
}

// hookComponentDecision walks hookComponentRows.
func hookComponentDecision(adapterActive, planFailsClosed bool) hookComponentVerdict {
	for _, r := range hookComponentRows {
		if r.adapterActive == adapterActive && r.planFailsClose == planFailsClosed {
			return r.verdict
		}
	}
	return hookRunAsBefore
}

// hookComponentSnapshotFn resolves the component state for the hook's config
// (a seam for tests). A config that does not load resolves the legacy
// everything-active snapshot.
var hookComponentSnapshotFn = func(ctx context.Context, configPath string) componentstate.Snapshot {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return componentstate.Legacy()
	}
	ctx, cancel := context.WithTimeout(ctx, hookComponentTimeout)
	defer cancel()
	return componentstate.ResolveGoverned(cfg.Components, nil, componentGovernanceFor(ctx, cfg))
}

// hookAdapterGate answers an inactive adapter's hook with the universal
// allow and reports true, or reports false (dispatch as before). It reads
// nothing from stdin when it lets the invocation through.
func hookAdapterGate(ctx context.Context, tool, event, label, configPath string, plan hookFailurePlan, stdin io.Reader, stdout, stderr io.Writer) bool {
	snap := hookComponentSnapshotFn(ctx, configPath)
	noteHookInvocationComponents(configPath, snap)
	if hookComponentDecision(snap.AdapterActive(tool), plan.FailClosed) != hookAllowInert {
		return false
	}
	fmt.Fprintf(stderr, "observer-hook: %s: the %s adapter is not active on this machine; allowing without recording (remove the leftover hook with `observer components teardown adapter.%s`)\n",
		label, tool, adapterBaseTool(tool))
	// The universal allow every receiverless binding answers with
	// (hook.HandleApprove's reply), without HandleApprove's forensic
	// hook-events.jsonl row: an inactive adapter's activity is not recorded
	// anywhere, not even as a receipt.
	_, _ = io.Copy(io.Discard, io.LimitReader(stdin, defaultHookBodyLimit))
	_ = json.NewEncoder(stdout).Encode(hook.Decision{Decision: "approve"})
	markHookReplied()
	return true
}

// adapterBaseTool maps a hook registration target to its adapter: the
// cross-OS "-windows" bridge and an Xcode agent-home target resolve to their
// base tool (clientwire.HookTargetBase), the same mapping
// componentstate.AdapterActive uses.
func adapterBaseTool(tool string) string { return clientwire.HookTargetBase(tool) }

// The invocation's component snapshot: the adapter gate resolves it once per
// `observer hook` invocation (above), and later decisions of the same
// invocation that depend on a component's selection (the security feedback,
// security_feedback.go hookFeedbackSelected) read it here instead of
// loading the config again. It is the same component state the
// registration writers use (registrationSelected resolves it the same way).
// resetHookInvocationState clears it.
var (
	hookInvocationSnapMu   sync.Mutex
	hookInvocationSnapPath string
	hookInvocationSnap     *componentstate.Snapshot
)

// noteHookInvocationComponents records the invocation's snapshot for
// configPath.
func noteHookInvocationComponents(configPath string, snap componentstate.Snapshot) {
	hookInvocationSnapMu.Lock()
	defer hookInvocationSnapMu.Unlock()
	hookInvocationSnapPath, hookInvocationSnap = configPath, &snap
}

// hookInvocationComponents returns the invocation's snapshot for
// configPath, resolving (and recording) it when the adapter gate has not
// run for this config (a handler called directly).
func hookInvocationComponents(configPath string) componentstate.Snapshot {
	hookInvocationSnapMu.Lock()
	if hookInvocationSnap != nil && hookInvocationSnapPath == configPath {
		snap := *hookInvocationSnap
		hookInvocationSnapMu.Unlock()
		return snap
	}
	hookInvocationSnapMu.Unlock()
	snap := hookComponentSnapshotFn(context.Background(), configPath)
	noteHookInvocationComponents(configPath, snap)
	return snap
}

// resetHookInvocationComponents forgets the invocation's snapshot.
func resetHookInvocationComponents() {
	hookInvocationSnapMu.Lock()
	defer hookInvocationSnapMu.Unlock()
	hookInvocationSnapPath, hookInvocationSnap = "", nil
}
