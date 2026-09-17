package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// THE LAUNCH BOUNDARY CONSULTS SPEND.
//
// Coverage answers "could this invocation be stopped?"; it says nothing about
// whether it SHOULD be. Until this file existed, the launch gate resolved the
// requirement, the Guard's readiness and a controllability proof and then
// started the vendor process without ever reading a dollar or a token — so a
// launch at or over an exhausted org cap started and was killed by the
// daemon's reconcile loop a second or two later, with nothing said at the
// terminal that started it.
//
// The decision itself is NOT recomputed here. It is the same
// guard.CheckInterventionBudget the node's process controller asks
// (cmd/observer/nodeintervention_policy.go), against the same rules, the same
// window calendars and the same accounting seam. Two things differ, and both
// are inputs rather than logic:
//
//   - PROCESS. A CLI launcher is not the daemon, so the daemon's shared Guard
//     may not exist in this process. The cold path builds one through the SAME
//     two owners the daemon composes with (acquireProcessCostEngine for the
//     price table, acquireProcessGuard for the Guard) and publishes the node's
//     verified org document onto it through the SAME boundary
//     (newOrgBudgetHandle.Prime). Re-implementing cap arithmetic here would be
//     a second budget truth, which is exactly what the org-budget boundary
//     exists to prevent.
//   - SOURCE READINESS. The daemon knows it live, from the capture cycle it
//     just ran. A launcher reads the per-tool report that cycle left behind.

var errBudgetLaunchDenied = errors.New("organization budget denies further spend on this node")

// budgetLaunchSpendAdmission refuses before process start when the managed
// budget would deny this TOOL's next request. A denial for another tool's
// broken accounting never lands here: the decision carries this tool's name,
// and CheckInterventionBudget composes per-tool coverage onto the node-wide
// windows for exactly that reason.
func budgetLaunchSpendAdmission(ctx context.Context, cfg config.Config, configPath string, st *store.Store, tool string, state managedBudgetLaunchState) error {
	now := time.Now().UTC()
	authority, err := nodeInterventionAuthority(ctx, st, os.Getuid(), now)
	if err != nil {
		return budgetLaunchStateFailure(tool, err)
	}
	gd := budgetLaunchSpendGuard(ctx, cfg, configPath, state)
	if gd == nil {
		// Fail closed, and name the cause the operator can act on: the Guard
		// itself, not the budget document.
		return budgetLaunchSpendRefusal(tool, guard.InterventionBudgetDecision{
			Deny: true, RuleID: "B-625", Reason: nodeInterventionGuardUnavailableReason,
		})
	}
	source := budgetLaunchAccountingSource(ctx, st, cfg.Observer.DBPath, tool)
	// NEITHER SessionID NOR Model IS PASSED, and neither can be (BUD-GUARD-1,
	// docs/audits/codebase-audit-2026-09-16.md). This runs BEFORE the process
	// starts: there is no session to name, and nothing names the model the
	// agent is about to pick — an argv scan would be a per-tool guess about a
	// flag the developer may not even have typed, and a cap denied on a guess
	// is worse than a cap that honestly does not reach here.
	//
	// So the org's per-TOOL caps (B-626/B-627) refuse a launch, because a
	// launch names its tool; the per-MODEL caps (B-628/B-629) do not, and bite
	// instead on the proxy request path and on the node's running-session pass
	// (see nodeInterventionBudget). The node-wide windows apply either way,
	// minus the per-session one, which an absent SessionID marks unavailable
	// rather than fabricating as zero. docs/budgets.md's
	// subject_scope_node_enforced caveat states exactly this split.
	decision := gd.CheckInterventionBudget(guard.InterventionBudgetInput{
		Tool:          tool,
		SourceReady:   source.Ready,
		SourceReason:  source.Reason,
		Now:           now,
		BudgetBinding: authority.BudgetBinding,
	})
	if !decision.Deny {
		return nil
	}
	return budgetLaunchSpendRefusal(tool, decision)
}

// budgetLaunchAccountingSource reports whether this tool's own accounting
// source was established, from the controller report the daemon's capture
// cycle leaves behind.
//
// A tool with NO entry is ready. That is not an optimistic default: the report
// covers the tools that had a governed process running in the last cycle, and
// a tool with no such process has nothing for the capture pass to catch up —
// the ordinary watcher has already landed whatever it produced. An unreadable,
// stale or unverifiable report is the same answer for the same reason; the
// report is honesty context, never the authority (it cannot be, since a
// launcher could otherwise be admitted by a file it wrote itself).
func budgetLaunchAccountingSource(ctx context.Context, st *store.Store, dbPath, tool string) nodeInterventionSource {
	ready := nodeInterventionSource{Tool: tool, Ready: true}
	status, err := readNodeInterventionStatus(ctx, st, dbPath)
	if err != nil {
		return ready
	}
	entry, reported := status.Capture[tool]
	if !reported {
		return ready
	}
	return nodeInterventionSource{Tool: tool, Ready: entry.Ready, Reason: entry.Reason}
}

// budgetLaunchSpendGuard returns the Guard that owns this process's budget
// decision. In the daemon it is the one the proxy already published, with the
// live org composition applied — this must never re-publish onto it, because
// the launcher's persisted document can be older than the daemon's last fetch.
// In a cold launcher process there is none, so one is built and the node's
// verified document is published onto it through the daemon's own boundary.
//
// THE COLD GUARD GETS ITS OWN DATABASE HANDLE, and keeps it. Both process
// registries it joins (the Guard's and the price engine's) are keyed by db
// path and outlive any single launch — the daemon's arrangement, and what
// makes a second launch in the same process (an Arena matrix, a benchmark
// run) reuse this work instead of repeating it. Binding them to the caller's
// handle, which the caller closes when its launch returns, would leave the
// cached Guard reading a closed database and reporting every window as
// unavailable accounting — a denial with no spend behind it.
func budgetLaunchSpendGuard(ctx context.Context, cfg config.Config, configPath string, state managedBudgetLaunchState) *guard.Guard {
	if gd := lookupProcessGuard(cfg.Observer.DBPath); gd != nil {
		return gd
	}
	logger := slog.Default()
	owned, database, closeOwned, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		logger.Warn("budget launch: cannot open the node database for a cold budget decision", "err", err)
		return nil
	}
	st := store.New(database)
	// The price table must exist BEFORE the Guard: buildGuardForStore's
	// accounting lookup reads the process-shared engine and never constructs
	// one, so an absent engine would price every managed row as a miss and
	// report the USD windows unavailable.
	acquireProcessCostEngine(ctx, owned, database, logger)
	gd := acquireProcessGuard(ctx, owned, st, logger)
	if gd == nil {
		closeOwned()
		return nil
	}
	newOrgBudgetHandle(gd, owned.Guard.Budget, func() bool { return state.Granted }, st, logger).
		Prime(budgetLaunchFetchOutcome(owned, state))
	return gd
}

// budgetLaunchFetchOutcome projects the durable evidence this launch state was
// composed from onto the fetch outcome the org-budget boundary publishes. A
// read FAILURE carries no body: on a node that requires an org budget,
// "unreadable" and "no cap" are opposite verdicts and only the first may arm
// the B-625 ceiling.
func budgetLaunchFetchOutcome(cfg config.Config, state managedBudgetLaunchState) orgclient.BudgetFetchOutcome {
	if state.CacheErr != nil {
		return orgclient.BudgetFetchOutcome{
			State: orgcontract.BudgetFetchUnverified, Witness: state.Cached.Witness,
		}
	}
	outcome := orgclient.BudgetFetchOutcome{
		Body:     state.Cached.Body,
		HaveBody: state.Cached.Have,
		Binding:  state.Cached.Binding,
		Witness:  state.Cached.Witness,
		State:    initialFetchState(cfg.Guard.Budget.FromOrg),
	}
	if state.Cached.Have {
		// Verified, but not by this process — the same honest pair the CLI
		// posture line reports (guardBudgetPostureLineWithGrant).
		outcome.State = orgcontract.BudgetFetchUnreachable
	}
	return outcome
}

// budgetLaunchSpendRefusal renders a spend denial through the safe launcher
// message path, carrying the rule id and the engine's own reason so the
// developer can name the cap to their admin instead of guessing.
func budgetLaunchSpendRefusal(tool string, decision guard.InterventionBudgetDecision) error {
	detail := decision.Reason
	if decision.RuleID != "" {
		detail = decision.RuleID + " " + detail
	}
	if detail == "" {
		detail = "the managed budget denied this launch"
	}
	err := fmt.Errorf("observer %s: %w; organization budget: %s", tool, errBudgetLaunchDenied, detail)
	return newVisibleLauncherError(err, err.Error()+"; contact your org admin")
}
