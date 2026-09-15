package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termsession"
)

// terminal_policystop.go wires dashboard.PolicyStopProvider onto the ONE
// shared terminal stack's *termsession.Manager plus the store's node-
// intervention audit trail (internal/store.LookupProcessControlStop). It is
// the seam that lets a dashboard terminal exit ("New Terminal", not a GUI
// launch) explain itself when an org-managed node's OWN node-intervention
// loop stopped the vendor process — resolving the SAME guard_events audit
// row cmd/observer/nodeintervention_audit.go already wrote, never a guess.
//
// Two facts compose here that neither seam has alone:
//   - the PTY child's OS pid + launch time (termsession.Manager, which keeps
//     the pid resolvable past exit — see ProcessAttributionForHandle);
//   - the audit row correlated by that pid within the run's own lifetime
//     window (store.LookupProcessControlStop).
// Composing them in cmd keeps both internal/intelligence/dashboard and
// internal/termsession free of any internal/store import (CLAUDE.md module-
// boundary rule #2 — no type leakage past a seam).

// policyStopProvider implements dashboard.PolicyStopProvider over one
// terminal stack's manager + the daemon's store.
type policyStopProvider struct {
	mgr *termsession.Manager
	st  *store.Store
}

// PolicyStopForHandle satisfies dashboard.PolicyStopProvider. It returns
// ok=false whenever the handle carries no recorded pid (every non-dashboard
// launch kind, and any handle the manager has already garbage-collected) or
// no matching audit row exists in the run's own window — never a guess.
func (p *policyStopProvider) PolicyStopForHandle(ctx context.Context, handle string) (dashboard.PolicyStop, bool) {
	if p == nil || p.mgr == nil || p.st == nil {
		return dashboard.PolicyStop{}, false
	}
	pid, launchedAt, ok := p.mgr.ProcessAttributionForHandle(handle)
	if !ok {
		return dashboard.PolicyStop{}, false
	}
	stop, found, err := p.st.LookupProcessControlStop(ctx, pid, launchedAt)
	if err != nil || !found {
		return dashboard.PolicyStop{}, false
	}
	return dashboard.PolicyStop{
		RuleID:   stop.RuleID,
		Decision: stop.Decision,
		Reason:   stop.Reason,
		At:       stop.At,
	}, true
}
