//go:build !sbo_omit_security

package main

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_baseline_org.go keeps the org's baseline approvals node-locally
// (security plan 4.5.2 and 7.5, lane LEFT-SHARED). The security managed
// pull serves a managed node the org's approvals of the baseline references
// its own finding rows reported (orgcontract approved_baselines, only to a
// node that advertised security.baseline_approvals, which
// internal/orgclient/security_pullcaps.go does). After every applied
// outcome the daemon replaces sec_org_baseline_approvals with the in-force
// list, or clears it when no pull is in force; `observer security baseline`
// and the dashboard's baseline card then label the project's baseline
// "approved by the org". A label only: no verdict, no pre-existing mark and
// no gate reads it. An individual node never pulls the rail, so its table
// stays empty and nothing changes there.

// securityBaselineOrgStore is the daemon's long-lived store the follower
// writes through (bound where the org push loop is built, start.go); nil
// in every other process, where the follower does nothing.
var securityBaselineOrgStore atomic.Pointer[store.Store]

// bindSecurityBaselineOrg binds (or, with nil, unbinds) the store.
func bindSecurityBaselineOrg(st *store.Store) { securityBaselineOrgStore.Store(st) }

func init() {
	securityManagedFollowers = append(securityManagedFollowers, followSecurityBaselineApprovals)
}

// securityBaselineApprovalsFor is what one applied state means for the
// table: the in-force body's approvals (nil clears).
func securityBaselineApprovalsFor(st securityManagedState) (int64, []orgcontract.SecurityBaselineApproval) {
	if !st.Outcome.InForce || st.Policy == nil {
		return st.Outcome.Version, nil
	}
	return st.Outcome.Version, st.Policy.ApprovedBaselines
}

// followSecurityBaselineApprovals is the follower: replace the table.
func followSecurityBaselineApprovals(st securityManagedState) {
	s := securityBaselineOrgStore.Load()
	if s == nil {
		return
	}
	version, approvals := securityBaselineApprovalsFor(st)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.ReplaceSecOrgBaselineApprovals(ctx, version, approvals); err != nil {
		slog.Default().Warn("security: the org's baseline approvals were not stored", "err", err)
	}
}

// securityBaselineOrgLine is the CLI's label line for a baseline the org
// approved, "" otherwise.
func securityBaselineOrgLine(b *secsvc.ApprovedBaseline) string {
	if b == nil || b.OrgApprovedAt == "" {
		return ""
	}
	return "Approved by the org on " + b.OrgApprovedAt + " (a label: it changes no finding or verdict)."
}
