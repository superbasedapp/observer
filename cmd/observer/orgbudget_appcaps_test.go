package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestPublishOrgAppBudget is the one Enforce model for app caps on the
// machine: they apply only with the org budget opted in and a verified body,
// and are authoritative only on a managed machine holding enforce.budget.
func TestPublishOrgAppBudget(t *testing.T) {
	body := orgcontract.BudgetPolicyBody{
		AppCaps:  []orgcontract.BudgetAppCap{{Scope: orgcontract.BudgetAppScopeEndUser, EndUserKey: "*", Period: "calendar_day", CapUSD: 1, Enforcement: "hard"}},
		AppOrgID: "org-1",
	}
	cases := []struct {
		name                   string
		fromOrg, have, granted bool
		wantApply, wantAuth    bool
	}{
		{"managed with enforce.budget", true, true, true, true, true},
		{"individual opted in", true, true, false, true, false},
		{"not opted in", false, true, true, false, false},
		{"no verified body", true, false, true, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			publishOrgAppBudget(orgclient.BudgetFetchOutcome{State: "ok", Body: body, HaveBody: c.have}, c.fromOrg, c.granted)
			snap, ok := loadOrgAppBudget()
			if ok != c.wantApply {
				t.Fatalf("apply = %v, want %v", ok, c.wantApply)
			}
			if ok && (snap.Authoritative != c.wantAuth || snap.OrgID != "org-1" || len(snap.Caps) != 1) {
				t.Errorf("snapshot = %+v", snap)
			}
		})
	}
	processOrgAppBudget.Store(nil)
}

// TestAnOrgBodyWithNoAppCapsKeepsTheMachinesOwnBudget pins review finding
// R-C03: a managed machine holding enforce.budget with a verified body that
// carries developer caps only (or comes from a server that predates
// app_budgets.v1) still applies its own [observability.admission.budget]
// caps; an empty app-cap set takes nothing over.
func TestAnOrgBodyWithNoAppCapsKeepsTheMachinesOwnBudget(t *testing.T) {
	t.Cleanup(func() { processOrgAppBudget.Store(nil) })
	body := orgcontract.BudgetPolicyBody{AppOrgID: "org-1"}
	publishOrgAppBudget(orgclient.BudgetFetchOutcome{State: "ok", Body: body, HaveBody: true}, true, true)
	snap, ok := loadOrgAppBudget()
	if !ok {
		t.Fatal("a verified body is applied (lowering-only) even with no app caps")
	}
	if snap.Authoritative {
		t.Fatal("a verified body with no app caps must not replace the machine's own admission budget")
	}
}

// TestOrgAppCapLinesNameAnExemption is the CLI half of ruling D29 (E-20,
// E-46): an exemption marker the org sends with no cap reads as an
// exemption from the default, not as a "$0" cap.
func TestOrgAppCapLinesNameAnExemption(t *testing.T) {
	snap := orgAppBudgetSnapshot{Apply: true, Caps: []orgcontract.BudgetAppCap{
		{Scope: orgcontract.BudgetAppScopeEndUser, EndUserKey: "*", Period: "calendar_day", CapUSD: 5, Enforcement: "hard"},
		{Scope: orgcontract.BudgetAppScopeEndUser, EndUserKey: "0123456789abcdef", Period: "calendar_day", Enforcement: orgcontract.BudgetAppExemptEnforcement},
	}}
	lines := orgAppCapLines(snap, true)
	if len(lines) != 3 || !strings.Contains(lines[2], "no cap (exempt from the default)") {
		t.Fatalf("lines = %q", lines)
	}
}
