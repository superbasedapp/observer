package api

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// TestProvisioningRules is one case per provisioningRules row, in table
// order, plus the ordering cases that matter (a waitlisted row that was
// later parked reads failed; an acked row beats its stale error class).
func TestProvisioningRules(t *testing.T) {
	t.Parallel()
	prov := pc.StateProvisioning
	cases := []struct {
		name string
		f    provisioningFacts
		want string
	}{
		{"active org", provisioningFacts{status: pc.StateActive}, "ready"},
		{"suspended org", provisioningFacts{status: pc.StateSuspended}, "ready"},
		{"pending deletion", provisioningFacts{status: pc.StatePendingDeletion}, "closing"},
		{"no create row", provisioningFacts{status: prov}, "unknown"},
		{"parked", provisioningFacts{status: prov, found: true, cs: store.OrgCreateStatus{State: "failed", LastErrorClass: waitlistErrorClass}}, "failed"},
		{"acked, org not yet active", provisioningFacts{status: prov, found: true, cs: store.OrgCreateStatus{State: "acked", LastErrorClass: "x"}}, "finishing"},
		{"waitlisted", provisioningFacts{status: prov, found: true, cs: store.OrgCreateStatus{State: "pending", Attempts: 3, LastErrorClass: waitlistErrorClass}}, "waitlisted"},
		{"never tried", provisioningFacts{status: prov, found: true, cs: store.OrgCreateStatus{State: "pending"}}, "queued"},
		{"retrying", provisioningFacts{status: prov, found: true, cs: store.OrgCreateStatus{State: "pending", Attempts: 2, LastErrorClass: "transport:timeout"}}, "retrying"},
		{"sent", provisioningFacts{status: prov, found: true, cs: store.OrgCreateStatus{State: "sent", Attempts: 1}}, "creating"},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		if got := provisioningStage(tc.f); got != tc.want {
			t.Errorf("%s: stage %q, want %q", tc.name, got, tc.want)
		}
		seen[tc.want] = true
	}
	for _, r := range provisioningRules {
		if !seen[r.stage] {
			t.Errorf("rule %q has no case", r.stage)
		}
	}
}

func TestOrgCaps(t *testing.T) {
	t.Parallel()
	org := func(role store.ConsoleRole, billing bool, st pc.TenantState, kind store.OrgKind) store.MyOrg {
		return store.MyOrg{Org: store.Org{Status: st, Kind: kind}, ConsoleRole: role, IsBillingOwner: billing}
	}
	cases := []struct {
		name string
		o    store.MyOrg
		want orgCapsJSON
	}{
		{"owner billing owner, active team", org(store.ConsoleOwner, true, pc.StateActive, store.OrgTeam), orgCapsJSON{Rename: true, ViewBilling: true, Checkout: true}},
		{"owner, provisioning", org(store.ConsoleOwner, true, pc.StateProvisioning, store.OrgTeam), orgCapsJSON{ViewBilling: true, Checkout: true}},
		{"admin", org(store.ConsoleAdmin, false, pc.StateActive, store.OrgTeam), orgCapsJSON{Rename: true, ViewBilling: true}},
		{"member billing owner", org(store.ConsoleMember, true, pc.StateActive, store.OrgTeam), orgCapsJSON{ViewBilling: true, Checkout: true}},
		{"member", org(store.ConsoleMember, false, pc.StateActive, store.OrgTeam), orgCapsJSON{}},
		{"personal org owner", org(store.ConsoleOwner, true, pc.StateActive, store.OrgPersonal), orgCapsJSON{Rename: true, ViewBilling: true}},
	}
	for _, tc := range cases {
		if got := orgCaps(tc.o); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestTenantHost(t *testing.T) {
	t.Parallel()
	s := &Server{tenantDomain: "superbased.app"}
	if got := s.tenantHost("acme"); got != "acme.superbased.app" {
		t.Errorf("host = %q", got)
	}
	if got := (&Server{}).tenantHost("acme"); got != "" {
		t.Errorf("no tenant domain gave host %q", got)
	}
}
