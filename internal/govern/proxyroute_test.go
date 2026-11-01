package govern

import "testing"

// TestEveryEnforcementAuthorityDeclaresWhereItEnforces pins the
// proxyResidentEnforcement table to the closed enforce.* family: a new
// sibling must say whether it acts in the API proxy before RequiresProxyRoute
// can be trusted to answer for it.
func TestEveryEnforcementAuthorityDeclaresWhereItEnforces(t *testing.T) {
	for _, tok := range EnforcementAuthorities() {
		if _, ok := proxyResidentEnforcement[tok]; !ok {
			t.Errorf("enforcement authority %q has no proxyResidentEnforcement row", tok)
		}
	}
	for tok := range proxyResidentEnforcement {
		if !EnforcementAuthority(tok) {
			t.Errorf("proxyResidentEnforcement names %q, which is not an enforce.* token", tok)
		}
	}
}

// TestRequiresProxyRoute is the decision table, one row per case: only a
// managed node whose live grant carries a proxy-resident enforce.* token
// requires the proxy route.
func TestRequiresProxyRoute(t *testing.T) {
	cases := []struct {
		name string
		eff  Effective
		want bool
	}{
		{"individual node with enforce.budget", Effective{Managed: false, Authority: []string{AuthorityEnforceBudget}}, false},
		{"managed, no authority", Effective{Managed: true}, false},
		{"managed, extraction only", Effective{Managed: true, Authority: []string{AuthorityExtractManaged}}, false},
		{"managed, enforce.mcp_access only", Effective{Managed: true, Authority: []string{AuthorityEnforceMCPAccess}}, false},
		{"managed, enforce.budget", Effective{Managed: true, Authority: []string{AuthorityEnforceBudget}}, true},
		{"managed, enforce.routing", Effective{Managed: true, Authority: []string{AuthorityEnforceRouting}}, true},
		{"managed, enforce.admission", Effective{Managed: true, Authority: []string{AuthorityEnforceAdmission}}, true},
		{"managed, enforce.egress", Effective{Managed: true, Authority: []string{AuthorityEnforceEgress}}, true},
		{"managed, mcp_access plus budget", Effective{Managed: true, Authority: []string{AuthorityEnforceMCPAccess, AuthorityEnforceBudget}}, true},
		{"managed, refused grant", Effective{State: StateGrantSignatureInvalid, Managed: true, Authority: []string{AuthorityEnforceBudget}}, false},
		{"managed, expired grant", Effective{State: StateGrantExpired, Managed: true, Authority: []string{AuthorityEnforceRouting}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.eff.RequiresProxyRoute(); got != tc.want {
				t.Fatalf("RequiresProxyRoute() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRoutePosture is the route-posture table (routeposture.go), one case per
// routePostureRules row in order, plus the edges that must fall through.
func TestRoutePosture(t *testing.T) {
	pin := func(v any) map[string]any { return map[string]any{MaintainRoutesKey: v} }
	budget := []string{AuthorityEnforceBudget}
	cases := []struct {
		name string
		eff  Effective
		want RoutePostureVerdict
	}{
		{"individual node, even with the pin", Effective{Managed: false, Authority: budget, Pinned: pin(true)}, RoutePostureVerdict{RoutePostureNone, RoutePostureSourceNotManaged}},
		{"admin ON without any enforce token", Effective{Managed: true, Pinned: pin(true)}, RoutePostureVerdict{RoutePostureMaintain, RoutePostureSourceAdminOn}},
		{"admin OFF overrides the enforce default", Effective{Managed: true, Authority: budget, Pinned: pin(false)}, RoutePostureVerdict{RoutePostureRelease, RoutePostureSourceAdminOff}},
		{"unset: enforce.budget is the default", Effective{Managed: true, Authority: budget}, RoutePostureVerdict{RoutePostureMaintain, RoutePostureSourceEnforceDefault}},
		{"unset, no proxy-resident authority", Effective{Managed: true, Authority: []string{AuthorityEnforceMCPAccess}}, RoutePostureVerdict{RoutePostureNone, RoutePostureSourceNotRequired}},
		{"refused grant is not managed", Effective{State: StateGrantSignatureInvalid, Managed: true, Authority: budget, Pinned: pin(true)}, RoutePostureVerdict{RoutePostureNone, RoutePostureSourceNotManaged}},
		{"a non-bool pin reads as unset", Effective{Managed: true, Pinned: pin("yes")}, RoutePostureVerdict{RoutePostureNone, RoutePostureSourceNotRequired}},
	}
	if len(routePostureRules) != 5 {
		t.Fatalf("%d routePostureRules rows: add a case for the new row", len(routePostureRules))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.eff.RoutePosture(); got != tc.want {
				t.Fatalf("RoutePosture() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
