//go:build !sbo_omit_security

package main

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/policystate"
)

// The SEC-E merge fixes (plans orchestrator merge of cloud/plans-sec-e).

// TestSecurityManagedRailPollsOnlyWithTheModule: the security consumer is
// registered once in a build with the module, and the shared poll step is
// offered its sink only where the security module is active, so a node with
// the module off makes no request for the rail.
func TestSecurityManagedRailPollsOnlyWithTheModule(t *testing.T) {
	n := 0
	for _, c := range managedPullConsumers {
		if c.rail == securityManagedRail {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("security consumers registered = %d, want 1", n)
	}
	on := config.Default()
	on.Components.Add = []string{securityManagedModule}
	for _, tc := range []struct {
		name string
		snap componentstate.Snapshot
		want bool
	}{
		{"module active", componentSnapshotForConfig(on), true},
		// The zero snapshot resolves nothing, so no optional module runs.
		{"module not active", componentstate.Snapshot{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := tc.snap
			if snap.ModuleActive(securityManagedModule) != tc.want {
				t.Fatalf("fixture: security module active = %v, want %v", !tc.want, tc.want)
			}
			if _, ok := managedPullSinks(snap)[securityManagedRail]; ok != tc.want {
				t.Fatalf("security sink offered = %v, want %v", ok, tc.want)
			}
		})
	}
	// The consent table gives the rail its own authority, enforce.security.
	rail, ok := orgcontract.LookupManagedPullRail(securityManagedRail)
	if !ok || rail.Authority != govern.AuthorityEnforceSecurity {
		t.Fatalf("rail %+v %v", rail, ok)
	}
	if c := managedPullConsent(govern.Effective{Managed: true, Authority: []string{govern.AuthorityEnforceSecurity}}, rail); !c.Managed || !c.HoldsAuthority {
		t.Fatalf("a managed node holding enforce.security must poll: %+v", c)
	}
	if c := managedPullConsent(govern.Effective{Authority: []string{govern.AuthorityEnforceSecurity}}, rail); c.Managed {
		t.Fatalf("an individual node must not poll: %+v", c)
	}
}

// TestSecurityManagedFromTheGrant (merge audit finding 4): "managed" for the
// floors and the pull is a live, honoured managed grant, never the
// enrolment record: a lapsed or refused grant reads individual.
func TestSecurityManagedFromTheGrant(t *testing.T) {
	now := time.Now()
	live := govern.LiveIdentity{Enrolled: true, OrgKey: "k", Generation: 3}
	grant := func(mut func(*govern.Grant)) *govern.Grant {
		g := &govern.Grant{
			OrgKey: "k", Generation: 3, OrgName: "Acme", ConsentMode: govern.ConsentManaged,
			Authority: []string{govern.AuthorityEnforceSecurity}, ExpiresAt: now.Add(time.Hour),
		}
		if mut != nil {
			mut(g)
		}
		return g
	}
	cases := []struct {
		name string
		g    *govern.Grant
		live govern.LiveIdentity
		want bool
	}{
		{"live managed grant", grant(nil), live, true},
		{"lapsed grant", grant(func(g *govern.Grant) { g.ExpiresAt = now.Add(-time.Minute) }), live, false},
		{"refused grant (does not verify)", grant(func(g *govern.Grant) { g.Integrity = govern.GrantIntegrityInvalid }), live, false},
		{"refused grant (identity changed)", grant(nil), govern.LiveIdentity{Enrolled: true, OrgKey: "k", Generation: 4}, false},
		{"individual consent", grant(func(g *govern.Grant) { g.ConsentMode = "" }), live, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eff := govern.Resolve(govern.Delivered{}, tc.g, tc.live, now)
			if got := securityManagedFrom(eff); got != tc.want {
				t.Fatalf("managed = %v, want %v (state %q, effective managed %v)", got, tc.want, eff.State, eff.Managed)
			}
			// A node that reads individual keeps its posture check and
			// never applies a managed-only key.
			facts := securityscanning.NodeFacts{Managed: securityManagedFrom(eff), Active: map[string]bool{"security.deps": true}, Local: securityLocalPosture(config.DefaultSecurityConfig())}
			spec := compileFloor(t, `{"require":{"online_checks":"required"}}`)
			for _, k := range securityscanning.Evaluate(spec, facts) {
				if k.Key == securityscanning.AxisOnlineChecks && (k.State == securityscanning.StateApplied) != tc.want {
					t.Fatalf("require.online_checks = %s on a node read managed=%v", k, tc.want)
				}
			}
		})
	}
}

// TestSecurityFloorsInertWithoutTheModule (merge audit item 11): with the
// security module inactive no floor is applied, every key reads
// not_applicable: module_inactive, and the point reports no floor.
func TestSecurityFloorsInertWithoutTheModule(t *testing.T) {
	withSecurityScanningNode(t, false, config.DefaultSecurityConfig(), "security.deps")
	installFloor(t, `{"require":{"finding_retention_days":730}}`, 4, true)
	if got := securityRetentionDaysNow(90); got != 730 {
		t.Fatalf("control: with the module the floor applies, got %d", got)
	}
	secScanning.mu.Lock()
	secScanning.moduleOff = true
	secScanning.mu.Unlock()
	if got := securityRetentionDaysNow(90); got != 90 {
		t.Fatalf("retention with the module off = %d, want the node's own 90", got)
	}
	spec := compileFloor(t, `{"require":{"finding_retention_days":730,"components":["security.deps"]}}`)
	for _, k := range securityscanning.Evaluate(spec, secScanning.facts()) {
		if k.State != securityscanning.StateNotApplicable || k.Reason != securityscanning.ReasonModuleInactive {
			t.Fatalf("key %s, want not_applicable: module_inactive", k)
		}
	}
	read := newSecurityScanningPointReader(nil, func() time.Time { return time.Unix(1, 0) })
	f, err := read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := policystate.Resolve(policystate.PointNodeSecurity, policystate.FamilySecurityScanning, f); r.Status != orgcontract.StatusNone || r.Reason != orgcontract.ReasonNoPolicy {
		t.Fatalf("point with the module off: %+v, want none/no_policy", r)
	}
}

// TestSecurityKeyStateOnManagedNode (merge audit item 6, revised by lane
// SEC-E4): a managed node's require.online_checks = required is applied,
// because its online checks now go to the org relay; the privacy floor and
// an individual node are unchanged.
func TestSecurityKeyStateOnManagedNode(t *testing.T) {
	req := securityscanning.KeyState{Key: securityscanning.AxisOnlineChecks, State: securityscanning.StateApplied, Floor: "required"}
	if got := securityKeyStateOnNode(req, securityscanning.NodeFacts{Managed: true}); got.State != securityscanning.StateApplied {
		t.Fatalf("managed: %s", got)
	}
	if got := securityKeyStateOnNode(req, securityscanning.NodeFacts{}); got.State != securityscanning.StateApplied {
		t.Fatalf("individual: %s", got)
	}
	forbid := securityscanning.KeyState{Key: securityscanning.AxisAllowOnlineChecks, State: securityscanning.StateApplied, Floor: "forbidden"}
	if got := securityKeyStateOnNode(forbid, securityscanning.NodeFacts{Managed: true}); got.State != securityscanning.StateApplied {
		t.Fatalf("the privacy floor is applied on a managed node too: %s", got)
	}
}
