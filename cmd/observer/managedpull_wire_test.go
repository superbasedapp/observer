package main

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestManagedPullConsentTableCoversEveryRail: every rail's authority has one
// consent row, so no rail falls through to "no consent" by omission.
func TestManagedPullConsentTableCoversEveryRail(t *testing.T) {
	for _, rail := range orgcontract.ManagedPullRails {
		n := 0
		for _, row := range managedPullConsentRows {
			if row.authority == rail.Authority {
				n++
			}
		}
		if n != 1 {
			t.Errorf("rail %q authority %q has %d consent rows, want 1", rail.Name, rail.Authority, n)
		}
	}
}

// TestManagedPullConsent: consent follows the honoured grant per rail.
func TestManagedPullConsent(t *testing.T) {
	sandbox, _ := orgcontract.LookupManagedPullRail("sandbox")
	security, _ := orgcontract.LookupManagedPullRail("security")
	cases := []struct {
		name string
		eff  govern.Effective
		rail orgcontract.ManagedPullRail
		want orgclient.ManagedPullConsent
	}{
		{
			"managed with enforce.sandbox",
			govern.Effective{Managed: true, Authority: []string{govern.AuthorityEnforceSandbox}},
			sandbox,
			orgclient.ManagedPullConsent{Managed: true, HoldsAuthority: true},
		},
		{
			"managed, the other token only",
			govern.Effective{Managed: true, Authority: []string{govern.AuthorityEnforceSecurity}},
			sandbox,
			orgclient.ManagedPullConsent{Managed: true},
		},
		{
			"security rail on its own token",
			govern.Effective{Managed: true, Authority: []string{govern.AuthorityEnforceSecurity}},
			security,
			orgclient.ManagedPullConsent{Managed: true, HoldsAuthority: true},
		},
		{
			"individual node holding the token",
			govern.Effective{Authority: []string{govern.AuthorityEnforceSandbox}},
			sandbox,
			orgclient.ManagedPullConsent{},
		},
		{
			"a rail nobody consents to",
			govern.Effective{Managed: true, Authority: []string{govern.AuthorityEnforceSandbox}},
			orgcontract.ManagedPullRail{Name: "x", Authority: "enforce.unknown"},
			orgclient.ManagedPullConsent{Managed: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := managedPullConsent(tc.eff, tc.rail); got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

// TestManagedPullSinksSkipInactiveModules: a consumer whose module is not
// active registers no sink, so its rail makes no request.
func TestManagedPullSinksSkipInactiveModules(t *testing.T) {
	saved := managedPullConsumers
	t.Cleanup(func() { managedPullConsumers = saved })
	managedPullConsumers = nil
	registerManagedPullConsumer(managedPullConsumer{
		rail:   "sandbox",
		active: func(componentstate.Snapshot) bool { return false }, sink: func(orgclient.ManagedPullOutcome) {},
	})
	registerManagedPullConsumer(managedPullConsumer{
		rail:   "security",
		active: func(componentstate.Snapshot) bool { return true }, sink: func(orgclient.ManagedPullOutcome) {},
	})
	sinks := managedPullSinks(componentstate.Legacy())
	if _, ok := sinks["sandbox"]; ok {
		t.Fatal("an inactive module must register no sink")
	}
	if _, ok := sinks["security"]; !ok {
		t.Fatal("an active module registers its sink")
	}
	managedPullConsumers = nil
	wireManagedPullRails(context.Background(), nil, componentstate.Legacy(), nil)
}
