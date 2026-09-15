package integration

import "testing"

func TestBudgetAdmissionChannelUsesOnlyVerifiedProxy(t *testing.T) {
	t.Parallel()

	proxied, ok := For("claude-code")
	if !ok {
		t.Fatal("claude-code capability missing")
	}
	if got := proxied.BudgetAdmissionChannel(); got != BudgetAdmissionObserverProxy {
		t.Fatalf("claude-code budget admission = %q, want %q", got, BudgetAdmissionObserverProxy)
	}

	muse, ok := For("muse")
	if !ok {
		t.Fatal("muse capability missing")
	}
	if !muse.Handoff.Launchable() {
		t.Fatal("test premise: Muse must remain an Observer-launchable tool")
	}
	if got := muse.BudgetAdmissionChannel(); got != BudgetAdmissionNone {
		t.Fatalf("Muse budget admission = %q, want none; launchability/hooks/sandbox must not imply spend control", got)
	}

	probeOnly := Capability{ProxyProbe: &ProxyRoute{Kind: RouteLauncher}}
	if got := probeOnly.BudgetAdmissionChannel(); got != BudgetAdmissionNone {
		t.Fatalf("unverified ProxyProbe budget admission = %q, want none", got)
	}
}
