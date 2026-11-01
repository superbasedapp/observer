//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// TestBoxRouteEvidenceIsNotProofOnTheTokenLane (OSH-R-008 [CHECK]): a
// launch inside a Windows MXC box presents its model proxy as
// http://127.0.0.1:<helper port>/t/<token>. Under a managed hard budget the
// host-side walk's coverage row does not take that as a proven route: it is
// refused as an unverified route unless a process cutoff covers the launch.
// So a managed hard-cap launch there fails closed; it can never be admitted
// on the strength of the box's own claim. Bubblewrap, process_lite and the
// OCI rows present the proxy at loopback on the proxy's own port inside the
// box, which is proof by construction.
func TestBoxRouteEvidenceIsNotProofOnTheTokenLane(t *testing.T) {
	var tool string
	for _, c := range integration.Capabilities() {
		if c.RouteProven() && c.BudgetAdmissionChannel() == integration.BudgetAdmissionObserverProxy {
			tool = c.Tool
			break
		}
	}
	if tool == "" {
		t.Skip("no proven-route tool in the registry")
	}
	const proxy = "http://127.0.0.1:8820"
	for _, boxURL := range []string{sandboxmxc.BaseURL(51234, "dG9rZW4"), "http://127.0.0.1:8820/t/dG9rZW4"} {
		ev := budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: boxURL}
		if checked, err := boxLaunchEvidence(ev); err != nil || checked.ProxyURL != boxURL {
			t.Fatalf("the host would not even read the box's evidence: %v", err)
		}
		if cause := budgetLaunchCoverageCause(nil, tool, ev, proxy); cause == budgetLaunchCovered {
			t.Fatalf("%s: the token lane %s was admitted as a proven route", tool, boxURL)
		}
	}
	// The loopback same-port form every Linux box presents is proof.
	ev := budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: proxy}
	if cause := budgetLaunchCoverageCause(nil, tool, ev, proxy); cause != budgetLaunchCovered {
		t.Fatalf("%s: the node proxy's own URL is not a proven route (%v)", tool, cause)
	}
}
