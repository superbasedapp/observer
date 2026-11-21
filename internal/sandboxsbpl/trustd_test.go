package sandboxsbpl

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestTLSMachServicesFollowTheGateway (F-015 R3, audit finding N4-R3): the
// certificate trust service, a side path that can fetch URLs on the box's
// behalf, is reachable only on a tier whose profile runs the egress
// gateway. One case per tier Seatbelt offers; the rule is read from the
// tier table (EgressProfile.Gateway), never from a tier name.
func TestTLSMachServicesFollowTheGateway(t *testing.T) {
	cases := []struct {
		tier sandbox.Egress
		want bool
	}{
		{sandbox.EgressInternet, true},
		{sandbox.EgressProxyOnly, false},
		{sandbox.EgressNone, false},
	}
	for _, c := range cases {
		t.Run(string(c.tier), func(t *testing.T) {
			prof, err := sandbox.ResolveEgress(string(c.tier))
			if err != nil {
				t.Fatal(err)
			}
			if prof.Gateway != c.want {
				t.Fatalf("the tier table's Gateway for %s is %v; this case expects %v", c.tier, prof.Gateway, c.want)
			}
			p, err := Build(baseRequest(c.tier))
			if err != nil {
				t.Fatal(err)
			}
			rules, err := Check(p.Text, p.ParamMap())
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range TLSMachServices {
				if got := Allowed(rules, p.ParamMap(), Query{Op: "mach-lookup", GlobalName: name}); got != c.want {
					t.Errorf("mach-lookup %s on %s: allowed %v, want %v", name, c.tier, got, c.want)
				}
			}
			// The base services stay on every tier.
			for _, name := range baseMachServices {
				if !Allowed(rules, p.ParamMap(), Query{Op: "mach-lookup", GlobalName: name}) {
					t.Errorf("mach-lookup %s on %s refused", name, c.tier)
				}
			}
		})
	}
	for _, name := range TLSMachServices {
		for _, base := range baseMachServices {
			if name == base {
				t.Errorf("%s is in both lists, so the tier rule cannot close it", name)
			}
		}
	}
}
