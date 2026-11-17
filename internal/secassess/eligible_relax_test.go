package secassess

import (
	"strings"
	"testing"
)

// internetFacts is a machine whose live tier is internet with a host list,
// where the tier relaxation is consented (plan section 13.9).
func internetFacts() Facts {
	f := goodFacts()
	f.Tier = "internet"
	f.TierRelaxOK = true
	f.TierRelax = TierFacts{Live: "internet", Hosts: []string{"registry.npmjs.org"}}
	f.GatewayPort = 3128
	return f
}

func relaxRequest(id ID) Request {
	r := goodRequest(id)
	r.TierRelax = true
	return r
}

// TestEligibleTierRelaxation: the tier row changes only what E8, E8b and E9
// accept, and never when any of the facts it depends on is missing.
func TestEligibleTierRelaxation(t *testing.T) {
	t.Parallel()
	t.Run("the tick under the internet tier with a host list passes", func(t *testing.T) {
		v := Eligible(PentestLocal, internetFacts(), relaxRequest(PentestLocal))
		if !v.OK || !v.TierRelaxed || !v.ForceSandbox || v.Backend != "bwrap" {
			t.Fatalf("verdict %+v", v)
		}
	})
	t.Run("an agent that is not proxy routed passes under the relaxed tier", func(t *testing.T) {
		f := internetFacts()
		f.ToolProxyRouted = false
		if v := Eligible(RedTeamLocal, f, relaxRequest(RedTeamLocal)); !v.OK {
			t.Fatalf("verdict %+v", v)
		}
	})
	t.Run("the same request without the tick is refused as before", func(t *testing.T) {
		v := Eligible(PentestLocal, internetFacts(), goodRequest(PentestLocal))
		if v.OK || v.Rule != "E8" || !strings.Contains(v.Reason, "internet") {
			t.Fatalf("verdict %+v", v)
		}
	})
	t.Run("the tick under proxy_only changes nothing", func(t *testing.T) {
		f := goodFacts()
		f.TierRelaxOK = true
		v := Eligible(PentestLocal, f, relaxRequest(PentestLocal))
		if !v.OK || v.TierRelaxed {
			t.Fatalf("verdict %+v", v)
		}
	})
	t.Run("the caller's consent is required", func(t *testing.T) {
		f := internetFacts()
		f.TierRelaxOK = false
		if v := Eligible(PentestLocal, f, relaxRequest(PentestLocal)); v.OK || v.Rule != "E8" {
			t.Fatalf("verdict %+v", v)
		}
	})
	t.Run("a missing host list is refused even with the consent", func(t *testing.T) {
		f := internetFacts()
		f.TierRelax.Hosts = nil
		if v := Eligible(PentestLocal, f, relaxRequest(PentestLocal)); v.OK || v.Rule != "E8" {
			t.Fatalf("verdict %+v", v)
		}
	})
	for _, tier := range []string{"host", "none"} {
		t.Run("the "+tier+" tier is never relaxed to", func(t *testing.T) {
			f := internetFacts()
			f.Tier, f.TierRelax.Live = tier, tier
			if v := Eligible(PentestLocal, f, relaxRequest(PentestLocal)); v.OK || v.Rule != "E8" {
				t.Fatalf("verdict %+v", v)
			}
		})
	}
	t.Run("E9 needs a backend that supports the live tier", func(t *testing.T) {
		f := internetFacts()
		f.Backends[1].Tiers = []string{"proxy_only"}
		if v := Eligible(PentestLocal, f, relaxRequest(PentestLocal)); v.OK || v.Rule != "E9" {
			t.Fatalf("verdict %+v", v)
		}
	})
}

// TestEligibleGatewayPort: E5 also refuses the in-box egress gateway's port.
func TestEligibleGatewayPort(t *testing.T) {
	t.Parallel()
	f := internetFacts()
	r := relaxRequest(PentestLocal)
	r.Target, r.ConfirmTarget = "http://127.0.0.1:3128/", "http://127.0.0.1:3128/"
	v := Eligible(PentestLocal, f, r)
	if v.OK || v.Rule != "E5" || !strings.Contains(v.Reason, "egress gateway") {
		t.Fatalf("verdict %+v", v)
	}
	// With no gateway in the live tier the port is free.
	f2 := goodFacts()
	if v := Eligible(PentestLocal, f2, r); !v.OK {
		t.Fatalf("a proxy_only box has no gateway: %+v", v)
	}
}
