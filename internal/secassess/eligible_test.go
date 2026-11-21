package secassess

import (
	"slices"
	"strings"
	"testing"
)

// goodFacts is a machine that passes every sandbox rule for a pen test.
func goodFacts() Facts {
	return Facts{
		ProjectOnDisk: true, SandboxProbed: true, Tier: "proxy_only",
		Backends: []BackendFact{
			{ID: "oci-runc", Label: "Containers", Available: true, Local: true, Tiers: []string{"proxy_only", "internet"}, FullCapture: true},
			{ID: "bwrap", Label: "Bubblewrap", Available: true, Local: true, Tiers: []string{"internet", "proxy_only", "none", "host"}, FullCapture: true},
		},
		ToolSandboxable: true, ToolProxyRouted: true, SourceLiveAvailable: true, ProxyPort: 8820,
	}
}

func goodRequest(id ID) Request {
	return Request{Kind: id, Target: "http://localhost:3000", ConfirmTarget: "http://localhost:3000/", Sandbox: true}
}

// TestEligibleRules: one row per rule of the table, each with the fact or
// request that trips it and the rule, code and a fragment of the sentence.
func TestEligibleRules(t *testing.T) {
	cases := []struct {
		name   string
		kind   ID
		mutate func(f *Facts, r *Request)
		rule   string
		code   string
		reason string
	}{
		{"E1 rasp is not agent-shaped", RASP, func(*Facts, *Request) {}, "E1", CodeNotLaunchable, "deployed application"},
		{"E2 project folder missing", ThreatModel, func(f *Facts, _ *Request) { f.ProjectOnDisk = false }, "E2", CodeProjectMissing, "not on this machine"},
		{"E3 no target", PentestLocal, func(_ *Facts, r *Request) { r.Target = "" }, "E3", CodeTargetRequired, "Name the development server"},
		{"E3 remote target", PentestLocal, func(_ *Facts, r *Request) { r.Target = "http://example.com:80/" }, "E3", CodeTargetRequired, "localhost, 127.0.0.1 or [::1]"},
		{"E3 no port", RedTeamLocal, func(_ *Facts, r *Request) { r.Target = "http://localhost/" }, "E3", CodeTargetRequired, "no port"},
		{"E3 an address past the launch cap", PentestLocal, func(_ *Facts, r *Request) {
			r.Target = "http://localhost:3000/" + strings.Repeat("a", MaxLaunchTargetBytes)
		}, "E3", CodeTargetRequired, "over 512 characters"},
		{"E3 credentials in the URL", PentestLocal, func(_ *Facts, r *Request) { r.Target = "http://u:p@localhost:3000/" }, "E3", CodeTargetRequired, "user information"},
		{"E4 confirmation differs", PentestLocal, func(_ *Facts, r *Request) { r.ConfirmTarget = "http://localhost:3001/" }, "E4", CodeTargetUnconfirmed, "does not match"},
		{"E4 no confirmation", RedTeamLocal, func(_ *Facts, r *Request) { r.ConfirmTarget = "" }, "E4", CodeTargetUnconfirmed, "does not match"},
		{"E5 the proxy port", PentestLocal, func(_ *Facts, r *Request) {
			r.Target, r.ConfirmTarget = "http://127.0.0.1:8820/", "http://127.0.0.1:8820/"
		}, "E5", CodeTargetReservedPort, "proxy port"},
		{"E6 not sandboxed", PentestLocal, func(_ *Facts, r *Request) { r.Sandbox = false }, "E6", CodeSandboxRequired, "only in a sandbox"},
		{"E7 no probe", PentestLocal, func(f *Facts, _ *Request) { f.SandboxProbed = false }, "E7", CodeSandboxUnavailable, "no sandbox support"},
		{"E7 no backend available", PentestLocal, func(f *Facts, _ *Request) {
			for i := range f.Backends {
				f.Backends[i].Available = false
			}
		}, "E7", CodeSandboxUnavailable, "No sandbox backend is available"},
		{"E7 tool cannot be sandboxed", PentestLocal, func(f *Facts, _ *Request) {
			f.ToolSandboxable, f.ToolSandboxReason = false, "state dirs not grounded"
		}, "E7", CodeSandboxUnavailable, "state dirs not grounded"},
		{"E8 internet tier", PentestLocal, func(f *Facts, _ *Request) { f.Tier = "internet" }, "E8", CodeTierNotConfined, "internet"},
		{"E8 empty tier means internet", RedTeamLocal, func(f *Facts, _ *Request) { f.Tier = "" }, "E8", CodeTierNotConfined, "internet"},
		{"E8 host tier", PentestLocal, func(f *Facts, _ *Request) { f.Tier = "host" }, "E8", CodeTierNotConfined, "host"},
		{"E8 none tier", PentestLocal, func(f *Facts, _ *Request) { f.Tier = "none" }, "E8", CodeTierNotConfined, "no route to its model"},
		{"E8b tool not proxy routed", PentestLocal, func(f *Facts, _ *Request) { f.ToolProxyRouted = false }, "E8b", CodeToolNotProxyRouted, "not routed through Observer's proxy"},
		{"E9 no grounded backend", PentestLocal, func(f *Facts, _ *Request) { f.Backends = f.Backends[:1] }, "E9", CodeBackendNotGrounded, "No sandbox backend on this machine is grounded"},
		{"E9 grounded backend beta", PentestLocal, func(f *Facts, _ *Request) { f.Backends[1].Beta = true }, "E9", CodeBackendNotGrounded, "grounded"},
		{"E9 grounded backend not full capture", PentestLocal, func(f *Facts, _ *Request) { f.Backends[1].FullCapture = false }, "E9", CodeBackendNotGrounded, "grounded"},
		{"E9 grounded backend lacks the tier", PentestLocal, func(f *Facts, _ *Request) { f.Backends[1].Tiers = []string{"internet"} }, "E9", CodeBackendNotGrounded, "grounded"},
		{"E9 grounded backend hosted", PentestLocal, func(f *Facts, _ *Request) { f.Backends[1].Local = false }, "E9", CodeBackendNotGrounded, "grounded"},
		{"E9 a named backend that is not grounded", PentestLocal, func(_ *Facts, r *Request) { r.Backend = "oci-runc" }, "E9", CodeBackendNotGrounded, "oci-runc is not one this assessment can use"},
		{"E10 a clone workspace", PentestLocal, func(_ *Facts, r *Request) { r.WorkspaceSource = "clone-local" }, "E10", CodeSourceNotLive, "live workspace"},
		{"E10 live unavailable", RedTeamLocal, func(f *Facts, _ *Request) { f.SourceLiveAvailable = false }, "E10", CodeSourceNotLive, "not available"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, r := goodFacts(), goodRequest(tc.kind)
			tc.mutate(&f, &r)
			v := Eligible(tc.kind, f, r)
			if v.OK || v.Rule != tc.rule || v.Code != tc.code || !strings.Contains(v.Reason, tc.reason) {
				t.Fatalf("verdict = %+v, want rule %s code %s reason containing %q", v, tc.rule, tc.code, tc.reason)
			}
		})
	}
	// Every rule of the table has at least one row above.
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.rule] = true
	}
	for _, id := range RuleIDs() {
		if !covered[id] {
			t.Errorf("rule %s has no test row", id)
		}
	}
}

// TestEligiblePasses: what a passing launch is made of, per kind.
func TestEligiblePasses(t *testing.T) {
	t.Run("pen test: forced sandbox, live source, the grounded backend", func(t *testing.T) {
		v := Eligible(PentestLocal, goodFacts(), goodRequest(PentestLocal))
		if !v.OK || !v.ForceSandbox || v.ForceSource != "live" || v.Backend != "bwrap" || v.Target.String() != "http://localhost:3000/" {
			t.Fatalf("verdict = %+v", v)
		}
	})
	t.Run("red team may name the grounded backend, or Automatic", func(t *testing.T) {
		for _, choice := range []string{"bwrap", "auto", ""} {
			r := goodRequest(RedTeamLocal)
			r.Backend = choice
			if v := Eligible(RedTeamLocal, goodFacts(), r); !v.OK || v.Backend != "bwrap" {
				t.Errorf("backend %q: %+v", choice, v)
			}
		}
	})
	t.Run("a plan read does not need the confirmation", func(t *testing.T) {
		r := goodRequest(PentestLocal)
		r.ConfirmTarget, r.Plan = "", true
		if v := Eligible(PentestLocal, goodFacts(), r); !v.OK {
			t.Fatalf("verdict = %+v", v)
		}
	})
	t.Run("optional-sandbox kinds are not judged by the sandbox rules", func(t *testing.T) {
		bad := Facts{ProjectOnDisk: true}
		for _, id := range []ID{ThreatModel, CSPMReadonly, IASTInstrumentedTests} {
			v := Eligible(id, bad, Request{Kind: id})
			if !v.OK || v.ForceSandbox || v.ForceSource != "" || v.Backend != "" {
				t.Errorf("%s: %+v", id, v)
			}
		}
	})
	t.Run("a loopback IPv6 target is accepted", func(t *testing.T) {
		r := goodRequest(PentestLocal)
		r.Target, r.ConfirmTarget = "http://[::1]:5173/app", "http://[::1]:5173/app"
		if v := Eligible(PentestLocal, goodFacts(), r); !v.OK {
			t.Fatalf("verdict = %+v", v)
		}
	})
	t.Run("an unknown kind is refused as not agent-shaped", func(t *testing.T) {
		if v := Eligible("nope", goodFacts(), Request{}); v.OK || v.Code != CodeNotLaunchable {
			t.Fatalf("verdict = %+v", v)
		}
	})
}

// TestRuleOrder: the first refusal wins, in table order.
func TestRuleOrder(t *testing.T) {
	want := []string{"E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E8b", "E9", "E10"}
	if got := RuleIDs(); !slices.Equal(got, want) {
		t.Fatalf("rules = %v", got)
	}
	// A request that breaks E2 and E3 reports E2.
	f, r := goodFacts(), goodRequest(PentestLocal)
	f.ProjectOnDisk, r.Target = false, ""
	if v := Eligible(PentestLocal, f, r); v.Rule != "E2" {
		t.Errorf("rule = %s", v.Rule)
	}
}

// TestGroundedBackends pins the table: bwrap only, grounded in the docs.
func TestGroundedBackends(t *testing.T) {
	if got := LoopbackBackendIDs(); !slices.Equal(got, []string{"bwrap"}) {
		t.Fatalf("grounded backends = %v", got)
	}
	for _, b := range loopbackBackends {
		if !strings.Contains(b.Ground, "docs/") {
			t.Errorf("%s has no grounding document", b.ID)
		}
	}
}

// TestAutoBackend: the backend the route picks when the caller names none is the
// first one rule E9 would accept, and "" when there is none. A plan refused before
// E9 has chosen reads it, so the two never differ (they read one function).
func TestAutoBackend(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *Facts)
		relax  bool
		want   string
	}{
		{"the one grounded row that is eligible", func(*Facts) {}, false, "bwrap"},
		{"the grounded row is not available", func(f *Facts) { f.Backends[1].Available = false }, false, ""},
		{"the grounded row is beta", func(f *Facts) { f.Backends[1].Beta = true }, false, ""},
		{"the grounded row is not local", func(f *Facts) { f.Backends[1].Local = false }, false, ""},
		{"the grounded row does not capture fully", func(f *Facts) { f.Backends[1].FullCapture = false }, false, ""},
		{"the grounded row lacks the live tier", func(f *Facts) { f.Backends[1].Tiers = []string{"none", "host"} }, false, ""},
		{"the relaxed tier needs the internet tier", func(f *Facts) { f.Backends[1].Tiers = []string{"proxy_only"} }, true, ""},
		{"the relaxed tier with the internet tier", func(*Facts) {}, true, "bwrap"},
		{"no backend at all", func(f *Facts) { f.Backends = nil }, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := goodFacts()
			c.mutate(&f)
			if got := AutoBackend(f, c.relax); got != c.want {
				t.Errorf("AutoBackend = %q, want %q", got, c.want)
			}
			// Rule E9 with no backend named chooses the same one, or refuses when there is none.
			r := goodRequest(PentestLocal)
			r.TierRelax = c.relax
			v := Eligible(PentestLocal, f, r)
			if c.want != "" && (!v.OK || v.Backend != c.want) {
				t.Errorf("E9 chose %q (ok %v rule %s), want %q", v.Backend, v.OK, v.Rule, c.want)
			}
		})
	}
}
