package sandboxadvise

import (
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
)

// offerableFacts are the facts of a refusal every row below departs from:
// an allow-list miss whose host the owner can add and the gateway then lets
// through, with no pin in force.
func offerableFacts() Facts {
	return Facts{Rule: "allow-list-miss", InBuild: true, ConfigWritable: true, HostListable: true, AllowedAfter: true}
}

// TestDecideRuleRows is one case per refusal rule: only an allow-list miss
// is offered; a provider host, a private range, a host-local or SSRF-floor
// refusal and every other rule never are, even with every other fact
// favourable.
func TestDecideRuleRows(t *testing.T) {
	cases := []struct {
		rule string
		want Reason
	}{
		{"allow-list-miss", ReasonOfferable},
		{"private-range", ReasonRuleNotOfferable},
		{"provider-host", ReasonRuleNotOfferable},
		{"host-local", ReasonRuleNotOfferable},
		{"tier-none", ReasonRuleNotOfferable},
		{"ssrf-floor", ReasonRuleNotOfferable},
		{"literal-ip", ReasonRuleNotOfferable},
		{"port-not-allowed", ReasonRuleNotOfferable},
		{"tls-server-name", ReasonRuleNotOfferable},
		{"a-rule-from-a-newer-build", ReasonRuleNotOfferable},
		{"", ReasonRuleNotOfferable},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			f := offerableFacts()
			f.Rule = c.rule
			got := Decide(f)
			if got.Reason != c.want || got.Offerable != (c.want == ReasonOfferable) {
				t.Fatalf("Decide(%q) = %+v, want %s", c.rule, got, c.want)
			}
			if !got.Offerable && got.Message == "" {
				t.Fatalf("a refused offer has no message: %+v", got)
			}
			// Explain is the capability a surface branches on (F-013,
			// audit finding N5-A6): set exactly for a rule an owner's host
			// list could lift.
			if got.Explain != (c.want == ReasonOfferable) {
				t.Fatalf("Decide(%q).Explain = %v", c.rule, got.Explain)
			}
		})
	}
	// A not-offered allow-list miss still explains itself.
	f := offerableFacts()
	f.AlreadyAllowed = true
	if got := Decide(f); got.Offerable || !got.Explain {
		t.Fatalf("a not-offered allow-list miss: %+v", got)
	}
}

// TestDecideFactRows is one case per decision-table row after the rule
// rows, in table order, each on an allow-list miss.
func TestDecideFactRows(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Facts)
		want Reason
	}{
		{"not in build", func(f *Facts) { f.InBuild = false }, ReasonNotInBuild},
		{"refused by the install step's list", func(f *Facts) { f.Key = "sandbox.install_hosts" }, ReasonNotTheHostList},
		{"install step's list wins over already allowed", func(f *Facts) { f.Key = "sandbox.install_hosts"; f.AlreadyAllowed = true }, ReasonNotTheHostList},
		{"the owner's list key", func(f *Facts) { f.Key = HostListKey }, ReasonOfferable},
		{"provider host stored as an allow-list miss", func(f *Facts) { f.ProviderHost = true }, ReasonProviderHost},
		{"provider host wins over already allowed", func(f *Facts) { f.ProviderHost = true; f.AlreadyAllowed = true }, ReasonProviderHost},
		{"already allowed today", func(f *Facts) { f.AlreadyAllowed = true }, ReasonAlreadyAllowed},
		{"host not listable", func(f *Facts) { f.HostListable = false }, ReasonHostNotListable},
		{"org pin refuses the host", func(f *Facts) { f.AllowedAfter = false; f.PinInForce = true }, ReasonOrgPinRefuses},
		{"org pin in force but allows the host", func(f *Facts) { f.PinInForce = true }, ReasonOfferable},
		{"gateway still refuses with no pin", func(f *Facts) { f.AllowedAfter = false }, ReasonHostNotListable},
		{"no config file", func(f *Facts) { f.ConfigWritable = false }, ReasonConfigNotWritable},
		{"offerable", func(*Facts) {}, ReasonOfferable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := offerableFacts()
			c.edit(&f)
			if got := Decide(f); got.Reason != c.want {
				t.Fatalf("Decide = %+v, want %s", got, c.want)
			}
		})
	}
}

// TestDecideProviderHostUnderPin: a provider-host refusal is refused for its
// rule before any fact is read, so the org pin never decides it.
func TestDecideProviderHostUnderPin(t *testing.T) {
	f := offerableFacts()
	f.Rule = "provider-host"
	f.PinInForce = true
	f.AllowedAfter = false
	if got := Decide(f); got.Reason != ReasonRuleNotOfferable {
		t.Fatalf("got %+v", got)
	}
}

// TestRulesMatchTheRefusalVocabulary pins the table to the frozen N1
// vocabulary: every rule the gateway can record has exactly one row.
func TestRulesMatchTheRefusalVocabulary(t *testing.T) {
	var want []string
	for _, r := range sandboxnet.RefusalRules {
		want = append(want, string(r))
	}
	if got := Rules(); !reflect.DeepEqual(got, want) {
		t.Fatalf("rule table %v, want the refusal vocabulary %v", got, want)
	}
	if HostListKey != sandboxnet.KeyEgressAllowHosts {
		t.Fatalf("HostListKey %q, want %q", HostListKey, sandboxnet.KeyEgressAllowHosts)
	}
}

// TestCopyHasNoDashes: the offer copy follows the plain-language rule.
func TestCopyHasNoDashes(t *testing.T) {
	texts := []string{ScopeLabel(ScopeNode)}
	for _, r := range ruleRows {
		texts = append(texts, r.why)
	}
	for _, r := range decideRows {
		texts = append(texts, r.msg(&ruleRows[1]))
	}
	for _, s := range texts {
		if strings.ContainsAny(s, "\u2013\u2014") {
			t.Fatalf("dash in %q", s)
		}
	}
}

func TestNormalizeAndWithHost(t *testing.T) {
	if got := NormalizeHost("  Registry.Example.COM "); got != "registry.example.com" {
		t.Fatalf("NormalizeHost = %q", got)
	}
	in := []string{"a.example.com"}
	got := WithHost(in, "b.example.com")
	if !reflect.DeepEqual(got, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("WithHost = %v", got)
	}
	if !reflect.DeepEqual(in, []string{"a.example.com"}) {
		t.Fatalf("WithHost changed its input: %v", in)
	}
	if got := WithHost(in, "a.example.com"); !reflect.DeepEqual(got, in) {
		t.Fatalf("WithHost duplicated: %v", got)
	}
	if got := WithHost(nil, "a.example.com"); !reflect.DeepEqual(got, []string{"a.example.com"}) {
		t.Fatalf("WithHost(nil) = %v", got)
	}
}
