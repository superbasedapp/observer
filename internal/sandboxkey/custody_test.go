package sandboxkey

import (
	"strings"
	"testing"
)

// TestBrokerTable: every row carries its citation; no row is offered while
// no broker client is built (the recorded state of lane GATES-SBX).
func TestBrokerTable(t *testing.T) {
	t.Parallel()
	for _, b := range Brokers() {
		if b.Vendor == "" || !strings.HasPrefix(b.Docs, "https://") || b.ReadOn == "" || b.Mechanism == "" {
			t.Fatalf("row without a citation: %+v", b)
		}
		if Offered(b.Vendor) != (b.Status == BrokerBuilt) {
			t.Fatalf("%s offered = %v with status %s", b.Vendor, Offered(b.Vendor), b.Status)
		}
	}
	if _, ok := BrokerFor("modal"); ok || Offered("modal") {
		t.Fatal("modal has no vendor broker row")
	}
}

// TestInjectedRefusals has one case per rule.
func TestInjectedRefusals(t *testing.T) {
	t.Parallel()
	ok := InjectedFacts{Vendor: "e2b", Offered: true}
	cases := []struct {
		name string
		edit func(*InjectedFacts)
		code string
	}{
		{"not offered", func(f *InjectedFacts) { f.Offered = false }, CodeCustodyNotOffered},
		{"org forbids", func(f *InjectedFacts) { f.OrgForbids = true }, CodeCustodyNotAllowed},
		{"org budgets", func(f *InjectedFacts) { f.OrgBudgetsEnforced = true }, CodeCustodyNotAllowed},
		{"managed, not allowed", func(f *InjectedFacts) { f.Managed = true }, CodeCustodyNotAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := ok
			c.edit(&f)
			code, why, allowed := InjectedRefusal(f)
			if allowed || code != c.code || why == "" {
				t.Fatalf("= %q %q %v", code, why, allowed)
			}
		})
	}
	if _, _, allowed := InjectedRefusal(ok); !allowed {
		t.Fatal("a sound launch was refused")
	}
	managedAllowed := ok
	managedAllowed.Managed, managedAllowed.OrgAllowed = true, true
	if _, _, allowed := InjectedRefusal(managedAllowed); !allowed {
		t.Fatal("an org-allowed managed launch was refused")
	}
}

func TestDisclosure(t *testing.T) {
	t.Parallel()
	d := Disclosure("provider_injected", "e2b", "proxy_and_transcripts")
	for _, want := range []string{"provider_injected", "e2b", InjectedCaptureCeiling, "Teardown deletes the broker rule"} {
		if !strings.Contains(d, want) {
			t.Fatalf("disclosure %q lacks %q", d, want)
		}
	}
	if !strings.Contains(Disclosure("home_relay", "e2b", "full"), "sentinel") {
		t.Fatal("home_relay disclosure")
	}
}

// TestDisclosureNamesEveryProvider: the home_relay consent line names each
// key a run can use (gap H2), and the in-box line where each key comes
// from (gap H3), by provider name, never a variable name.
func TestDisclosureNamesEveryProvider(t *testing.T) {
	t.Parallel()
	d := Disclosure("home_relay", "E2B", "full", "openai", "anthropic")
	for _, want := range []string{"Anthropic API key and OpenAI API key", "sentinel", "own model host", "Capture: full"} {
		if !strings.Contains(d, want) {
			t.Fatalf("disclosure %q lacks %q", d, want)
		}
	}
	if Disclosure("home_relay", "E2B", "full", "nosuch") != Disclosure("home_relay", "E2B", "full") {
		t.Fatal("an unknown provider changed the line")
	}
	cases := []struct {
		env, stored []string
		want        []string
	}{
		{nil, nil, []string{"starts without one"}},
		{[]string{"openai"}, nil, []string{"environment: OpenAI API key"}},
		{nil, []string{"anthropic"}, []string{"stored on this machine: Anthropic API key"}},
		{[]string{"openai"}, []string{"openai", "anthropic"}, []string{"environment: OpenAI API key", "stored on this machine: Anthropic API key"}},
	}
	for _, c := range cases {
		line := InBoxDisclosure(c.env, c.stored)
		if !strings.Contains(line, "readable by the agent") {
			t.Fatalf("%q lacks who can read it", line)
		}
		for _, w := range c.want {
			if !strings.Contains(line, w) {
				t.Errorf("env %v stored %v: %q lacks %q", c.env, c.stored, line, w)
			}
		}
		if strings.Contains(line, "_API_KEY") {
			t.Errorf("%q names a variable", line)
		}
	}
}
