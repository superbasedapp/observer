package sandboxkey

import (
	"slices"
	"strings"
	"testing"
)

// TestHomeKeyRules is one case per row of homeKeyRules, plus the order
// cases that matter (an in-box custody wins over every home fact; the org
// route serves any tool; the node-wide answer never reads the tool).
func TestHomeKeyRules(t *testing.T) {
	t.Parallel()
	inj := HomeKeyFacts{InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"anthropic"}}
	tool := func(f HomeKeyFacts, providers ...string) HomeKeyFacts {
		f.ForTool, f.ToolProviders, f.ToolUsable = true, providers, providers
		return f
	}
	open := allIDs()
	inBox := HomeKeyFacts{Custody: "in_box_api_key"}
	cases := []struct {
		name     string
		in       HomeKeyFacts
		ok       bool
		code     string
		message  bool // a served verdict that carries a line
		provided []string
	}{
		{"in-box key, node-wide", inBox, true, HomeKeyServedInBox, false, nil},
		{"in-box key from the daemon's environment", func() HomeKeyFacts { f := tool(inBox, open...); f.InBoxEnvProviders = []string{"openai"}; return f }(), true, HomeKeyServedInBox, true, []string{"openai"}},
		{"in-box key from a stored key, component on", func() HomeKeyFacts {
			f := tool(inBox, open...)
			f.InjectionSelected, f.StoredProviders = true, []string{"anthropic"}
			return f
		}(), true, HomeKeyServedInBox, true, []string{"anthropic"}},
		{"in-box: a stored key is not read with the component off", func() HomeKeyFacts { f := tool(inBox, open...); f.StoredProviders = []string{"anthropic"}; return f }(), true, HomeKeyInBoxNoKey, true, nil},
		{"in-box: a key the tool cannot use is no source", func() HomeKeyFacts { f := tool(inBox, "anthropic"); f.InBoxEnvProviders = []string{"openai"}; return f }(), true, HomeKeyInBoxNoKey, true, nil},
		{"in-box: no key anywhere is a line, not a refusal", tool(inBox, open...), true, HomeKeyInBoxNoKey, true, nil},
		{"in-box key ignores an unserved home key", tool(inBox), true, HomeKeyInBoxNoKey, true, nil},
		{"in-box login not built", HomeKeyFacts{Custody: "in_box_oauth_seed", OrgRoute: true}, false, HomeKeyLoginNotBuilt, false, nil},
		{"provider_injected not offered", HomeKeyFacts{Custody: "provider_injected", OrgRoute: true}, false, HomeKeyCustodyNotOffered, false, nil},
		{"unknown custody not offered", HomeKeyFacts{Custody: "bogus"}, false, HomeKeyCustodyNotOffered, false, nil},
		{"org route, node-wide", HomeKeyFacts{OrgRoute: true}, true, HomeKeyServedOrgRoute, false, nil},
		{"org route serves a tool with no provider", tool(HomeKeyFacts{Custody: "home_relay", OrgRoute: true}), true, HomeKeyServedOrgRoute, false, nil},
		{"injection selected, no proxy in the build", HomeKeyFacts{InjectionSelected: true, StoredProviders: []string{"anthropic"}}, false, HomeKeyInjectionNotBuilt, false, nil},
		{"the default: nothing serves", HomeKeyFacts{}, false, HomeKeyNothingServes, false, nil},
		{"nothing serves for a tool either", tool(HomeKeyFacts{}, "anthropic"), false, HomeKeyNothingServes, false, nil},
		{"injection on, no key stored", HomeKeyFacts{InjectionSelected: true, InjectionBuilt: true}, false, HomeKeyNothingServes, false, nil},
		{"a key stored but injection off", HomeKeyFacts{InjectionBuilt: true, StoredProviders: []string{"anthropic"}}, false, HomeKeyNothingServes, false, nil},
		{"injection ready, node-wide", inj, true, HomeKeyServedInjection, false, nil},
		{"injection ready, tool with no provider", tool(inj), false, HomeKeyToolProvider, false, nil},
		{"injection ready, tool key missing", tool(inj, "openai"), false, HomeKeyToolKeyMissing, false, nil},
		{"injection ready, open tool, none of its keys stored", tool(HomeKeyFacts{InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"nosuch"}}, open...), false, HomeKeyToolKeyMissing, false, nil},
		{"injection ready, tool key stored", tool(inj, "anthropic"), true, HomeKeyServedInjection, false, []string{"anthropic"}},
		{"injection ready, open tool, one of its keys stored", tool(inj, open...), true, HomeKeyServedInjection, true, []string{"anthropic"}},
		{"injection ready, open tool, two keys stored", tool(HomeKeyFacts{InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"openai", "anthropic"}}, open...), true, HomeKeyServedInjection, true, []string{"anthropic", "openai"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := HomeKey(tc.in)
			if v.OK != tc.ok || v.Code != tc.code {
				t.Fatalf("HomeKey(%+v) = %v %q, want %v %q", tc.in, v.OK, v.Code, tc.ok, tc.code)
			}
			if !v.OK && (v.Message == "" || v.Technical == "") {
				t.Fatalf("a refusal must carry a message and a technical detail: %+v", v)
			}
			if v.OK && (v.Message != "") != tc.message {
				t.Fatalf("served verdict line %q, want a line: %v", v.Message, tc.message)
			}
			if v.Blocking() == v.OK {
				t.Fatalf("Blocking() = %v for OK %v", v.Blocking(), v.OK)
			}
			if !slices.Equal(v.Providers, tc.provided) {
				t.Fatalf("Providers = %v, want %v", v.Providers, tc.provided)
			}
		})
	}
}

// TestHomeKeyNamesEveryBoundProvider: a served line names exactly the
// providers that get a key, and says when the tool can use others that get
// none.
func TestHomeKeyNamesEveryBoundProvider(t *testing.T) {
	t.Parallel()
	f := HomeKeyFacts{InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"openai", "anthropic"}, ForTool: true, ToolProviders: allIDs(), ToolUsable: allIDs()}
	v := HomeKey(f)
	if !strings.Contains(v.Message, "Anthropic API key and OpenAI API key") || !strings.Contains(v.Message, "Other providers") {
		t.Fatalf("line %q", v.Message)
	}
	f.ToolProviders = []string{"anthropic", "openai"}
	if v := HomeKey(f); strings.Contains(v.Message, "Other providers") {
		t.Fatalf("every injectable provider is bound, but the line says otherwise: %q", v.Message)
	}
	f.StoredProviders = nil
	f.Custody, f.InBoxEnvProviders = "in_box_api_key", []string{"xai", "google"}
	if v := HomeKey(f); !strings.Contains(v.Message, "Gemini API key and xAI API key") {
		t.Fatalf("in-box line %q", v.Message)
	}
}

// TestHomeKeyRulesEveryRowReached: each row's code is produced by a case
// above (a row nothing reaches is dead or shadowed).
func TestHomeKeyRulesEveryRowReached(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, f := range []HomeKeyFacts{
		{Custody: "in_box_api_key"},
		{Custody: "in_box_api_key", ForTool: true},
		{Custody: "in_box_api_key", ForTool: true, ToolUsable: []string{"xai"}, InBoxEnvProviders: []string{"xai"}},
		{Custody: "in_box_oauth_seed"},
		{Custody: "provider_injected"},
		{OrgRoute: true},
		{InjectionSelected: true},
		{},
		{InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"xai"}},
		{InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"xai"}, ForTool: true},
		{InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"xai"}, ForTool: true, ToolProviders: []string{"openai"}},
		{InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"xai"}, ForTool: true, ToolProviders: []string{"xai"}},
		{Custody: "auto"},
		{Custody: "in_box_api_key", ForTool: true, InBoxRefused: true},
	} {
		seen[HomeKey(f).Code] = true
	}
	for _, r := range homeKeyRules {
		if !seen[r.code] {
			t.Errorf("row %s is never reached", r.code)
		}
	}
}

// TestHomeKeyMessagesArePlain: a person's sentence names no config key,
// enum value, command or component id (docs/app-design-system.md "Copy
// rules"); those live in Technical only.
func TestHomeKeyMessagesArePlain(t *testing.T) {
	t.Parallel()
	banned := []string{"home_relay", "in_box_api_key", "in_box_oauth_seed", "provider_injected", "key_pool", "[", "`", "observer sandbox", "terminals.sandbox", "_", "anthropic", "openai", "openrouter", "sentinel"}
	for _, r := range homeKeyRules {
		if r.message == nil {
			continue
		}
		for _, ids := range [][]string{{"anthropic"}, {"openai", "anthropic"}, allIDs(), {"nosuch"}} {
			msg := r.message(HomeKeyFacts{ToolProviders: ids, ToolUsable: ids, StoredProviders: ids[:1], InBoxEnvProviders: ids, Custody: "bogus"})
			for _, b := range banned {
				if strings.Contains(msg, b) {
					t.Errorf("row %s message %q carries %q", r.code, msg, b)
				}
			}
			if strings.ContainsAny(msg, "–—") {
				t.Errorf("row %s message %q carries a dash", r.code, msg)
			}
		}
	}
}

// legacyProviderForTool is the one-provider rule every hosted launch was
// decided by before a run could bind several providers (the removed
// ProviderForTool), kept here to pin that nothing it served is lost.
func legacyProviderForTool(vendorLocked bool, families []string) string {
	if !vendorLocked || len(families) != 1 {
		return ""
	}
	if p, ok := ProviderFor(families[0]); ok {
		return p.ID
	}
	return ""
}

// TestHomeKeyMatchesTheOldLaunchRule: node-wide, the table answers exactly
// what the launch's homeRelayOK used to (org route, or injection ready with
// at least one key) for the default custody; and per tool, every launch the
// old one-provider rule served is still served, with the same provider
// bound, whatever the tool's route says. So no launch that ran before is
// refused now.
func TestHomeKeyMatchesTheOldLaunchRule(t *testing.T) {
	t.Parallel()
	for _, org := range []bool{false, true} {
		for _, sel := range []bool{false, true} {
			for _, built := range []bool{false, true} {
				for _, keys := range [][]string{nil, {"anthropic"}} {
					old := org || (sel && built && len(keys) > 0)
					got := HomeKey(HomeKeyFacts{Custody: "home_relay", OrgRoute: org, InjectionSelected: sel, InjectionBuilt: built, StoredProviders: keys}).OK
					if got != old {
						t.Errorf("org=%v sel=%v built=%v keys=%v: HomeKey ok=%v, the old rule %v", org, sel, built, keys, got, old)
					}
				}
			}
		}
	}
	routes := []ToolRoute{}
	for _, locked := range []bool{false, true} {
		for _, fams := range [][]string{nil, {"anthropic"}, {"xai"}, {"openai", "anthropic"}, {"nosuch"}} {
			for _, routed := range []bool{false, true} {
				for _, rp := range [][]string{nil, {}, {"openrouter"}} {
					routes = append(routes, ToolRoute{VendorLocked: locked, Families: fams, Routed: routed, RouteProviders: rp})
				}
			}
		}
	}
	for _, tr := range routes {
		old := legacyProviderForTool(tr.VendorLocked, tr.Families)
		for _, stored := range [][]string{nil, {"anthropic"}, {"xai"}, allIDs()} {
			f := HomeKeyFacts{Custody: "home_relay", InjectionSelected: true, InjectionBuilt: true, StoredProviders: stored, ForTool: true, ToolProviders: InjectableProviders(tr), ToolUsable: UsableProviders(tr)}
			oldOK := old != "" && slices.Contains(stored, old) && len(stored) > 0
			v := HomeKey(f)
			if oldOK && (!v.OK || !slices.Contains(v.Providers, old)) {
				t.Errorf("%+v stored %v: the old rule served %s, now %v %s providers %v", tr, stored, old, v.OK, v.Code, v.Providers)
			}
			if old != "" && !slices.Equal(InjectableProviders(tr), []string{old}) {
				t.Errorf("%+v: a one-provider tool now binds %v, not just %s", tr, InjectableProviders(tr), old)
			}
		}
	}
}
