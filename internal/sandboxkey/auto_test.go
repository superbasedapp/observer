package sandboxkey

import (
	"strings"
	"testing"
)

// TestResolveCustodyRules is one case per row of custodyRules (decision
// SBXD-1), plus the order cases that matter.
func TestResolveCustodyRules(t *testing.T) {
	t.Parallel()
	served := HomeKeyFacts{InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"openai"}}
	tool := func(f HomeKeyFacts, providers ...string) HomeKeyFacts {
		f.ForTool, f.ToolProviders, f.ToolUsable = true, providers, allIDs()
		return f
	}
	with := func(f HomeKeyFacts, change func(*HomeKeyFacts)) HomeKeyFacts { change(&f); return f }
	cases := []struct {
		name    string
		in      HomeKeyFacts
		rule    string
		custody string
	}{
		{"the tool's own setting wins", with(tool(served, "openai"), func(f *HomeKeyFacts) { f.Custody, f.ToolCustody = "auto", "in_box_api_key" }), CustodyRuleToolSetting, "in_box_api_key"},
		{"a tool setting is read only for a tool", with(served, func(f *HomeKeyFacts) { f.Custody, f.ToolCustody = "home_relay", "in_box_api_key" }), CustodyRuleNodeSetting, "home_relay"},
		{"an explicit node setting keeps its meaning", tool(with(served, func(f *HomeKeyFacts) { f.Custody = "in_box_api_key" }), "openai"), CustodyRuleNodeSetting, "in_box_api_key"},
		{"the empty value is home_relay", tool(HomeKeyFacts{}, "openai"), CustodyRuleNodeSetting, "home_relay"},
		{"a tool set to auto on a home_relay node is auto for it", with(tool(HomeKeyFacts{Custody: "home_relay"}), func(f *HomeKeyFacts) { f.ToolCustody = "auto" }), CustodyRuleNothingHome, "in_box_api_key"},
		{"auto on a row that keeps keys home", with(tool(HomeKeyFacts{Custody: "auto"}), func(f *HomeKeyFacts) { f.InBoxRefused = true }), CustodyRuleRowKeepsKey, "home_relay"},
		{"auto, node-wide", HomeKeyFacts{Custody: "auto"}, CustodyRuleNodeWide, "auto"},
		{"auto, this machine adds the key", tool(with(served, func(f *HomeKeyFacts) { f.Custody = "auto" }), "openai"), CustodyRuleHomeServes, "home_relay"},
		{"auto, the org route serves any tool", tool(HomeKeyFacts{Custody: "auto", OrgRoute: true}), CustodyRuleHomeServes, "home_relay"},
		{"auto, no stored key of the route's providers", tool(with(served, func(f *HomeKeyFacts) { f.Custody = "auto" }), "anthropic"), CustodyRuleNothingHome, "in_box_api_key"},
		{"auto, a tool with no proxy route", tool(with(served, func(f *HomeKeyFacts) { f.Custody = "auto" })), CustodyRuleNothingHome, "in_box_api_key"},
		{"auto, nothing at home at all", tool(HomeKeyFacts{Custody: "auto"}, "openai"), CustodyRuleNothingHome, "in_box_api_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := ResolveCustody(tc.in)
			if r.Rule != tc.rule || r.Custody != tc.custody {
				t.Fatalf("ResolveCustody = %s %s, want %s %s", r.Rule, r.Custody, tc.rule, tc.custody)
			}
			if r.Why == "" || r.Technical == "" {
				t.Fatalf("a resolution must say why: %+v", r)
			}
			for _, b := range []string{"home_relay", "in_box", "auto", "[", "`", "_"} {
				if strings.Contains(r.Why, b) {
					t.Fatalf("plain words %q carry %q", r.Why, b)
				}
			}
		})
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		seen[ResolveCustody(tc.in).Rule] = true
	}
	for _, r := range custodyRules {
		if !seen[r.rule] {
			t.Errorf("row %s is never reached", r.rule)
		}
	}
}

// TestHomeKeyAuto: under auto, every launch is served (none is refused by
// the custody), the node-wide answer reads served so the setup step is
// done, the line names the resolved custody, and a row that keeps keys home
// resolves to home_relay or a plain refusal, never a key in the box.
func TestHomeKeyAuto(t *testing.T) {
	t.Parallel()
	if v := HomeKey(HomeKeyFacts{Custody: "auto"}); !v.OK || v.Code != HomeKeyServedAuto {
		t.Fatalf("node-wide auto = %+v", v)
	}
	for _, f := range []HomeKeyFacts{
		{Custody: "auto", ForTool: true},
		{Custody: "auto", ForTool: true, ToolProviders: []string{"openai"}, ToolUsable: allIDs()},
		{Custody: "auto", ForTool: true, ToolProviders: []string{"openai"}, ToolUsable: allIDs(), InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"anthropic"}},
	} {
		v := HomeKey(f)
		if !v.OK || v.Resolution.Custody != "in_box_api_key" || !strings.HasPrefix(v.Message, v.Resolution.Why) {
			t.Fatalf("auto with nothing at home %+v = %+v", f, v)
		}
	}
	home := HomeKey(HomeKeyFacts{Custody: "auto", ForTool: true, ToolProviders: []string{"openai"}, ToolUsable: allIDs(), InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"openai"}})
	if !home.OK || home.Code != HomeKeyServedInjection || home.Resolution.Custody != "home_relay" || home.Message == "" {
		t.Fatalf("auto, home serves = %+v", home)
	}
	org := HomeKey(HomeKeyFacts{Custody: "auto", ForTool: true, InBoxRefused: true, ToolUsable: allIDs()})
	if org.OK || org.Resolution.Custody != "home_relay" || org.Code != HomeKeyNothingServes {
		t.Fatalf("auto on a row that keeps keys home, nothing serves = %+v", org)
	}
	if v := HomeKey(HomeKeyFacts{Custody: "auto", ToolCustody: "in_box_api_key", ForTool: true, InBoxRefused: true}); v.OK || v.Code != HomeKeyRowKeepsKeyHome {
		t.Fatalf("an in-box tool setting on a row that keeps keys home = %+v", v)
	}
}

// TestHomeKeyExplicitHomeRelayUnchanged: an explicit home_relay node's
// lines are exactly the old ones (no resolution sentence is added).
func TestHomeKeyExplicitHomeRelayUnchanged(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"", "home_relay"} {
		f := HomeKeyFacts{Custody: c, ForTool: true, ToolProviders: []string{"openai"}, ToolUsable: allIDs(), InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"openai"}}
		if v := HomeKey(f); !v.OK || v.Message != "" || v.Technical != "" {
			t.Fatalf("custody %q: %+v", c, v)
		}
		f.StoredProviders = []string{"anthropic"}
		v := HomeKey(f)
		if v.OK || strings.Contains(v.Message, "settings") {
			t.Fatalf("custody %q refusal %+v", c, v)
		}
	}
}

// TestHomeKeyInBoxSources: the tool's own saved keys and its login are
// in-box sources named on the line, and a tool with only those is served.
func TestHomeKeyInBoxSources(t *testing.T) {
	t.Parallel()
	base := HomeKeyFacts{Custody: "in_box_api_key", ForTool: true, ToolUsable: allIDs(), ToolName: "OpenCode"}
	saved := base
	saved.ToolSavedKeys, saved.ToolSavedProviders = true, []string{"openai", "anthropic"}
	v := HomeKey(saved)
	if !v.OK || v.Code != HomeKeyServedInBox || !strings.Contains(v.Message, "OpenCode saved itself") {
		t.Fatalf("saved keys line %+v", v)
	}
	saved.InBoxEnvProviders = []string{"openai"}
	if v := HomeKey(saved); !strings.Contains(v.Message, "your OpenAI API key") || !strings.Contains(v.Message, "the Anthropic API key OpenCode saved") {
		t.Fatalf("a named source is not repeated as saved: %q", v.Message)
	}
	login := base
	login.LoginSeed, login.ToolName = true, "Claude Code"
	v = HomeKey(login)
	if !v.OK || v.Code != HomeKeyServedInBox || !strings.Contains(v.Message, "never the refresh token") {
		t.Fatalf("login line %+v", v)
	}
	if v := HomeKey(base); v.Code != HomeKeyInBoxNoKey {
		t.Fatalf("no source %+v", v)
	}
}

// TestMayPutKeyInBox is one case per answer.
func TestMayPutKeyInBox(t *testing.T) {
	t.Parallel()
	cases := []struct {
		node    string
		byTool  map[string]string
		refused bool
		want    bool
	}{
		{"home_relay", nil, false, false},
		{"", nil, false, false},
		{"auto", nil, false, true},
		{"in_box_api_key", nil, false, true},
		{"home_relay", map[string]string{"droid": "in_box_api_key"}, false, true},
		{"home_relay", map[string]string{"droid": "auto"}, false, true},
		{"home_relay", map[string]string{"droid": "home_relay"}, false, false},
		{"auto", nil, true, false},
	}
	for _, tc := range cases {
		if got := MayPutKeyInBox(tc.node, tc.byTool, tc.refused); got != tc.want {
			t.Errorf("MayPutKeyInBox(%q, %v, %v) = %v, want %v", tc.node, tc.byTool, tc.refused, got, tc.want)
		}
	}
}

// TestKeepHomeOffers: one case per answer.
func TestKeepHomeOffers(t *testing.T) {
	t.Parallel()
	inj := func(custody string, stored []string, providers ...string) HomeKeyFacts {
		return HomeKeyFacts{Custody: custody, ForTool: true, InjectionSelected: true, InjectionBuilt: true, StoredProviders: stored, ToolProviders: providers, ToolUsable: allIDs()}
	}
	cases := []struct {
		name string
		in   HomeKeyFacts
		want []string
	}{
		{"auto, no key of the route's provider: offer it", inj("auto", nil, "openai"), []string{"openai"}},
		{"auto, another key stored: offer the route's", inj("auto", []string{"anthropic"}, "openai"), []string{"openai"}},
		{"auto, already kept home: none", inj("auto", []string{"openai"}, "openai"), nil},
		{"home_relay, key missing: offer it", inj("home_relay", []string{"anthropic"}, "openai"), []string{"openai"}},
		{"home_relay with nothing stored: offer every route provider", inj("home_relay", nil, "openai", "anthropic"), []string{"anthropic", "openai"}},
		{"explicit in-box: none (storing would put it in the box)", inj("in_box_api_key", nil, "openai"), nil},
		{"a tool with no proxy route: none", inj("auto", nil), nil},
		{"injection not selected: none", func() HomeKeyFacts { f := inj("auto", nil, "openai"); f.InjectionSelected = false; return f }(), nil},
		{"node-wide: none", func() HomeKeyFacts { f := inj("auto", nil, "openai"); f.ForTool = false; return f }(), nil},
		{"a row that keeps keys home: offer it", func() HomeKeyFacts { f := inj("auto", nil, "openai"); f.InBoxRefused = true; return f }(), []string{"openai"}},
	}
	for _, tc := range cases {
		if got := KeepHomeOffers(tc.in); !equalIDs(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
