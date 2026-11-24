package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestSDKKeyHintRules walks sdkKeyHintRules one case per row, in order (U-26,
// SR-9).
func TestSDKKeyHintRules(t *testing.T) {
	on := func(keys string) sdkKeyHintFacts {
		return sdkKeyHintFacts{enrolled: true, appsOn: true, sdkKeys: keys}
	}
	cases := []struct {
		name  string
		f     sdkKeyHintFacts
		lines bool
	}{
		{"not_enrolled", sdkKeyHintFacts{enrolled: false, appsOn: true}, false},
		{"apps_off", sdkKeyHintFacts{enrolled: true, appsOn: false}, false},
		{"has_key", sdkKeyHintFacts{enrolled: true, appsOn: true, holdsKey: true, sdkKeys: orgcontract.SDKKeysMember}, false},
		{"member_keys", on(orgcontract.SDKKeysMember), true},
		{"admin_only", on(orgcontract.SDKKeysAdminOnly), true},
		{"not_on_plan", on(orgcontract.SDKKeysNotOnPlan), true},
		{"unknown", on(""), true},
	}
	if len(cases) != len(sdkKeyHintRules) {
		t.Fatalf("cases %d, rules %d: add a case per rule", len(cases), len(sdkKeyHintRules))
	}
	for i, c := range cases {
		if sdkKeyHintRules[i].name != c.name {
			t.Fatalf("rule %d is %q, case is %q", i, sdkKeyHintRules[i].name, c.name)
		}
		got := sdkKeyHintLines(c.f)
		if (len(got) > 0) != c.lines {
			t.Errorf("%s: lines=%q", c.name, got)
		}
	}
	// What each wording must and must not say: the sign-in command is a
	// plain instruction only when the organization said it mints member
	// keys; an admin-only organization is never sent to it.
	words := []struct {
		keys          string
		want, notWant []string
	}{
		{orgcontract.SDKKeysMember, []string{"separate", "run `observer sdk sign-in`", "Get my SDK key"}, []string{"admin"}},
		{orgcontract.SDKKeysAdminOnly, []string{"does not give members", "ask an admin", "Machine identities"}, []string{"observer sdk sign-in"}},
		{orgcontract.SDKKeysNotOnPlan, []string{"does not include AI Apps", "billing owner", "https://cloud.superbased.app/portal/"}, []string{"observer sdk sign-in", "ask an admin for an SDK key", "/billing"}},
		{"", []string{"separate", "If your organization", "`observer sdk sign-in`", "ask an admin"}, []string{"run `observer sdk sign-in`"}},
		{"some_future_value", []string{"If your organization"}, nil},
	}
	for _, w := range words {
		text := strings.Join(sdkKeyHintLines(on(w.keys)), "\n")
		for _, want := range w.want {
			if !strings.Contains(text, want) {
				t.Errorf("sdk_keys=%q: hint %q lacks %q", w.keys, text, want)
			}
		}
		for _, bad := range w.notWant {
			if strings.Contains(text, bad) {
				t.Errorf("sdk_keys=%q: hint %q says %q", w.keys, text, bad)
			}
		}
	}
}

// TestSDKKeyHintFactsFor reads the AI Apps switch and the key description
// file under the observer directory; a fresh machine holds no key.
func TestSDKKeyHintFactsFor(t *testing.T) {
	var cfg config.Config
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	cfg.Observability.Enabled = true
	f := sdkKeyHintFactsFor(cfg, true, orgcontract.SDKKeysMember)
	if !f.enrolled || !f.appsOn || f.holdsKey || f.sdkKeys != orgcontract.SDKKeysMember {
		t.Fatalf("facts = %+v, want enrolled, apps on, no key", f)
	}
	if lines := sdkKeyHintLines(f); len(lines) == 0 {
		t.Fatal("a fresh enrolled machine with AI Apps on gets the hint")
	}
}
