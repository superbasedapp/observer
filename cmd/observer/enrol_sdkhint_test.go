package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestSDKKeyHintRules walks sdkKeyHintRules one case per row, in order (U-26).
func TestSDKKeyHintRules(t *testing.T) {
	cases := []struct {
		name  string
		f     sdkKeyHintFacts
		lines bool
	}{
		{"not_enrolled", sdkKeyHintFacts{enrolled: false, appsOn: true}, false},
		{"apps_off", sdkKeyHintFacts{enrolled: true, appsOn: false}, false},
		{"has_key", sdkKeyHintFacts{enrolled: true, appsOn: true, holdsKey: true}, false},
		{"needs_key", sdkKeyHintFacts{enrolled: true, appsOn: true}, true},
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
	text := strings.Join(sdkKeyHintLines(sdkKeyHintFacts{enrolled: true, appsOn: true}), "\n")
	for _, want := range []string{"separate", "observer sdk sign-in", "Get my SDK key"} {
		if !strings.Contains(text, want) {
			t.Errorf("hint %q lacks %q", text, want)
		}
	}
}

// TestSDKKeyHintFactsFor reads the AI Apps switch and the key description
// file under the observer directory; a fresh machine holds no key.
func TestSDKKeyHintFactsFor(t *testing.T) {
	var cfg config.Config
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	cfg.Observability.Enabled = true
	f := sdkKeyHintFactsFor(cfg, true)
	if !f.enrolled || !f.appsOn || f.holdsKey {
		t.Fatalf("facts = %+v, want enrolled, apps on, no key", f)
	}
	if lines := sdkKeyHintLines(f); len(lines) == 0 {
		t.Fatal("a fresh enrolled machine with AI Apps on gets the hint")
	}
}
