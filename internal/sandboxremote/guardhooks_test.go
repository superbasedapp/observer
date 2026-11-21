package sandboxremote

import (
	"fmt"
	"strings"
	"testing"
)

// TestResolveGuardHooksRules: one case per row of guardHooksRules, plus the
// "" = auto reading; the no-hook sentence (HostedHookNote) is said exactly
// when the box gets no hooks.
func TestResolveGuardHooksRules(t *testing.T) {
	cases := []struct {
		name   string
		in     GuardHooksInput
		seed   bool
		reason string
	}{
		{"off wins over everything", GuardHooksInput{Mode: GuardHooksOff, Enforcing: true, Covered: true}, false, GuardHooksReasonOff},
		{"tool not covered", GuardHooksInput{Mode: GuardHooksOn, Enforcing: true, Covered: false}, false, GuardHooksReasonNotCovered},
		{"on seeds without enforcement", GuardHooksInput{Mode: GuardHooksOn, Covered: true}, true, GuardHooksReasonOn},
		{"auto with enforcement", GuardHooksInput{Mode: GuardHooksAuto, Enforcing: true, Covered: true}, true, GuardHooksReasonEnforcing},
		{"auto without enforcement", GuardHooksInput{Mode: GuardHooksAuto, Covered: true}, false, GuardHooksReasonNotEnforcing},
		{"empty reads as auto", GuardHooksInput{Mode: "", Enforcing: true, Covered: true}, true, GuardHooksReasonEnforcing},
		{"auto not covered", GuardHooksInput{Mode: "", Enforcing: true}, false, GuardHooksReasonNotCovered},
	}
	if len(cases) < len(guardHooksRules) {
		t.Fatalf("%d cases for %d rows", len(cases), len(guardHooksRules))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.in.Tool = "Claude Code"
			got := ResolveGuardHooks(c.in)
			if got.Seed != c.seed || got.Reason != c.reason {
				t.Fatalf("got seed=%v reason=%s, want seed=%v reason=%s", got.Seed, got.Reason, c.seed, c.reason)
			}
			if says := strings.Contains(got.Message, HostedHookNote); says == got.Seed {
				t.Fatalf("the no-hook sentence must be said exactly when no hooks are seeded: seed=%v message=%q", got.Seed, got.Message)
			}
			if !strings.Contains(got.Technical, c.reason) || strings.Contains(got.Message, "guard_hooks") {
				t.Fatalf("internal names belong in Technical only: %+v", got)
			}
		})
	}
}

// TestGuardHooksConsentLineStatesTheRule: each mode's line, the auto rule
// named once with the covered tools, and the consent screen's line set by
// label.
func TestGuardHooksConsentLineStatesTheRule(t *testing.T) {
	for _, m := range append([]string{""}, GuardHooksModes...) {
		line := GuardHooksConsentLine(m, []string{"Claude Code", "Qwen Code"})
		switch NormalizeGuardHooks(m) {
		case GuardHooksOff:
			if !strings.Contains(line, HostedHookNote) {
				t.Errorf("off: %q", line)
			}
		case GuardHooksOn, GuardHooksAuto:
			if !strings.Contains(line, "Claude Code, Qwen Code") || !strings.Contains(line, "blocked") {
				t.Errorf("%s: %q", m, line)
			}
		}
	}
	if !strings.Contains(GuardHooksConsentLine("", nil), "Whenever guard enforcement is on") {
		t.Error("auto must state its rule")
	}
	v, _ := VendorFor(VendorModal)
	f := baseFacts()
	f.Provider = v.ID
	s := BuildConsentScreen(v, f, Manifest{Root: "/w/p"}, v.EstimateCost(60))
	s.SetHookLine("X-LINE")
	if text := fmt.Sprint(s.Lines); !strings.Contains(text, "{Hooks and guard X-LINE}") {
		t.Fatalf("hook line not replaced: %s", text)
	}
}
