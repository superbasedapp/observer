package policy

import (
	"testing"
	"time"
)

// TestOrgFloorBackstop (OSH-R-014): a rule the organization's layer defined
// or tuned is a strictness floor. No below-org disable removes it, the
// config-level [guard.rules] disable included (it never passes the guard
// merge), and no below-org override relaxes or caps it. A rule the org did
// not touch stays disable-able, and the org's own override still applies.
func TestOrgFloorBackstop(t *testing.T) {
	t.Parallel()
	ev := Event{
		Kind: KindShellExec, Target: "rm -rf ~/projects", Cwd: "/home/u/proj",
		ProjectRoot: "/home/u/proj", SessionID: "s", Now: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC),
	}
	deny := DecisionDeny
	allow := DecisionAllow
	cases := []struct {
		name string
		cfg  Config
		want Decision
	}{
		{"untouched builtin disabled by config", Config{Disabled: []string{"R-101"}}, DecisionAllow},
		{"org-tuned builtin survives a config disable", Config{
			Disabled:  []string{"R-101"},
			Overrides: []Override{{RuleID: "R-101", Decision: &deny, Source: SourceOrg}},
		}, DecisionDeny},
		{"org-tuned builtin survives a user relax", Config{
			Overrides: []Override{
				{RuleID: "R-101", Decision: &deny, Source: SourceOrg},
				{RuleID: "R-101", Decision: &allow, Source: "user"},
			},
		}, DecisionDeny},
		{"org-tuned builtin survives a trusted-project cap", Config{
			Overrides: []Override{
				{RuleID: "R-101", Decision: &deny, Source: SourceOrg},
				{RuleID: "R-101", EnforceOff: true, Source: "trusted_project"},
			},
		}, DecisionDeny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Mode, tc.cfg.Home = ModeEnforce, "/home/u"
			eng, err := New(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			v := eng.Evaluate(ev)
			got := DecisionAllow
			if v.RuleID == "R-101" {
				got = v.Decision
			}
			if got != tc.want {
				t.Fatalf("R-101 decision = %s (verdict %s %s), want %s", got, v.RuleID, v.Decision, tc.want)
			}
		})
	}

	// An org-DEFINED rule survives a config disable of its id.
	orgRule := Rule{
		ID: "U-990", Category: CategoryDestructive, Severity: SeverityHigh,
		AppliesTo: []EventKind{KindShellExec}, Observe: DecisionFlag, Enforce: DecisionDeny,
		Doc: "org rule U-990", Source: SourceOrg,
		Match: func(mc *MatchContext) (bool, string) { return mc.Event.Target == "touch /tmp/org-floor", "org floor" },
	}
	eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u", ExtraRules: []Rule{orgRule}, Disabled: []string{"U-990"}})
	if err != nil {
		t.Fatal(err)
	}
	if v := eng.Evaluate(Event{Kind: KindShellExec, Target: "touch /tmp/org-floor", Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", SessionID: "s"}); v.RuleID != "U-990" || v.Decision != DecisionDeny {
		t.Fatalf("org rule after a config disable: %s %s, want U-990 deny", v.RuleID, v.Decision)
	}
}
