package policy

import (
	"testing"
	"time"
)

// TestDecisionPinnedBy pins which layer an override attributes a rule's
// stance to (guard-rules live audit 2026-10-15, F1): an explicit decision
// or `enforce = true` pins, `enforce = false` clears the pin, and a later
// lower-trust escalation never takes an org pin away.
func TestDecisionPinnedBy(t *testing.T) {
	t.Parallel()
	deny := DecisionDeny
	ev := Event{
		Kind: KindShellExec, Target: "rm -rf ~/projects", Cwd: "/home/u/proj",
		ProjectRoot: "/home/u/proj", SessionID: "s", Now: time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC),
	}
	cases := []struct {
		name      string
		overrides []Override
		want      string
	}{
		{"catalog defaults", nil, ""},
		{"org decision", []Override{{RuleID: "R-101", Decision: &deny, Source: "org"}}, "org"},
		{"org enforce only", []Override{{RuleID: "R-101", Enforced: true, Source: "org"}}, "org"},
		{"org overridable only", []Override{{RuleID: "R-101", Overridable: true, Source: "org"}}, ""},
		{"org cap clears", []Override{{RuleID: "R-101", EnforceOff: true, Source: "org"}}, ""},
		{"user decision", []Override{{RuleID: "R-101", Decision: &deny, Source: "user"}}, "user"},
		{"org pin survives a later user escalation", []Override{
			{RuleID: "R-101", Decision: &deny, Source: "org"},
			{RuleID: "R-101", Enforced: true, Source: "user"},
		}, "org"},
		{"user pin then org pin", []Override{
			{RuleID: "R-101", Enforced: true, Source: "user"},
			{RuleID: "R-101", Decision: &deny, Source: "org"},
		}, "org"},
		{"empty source pins as builtin", []Override{{RuleID: "R-101", Enforced: true}}, SourceBuiltin},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u", Overrides: tc.overrides})
			if err != nil {
				t.Fatal(err)
			}
			v := eng.Evaluate(ev)
			if v.RuleID != "R-101" || v.DecisionPinnedBy != tc.want {
				t.Fatalf("verdict = %s pinnedBy=%q, want R-101 pinnedBy=%q", v.RuleID, v.DecisionPinnedBy, tc.want)
			}
		})
	}
}
