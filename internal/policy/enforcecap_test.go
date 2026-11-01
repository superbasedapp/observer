package policy

import (
	"testing"
	"time"
)

// TestEnforceOffOverrideCapsAtFlag pins the engine half of Sol A2-06: an
// explicit `enforce = false` override caps the row at FLAG in both modes,
// a later `enforce = true` clears it, and the protected-row backstop
// refuses it on an integrity rule.
func TestEnforceOffOverrideCapsAtFlag(t *testing.T) {
	t.Parallel()
	ev := Event{
		Kind: KindShellExec, Target: "rm -rf ~/projects", Cwd: "/home/u/proj",
		ProjectRoot: "/home/u/proj", SessionID: "s", Now: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC),
	}
	cases := []struct {
		name      string
		mode      Mode
		overrides []Override
		want      Decision
		cappedBy  string
	}{
		{"enforce mode uncapped", ModeEnforce, nil, DecisionDeny, ""},
		{"enforce mode capped", ModeEnforce, []Override{{RuleID: "R-101", EnforceOff: true, Source: "user"}}, DecisionFlag, "user"},
		{"observe mode per-rule enforced", ModeObserve, []Override{{RuleID: "R-101", Enforced: true, Source: "user"}}, DecisionDeny, ""},
		// Both from the user layer: an org-pinned row is a floor a user
		// cap may not lower (OSH-R-014, TestOrgFloorBackstop).
		{"observe mode capped clears enforced", ModeObserve, []Override{
			{RuleID: "R-101", Enforced: true, Source: "user"},
			{RuleID: "R-101", EnforceOff: true, Source: "user"},
		}, DecisionFlag, "user"},
		{"later enforce clears cap", ModeEnforce, []Override{
			{RuleID: "R-101", EnforceOff: true, Source: "org"},
			{RuleID: "R-101", Enforced: true, Source: "user"},
		}, DecisionDeny, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := New(Config{Mode: tc.mode, Home: "/home/u", Overrides: tc.overrides})
			if err != nil {
				t.Fatal(err)
			}
			v := eng.Evaluate(ev)
			if v.RuleID != "R-101" || v.Decision != tc.want || v.EnforceCappedBy != tc.cappedBy {
				t.Fatalf("verdict = %s %s cappedBy=%q, want R-101 %s cappedBy=%q", v.RuleID, v.Decision, v.EnforceCappedBy, tc.want, tc.cappedBy)
			}
			if got := eng.RuleEnforceCapped("R-101"); got != (tc.cappedBy != "") {
				t.Errorf("RuleEnforceCapped = %v", got)
			}
		})
	}
	eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u", Overrides: []Override{{RuleID: "R-160", EnforceOff: true, Source: "user"}}})
	if err != nil {
		t.Fatal(err)
	}
	if eng.RuleEnforceCapped("R-160") {
		t.Error("an integrity rule was capped by a below-org override")
	}
}
