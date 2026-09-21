package policy

import "testing"

// TestProtectedIntegrityRule_Backstop pins the policy.New hard backstop for
// the guard's own integrity rules R-160/R-161 (adversarial-review F1): a
// below-org disable or weakening override on either is refused at
// construction, while an ESCALATION passes. This is the last line of
// defence even if the guard merge layer missed a path — every disable
// funnels to Config.Disabled and every weakening override to Config.Overrides.
func TestProtectedIntegrityRule_Backstop(t *testing.T) {
	t.Parallel()

	// R-160 fires on an agent write under ~/.observer.
	ev160 := Event{Kind: KindConfigChange, ActionType: "write_file", Target: "/home/u/.observer/guard-policy.toml"}
	// R-161 fires on an in-repo project guard-policy write.
	ev161 := Event{Kind: KindConfigChange, ActionType: "write_file", Target: "/home/u/proj/.observer/guard-policy.toml"}

	allow := DecisionAllow
	deny := DecisionDeny

	t.Run("disable is refused", func(t *testing.T) {
		t.Parallel()
		eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u", Disabled: []string{"R-160", "R-161"}})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if v := eng.Evaluate(ev160); v.RuleID != "R-160" || v.Decision != DecisionDeny {
			t.Errorf("Config.Disabled R-160 backstop: verdict=%+v, want R-160/deny", v)
		}
		if v := eng.Evaluate(ev161); v.RuleID != "R-161" || v.Decision != DecisionFlag {
			t.Errorf("Config.Disabled R-161 backstop: verdict=%+v, want R-161/flag", v)
		}
	})

	t.Run("weakening override is dropped", func(t *testing.T) {
		t.Parallel()
		eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u", Overrides: []Override{
			{RuleID: "R-160", Decision: &allow, Source: "user"},
			{RuleID: "R-161", Decision: &allow, Source: "trusted_project"},
		}})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if v := eng.Evaluate(ev160); v.RuleID != "R-160" || v.Decision != DecisionDeny {
			t.Errorf("weaken R-160 backstop: verdict=%+v, want R-160/deny", v)
		}
		// R-161 relaxed to allow would make its verdict allow; the drop keeps
		// it at its builtin flag stance.
		if v := eng.Evaluate(ev161); v.RuleID != "R-161" || v.Decision != DecisionFlag {
			t.Errorf("weaken R-161 backstop: verdict=%+v, want R-161/flag", v)
		}
	})

	t.Run("escalation still applies", func(t *testing.T) {
		t.Parallel()
		// Raising R-161 flag->deny is an escalation, not a weakening: it
		// must pass the backstop.
		eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u", Overrides: []Override{
			{RuleID: "R-161", Decision: &deny, Source: "trusted_project"},
		}})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if v := eng.Evaluate(ev161); v.RuleID != "R-161" || v.Decision != DecisionDeny {
			t.Errorf("escalate R-161 flag->deny: verdict=%+v, want R-161/deny", v)
		}
	})
}
