package nodegov

import "testing"

// TestGuardBudgetPinnableRows dedicated-pins the org-budget POSTURE pair
// (org-budget plan §3.3a, wave W3a) on top of the generic coverage every
// PinnableKeys row already gets from TestEveryPinnableKeyResolvesInConfig /
// TestVocabularyIsComplete.
//
// The two rows carry DIFFERENT directions on purpose, and getting either wrong
// is a real governance defect rather than a cosmetic one:
//
//   - guard.budget.hard is DirRestrictiveOnly with Safe=true, because the
//     RESTRICTIVE value of a spend-BLOCKING flag is true. DirFree here would
//     let an org command a node to STOP blocking on budget breach, i.e. push
//     a fleet from enforcing to advisory.
//   - guard.budget.from_org is DirFree, because whether to apply the org's
//     budget at all is a posture with two legitimate answers; the direction
//     that matters (an applied org budget may only LOWER a developer's own
//     thresholds unless the node is managed and holds enforce.budget) lives in
//     govern.LowerFloat/LowerInt, not in this table.
func TestGuardBudgetPinnableRows(t *testing.T) {
	cases := []struct {
		key       string
		direction Direction
		safe      any
	}{
		{"guard.budget.hard", DirRestrictiveOnly, true},
		{"guard.budget.from_org", DirFree, nil},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			row, ok := LookupPinnableKey(tc.key)
			if !ok {
				t.Fatalf("%s is not registered as a pinnable key — the org cannot set the budget posture", tc.key)
			}
			if row.Kind != "bool" {
				t.Errorf("Kind = %q, want %q", row.Kind, "bool")
			}
			if row.Direction != tc.direction {
				t.Errorf("Direction = %v, want %v", row.Direction, tc.direction)
			}
			if row.Safe != tc.safe {
				t.Errorf("Safe = %v, want %v", row.Safe, tc.safe)
			}
			if row.Enum != nil {
				t.Errorf("Enum = %v, want nil for a bool key", row.Enum)
			}
			if row.Label == "" {
				t.Error("Label is empty — the admin console would render a blank picker row")
			}
		})
	}
}

// TestCompileBody_GuardBudgetPosture is the publish/accept round trip: an org
// may pin budget blocking ON, may pin from_org either way, and may NOT pin
// budget blocking OFF (the restrictive-only refusal, checked at publish lint
// and at agent accept by the same compiler).
func TestCompileBody_GuardBudgetPosture(t *testing.T) {
	accepted := []struct {
		name string
		raw  string
		key  string
		want bool
	}{
		{"hard:true compiles", `{"schema":2,"pinned":{"guard.budget.hard":true}}`, "guard.budget.hard", true},
		{"from_org:true compiles", `{"schema":2,"pinned":{"guard.budget.from_org":true}}`, "guard.budget.from_org", true},
		{"from_org:false compiles", `{"schema":2,"pinned":{"guard.budget.from_org":false}}`, "guard.budget.from_org", false},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			spec, _, err := CompileBody([]byte(tc.raw), schema2Max)
			if err != nil {
				t.Fatalf("CompileBody: %v", err)
			}
			if got, ok := spec.Pinned[tc.key].(bool); !ok || got != tc.want {
				t.Fatalf("spec.Pinned[%q] = %#v, want %v", tc.key, spec.Pinned[tc.key], tc.want)
			}
		})
	}

	t.Run("hard:false is refused", func(t *testing.T) {
		if _, _, err := CompileBody([]byte(`{"schema":2,"pinned":{"guard.budget.hard":false}}`), schema2Max); err == nil {
			t.Fatal("the compiler accepted guard.budget.hard:false — an org could command a fleet to STOP blocking on budget breach")
		}
	})
}

// TestGuardBudgetNumbersAreNotPinnable is the §3.3a structural statement: the
// POSTURE rides this rail, the NUMBERS never do. A pinned value is one value
// for a whole body, so a pinnable cap would be one number for the whole fleet
// masquerading as a per-developer budget — and it would collide with the
// per-caller signed body that is the real owner of those numbers.
func TestGuardBudgetNumbersAreNotPinnable(t *testing.T) {
	for _, key := range []string{
		"guard.budget.session_usd", "guard.budget.daily_usd",
		"guard.budget.weekly_usd", "guard.budget.monthly_usd",
		"guard.budget.session_tokens", "guard.budget.daily_tokens",
		"guard.budget.weekly_tokens", "guard.budget.monthly_tokens",
	} {
		if IsPinnableKey(key) {
			t.Errorf("%s is pinnable — a fleet-wide constant would be masquerading as a per-developer cap; the numbers ride GET /api/agent/budget", key)
		}
	}
}
