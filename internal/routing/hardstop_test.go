package routing

import "testing"

// TestDecide_HardStopThreadedOntoDecision pins the G1-HARDSTOP fix at the
// engine seam: the three §R14 exhaustion behaviors now differ on the Decision
// row exactly as documented. hard_stop and degrade_all share the same
// degrade_all cap (neither blocks — G7), but only hard_stop sets
// Decision.HardStop and records ReasonBudgetHardStop; advise_only sets
// AdviseOnly and neither of the others.
func TestDecide_HardStopThreadedOntoDecision(t *testing.T) {
	t.Parallel()
	withBudget := func(exhausted string) *Snapshot {
		s := testSnapshot()
		s.BudgetBurn = []BudgetBurnState{{
			Scope: "global", LimitUSD: 100, SpentUSD: 105,
			Window: "week", Bands: DefaultBudgetBands, Exhausted: exhausted,
		}}
		return s
	}
	cases := []struct {
		name       string
		exhausted  string
		wantStop   bool
		wantAdvise bool
		wantReason bool
	}{
		{name: "advise_only", exhausted: BudgetAdviseOnly, wantAdvise: true},
		{name: "degrade_all", exhausted: BudgetDegradeAll},
		{name: "hard_stop", exhausted: BudgetHardStop, wantStop: true, wantReason: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(valuePolicy(t), withBudget(tc.exhausted), readOnlyInput())
			if d.HardStop != tc.wantStop {
				t.Errorf("HardStop = %v, want %v", d.HardStop, tc.wantStop)
			}
			if d.AdviseOnly != tc.wantAdvise {
				t.Errorf("AdviseOnly = %v, want %v", d.AdviseOnly, tc.wantAdvise)
			}
			if got := hasReason(d.ReasonCodes, ReasonBudgetHardStop); got != tc.wantReason {
				t.Errorf("ReasonBudgetHardStop recorded = %v, want %v (reasons %v)", got, tc.wantReason, d.ReasonCodes)
			}
		})
	}
	// hard_stop and degrade_all select the SAME model (same cap): the
	// difference is the signal, never a broken turn.
	hs := Decide(valuePolicy(t), withBudget(BudgetHardStop), readOnlyInput())
	da := Decide(valuePolicy(t), withBudget(BudgetDegradeAll), readOnlyInput())
	if hs.SelectedModel != da.SelectedModel || hs.SelectedModel == "" {
		t.Fatalf("hard_stop selected %q, degrade_all %q — caps must match", hs.SelectedModel, da.SelectedModel)
	}
}
