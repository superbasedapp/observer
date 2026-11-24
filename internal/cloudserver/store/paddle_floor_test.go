package store

import "testing"

// TestPaddlePlanFloor pins the one plan-version floor both Paddle branches
// apply (paddle_floor.go; D-299 on the account path, NEW-12 on the org path):
// a mapped plan never moves a held plan back to an OLDER version of the same
// plan. A same or newer mapped version, a different plan, and a new
// subscription (nothing held) pass through, and only Version ever changes.
func TestPaddlePlanFloor(t *testing.T) {
	t.Parallel()
	businessV1 := PaddlePlan{Name: "business", Version: 1, Interval: "month", Display: "$40/seat"}
	tests := []struct {
		name   string
		mapped PaddlePlan
		held   []PaddlePlan
		want   int
	}{
		// The four NEW-12 cases, on the org path's plan: a renewal whose
		// price maps to an older, the same or a newer version than the row
		// holds, and a new subscription.
		{"renewal at a lower version keeps the held version", businessV1, []PaddlePlan{{Name: "business", Version: 2}}, 2},
		{"renewal at the same version is unchanged", PaddlePlan{Name: "business", Version: 2}, []PaddlePlan{{Name: "business", Version: 2}}, 2},
		{"renewal at a higher version moves forward", PaddlePlan{Name: "business", Version: 3}, []PaddlePlan{{Name: "business", Version: 2}}, 3},
		{"new subscription takes the mapped version", businessV1, nil, 1},
		// The account path's D-299 cases (the plan in force).
		{"account plan: older mapped version is raised", PaddlePlan{Name: PlanPlusBeta, Version: 2, Interval: "month"}, []PaddlePlan{{Name: PlanPlusBeta, Version: 3}}, 3},
		{"account plan: v1 legacy price is raised", PaddlePlan{Name: PlanPlusBeta, Version: 1}, []PaddlePlan{{Name: PlanPlusBeta, Version: 3}}, 3},
		{"a different plan (activation from free) is unchanged", PaddlePlan{Name: PlanPlusBeta, Version: 2}, []PaddlePlan{{Name: PlanFree, Version: 3}}, 2},
		{"a tier change (team to business) is unchanged", businessV1, []PaddlePlan{{Name: "team", Version: 4}}, 1},
		// Several records of what is held (the account path passes the plan
		// in force and the row): the highest same-name version wins.
		{"the highest held version of the same plan wins", PaddlePlan{Name: PlanPlusBeta, Version: 1}, []PaddlePlan{{Name: PlanPlusBeta, Version: 3}, {Name: PlanPlusBeta, Version: 5}, {Name: PlanFree, Version: 9}}, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := paddlePlanFloor(tt.mapped, tt.held...)
			if got.Version != tt.want || got.Name != tt.mapped.Name || got.Interval != tt.mapped.Interval ||
				got.Display != tt.mapped.Display || got.NoTrialOf != tt.mapped.NoTrialOf {
				t.Fatalf("paddlePlanFloor(%+v, %+v) = %+v, want version %d and every other field unchanged",
					tt.mapped, tt.held, got, tt.want)
			}
		})
	}
}
