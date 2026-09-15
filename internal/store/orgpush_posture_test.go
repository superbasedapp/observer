package store

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestPushBatchPostureOnlyIsNotEmpty pins SF-19 at the predicate: an
// envelope-level POSTURE row is enough on its own to make a batch worth
// pushing.
//
// Before this, PushBatch.Empty() was RowCount()==0 && !hasAggregates(), and
// neither half counted BudgetPosture or UpdatePosture — so a managed node whose
// intervention controller was running but which produced no new rows this tick
// pushed nothing at all, the server never heard the posture, and the Budgets
// page rendered `direct_control = not_reported` (an ABSENCE) over a node that
// was in fact controlling processes. A posture that only ships alongside
// unrelated telemetry is one an admin cannot rely on.
//
// Table-driven per CLAUDE.md #5: one row per way a batch can be non-empty, so
// a future family cannot quietly drop out of the predicate.
func TestPushBatchPostureOnlyIsNotEmpty(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		batch     PushBatch
		wantEmpty bool
		why       string
	}{
		{
			name:      "nothing at all",
			batch:     PushBatch{},
			wantEmpty: true,
			why:       "a node with no rows, no aggregates and no posture must still skip the envelope",
		},
		{
			name: "budget posture only",
			batch: PushBatch{BudgetPosture: &orgcontract.BudgetPostureRow{
				EnforcementPoint: orgcontract.BudgetPointGuard,
				Mode:             "enforce",
				FetchState:       orgcontract.BudgetFetchOK,
				FromOrg:          true, LastFetchOK: true, Capped: true,
				Coverage:      orgcontract.BudgetCoverageProxyOnly,
				DirectControl: orgcontract.DirectControlPartial,
			}},
			wantEmpty: false,
			why:       "SF-19: an idle tick is exactly when the admin most needs to hear the posture",
		},
		{
			name:      "update posture only",
			batch:     PushBatch{UpdatePosture: &orgcontract.UpdatePostureRow{Version: "v1.30.0", State: "idle"}},
			wantEmpty: false,
			why:       "the update posture is the same class of self-report and shipped with the same defect",
		},
		{
			name: "both postures",
			batch: PushBatch{
				BudgetPosture: &orgcontract.BudgetPostureRow{EnforcementPoint: orgcontract.BudgetPointGuard},
				UpdatePosture: &orgcontract.UpdatePostureRow{Version: "v1.30.0", State: "idle"},
			},
			wantEmpty: false,
		},
		{
			name:      "aggregate only, unchanged behaviour",
			batch:     PushBatch{RoutingSummaries: []orgcontract.RoutingSummaryRow{{Day: "2026-09-14"}}},
			wantEmpty: false,
			why:       "the pre-existing aggregate-only rule must be untouched by the posture addition",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.batch.Empty(); got != tc.wantEmpty {
				t.Fatalf("Empty() = %v, want %v (RowCount=%d) — %s",
					got, tc.wantEmpty, tc.batch.RowCount(), tc.why)
			}
			// A posture must never be mistaken for row-level progress: it
			// carries no cursor, so counting it would advance nothing and
			// would corrupt the forward-progress accounting.
			if tc.batch.RowCount() != 0 {
				t.Fatalf("RowCount() = %d, want 0; no case here seeds a row-bearing family", tc.batch.RowCount())
			}
		})
	}
}

// TestComposeBudgetPostureMakesTheBatchPushable is the same rule one layer
// down, through the real seam: wiring a provider is all it takes for an
// otherwise-idle SelectUnpushedSince to produce a batch the push loop will
// deliver.
func TestComposeBudgetPostureMakesTheBatchPushable(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// No seeded activity at all: without the provider this is the idle tick
	// that used to drop the posture on the floor.
	idle, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "o", "u", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (idle): %v", err)
	}
	if !idle.Empty() {
		t.Fatalf("an idle node with no posture provider produced a non-empty batch: %+v", idle)
	}

	s.SetBudgetPostureProvider(func() (orgcontract.BudgetPostureRow, bool) {
		return orgcontract.BudgetPostureRow{
			EnforcementPoint: orgcontract.BudgetPointGuard,
			Mode:             "enforce",
			DirectControl:    orgcontract.DirectControlPartial,
		}, true
	})
	withPosture, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "o", "u", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (posture): %v", err)
	}
	if withPosture.BudgetPosture == nil {
		t.Fatal("the provider was wired but no posture was composed")
	}
	if withPosture.Empty() {
		t.Fatal("a posture-only batch reported Empty; PushOnce would early-return and the admin would see not_reported")
	}

	// ok=false is still "nothing to report", and must stay byte-identical to
	// a node without the feature.
	s.SetBudgetPostureProvider(func() (orgcontract.BudgetPostureRow, bool) {
		return orgcontract.BudgetPostureRow{}, false
	})
	none, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "o", "u", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (no posture): %v", err)
	}
	if none.BudgetPosture != nil || !none.Empty() {
		t.Fatalf("a provider reporting nothing produced %+v; want a nil posture and an empty batch", none.BudgetPosture)
	}
}
