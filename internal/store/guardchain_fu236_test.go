package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestVerifyGuardChainRepairHint pins FU-236: the walk counts the rows that
// fail as rewritten with no action id (the GUARD-CHAIN-1 maintenance shape
// `observer guard repair-anchors` can prove) and the status surfaces name
// the documented repair command for what it found.
func TestVerifyGuardChainRepairHint(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		damage     string
		wantOK     bool
		wantAction int
		wantHint   string
	}{
		{"intact chain: no hint", "", true, 0, ""},
		{
			"actionless row no longer hashes: repair-anchors",
			`UPDATE guard_events SET session_id = 'changed' WHERE id = 2`, false, 1, "repair-anchors",
		},
		{
			"deleted middle row: the link tools",
			`DELETE FROM guard_events WHERE id = 2`, false, 0, "relink-gaps",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, database := newTestStore(t)
			ctx := context.Background()
			var seed []GuardEventRow
			for i := 0; i < 3; i++ {
				seed = append(seed, guardEventFixture("s1", "R-150", t0Guard.Add(time.Duration(i)*time.Second)))
			}
			if _, err := s.InsertGuardEvents(ctx, seed); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if tc.damage != "" {
				if _, err := database.Exec(tc.damage); err != nil {
					t.Fatalf("%s: %v", tc.damage, err)
				}
			}
			report, err := s.VerifyGuardChain(ctx)
			if err != nil {
				t.Fatalf("VerifyGuardChain: %v", err)
			}
			if report.OK != tc.wantOK || report.ActionlessRewritten != tc.wantAction {
				t.Fatalf("report = %+v, want OK=%v actionless=%d", report, tc.wantOK, tc.wantAction)
			}
			hint := GuardChainRepairHint(report)
			if (tc.wantHint == "") != (hint == "") || !strings.Contains(hint, tc.wantHint) {
				t.Fatalf("hint = %q, want it to name %q", hint, tc.wantHint)
			}
		})
	}
}
