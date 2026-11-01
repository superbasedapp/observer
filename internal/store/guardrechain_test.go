package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestRechainGuardGaps re-links only over deletion gaps. Each case starts
// from seedGuardDuplicates after a delete-only dedup, which removes seeded
// rows 1 and 4 and so leaves gaps at seeded rows 2 and 5.
func TestRechainGuardGaps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		// damage, when set, is SQL run (with the seeded id at damageRow)
		// after the dedup to put a non-gap break in the chain.
		damage      string
		damageRow   int
		apply       bool
		wantGaps    int
		wantRefused bool
		wantApplied bool
		wantChainOK bool
	}{
		{name: "dry run reports the gaps and writes nothing", wantGaps: 2},
		{name: "apply re-links and records a marker", apply: true, wantGaps: 2, wantApplied: true, wantChainOK: true},
		{
			name: "an edited row refuses", damage: `UPDATE guard_events SET reason = 'edited' WHERE id = ?`, damageRow: 3,
			apply: true, wantGaps: 1, wantRefused: true,
		},
		{
			name: "a broken link with its predecessor present refuses", damage: `UPDATE guard_events SET chain_prev = 'x' WHERE id = ?`, damageRow: 3,
			apply: true, wantGaps: 1, wantRefused: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, _ := newTestStore(t)
			ids := seedGuardDuplicates(t, s)
			if _, err := s.DedupGuardEvents(ctx, GuardDedupOptions{Apply: true, KeepHashes: true}); err != nil {
				t.Fatalf("DedupGuardEvents: %v", err)
			}
			if tc.damage != "" {
				if _, err := s.db.ExecContext(ctx, tc.damage, ids[tc.damageRow]); err != nil {
					t.Fatalf("damage: %v", err)
				}
			}
			before := guardChainHashes(t, s)
			rowsBefore := guardRowCount(t, s)

			report, err := s.RechainGuardGaps(ctx, tc.apply, now)
			if err != nil {
				t.Fatalf("RechainGuardGaps: %v", err)
			}
			if report.Gaps != tc.wantGaps || report.Applied != tc.wantApplied || (report.Refused != "") != tc.wantRefused {
				t.Fatalf("report = %+v, want gaps %d applied %v refused %v", report, tc.wantGaps, tc.wantApplied, tc.wantRefused)
			}
			if report.FirstGapID != ids[2] {
				t.Errorf("FirstGapID = %d, want %d", report.FirstGapID, ids[2])
			}

			if !tc.wantApplied {
				after := guardChainHashes(t, s)
				if len(after) != len(before) {
					t.Fatalf("rows = %d, want %d unchanged", len(after), len(before))
				}
				for id, hash := range before {
					if after[id] != hash {
						t.Errorf("row %d rewritten without --apply or on a refusal", id)
					}
				}
				return
			}

			if got := guardRowCount(t, s); got != rowsBefore+1 {
				t.Errorf("rows = %d, want %d (one marker added)", got, rowsBefore+1)
			}
			var rule, reason string
			if err := s.db.QueryRowContext(ctx,
				`SELECT rule_id, reason FROM guard_events WHERE id = ?`, report.MarkerID).Scan(&rule, &reason); err != nil {
				t.Fatalf("marker: %v", err)
			}
			if rule != GuardRechainRuleID || !strings.Contains(reason, report.OldTailHash) || report.OldTailHash == "" {
				t.Errorf("marker = %s %q, want %s naming the old tail %s", rule, reason, GuardRechainRuleID, report.OldTailHash)
			}
			// Rows before the first gap keep their hashes.
			after := guardChainHashes(t, s)
			if after[ids[0]] != before[ids[0]] {
				t.Error("a row before the first gap was rewritten")
			}
			chain, err := s.VerifyGuardChain(ctx)
			if err != nil {
				t.Fatalf("VerifyGuardChain: %v", err)
			}
			if chain.OK != tc.wantChainOK {
				t.Errorf("chain = %+v, want OK=%v", chain, tc.wantChainOK)
			}
			again, err := s.RechainGuardGaps(ctx, true, now)
			if err != nil || again.Gaps != 0 || again.Applied {
				t.Errorf("second run = (%+v, %v), want nothing to do", again, err)
			}
		})
	}
}

// TestRechainGuardGaps_IntactChain is a no-op on a chain with no gaps.
func TestRechainGuardGaps_IntactChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := newTestStore(t)
	seedGuardDuplicates(t, s)
	report, err := s.RechainGuardGaps(ctx, true, time.Now().UTC())
	if err != nil || report.Gaps != 0 || report.Applied || report.Refused != "" {
		t.Errorf("report = (%+v, %v), want nothing to do", report, err)
	}
	if got := guardRowCount(t, s); got != 6 {
		t.Errorf("rows = %d, want 6 (no marker on a no-op)", got)
	}
}
