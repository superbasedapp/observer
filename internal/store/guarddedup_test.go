package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// seedGuardDuplicates stores two actions and six guard rows: the original
// flag for each action, two re-parse copies of action A's flag, and two
// identical hook rows (no action anchor), which are real separate events.
// It returns the ids of the rows in insert order.
func seedGuardDuplicates(t *testing.T, s *Store) []int64 {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 10, 21, 18, 0, 0, 0, time.UTC)
	if _, err := s.Ingest(ctx, []models.ToolEvent{
		{
			SourceFile: "s.db", SourceEventID: "a", SessionID: "sD", ProjectRoot: "/p", Timestamp: now,
			Tool: models.ToolStakpak, ActionType: models.ActionRunCommand, Target: "a", Success: true,
		},
		{
			SourceFile: "s.db", SourceEventID: "b", SessionID: "sD", ProjectRoot: "/p", Timestamp: now,
			Tool: models.ToolStakpak, ActionType: models.ActionRunCommand, Target: "b", Success: true,
		},
	}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	actionID := func(ev string) *int64 {
		var id int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT id FROM actions WHERE source_event_id = ?`, ev).Scan(&id); err != nil {
			t.Fatalf("action %s: %v", ev, err)
		}
		return &id
	}
	a, b := actionID("a"), actionID("b")
	row := func(action *int64, rule string) GuardEventRow {
		return GuardEventRow{
			TS: now, SessionID: "sD", ActionID: action, Tool: models.ToolStakpak,
			EventKind: "file_access", RuleID: rule, Decision: "flag", TargetHash: rule,
		}
	}
	if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{
		row(a, "R-150"), row(a, "R-150"), row(nil, "R-110"),
		row(b, "R-152"), row(a, "R-150"), row(nil, "R-110"),
	}); err != nil {
		t.Fatalf("InsertGuardEvents: %v", err)
	}
	var ids []int64
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM guard_events ORDER BY id`)
	if err != nil {
		t.Fatalf("ids: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

func guardRowCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM guard_events`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestDedupGuardEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name string
		// tamper names the seeded row (index) whose reason is edited after
		// insert, or -1 for none.
		tamper      int
		opts        GuardDedupOptions
		wantApplied bool
		wantRefused bool
		wantRows    int
		// wantBreak is the seeded row (index) VerifyGuardChain reports as
		// the first divergence afterwards, or -1 for an intact chain.
		wantBreak int
	}{
		{name: "dry run reports and writes nothing", tamper: -1, wantRows: 6, wantBreak: -1},
		{name: "apply removes repeats and keeps the chain whole", tamper: -1, opts: GuardDedupOptions{Apply: true}, wantApplied: true, wantRows: 4, wantBreak: -1},
		{name: "a break inside the re-hash range refuses", tamper: 3, opts: GuardDedupOptions{Apply: true}, wantRefused: true, wantRows: 6, wantBreak: 3},
		{name: "a break before the first repeat is left as it was", tamper: 0, opts: GuardDedupOptions{Apply: true}, wantApplied: true, wantRows: 4, wantBreak: 0},
		{name: "delete-only dry run writes nothing", tamper: 3, opts: GuardDedupOptions{KeepHashes: true}, wantRows: 6, wantBreak: 3},
		// Deleting seeded row 1 leaves row 2 linked to a hash that is gone.
		{name: "delete-only removes repeats and rewrites no hash", tamper: -1, opts: GuardDedupOptions{Apply: true, KeepHashes: true}, wantApplied: true, wantRows: 4, wantBreak: 2},
		{name: "delete-only is not refused by an existing break", tamper: 3, opts: GuardDedupOptions{Apply: true, KeepHashes: true}, wantApplied: true, wantRows: 4, wantBreak: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, _ := newTestStore(t)
			ids := seedGuardDuplicates(t, s)
			if tc.tamper >= 0 {
				if _, err := s.db.ExecContext(ctx,
					`UPDATE guard_events SET reason = 'edited' WHERE id = ?`, ids[tc.tamper]); err != nil {
					t.Fatalf("tamper: %v", err)
				}
			}
			before := guardChainHashes(t, s)

			report, err := s.DedupGuardEvents(ctx, tc.opts)
			if err != nil {
				t.Fatalf("DedupGuardEvents: %v", err)
			}
			if report.Duplicates != 2 || report.FirstDuplicateID != ids[1] || report.ByTool[models.ToolStakpak] != 2 {
				t.Errorf("report = %+v, want 2 stakpak duplicates from id %d", report, ids[1])
			}
			if report.Applied != tc.wantApplied || (report.Refused != "") != tc.wantRefused {
				t.Errorf("applied/refused = %v/%q, want %v/%v", report.Applied, report.Refused, tc.wantApplied, tc.wantRefused)
			}
			if got := guardRowCount(t, s); got != tc.wantRows {
				t.Errorf("rows = %d, want %d", got, tc.wantRows)
			}
			if tc.opts.KeepHashes {
				if report.Rehashed != 0 {
					t.Errorf("Rehashed = %d, want 0 in delete-only mode", report.Rehashed)
				}
				for id, hash := range guardChainHashes(t, s) {
					if before[id] != hash {
						t.Errorf("row %d hash changed in delete-only mode", id)
					}
				}
			}

			chain, err := s.VerifyGuardChain(ctx)
			if err != nil {
				t.Fatalf("VerifyGuardChain: %v", err)
			}
			if tc.wantBreak < 0 {
				if !chain.OK {
					t.Errorf("chain = %+v, want OK", chain)
				}
			} else if chain.OK || chain.FirstDivergenceID != ids[tc.wantBreak] {
				t.Errorf("chain = %+v, want the first break at id %d", chain, ids[tc.wantBreak])
			}

			if tc.wantApplied {
				again, err := s.DedupGuardEvents(ctx, tc.opts)
				if err != nil || again.Duplicates != 0 || again.Applied {
					t.Errorf("second run = (%+v, %v), want nothing left to do", again, err)
				}
			}
		})
	}
}

// guardChainHashes maps every guard_events id to its stored chain_hash.
func guardChainHashes(t *testing.T, s *Store) map[int64]string {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `SELECT id, chain_hash FROM guard_events`)
	if err != nil {
		t.Fatalf("hashes: %v", err)
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var hash string
		if err := rows.Scan(&id, &hash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[id] = hash
	}
	return out
}

// TestDedupGuardEvents_NewRowsChainOnTheRewrite pins that a row appended
// after the cleanup links onto the re-hashed tail.
func TestDedupGuardEvents_NewRowsChainOnTheRewrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := newTestStore(t)
	seedGuardDuplicates(t, s)
	if _, err := s.DedupGuardEvents(ctx, GuardDedupOptions{Apply: true}); err != nil {
		t.Fatalf("DedupGuardEvents: %v", err)
	}
	if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{{
		TS: time.Date(2026, 10, 21, 19, 0, 0, 0, time.UTC), SessionID: "sD", Tool: models.ToolStakpak,
		EventKind: "shell_exec", RuleID: "R-110", Decision: "flag",
	}}); err != nil {
		t.Fatalf("InsertGuardEvents: %v", err)
	}
	if chain, err := s.VerifyGuardChain(ctx); err != nil || !chain.OK {
		t.Errorf("chain after a new row = (%+v, %v), want OK", chain, err)
	}
}
