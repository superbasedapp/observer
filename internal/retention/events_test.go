package retention

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// seedEventTables opens a fresh DB and lands one project / session /
// api_turn (the FK parents both event tables need, since db.Open enables
// foreign_keys) plus the caller's event rows at the given ages relative to
// fakeNow — the package's MIDDAY-UTC anchor, so a horizon boundary never
// lands on a date rollover.
func seedEventTables(t *testing.T, compactionAges, compressionAges []time.Duration) (string, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "events.db")
	d, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	now := fakeNow.Format(time.RFC3339Nano)
	if _, err := d.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/repo', ?)`, now); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('sess-1', 1, 'claude-code', ?)`, now); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO api_turns (id, session_id, project_id, timestamp, provider, model, input_tokens, output_tokens)
		 VALUES (1, 'sess-1', 1, ?, 'anthropic', 'claude-sonnet-4', 10, 10)`, now); err != nil {
		t.Fatalf("seed api_turn: %v", err)
	}

	for _, age := range compactionAges {
		ts := fakeNow.Add(age).Format(time.RFC3339Nano)
		if _, err := d.ExecContext(ctx,
			`INSERT INTO compaction_events (session_id, project_id, timestamp, tool, file_state_snapshot)
			 VALUES ('sess-1', 1, ?, 'claude-code', '{"files":[]}')`, ts); err != nil {
			t.Fatalf("seed compaction_event: %v", err)
		}
	}
	for _, age := range compressionAges {
		ts := fakeNow.Add(age).Format(time.RFC3339Nano)
		if _, err := d.ExecContext(ctx,
			`INSERT INTO compression_events (api_turn_id, timestamp, mechanism, original_bytes, compressed_bytes)
			 VALUES (1, ?, 'rolling_summary', 1000, 100)`, ts); err != nil {
			t.Fatalf("seed compression_event: %v", err)
		}
	}
	return dbPath, d
}

func countRows(t *testing.T, d *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := d.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

const day = 24 * time.Hour

// TestSweepEventTables is the table-driven half: one row per horizon shape,
// with fixtures seeded on BOTH sides of each boundary. compaction_events and
// compression_events had no retention at all before migration-era 2026-09-16
// (1.4 GiB / 915 MB on the operator's live DB), so the cases that matter are
// "0 keeps everything" and "the horizon deletes only what is past it".
func TestSweepEventTables(t *testing.T) {
	compactionAges := []time.Duration{-120 * day, -45 * day, -31 * day, -29 * day, -1 * day}
	compressionAges := []time.Duration{-200 * day, -91 * day, -89 * day, -2 * day}

	tests := []struct {
		name            string
		days            EventSweepDays
		wantCompaction  int // rows LEFT
		wantCompression int
		wantDeleted     EventSweepCounts
	}{
		{
			name:            "both horizons disabled keeps everything",
			days:            EventSweepDays{},
			wantCompaction:  len(compactionAges),
			wantCompression: len(compressionAges),
			wantDeleted:     EventSweepCounts{},
		},
		{
			name:            "defaults: 30d compaction, 90d compression",
			days:            EventSweepDays{CompactionEventsDays: 30, CompressionEventsDays: 90},
			wantCompaction:  2, // -29d, -1d
			wantCompression: 2, // -89d, -2d
			wantDeleted: EventSweepCounts{
				"compaction_events":  3,
				"compression_events": 2,
			},
		},
		{
			name:            "one horizon on, the other left forever",
			days:            EventSweepDays{CompactionEventsDays: 30},
			wantCompaction:  2,
			wantCompression: len(compressionAges),
			wantDeleted:     EventSweepCounts{"compaction_events": 3},
		},
		{
			name:            "a horizon older than every row deletes nothing",
			days:            EventSweepDays{CompactionEventsDays: 3650, CompressionEventsDays: 3650},
			wantCompaction:  len(compactionAges),
			wantCompression: len(compressionAges),
			wantDeleted: EventSweepCounts{
				"compaction_events":  0,
				"compression_events": 0,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, d := seedEventTables(t, compactionAges, compressionAges)
			p := New(d)

			got, err := p.sweepEventTables(context.Background(), tc.days)
			if err != nil {
				t.Fatalf("sweepEventTables: %v", err)
			}
			if len(got) != len(tc.wantDeleted) {
				t.Fatalf("swept tables = %v, want %v", got, tc.wantDeleted)
			}
			for table, want := range tc.wantDeleted {
				if got[table] != want {
					t.Errorf("%s deleted = %d, want %d (all: %v)", table, got[table], want, got)
				}
			}
			if n := countRows(t, d, "compaction_events"); n != tc.wantCompaction {
				t.Errorf("compaction_events left = %d, want %d", n, tc.wantCompaction)
			}
			if n := countRows(t, d, "compression_events"); n != tc.wantCompression {
				t.Errorf("compression_events left = %d, want %d", n, tc.wantCompression)
			}
		})
	}
}

// TestSweepEventTablesIsIdempotent pins the property the daily tick relies
// on: a second pass inside the same horizon removes nothing more.
func TestSweepEventTablesIsIdempotent(t *testing.T) {
	_, d := seedEventTables(t,
		[]time.Duration{-120 * day, -1 * day},
		[]time.Duration{-200 * day, -2 * day})
	p := New(d)
	days := EventSweepDays{CompactionEventsDays: 30, CompressionEventsDays: 90}

	first, err := p.sweepEventTables(context.Background(), days)
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	if first.Total() != 2 {
		t.Fatalf("first sweep deleted %d rows, want 2 (%v)", first.Total(), first)
	}
	second, err := p.sweepEventTables(context.Background(), days)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if second.Total() != 0 {
		t.Fatalf("second sweep deleted %d rows, want 0 (%v)", second.Total(), second)
	}
}

// TestSweepEventTablesBatchesAreBounded drives a rule past its batch size to
// prove the loop keeps going until the backlog drains AND that each statement
// is bounded — the live-daemon requirement that rules out one giant DELETE
// over millions of rows.
func TestSweepEventTablesBatchesAreBounded(t *testing.T) {
	// compaction_events batches at 2,000; seed one batch plus a remainder.
	ages := make([]time.Duration, 0, 2_050)
	for i := 0; i < 2_050; i++ {
		ages = append(ages, -100*day)
	}
	_, d := seedEventTables(t, ages, nil)
	p := New(d)

	got, err := p.sweepEventTables(context.Background(), EventSweepDays{CompactionEventsDays: 30})
	if err != nil {
		t.Fatalf("sweepEventTables: %v", err)
	}
	if got["compaction_events"] != 2_050 {
		t.Fatalf("deleted = %d, want 2050 (%v)", got["compaction_events"], got)
	}
	if n := countRows(t, d, "compaction_events"); n != 0 {
		t.Fatalf("compaction_events left = %d, want 0", n)
	}
}

// TestRunSweepsEventTables pins the wiring: Run reports the sweep on Result
// so `observer prune` and the daily tick can print it.
func TestRunSweepsEventTables(t *testing.T) {
	dbPath, d := seedEventTables(t,
		[]time.Duration{-120 * day, -1 * day},
		[]time.Duration{-200 * day, -2 * day})

	res, err := New(d).Run(context.Background(), Options{
		DBPath:     dbPath,
		EventSweep: EventSweepDays{CompactionEventsDays: 30, CompressionEventsDays: 90},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.EventRowsDeleted["compaction_events"] != 1 {
		t.Errorf("compaction_events = %d, want 1 (%v)", res.EventRowsDeleted["compaction_events"], res.EventRowsDeleted)
	}
	if res.EventRowsDeleted["compression_events"] != 1 {
		t.Errorf("compression_events = %d, want 1 (%v)", res.EventRowsDeleted["compression_events"], res.EventRowsDeleted)
	}
}

// TestRunWithoutEventHorizonsIsUnchanged pins the additive guarantee: a
// zero-valued Options.EventSweep sweeps nothing, so every existing caller
// that has not opted in behaves exactly as it did before.
func TestRunWithoutEventHorizonsIsUnchanged(t *testing.T) {
	dbPath, d := seedEventTables(t,
		[]time.Duration{-500 * day},
		[]time.Duration{-500 * day})

	res, err := New(d).Run(context.Background(), Options{DBPath: dbPath})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.EventRowsDeleted.Total() != 0 {
		t.Fatalf("swept %d rows with no horizons configured (%v)", res.EventRowsDeleted.Total(), res.EventRowsDeleted)
	}
	if n := countRows(t, d, "compaction_events"); n != 1 {
		t.Fatalf("compaction_events left = %d, want 1", n)
	}
	if n := countRows(t, d, "compression_events"); n != 1 {
		t.Fatalf("compression_events left = %d, want 1", n)
	}
}
