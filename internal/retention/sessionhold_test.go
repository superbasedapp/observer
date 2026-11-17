package retention

import (
	"context"
	"testing"
	"time"
)

// TestLocalSessionHoldStopsEveryPass: a session under a local hold
// (`observer sessions hold`, local_session_holds) survives the aged-actions
// pass, the orphaned-session sweep, the size-cap shed and the compaction
// sweep; releasing the hold lets the next pass remove it.
func TestLocalSessionHoldStopsEveryPass(t *testing.T) {
	ctx := context.Background()
	dbPath, st := seed(t)
	d := openExisting(t, dbPath)
	// sess-a is the -200d session.
	if created, err := st.HoldSession(ctx, "sess-a", "keep for the audit", fakeNow); err != nil || !created {
		t.Fatalf("HoldSession = %v, %v", created, err)
	}
	old := fakeNow.Add(-150 * day).Format(time.RFC3339Nano)
	if _, err := d.ExecContext(ctx,
		`INSERT INTO compaction_events (session_id, project_id, timestamp, tool, file_state_snapshot)
		 SELECT 'sess-a', project_id, ?, 'claude-code', '{}' FROM sessions WHERE id = 'sess-a'`, old); err != nil {
		t.Fatalf("seed compaction: %v", err)
	}

	for _, opts := range []struct {
		name string
		o    Options
	}{
		{"age", Options{MaxAgeDays: 100, DBPath: dbPath, EventSweep: EventSweepDays{CompactionEventsDays: 100}}},
		{"size cap", Options{MaxDBSizeMB: 1, DBPath: dbPath}},
	} {
		res, err := New(d).Run(ctx, opts.o)
		if err != nil {
			t.Fatalf("%s: Run: %v", opts.name, err)
		}
		// The age pass reaches only the held session; the size-cap shed
		// also reaches the -90d one, which is not held.
		if opts.name == "age" && (res.ActionsDeleted != 0 || res.OrphanedSessionsDeleted != 0 || res.EventRowsDeleted.Total() != 0) {
			t.Fatalf("%s: a held session lost rows: %+v", opts.name, res)
		}
		if held, err := st.IsSessionHeld(ctx, "sess-a"); err != nil || !held {
			t.Fatalf("%s: hold lost: %v %v", opts.name, held, err)
		}
		var sessions int
		if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE id = 'sess-a'`).Scan(&sessions); err != nil || sessions != 1 {
			t.Fatalf("%s: the held session row is gone", opts.name)
		}
		for _, table := range []string{"actions", "compaction_events"} {
			var n int
			if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE session_id = 'sess-a'`).Scan(&n); err != nil || n != 1 { //nolint:gosec // test literal
				t.Fatalf("%s: %s rows of the held session = %d, %v", opts.name, table, n, err)
			}
		}
	}

	if ok, err := st.ReleaseSessionHold(ctx, "sess-a"); err != nil || !ok {
		t.Fatalf("ReleaseSessionHold = %v, %v", ok, err)
	}
	res, err := New(d).Run(ctx, Options{MaxAgeDays: 100, DBPath: dbPath, EventSweep: EventSweepDays{CompactionEventsDays: 100}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ActionsDeleted != 1 || res.EventRowsDeleted.Total() != 1 {
		t.Fatalf("after release: actions %d, events %v", res.ActionsDeleted, res.EventRowsDeleted)
	}
	// The compaction row was the session's last reference; it goes on the
	// pass after the one that removed the row.
	if res, err = New(d).Run(ctx, Options{MaxAgeDays: 100, DBPath: dbPath}); err != nil || res.OrphanedSessionsDeleted != 1 {
		t.Fatalf("orphan after release: %+v, %v", res, err)
	}
}
