package retention

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestDeleteActionsOlderCrossesBatches (2026-10-18): a prune larger than one
// batch removes every aged action and its dependents across several short
// transactions, and leaves younger actions alone.
func TestDeleteActionsOlderCrossesBatches(t *testing.T) {
	dbPath, _ := seed(t)
	d := openExisting(t, dbPath)
	ctx := context.Background()
	var sessionID string
	var projectID int64
	if err := d.QueryRowContext(ctx, `SELECT session_id, project_id FROM actions ORDER BY timestamp LIMIT 1`).Scan(&sessionID, &projectID); err != nil {
		t.Fatal(err)
	}
	old := fakeNow.Add(-300 * 24 * time.Hour)
	const extra = retentionBatchSize*2 + 500
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < extra; i++ {
		ts := old.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		r, err := tx.ExecContext(ctx, `INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target)
			VALUES (?, ?, ?, 'run_command', 'claude-code', 0, ?)`, sessionID, projectID, ts, fmt.Sprintf("cmd %d", i))
		if err != nil {
			t.Fatal(err)
		}
		id, _ := r.LastInsertId()
		if i%10 == 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO failure_context (action_id, session_id, project_id, timestamp, command_hash, command_summary, error_category)
				VALUES (?, ?, ?, ?, 'h', 's', 'exit')`, id, sessionID, projectID, ts); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var before int
	_ = d.QueryRowContext(ctx, `SELECT count(*) FROM actions`).Scan(&before)

	res := &Result{}
	cutoff := fakeNow.Add(-150 * 24 * time.Hour).Format(time.RFC3339Nano)
	if err := New(d).deleteActionsOlder(ctx, cutoff, nil, res); err != nil {
		t.Fatalf("deleteActionsOlder: %v", err)
	}
	// The extra rows plus the seeded -200d action are aged; -90d and -10d stay.
	if res.ActionsDeleted != extra+1 {
		t.Errorf("actions deleted = %d; want %d", res.ActionsDeleted, extra+1)
	}
	var after, agedLeft, fcLeft int
	_ = d.QueryRowContext(ctx, `SELECT count(*) FROM actions`).Scan(&after)
	_ = d.QueryRowContext(ctx, `SELECT count(*) FROM actions WHERE timestamp < ?`, cutoff).Scan(&agedLeft)
	_ = d.QueryRowContext(ctx, `SELECT count(*) FROM failure_context WHERE timestamp < ?`, cutoff).Scan(&fcLeft)
	if agedLeft != 0 || fcLeft != 0 || after != before-(extra+1) {
		t.Errorf("after prune: aged actions %d, aged failure_context %d, total %d (before %d)", agedLeft, fcLeft, after, before)
	}
}

// TestPruneDoesNotStallWriters reproduces the 2026-10-18 live stall: while a
// large prune runs, an unrelated writer (the watcher's role) must keep
// committing. The single-transaction prune held the write lock for its whole
// duration; batches release it between every retentionBatchSize rows, and
// the pause between them outlasts SQLite's busy-handler poll, so a waiting
// writer commits at the next batch boundary.
//
// The bound is in batches, not time: each write counts how many batches the
// prune committed while it waited (the aged-row count read just before and
// just after it), so a slow, loaded host that stretches every batch does not
// change the answer (2026-11-17: the old bound, a fraction of the whole
// prune's time, failed on a loaded Docker sandbox). A write may see the
// batch it waited on plus one committed on either side of its two reads, so
// three is the most an honest boundary-wait shows; the single-transaction
// prune shows every batch, and the old 20 ms pause showed 4, 5 and 14 under
// load.
func TestPruneDoesNotStallWriters(t *testing.T) {
	if testing.Short() {
		t.Skip("contention test")
	}
	dbPath, _ := seed(t)
	d := openExisting(t, dbPath)
	ctx := context.Background()
	var sessionID string
	var projectID int64
	if err := d.QueryRowContext(ctx, `SELECT session_id, project_id FROM actions ORDER BY timestamp LIMIT 1`).Scan(&sessionID, &projectID); err != nil {
		t.Fatal(err)
	}
	old := fakeNow.Add(-300 * 24 * time.Hour)
	const aged = 15 * retentionBatchSize
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < aged; i++ {
		ts := old.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target)
			VALUES (?, ?, ?, 'run_command', 'claude-code', 1, 'x')`, sessionID, projectID, ts); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS zz_writer (n INTEGER)`); err != nil {
		t.Fatal(err)
	}
	cutoff := fakeNow.Add(-150 * 24 * time.Hour).Format(time.RFC3339Nano)
	// left reads the aged rows still committed (a WAL read: it never waits
	// on the prune's write lock).
	left := func() int {
		var n int
		if err := d.QueryRowContext(ctx, `SELECT count(*) FROM actions WHERE timestamp < ?`, cutoff).Scan(&n); err != nil {
			t.Fatalf("count aged actions: %v", err)
		}
		return n
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- New(d).deleteActionsOlder(ctx, cutoff, nil, &Result{})
	}()
	const maxSpan = 3
	var worst time.Duration
	worstSpan, writes, midPrune := 0, 0, 0
	for pruning := true; pruning; {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("prune: %v", err)
			}
			pruning = false
		default:
			before := left()
			t0 := time.Now()
			if _, err := d.ExecContext(ctx, `INSERT INTO zz_writer (n) VALUES (?)`, writes); err != nil {
				t.Fatalf("writer during prune: %v", err)
			}
			wait := time.Since(t0)
			after := left()
			writes++
			if after > 0 && after < aged {
				midPrune++
			}
			span := (before - after + retentionBatchSize - 1) / retentionBatchSize
			if span > worstSpan {
				worstSpan = span
			}
			if wait > worst {
				worst = wait
			}
			if span > maxSpan {
				t.Errorf("a write waited %v while the prune committed %d batches (%d aged rows left before it, %d after): batches should let a waiting writer in at the next boundary", wait, span, before, after)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	t.Logf("prune of %d actions (%d batches) took %v; %d writes, %d of them mid-prune; worst wait %v, most batches a write waited across %d",
		aged, aged/retentionBatchSize, time.Since(start), writes, midPrune, worst, worstSpan)
	// A write landed while some but not all of the aged rows were gone: the
	// prune committed part of its work and let a writer in before finishing,
	// which a single transaction never does.
	if midPrune == 0 {
		t.Fatalf("no write committed while the prune was part way (%d writes in all); the writer was starved", writes)
	}
}
