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
// committing promptly. The single-transaction prune held the write lock for
// its whole duration; batches release it every retentionBatchSize rows.
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
	const aged = 15000
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

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- New(d).deleteActionsOlder(ctx, fakeNow.Add(-150*24*time.Hour).Format(time.RFC3339Nano), nil, &Result{})
	}()
	var worst time.Duration
	writes := 0
	for pruning := true; pruning; {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("prune: %v", err)
			}
			pruning = false
		default:
			t0 := time.Now()
			if _, err := d.ExecContext(ctx, `INSERT INTO zz_writer (n) VALUES (?)`, writes); err != nil {
				t.Fatalf("writer during prune: %v", err)
			}
			if w := time.Since(t0); w > worst {
				worst = w
			}
			writes++
			time.Sleep(5 * time.Millisecond)
		}
	}
	total := time.Since(start)
	t.Logf("prune of %d actions took %v; %d concurrent writes, worst wait %v", aged, total, writes, worst)
	if writes < 3 {
		t.Fatalf("only %d writes completed during the prune; the writer was starved", writes)
	}
	if worst > total/2 && total > 200*time.Millisecond {
		t.Errorf("a writer waited %v of a %v prune; batches should release the lock", worst, total)
	}
}
