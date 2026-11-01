package retention

import (
	"context"
	"strings"
	"testing"
)

// TestDeleteBatchExcerptsSeeksByRowid pins T-415 for the batched delete
// (2026-10-18): the FTS5 excerpt table must be reached by rowid (idxStr "=")
// through the migration-147 c0 index on the content table, never by a scan of
// every excerpt.
func TestDeleteBatchExcerptsSeeksByRowid(t *testing.T) {
	dbPath, _ := seed(t)
	d := openExisting(t, dbPath)
	rows, err := d.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+deleteBatchExcerptsSQLPrefix+"?,?))", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan, "\n")
	sawVTab, sawC0 := false, false
	for _, line := range plan {
		if strings.Contains(line, "action_excerpts VIRTUAL TABLE") {
			sawVTab = true
			if !strings.Contains(line, "INDEX 0:=") {
				t.Errorf("excerpt table not reached by rowid: %q\nplan:\n%s", line, joined)
			}
		}
		if strings.Contains(line, "action_excerpts_content") {
			sawC0 = true
			if !strings.Contains(line, "c0=?") {
				t.Errorf("content table not seeked by c0: %q\nplan:\n%s", line, joined)
			}
		}
	}
	if !sawVTab || !sawC0 {
		t.Errorf("plan missing the batch seek path (vtab=%v c0=%v):\n%s", sawVTab, sawC0, joined)
	}
}

// TestRun_AgePruningRemovesLegacyDuplicateExcerpts pins that the reshaped
// delete still removes every excerpt row of an aged action, including a
// legacy duplicate at an arbitrary rowid, and leaves younger actions' rows.
func TestRun_AgePruningRemovesLegacyDuplicateExcerpts(t *testing.T) {
	dbPath, _ := seed(t)
	d := openExisting(t, dbPath)
	ctx := context.Background()
	var oldest int64
	if err := d.QueryRowContext(ctx, `SELECT id FROM actions ORDER BY timestamp LIMIT 1`).Scan(&oldest); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO action_excerpts (rowid, action_id, tool_name, target, excerpt, error_message)
		 VALUES (987654, ?, 'Bash', 'dup', 'legacy duplicate body', '')`, oldest); err != nil {
		t.Fatal(err)
	}
	res, err := New(d).Run(ctx, Options{MaxAgeDays: 100, DBPath: dbPath})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExcerptsDeleted != 2 {
		t.Errorf("excerpts deleted = %d, want 2 (the aged row and its legacy duplicate)", res.ExcerptsDeleted)
	}
	var left, total int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM action_excerpts_content WHERE c0 = ?`, oldest).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("aged action still has %d excerpt rows", left)
	}
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM action_excerpts`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Errorf("remaining excerpts = %d, want 2 (the two younger actions)", total)
	}
}
