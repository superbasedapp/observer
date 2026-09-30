package dashboard

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// sessionsDataQueryShape is handleSessions' page query reduced to what
// decides its plan: the same FROM / JOIN, the always-present non-empty
// predicate, the per-row correlated subqueries, and the ORDER BY the handler
// builds. Only the SELECT list is trimmed.
func sessionsDataQueryShape(order string) string {
	return `SELECT s.id,
	        COALESCE(s.ended_at, (SELECT MAX(a.timestamp) FROM actions a WHERE a.session_id = s.id), '') AS last_seen_at,
	        (SELECT COUNT(*) FROM actions a WHERE a.session_id = s.id) AS total_actions
	   FROM sessions s
	   LEFT JOIN projects p ON p.id = s.project_id
	  WHERE ` + nonEmptySessionPredicateS + `
	  ORDER BY ` + order + ` LIMIT ? OFFSET ?`
}

// TestSessionsDefaultOrderUsesIndex pins the default Sessions sort (perf
// re-measure 2026-09-30): ORDER BY started_at must walk idx_sessions_started
// so the LIMIT stops the scan. The old clause repeated its first term
// ("s.started_at DESC, s.started_at DESC, s.id ASC"), which made SQLite SCAN
// every session and sort in a temp b-tree, evaluating each row's correlated
// action subqueries first. Without sqlite_stat1 the plan does not depend on
// row counts, so an empty database reproduces the node's plan.
func TestSessionsDefaultOrderUsesIndex(t *testing.T) {
	database := openOrderTestDB(t)
	for _, desc := range []bool{true, false} {
		q := sessionsDataQueryShape(sessionsSQLOrderClause("started_at", desc))
		plan := explainPlan(t, database, q, 6, 0)
		if !strings.Contains(plan, "idx_sessions_started") {
			t.Errorf("desc=%v: default sort does not use idx_sessions_started:\n%s", desc, plan)
		}
		if strings.Contains(plan, "TEMP B-TREE FOR ORDER BY") {
			t.Errorf("desc=%v: default sort sorts the whole table:\n%s", desc, plan)
		}
	}
	// The regressed shape, kept as the deny row: it must still be the slow
	// plan, or this test no longer proves anything.
	old := sessionsDataQueryShape("s.started_at DESC, s.started_at DESC, s.id ASC")
	if plan := explainPlan(t, database, old, 6, 0); !strings.Contains(plan, "TEMP B-TREE FOR ORDER BY") {
		t.Fatalf("the regressed clause no longer reproduces the full sort; update the pin:\n%s", plan)
	}
}

// TestSessionsDefaultOrderMatchesOldClause pins that dropping the repeated
// term changes no row order: ties on started_at resolve by id ASC both ways.
func TestSessionsDefaultOrderMatchesOldClause(t *testing.T) {
	database := openOrderTestDB(t)
	ctx := context.Background()
	stamps := []string{
		"2026-09-01T10:00:00Z", "2026-09-02T10:00:00Z", "2026-09-02T10:00:00Z",
		"2026-09-03T10:00:00Z", "2026-09-02T10:00:00Z", "2026-09-01T10:00:00Z",
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/order', '2026-09-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	for i, ts := range stamps {
		id := []string{"f", "b", "d", "a", "c", "e"}[i]
		if _, err := database.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, 1, 'claude-code', ?)`, id, ts); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens) VALUES (?, ?, 'anthropic', 'm', 1, 1)`, id, ts); err != nil {
			t.Fatalf("seed api_turn: %v", err)
		}
	}
	ids := func(order string, limit, offset int) []string {
		rows, err := database.QueryContext(ctx, sessionsDataQueryShape(order), limit, offset)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id string
			var last sql.NullString
			var n int
			if err := rows.Scan(&id, &last, &n); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out = append(out, id)
		}
		return out
	}
	for _, desc := range []bool{true, false} {
		dir := "ASC"
		if desc {
			dir = "DESC"
		}
		oldClause := "s.started_at " + dir + ", s.started_at DESC, s.id ASC"
		for _, page := range [][2]int{{6, 0}, {2, 0}, {2, 2}, {2, 4}} {
			got := strings.Join(ids(sessionsSQLOrderClause("started_at", desc), page[0], page[1]), ",")
			want := strings.Join(ids(oldClause, page[0], page[1]), ",")
			if got != want {
				t.Errorf("desc=%v page=%v: order %q, old clause %q", desc, page, got, want)
			}
		}
	}
}

func openOrderTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "order.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func explainPlan(t *testing.T, database *sql.DB, q string, args ...any) string {
	t.Helper()
	rows, err := database.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+q, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("explain scan: %v", err)
		}
		b.WriteString(detail + "\n")
	}
	return b.String()
}
