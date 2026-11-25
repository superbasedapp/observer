package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// sessionsColumn is one column of the live sessions schema.
type sessionsColumn struct {
	name, typ string
}

// liveSessionsColumns reads the sessions columns from a migrated node
// database, in schema order.
func liveSessionsColumns(t *testing.T, database *sql.DB) []sessionsColumn {
	t.Helper()
	rows, err := database.Query(`SELECT name, type FROM pragma_table_info('sessions') ORDER BY cid`)
	if err != nil {
		t.Fatalf("read sessions columns: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var cols []sessionsColumn
	for rows.Next() {
		var c sessionsColumn
		if err := rows.Scan(&c.name, &c.typ); err != nil {
			t.Fatalf("scan sessions column: %v", err)
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read sessions columns: %v", err)
	}
	if len(cols) < 20 {
		t.Fatalf("sessions has %d columns: the schema did not load", len(cols))
	}
	return cols
}

// distinctSessionValue is a value for column i of the given type that no
// other column shares, so a column copied from the wrong source is caught
// as surely as a dropped one. The few columns another rule reads as a time
// or a foreign key get a value of that shape.
func distinctSessionValue(i int, c sessionsColumn) any {
	switch c.name {
	case "project_id":
		return int64(1)
	case "tool":
		return "openclaw"
	case "started_at":
		return "2026-04-30T00:00:00Z"
	case "ended_at":
		return "2026-04-30T01:00:00Z"
	}
	switch strings.ToUpper(c.typ) {
	case "INTEGER":
		return int64(1000 + i)
	case "REAL":
		return float64(i) + 0.25
	default:
		return "legacy-" + c.name
	}
}

// openclawMergeFixture writes the sessions.json that maps the canonical
// alias onto the legacy raw id, and returns the agents dir to scan.
func openclawMergeFixture(t *testing.T, root, canonical, legacy string) string {
	t.Helper()
	dir := filepath.Join(root, ".openclaw", "agents", "main", "sessions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{%q: {"sessionId": %q, "systemPromptReport": {"sessionKey": %q}}}`, canonical, legacy, canonical)
	if err := os.WriteFile(filepath.Join(dir, "sessions.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, ".openclaw", "agents")
}

func openMergeDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	root := t.TempDir()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(root, "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec(`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/merge', '2026-04-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	return database, root
}

// insertSessionRow inserts one sessions row with the given column values.
func insertSessionRow(t *testing.T, database *sql.DB, id string, cols []sessionsColumn, value func(i int, c sessionsColumn) any) {
	t.Helper()
	names := []string{"id"}
	args := []any{id}
	for i, c := range cols {
		if c.name == "id" {
			continue
		}
		v := value(i, c)
		if v == nil {
			continue
		}
		names = append(names, c.name)
		args = append(args, v)
	}
	q := "INSERT INTO sessions (" + strings.Join(names, ", ") + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?, ", len(names)), ", ") + ")"
	if _, err := database.Exec(q, args...); err != nil {
		t.Fatalf("insert session %s: %v", id, err)
	}
}

// sessionRowValues reads every column of one sessions row as text.
func sessionRowValues(t *testing.T, database *sql.DB, id string, cols []sessionsColumn) map[string]sql.NullString {
	t.Helper()
	exprs := make([]string, len(cols))
	for i, c := range cols {
		exprs[i] = "CAST(" + c.name + " AS TEXT)"
	}
	vals := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := database.QueryRow("SELECT "+strings.Join(exprs, ", ")+" FROM sessions WHERE id = ?", id).Scan(ptrs...); err != nil {
		t.Fatalf("read session %s: %v", id, err)
	}
	out := map[string]sql.NullString{}
	for i, c := range cols {
		out[c.name] = vals[i]
	}
	return out
}

// TestOpenClawSessionMergeCopiesEverySessionsColumn pins CORE-05: the
// openclaw session-id backfill must carry EVERY sessions column of the
// legacy row onto the canonical id. The column list is read from the live
// schema here too, so a column a future migration adds is covered with no
// edit to this test, and a merge that names its columns by hand fails on
// the first one it misses (before the fix it dropped surface, workspace,
// org_id, user_email, the lineage columns and about twenty more).
func TestOpenClawSessionMergeCopiesEverySessionsColumn(t *testing.T) {
	ctx := context.Background()
	database, root := openMergeDB(t)
	cols := liveSessionsColumns(t, database)
	const canonical, legacy = "agent:main:explicit:merge", "merge-raw"

	insertSessionRow(t, database, legacy, cols, distinctSessionValue)
	want := sessionRowValues(t, database, legacy, cols)

	res, err := backfillOpenClawSessionID(ctx, database, []string{openclawMergeFixture(t, root, canonical, legacy)}, 0)
	if err != nil {
		t.Fatalf("backfillOpenClawSessionID: %v", err)
	}
	if res.SessionsDeleted != 1 {
		t.Fatalf("SessionsDeleted = %d, want 1 (the legacy row merged away)", res.SessionsDeleted)
	}
	got := sessionRowValues(t, database, canonical, cols)
	for _, c := range cols {
		if c.name == "id" {
			continue
		}
		if !want[c.name].Valid {
			t.Fatalf("fixture left %s NULL: every column must carry a value", c.name)
		}
		if got[c.name] != want[c.name] {
			t.Errorf("merged session column %s = %v, want the legacy row's %v: the merge dropped it", c.name, got[c.name], want[c.name])
		}
	}
}

// TestOpenClawSessionMergeFillsWithoutOverwriting pins the conflict half: when
// the canonical row already exists, a column the rule table does not name is
// filled from the legacy row only where the canonical row is NULL or empty,
// and a value it already holds is kept.
func TestOpenClawSessionMergeFillsWithoutOverwriting(t *testing.T) {
	ctx := context.Background()
	database, root := openMergeDB(t)
	cols := liveSessionsColumns(t, database)
	const canonical, legacy = "agent:main:explicit:fill", "fill-raw"

	insertSessionRow(t, database, legacy, cols, distinctSessionValue)
	if _, err := database.Exec(`INSERT INTO sessions (id, project_id, tool, started_at, surface, workspace)
		VALUES (?, 1, 'openclaw', '2026-04-30T00:00:00Z', '', 'canonical-workspace')`, canonical); err != nil {
		t.Fatal(err)
	}
	if _, err := backfillOpenClawSessionID(ctx, database, []string{openclawMergeFixture(t, root, canonical, legacy)}, 0); err != nil {
		t.Fatalf("backfillOpenClawSessionID: %v", err)
	}
	got := sessionRowValues(t, database, canonical, cols)
	for col, want := range map[string]string{
		"surface":            "legacy-surface",      // empty on the canonical row: filled
		"user_email":         "legacy-user_email",   // NULL on the canonical row: filled
		"workspace":          "canonical-workspace", // held by the canonical row: kept
		"org_id":             "legacy-org_id",
		"vendor_session_ref": "legacy-vendor_session_ref",
	} {
		if got[col].String != want {
			t.Errorf("canonical %s = %q, want %q", col, got[col].String, want)
		}
	}
}

// TestOpenClawSessionMergeRulesNameLiveColumns keeps the rule table honest:
// every column it names exists in the sessions schema, and the generated
// statement never copies id.
func TestOpenClawSessionMergeRulesNameLiveColumns(t *testing.T) {
	database, _ := openMergeDB(t)
	live := map[string]bool{}
	for _, c := range liveSessionsColumns(t, database) {
		live[c.name] = true
	}
	for col := range openclawSessionMergeRules {
		if !live[col] {
			t.Errorf("openclawSessionMergeRules names %q, which sessions no longer has", col)
		}
	}
	q, err := openclawSessionMergeSQL(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	head, sets, ok := strings.Cut(q, "DO UPDATE SET")
	if !ok {
		t.Fatalf("merge statement has no conflict clause:\n%s", q)
	}
	insertList, _, _ := strings.Cut(strings.TrimPrefix(head, "INSERT INTO sessions (id, "), ")")
	for _, c := range strings.Split(insertList, ", ") {
		if c == "id" {
			t.Errorf("merge statement copies id a second time:\n%s", q)
		}
	}
	for _, set := range strings.Split(sets, ",\n") {
		if col, _, _ := strings.Cut(strings.TrimSpace(set), " "); col == "id" {
			t.Errorf("merge statement updates id:\n%s", q)
		}
	}
}
