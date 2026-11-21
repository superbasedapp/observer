package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
)

const approvalsUniqueFile = "218_guard_approvals_unique.sql"

// TestMigration218GuardApprovalsUnique grades the P-232 cleanup (the release
// line's 213, renumbered to 218 at the main merge, P-247): a database
// holding duplicate grants (the operator's two S-794 global rows among
// them) upgrades to one row per (rule_id, scope, session_id,
// project_root_hash) key, the lowest id surviving with the group's latest
// expiry (an empty expires_at = never, later than any expiry), rows with a distinct key
// untouched, and the unique index then refusing a new duplicate.
func TestMigration218GuardApprovalsUnique(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "observer.db")
	database, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(30000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer database.Close()
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, lineageWithout(t, approvalsUniqueFile), lateSteps); err != nil {
		t.Fatalf("migrate to 217: %v", err)
	}
	type seed struct {
		id                                  int64
		rule, scope, session, hash, expires string
	}
	// RFC3339Nano spellings with trimmed fractions on purpose: as text
	// "05Z" sorts after "05.5Z", so only a time comparison picks right.
	seeds := []seed{
		// The operator's duplicate: two never-expiring S-794 global rows.
		{9, "S-794", "global", "", "", ""},
		{10, "S-794", "global", "", "", ""},
		// Three session duplicates with expiries: the latest wins on id 11.
		{11, "S-793", "session", "sA", "", "2026-11-03T05:48:17Z"},
		{12, "S-793", "session", "sA", "", "2026-11-04T05:48:17.5Z"},
		{13, "S-793", "session", "sA", "", "2026-11-04T05:48:17Z"},
		// A ttl row and a never row: never wins on the lower ttl id.
		{14, "R-110", "project", "", "abc", "2026-11-04T00:00:00Z"},
		{15, "R-110", "project", "", "abc", ""},
		// Same rule, other anchors: distinct keys, untouched.
		{16, "S-793", "session", "sB", "", "2026-11-05T00:00:00Z"},
		{17, "S-793", "project", "", "abc", ""},
		{18, "S-793", "global", "", "", "2026-11-06T00:00:00Z"},
	}
	for _, s := range seeds {
		if _, err := database.ExecContext(ctx, `INSERT INTO guard_approvals (id, ts, rule_id, scope, session_id, project_root_hash, granted_by, expires_at)
			VALUES (?, '2026-11-03T00:00:00Z', ?, ?, ?, ?, 'dashboard', ?)`, s.id, s.rule, s.scope, s.session, s.hash, s.expires); err != nil {
			t.Fatalf("seed %d: %v", s.id, err)
		}
	}
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, migrations.Files, lateSteps); err != nil {
		t.Fatalf("migrate through 218: %v", err)
	}
	want := map[int64]string{
		9:  "",
		11: "2026-11-04T05:48:17.5Z",
		14: "",
		16: "2026-11-05T00:00:00Z",
		17: "",
		18: "2026-11-06T00:00:00Z",
	}
	rows, err := database.QueryContext(ctx, `SELECT id, expires_at FROM guard_approvals ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64]string{}
	for rows.Next() {
		var id int64
		var exp string
		if err := rows.Scan(&id, &exp); err != nil {
			t.Fatal(err)
		}
		got[id] = exp
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("survivors = %v, want %v", got, want)
	}
	for id, exp := range want {
		if g, ok := got[id]; !ok || g != exp {
			t.Errorf("id %d expires_at = %q (present %v), want %q", id, g, ok, exp)
		}
	}
	if !indexExists(t, database, "idx_guard_approvals_key") {
		t.Fatal("idx_guard_approvals_key missing after 218")
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO guard_approvals (ts, rule_id, scope, session_id, project_root_hash, granted_by, expires_at)
		VALUES ('2026-11-03T00:00:00Z', 'S-794', 'global', '', '', 'dashboard', '')`); err == nil {
		t.Fatal("a duplicate S-794 global grant was accepted after 218")
	}
}
