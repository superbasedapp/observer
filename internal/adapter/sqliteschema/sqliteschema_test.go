package sqliteschema

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// countProbe is the other spelling six adapters used before TableExists
// was shared (COUNT(*) > 0 over the same filter). The test checks the two
// agree on every case, which is what made merging them behaviour-preserving.
func countProbe(ctx context.Context, db *sql.DB, name string) bool {
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

func TestTableExists(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range []string{
		`CREATE TABLE messages (id TEXT)`,
		`CREATE VIEW recent AS SELECT id FROM messages`,
		`CREATE INDEX messages_id ON messages(id)`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		want bool
	}{
		{"messages", true},
		{"Messages", false},
		{"recent", false},
		{"messages_id", false},
		{"missing", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := TableExists(ctx, db, tc.name); got != tc.want {
			t.Errorf("TableExists(%q) = %v, want %v", tc.name, got, tc.want)
		}
		if got := countProbe(ctx, db, tc.name); got != tc.want {
			t.Errorf("count probe (%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if TableExists(cancelled, db, "messages") || countProbe(cancelled, db, "messages") {
		t.Error("a failed query must report false")
	}
}
