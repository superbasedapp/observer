package db

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

// TestRetentionParentsHaveIndexedChildren (2026-10-18): retention deletes
// rows from these parents with foreign_keys ON, which makes SQLite look up
// children in every referencing table per deleted row. An unindexed child
// column is a full scan of that table per row; guard_events.action_id with no
// index made a month's prune run for hours under the write lock and stalled
// ingestion. Every child column of a retention parent must lead an index.
func TestRetentionParentsHaveIndexedChildren(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "fk.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	parents := map[string]bool{"actions": true, "sessions": true}

	tables, err := stringsOf(ctx, database, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		rows, err := database.QueryContext(ctx, fmt.Sprintf(`SELECT "table", "from" FROM pragma_foreign_key_list(%q)`, table))
		if err != nil {
			continue // virtual tables have no FK list
		}
		type fk struct{ parent, col string }
		var fks []fk
		for rows.Next() {
			var f fk
			if err := rows.Scan(&f.parent, &f.col); err == nil && parents[f.parent] {
				fks = append(fks, f)
			}
		}
		_ = rows.Close()
		for _, f := range fks {
			leads, err := stringsOf(ctx, database, fmt.Sprintf(
				`SELECT ii.name FROM pragma_index_list(%q) il JOIN pragma_index_info(il.name) ii WHERE ii.seqno = 0`, table))
			if err != nil {
				t.Fatal(err)
			}
			indexed := false
			for _, c := range leads {
				if c == f.col {
					indexed = true
				}
			}
			if !indexed {
				t.Errorf("%s.%s references %s but leads no index: every %s delete would scan %s", table, f.col, f.parent, f.parent, table)
			}
		}
	}
}

// stringsOf runs q and returns its single text column as a slice.
func stringsOf(ctx context.Context, d *sql.DB, q string) ([]string, error) {
	rows, err := d.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
