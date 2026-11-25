package sqliteschema

import (
	"context"
	"database/sql"
)

// TableExists reports whether db has a table with exactly this name. Any
// query error (an unreadable or non-SQLite file, a cancelled ctx) reports
// false: callers treat an unreadable catalogue as "absent".
//
// The match is exact: sqlite_master.name compares with the BINARY
// collation, so a differently cased name is a different table, and a view
// or index with the name does not count.
func TableExists(ctx context.Context, db *sql.DB, name string) bool {
	var got string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&got)
	return err == nil && got == name
}
