package opencode

import (
	"context"
	"database/sql"
)

// storeSchema records which OpenCode storage generations one opencode.db
// carries. Both can be present at once: OpenCode 2.x upgrades a 1.x
// database in place, copying every 1.x session into session_v2 and its
// messages into session_message while leaving the 1.x tables behind.
//
//   - v1: the original `session` + `message` + `part` tables (OpenCode
//     1.x, and the forks that track it).
//   - v2: `session_v2` + `session_message` (OpenCode 2.x; a fresh 2.x
//     install has NO `session`, `message` or `part` table). Grounded
//     2026-10-20 against upstream migration 20260804233008_loose_psylocke
//     and schema.gen.ts at tag v2.1.1, and against a live
//     `@opencode-ai/cli` 0.0.0-beta-19271 database created in a scratch
//     home (the 2.0 preview CLI; its update check reports 2.0.1 as the
//     current release).
type storeSchema struct {
	v1 bool
	v2 bool
}

// known reports whether at least one storage generation is present.
func (s storeSchema) known() bool { return s.v1 || s.v2 }

// schemaRequirements is the table set each generation needs, walked by
// detectSchema. One row per generation.
var schemaRequirements = []struct {
	set    func(*storeSchema)
	tables []string
}{
	{func(s *storeSchema) { s.v1 = true }, []string{"session", "message", "part"}},
	{func(s *storeSchema) { s.v2 = true }, []string{"session_v2", "session_message"}},
}

// detectSchema resolves the storage generations from the set of table
// names a database carries.
func detectSchema(tables map[string]bool) storeSchema {
	var s storeSchema
	for _, req := range schemaRequirements {
		ok := true
		for _, t := range req.tables {
			if !tables[t] {
				ok = false
				break
			}
		}
		if ok {
			req.set(&s)
		}
	}
	return s
}

// listTables returns the names of every table in the database.
func listTables(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

// watermarkQueries is the per-table watermark read, one row per table
// whose time_updated (epoch milliseconds, one clock across both
// generations) can advance when OpenCode writes. A row only runs when
// its table exists, so neither generation's absence is an error.
var watermarkQueries = []struct {
	table string
	query string
}{
	{"message", `SELECT COALESCE(MAX(time_updated), 0) FROM message`},
	{"part", `SELECT COALESCE(MAX(time_updated), 0) FROM part`},
	{"session", `SELECT COALESCE(MAX(time_updated), 0) FROM session`},
	{"session_message", `SELECT COALESCE(MAX(time_updated), 0) FROM session_message`},
	{"session_v2", `SELECT COALESCE(MAX(time_updated), 0) FROM session_v2`},
}

// maxWatermark returns the newest time_updated across the present
// tables of watermarkQueries.
func maxWatermark(ctx context.Context, db *sql.DB, tables map[string]bool) (int64, error) {
	var latest int64
	for _, w := range watermarkQueries {
		if !tables[w.table] {
			continue
		}
		var v int64
		if err := db.QueryRowContext(ctx, w.query).Scan(&v); err != nil {
			return 0, err
		}
		if v > latest {
			latest = v
		}
	}
	return latest, nil
}

// noSchemaDetail is the once-per-file warning for a database with no
// known OpenCode tables (a store still bootstrapping, or a foreign file
// that happens to be named opencode.db).
const noSchemaDetail = "no OpenCode session tables yet (neither session/message/part nor session_v2/session_message); skipping until they appear"
