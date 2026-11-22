package zcode

import (
	"context"
	"database/sql"
)

// malformedRowsQuery counts the message and part rows in this pass's
// window whose data column every loader's json_valid guard skips.
const malformedRowsQuery = `
	SELECT (SELECT COUNT(*) FROM message WHERE time_updated > ? AND NOT json_valid(data))
	     + (SELECT COUNT(*) FROM part WHERE time_updated > ? AND NOT json_valid(data))`

// countMalformedRows returns how many rows the json_valid guards skipped in
// the window after fromOffset (CAPTURE-02). Without those guards one
// malformed data column fails every pass and capture stops for good; the
// count only makes the skip visible, so a query error yields 0 rather than
// failing a pass that already succeeded.
func countMalformedRows(ctx context.Context, db *sql.DB, fromOffset int64) int64 {
	var n int64
	if err := db.QueryRowContext(ctx, malformedRowsQuery, fromOffset, fromOffset).Scan(&n); err != nil {
		return 0
	}
	return n
}
