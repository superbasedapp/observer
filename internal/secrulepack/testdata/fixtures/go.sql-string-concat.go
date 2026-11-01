package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func search(ctx context.Context, db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: go.sql-string-concat
	_, _ = db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
	// ruleid: go.sql-string-concat
	_, _ = db.ExecContext(ctx, "DELETE FROM users WHERE name = '"+r.FormValue("who")+"'")
	q := "SELECT * FROM orders WHERE region = '" + r.PathValue("region") + "'"
	// ruleid: go.sql-string-concat
	_ = db.QueryRowContext(ctx, q)
	// ok: go.sql-string-concat
	_, _ = db.Query("SELECT * FROM users WHERE name = ?", name)
	id, _ := strconv.Atoi(r.FormValue("id"))
	// ok: go.sql-string-concat
	_, _ = db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
}

// The false-positive shapes of the 1.1.0 rule: identifiers and placeholder
// lists the program builds from its own constants.
const usersTable = "users"

func internal(ctx context.Context, db *sql.DB, cols []string, ids []int64) {
	// ok: go.sql-string-concat
	_, _ = db.Query("SELECT " + strings.Join(cols, ", ") + " FROM " + usersTable)
	marks := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, v := range ids {
		args[i] = v
	}
	// ok: go.sql-string-concat
	_, _ = db.QueryContext(ctx, "SELECT name FROM users WHERE id IN ("+marks+")", args...)
	where := " WHERE deleted = 0"
	// ok: go.sql-string-concat
	_, _ = db.ExecContext(ctx, fmt.Sprintf("UPDATE %s SET seen = 1%s", usersTable, where))
}
