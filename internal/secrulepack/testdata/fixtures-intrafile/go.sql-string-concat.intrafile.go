package store

import (
	"database/sql"
	"net/http"
	"strconv"
)

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that builds the statement.
func findUser(db *sql.DB, name string) (*sql.Rows, error) {
	// ruleid: go.sql-string-concat
	return db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

func lookup(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	_, _ = findUser(db, r.FormValue("name"))
}

func requestedName(r *http.Request) string {
	return r.URL.Query().Get("name")
}

func lookupReturned(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// ruleid: go.sql-string-concat
	_, _ = db.Query("SELECT * FROM users WHERE name = '" + requestedName(r) + "'")
}

// The sanitizer sits in the helper: the id is parsed to an integer before
// the caller builds the statement.
func asID(value string) int {
	n, _ := strconv.Atoi(value)
	return n
}

func lookupByID(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	// ok: go.sql-string-concat
	_, _ = db.Query("SELECT * FROM users WHERE id = " + strconv.Itoa(asID(r.FormValue("id"))))
}
