//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"database/sql"
	"fmt"
)

// terminal_sandbox_dbcopy_check_linux.go is the one check every host-side
// copy of a guest SQLite store passes before it is kept (the oci-runsc
// projection's db-copy and, since lane LEFT-SBX, the hosted rows' in-box
// database export).

// checkGuestDBCopy opens a host-side copy read-only, with trusted_schema
// off (no schema-defined function or view runs) and query_only on, and
// runs quick_check, so a malformed copy is refused before anything reads
// it.
func checkGuestDBCopy(p string) error {
	db, err := sql.Open("sqlite", "file:"+p+"?mode=ro&_pragma=trusted_schema(0)&_pragma=query_only(1)")
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	var res string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return fmt.Errorf("quick_check: %s", res)
	}
	return nil
}
