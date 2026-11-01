//go:build sbo_omit_security || sbo_omit_security_deps

package main

import (
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// scannerDBDash has no seam without the security.deps component: the
// dashboard's accept route answers 404.
func scannerDBDash(string, *sql.DB) *dashapi.ScannerDB { return nil }
