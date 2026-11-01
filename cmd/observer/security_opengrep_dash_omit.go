//go:build sbo_omit_security || sbo_omit_security_scan_opengrep

package main

import (
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// opengrepDash is nil in a build without the code rules: the card's route
// answers 404.
func opengrepDash(string, *sql.DB) *dashapi.Opengrep { return nil }
