//go:build sbo_omit_security || sbo_omit_security_dast

package main

import (
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// securityDASTDash is nil: the DAST checker is not in this build.
func securityDASTDash(string, *sql.DB) *dashapi.SecurityDAST { return nil }
