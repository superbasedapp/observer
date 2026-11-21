//go:build sbo_omit_security

package main

import (
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// securityScanNowDash is nil: security is not in this build.
func securityScanNowDash(string, *sql.DB) *dashapi.SecurityScanNow { return nil }
