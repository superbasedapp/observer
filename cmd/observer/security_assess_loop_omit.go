//go:build sbo_omit_security || sbo_omit_ui_dashboard

package main

import (
	"context"
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// security_assess_loop_omit.go stands in for security_assess_loop.go in a
// build without the security module or without the dashboard (which owns the
// live terminals the loop reconciles against): no loop starts.
func startSecurityAssessRelax(context.Context, *gatedGroup, string, string, *sql.DB, func(string) (dashapi.TerminalSessionLink, bool), func(string)) {
}
