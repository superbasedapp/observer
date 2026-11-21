//go:build sbo_omit_security

package main

import (
	"context"
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// security_assess_wire_omit.go stands in for security_assess_wire.go in a
// build without the security module: no guard accessor is wired (the Options
// field stays nil and the module's routes answer component_not_installed). The
// loop's own twin is security_assess_loop_omit.go.

func dashboardRuleRelaxation(string, *sql.DB) func(context.Context, string, []string) map[string]dashapi.RuleRelaxationFact {
	return nil
}
