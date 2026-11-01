//go:build sbo_omit_security || sbo_omit_security_scan_actionlint

package main

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/diag"
)

// security_actionlint_omit.go stands in for security_actionlint.go in a
// build without security.scan.actionlint (the minimal and developer
// distros): no `observer security actionlint` verb and one doctor line.

func securityActionlintSubcommands() []*cobra.Command { return nil }

func securityActionlintDoctorCheck(context.Context, string) diag.Check {
	return diag.Check{Name: "security.scan.actionlint", Status: diag.StatusOK, Message: "actionlint: not in this build"}
}
