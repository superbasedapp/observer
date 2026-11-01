//go:build sbo_omit_security || sbo_omit_security_scan_opengrep

package main

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/diag"
)

// security_opengrep_cmd_omit.go stands in for security_opengrep_cmd.go in a
// build without security.scan.opengrep: no `observer security code` verb
// and one doctor line.

func securityCodeSubcommands() []*cobra.Command { return nil }

func securityCodeDoctorCheck(context.Context, string) diag.Check {
	return diag.Check{Name: "security.scan.opengrep", Status: diag.StatusOK, Message: "Code rules (Opengrep): not in this build"}
}
