//go:build sbo_omit_security

package main

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_cli_omit.go stands in for security_cli.go without the security
// module: `observer security` answers "not in this build" (exit 3) and the
// doctor prints one line.

func newSecurityCmd() *cobra.Command {
	return compiledOutVerb("security", "Code security (not in this build)", "security")
}

func securityDoctorCheck(context.Context, string, *store.Store) diag.Check {
	return diag.Check{Name: "security", Status: diag.StatusOK, Message: "Code security: not in this build"}
}
