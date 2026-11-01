//go:build sbo_omit_security

package main

import (
	"context"
	"database/sql"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
)

// security_iac_omit.go stands in for the IaC driver files in a build
// without the security module: no `observer security iac` verb and one
// doctor line.

func securityIaCSubcommands() []*cobra.Command { return nil }

func securityIaCDoctorCheck(context.Context, string) diag.Check {
	return diag.Check{Name: "security.scan.iac", Status: diag.StatusOK, Message: "IaC checks (Trivy, KICS): not in this build"}
}

// iacDash is nil without the security module (the route answers 404).
func iacDash(string, *sql.DB) *dashapi.IaC { return nil }
