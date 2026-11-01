//go:build sbo_omit_security || sbo_omit_security_scan_sarif_import

package main

import (
	"context"
	"database/sql"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
)

// security_sarifimport_omit.go stands in for security_sarifimport.go in a
// build without security.scan.sarif-import: no `observer security
// import-sarif` verb, no dashboard upload and one doctor line.

func securitySARIFImportSubcommands() []*cobra.Command { return nil }

func securitySARIFImportDoctorCheck(context.Context, string) diag.Check {
	return diag.Check{Name: "security.scan.sarif-import", Status: diag.StatusOK, Message: "SARIF import: not in this build"}
}

func sarifImportDash(*sql.DB) *dashapi.SARIFImport { return nil }
