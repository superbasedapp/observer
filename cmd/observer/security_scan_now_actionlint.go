//go:build !sbo_omit_security && !sbo_omit_security_scan_actionlint

package main

import (
	"context"
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The workflow lint's "Scan now" row (security.scan.actionlint):
// `observer security actionlint <root>`'s run.
func init() {
	registerScanNowStep(scanNowStep{
		id: "actionlint", label: "GitHub workflows (actionlint)", rank: 10,
		ready: func(_ context.Context, configPath string, database *sql.DB) (bool, string) {
			if database == nil {
				return false, "no database in this process"
			}
			if !actionlintSelected(componentSnapshotFor(configPath)) {
				return false, "not selected (" + actionlintComponent + ")"
			}
			return true, ""
		},
		run: func(ctx context.Context, _ string, database *sql.DB, root string, _ dashapi.SecurityScanOptions) dashapi.SecurityScanResult {
			rep, err := runActionlint(ctx, store.New(database), root, scanNowCheckout(root))
			if err != nil {
				return scanNowFailed(err)
			}
			return dashapi.SecurityScanResult{Outcome: rep.Outcome, Reason: rep.Reason, Findings: rep.Findings, New: rep.New}
		},
	})
}
