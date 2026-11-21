//go:build !sbo_omit_security

package main

import (
	"context"
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// The IaC engines' "Scan now" rows (security.scan.trivy, security.scan.kics):
// `observer security iac scan --engine <id>`'s run. An engine its omit tag
// removed from the build reads "not in this build" (iacBindings is read at
// call time, after every engine file's init ran).
func init() {
	for _, row := range []struct {
		id    seciac.EngineID
		label string
		rank  int
	}{
		{seciac.Trivy, "IaC misconfigurations (Trivy)", 40},
		{seciac.KICS, "IaC misconfigurations (KICS)", 41},
	} {
		id := row.id
		registerScanNowStep(scanNowStep{
			id: "iac." + string(id), label: row.label, rank: row.rank,
			ready: func(ctx context.Context, configPath string, database *sql.DB) (bool, string) {
				if _, ok := iacBindings[id]; !ok {
					return false, "not in this build"
				}
				e, err := iacEnvFor(configPath, database, id)
				if err != nil {
					return false, err.Error()
				}
				if e == nil {
					return false, "not selected (" + iacComponent(id) + ")"
				}
				if !iacEngineInstalled(ctx, e) {
					return false, string(id) + " is not installed"
				}
				return true, ""
			},
			run: func(ctx context.Context, configPath string, database *sql.DB, root string, _ dashapi.SecurityScanOptions) dashapi.SecurityScanResult {
				e, err := iacEnvFor(configPath, database, id)
				if err != nil {
					return scanNowFailed(err)
				}
				if e == nil {
					return dashapi.SecurityScanResult{Outcome: dashapi.SecurityScanSkipped, Reason: "not selected"}
				}
				t := secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeManual, CheckoutRoot: scanNowCheckout(root)}
				rep, err := runIaCScan(ctx, e, t)
				if err != nil {
					return scanNowFailed(err, errIaCScanBusy)
				}
				return dashapi.SecurityScanResult{Outcome: rep.Outcome, Reason: rep.Reason, Findings: rep.Findings, New: rep.New}
			},
		})
	}
}
