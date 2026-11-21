//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// The code rules' "Scan now" row (security.scan.opengrep): a full manual
// scan, `observer security code scan <root>`'s run.
func init() {
	registerScanNowStep(scanNowStep{
		id: "code", label: "Code rules (Opengrep)", rank: 30,
		ready: func(ctx context.Context, configPath string, _ *sql.DB) (bool, string) {
			if !codeScanSelected(componentSnapshotFor(configPath)) {
				return false, "not selected (security.scan.opengrep)"
			}
			e, err := openCodeEnv(ctx, configPath)
			if err != nil {
				return false, err.Error()
			}
			defer e.cleanup()
			if !codeEngineInstalled(ctx, e) {
				return false, "Opengrep is not installed"
			}
			return true, ""
		},
		run: func(ctx context.Context, configPath string, _ *sql.DB, root string, _ dashapi.SecurityScanOptions) dashapi.SecurityScanResult {
			e, err := openCodeEnv(ctx, configPath)
			if err != nil {
				return scanNowFailed(err)
			}
			defer e.cleanup()
			res, created, err := runCodeScanCounted(ctx, e, secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeManual})
			if err != nil {
				return scanNowFailed(err, errCodeScanBusy)
			}
			return scanNowFromRun(res, created)
		},
	})
}
