//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"database/sql"
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
)

// scanNowDepsID is the dependency scanners' step id, the one step that can
// match online.
const scanNowDepsID = "deps"

// The dependency scanners' "Scan now" row (security.scan.scalibr and
// security.scan.osv): `observer security scan <root>`'s run over every
// selected driver, without waiting for a lease another scan holds. Its
// matching is the CLI's own (depsRunMatchers): the SuperBased lookup where
// its gate is open, and, when the job asked for online checks ("Also check
// online", decision P-1 of
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md, which supersedes
// ruling Q9 (a)'s CLI-only --online), api.osv.dev (the org relay on a
// managed node) and the git submodule commits behind the same online gate.
// Where that gate is closed for the project the run stays local and its
// result says why (SecurityScanResult.Online), never "checked online".
func init() {
	registerScanNowStep(scanNowStep{
		id: scanNowDepsID, label: "Dependencies (OSV)", rank: 20,
		ready: func(_ context.Context, configPath string, _ *sql.DB) (bool, string) {
			if !depsScanSelected(componentSnapshotFor(configPath)) {
				return false, "not selected (security.scan.scalibr or security.scan.osv)"
			}
			return true, ""
		},
		run: func(ctx context.Context, configPath string, _ *sql.DB, root string, opts dashapi.SecurityScanOptions) dashapi.SecurityScanResult {
			e, err := openDepsScanEnv(ctx, configPath)
			if err != nil {
				return scanNowFailed(err)
			}
			defer e.cleanup()
			ids, err := depsScanComponents(componentSnapshotForConfig(e.cfg), "")
			if err != nil {
				return dashapi.SecurityScanResult{Outcome: dashapi.SecurityScanSkipped, Reason: err.Error()}
			}
			runner := extrunhost.NewRunner(extrunhost.Options{})
			run := e.depsRunMatchers(root, opts.Online)
			out := dashapi.SecurityScanResult{Outcome: string(secscan.OutcomeClean)}
			var reasons []string
			for _, id := range ids {
				d, err := e.depsDriverAt(id, runner, run.matcher, root, nil)
				if err != nil {
					return scanNowFailed(err)
				}
				res, err := e.scanOne(ctx, d, root, secscan.Target{Scope: policy.FindingScopeManual}, false, nil, depsOnlineAttached(id, run.matcher))
				if err != nil {
					return scanNowFailed(err, errDepsScanBusy)
				}
				out.Findings += len(res.Findings)
				out.Outcome = worseScanOutcome(out.Outcome, string(res.Coverage.Outcome))
				if res.Coverage.Reason != "" {
					reasons = append(reasons, d.Row().ID+": "+res.Coverage.Reason)
				}
			}
			out.Reason = strings.Join(reasons, "; ")
			out.Online = scanNowOnlineNote(opts.Online, run, slices.Contains(ids, depscan.ScalibrComponent))
			return out
		},
	})
	scanNowOnline = scanNowDepsOnline
}

// scanNowOnlineNote is the deps step result's online word (dashapi
// SecurityScanResult.Online): "" when online checks were not asked; else
// the first row that holds, top-down. scalibr reports that the linked
// driver ran (only it matches online, depsOnlineAttached).
func scanNowOnlineNote(asked bool, run depsRunOnline, scalibr bool) string {
	rows := []struct {
		when bool
		word string
	}{
		{!asked, ""},
		{run.blocked != "", run.blocked},
		{!scalibr, dashapi.SecurityScanOnlineNeedsSCALIBR},
		{!run.direct, dashapi.SecurityScanOnlineUnavailable},
		{true, dashapi.SecurityScanOnlineChecked},
	}
	for _, r := range rows {
		if r.when {
			return r.word
		}
	}
	return ""
}

// scanNowDepsOnline is the scan dialog's online option state (dashapi
// SecurityScanNow.Online), read under the organization-wide floor: the
// online gate (depsOnlineGate: online checks on, the disclosure recorded),
// then the linked driver (only SCALIBR matches online). It opens no
// database: the gate reads the config and the signed disclosure record
// only, and managed (the seam's cached lookup) says whether matching goes
// to the org relay.
func scanNowDepsOnline(_ context.Context, configPath string, managed func() bool) dashapi.SecurityScanOnline {
	out := dashapi.SecurityScanOnline{Step: scanNowDepsID}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		out.Reason = "config_unreadable"
		return out
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		out.Reason = "config_unreadable"
		return out
	}
	e := &depsScanEnv{cfg: cfg, dir: secposture.LayoutFor(resolved).Dir}
	e.disclose = readDepsDisclosure(e.dir)
	if managed != nil {
		e.managed = managed()
	}
	snap := componentSnapshotForConfig(cfg)
	scalibr := scalibrfacade.Compiled && securitySelected(snap, depscan.ScalibrComponent) && securitySelected(snap, securityDepsComponent)
	return scanNowOnlineState(e, scalibr)
}

// scanNowOnlineState decides the dialog's online option from the env's
// online gate and whether the linked driver can run here.
func scanNowOnlineState(e *depsScanEnv, scalibr bool) dashapi.SecurityScanOnline {
	out := dashapi.SecurityScanOnline{Step: scanNowDepsID, Relay: e.managed}
	out.Reason = e.onlineBlocked()
	if out.Reason == "" && !scalibr {
		out.Reason = dashapi.SecurityScanOnlineNeedsSCALIBR
	}
	out.Open = out.Reason == ""
	return out
}

// scanOutcomeRank orders run outcomes from best to worst, so several
// drivers' runs fold into the one the page shows.
var scanOutcomeRank = map[string]int{"clean": 0, "findings": 1, "unknown": 2, "not_scanned": 3, "failed": 4}

func worseScanOutcome(a, b string) string {
	if scanOutcomeRank[b] > scanOutcomeRank[a] {
		return b
	}
	return a
}
