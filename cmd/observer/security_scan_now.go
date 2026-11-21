//go:build !sbo_omit_security

package main

import (
	"context"
	"database/sql"
	"errors"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_scan_now.go is the dashboard seam of the Code security page's
// "Scan now" (dashapi.SecurityScanNow): one row per scanner a manual run
// can start, registered from each scanner's own build-tagged file
// (security_scan_now_code.go, _iac.go, _deps.go, _actionlint.go), so a
// build that omits a scanner has no row for it. A row's run is the same
// function its CLI verb calls with scope manual, recorded through the one
// findings writer; nothing here scans or records on its own.

// scanNowStep is one scanner row.
type scanNowStep struct {
	id    string
	label string
	// rank orders the rows on the page (the cheap checks first).
	rank int
	// ready reports whether the step can run now, else why not.
	ready func(ctx context.Context, configPath string, database *sql.DB) (bool, string)
	// run scans the project at root once, under the job's options (a step
	// with no use for an option ignores it).
	run func(ctx context.Context, configPath string, database *sql.DB, root string, opts dashapi.SecurityScanOptions) dashapi.SecurityScanResult
}

// scanNowSteps are the compiled rows (registered from init only).
var scanNowSteps []scanNowStep

// scanNowExtractors lists the linked dependency extractors for the Code
// security page's Coverage tab (set from init by security_scan_now_
// extractors.go in a build with the dependency scanners; nil otherwise).
var scanNowExtractors func() []dashapi.SecurityExtractor

// scanNowOnline is the online dependency check's state for the scan
// dialog (set from init by security_scan_now_deps.go in a build with the
// dependency scanners; nil otherwise, and the dialog offers no online
// option). managed reports a managed node (nil: not managed).
var scanNowOnline func(ctx context.Context, configPath string, managed func() bool) dashapi.SecurityScanOnline

func registerScanNowStep(s scanNowStep) {
	scanNowSteps = append(scanNowSteps, s)
	sort.SliceStable(scanNowSteps, func(i, j int) bool { return scanNowSteps[i].rank < scanNowSteps[j].rank })
}

// securityScanNowDash returns the seam for the config at configPath.
func securityScanNowDash(configPath string, database *sql.DB) *dashapi.SecurityScanNow {
	seam := &dashapi.SecurityScanNow{
		Steps: func(ctx context.Context) []dashapi.SecurityScanStep {
			out := make([]dashapi.SecurityScanStep, 0, len(scanNowSteps))
			for _, s := range scanNowSteps {
				ok, why := s.ready(ctx, configPath, database)
				out = append(out, dashapi.SecurityScanStep{ID: s.id, Label: s.label, Ready: ok, Reason: why})
			}
			return out
		},
		Scan: func(ctx context.Context, root, id string, opts dashapi.SecurityScanOptions) dashapi.SecurityScanResult {
			for _, s := range scanNowSteps {
				if s.id != id {
					continue
				}
				if ok, why := s.ready(ctx, configPath, database); !ok {
					return dashapi.SecurityScanResult{ID: s.id, Label: s.label, Outcome: dashapi.SecurityScanSkipped, Reason: why}
				}
				res := s.run(ctx, configPath, database, root, opts)
				res.ID, res.Label = s.id, s.label
				securityRT.notify()
				return res
			}
			return dashapi.SecurityScanResult{ID: id, Label: id, Outcome: dashapi.SecurityScanSkipped, Reason: "not in this build"}
		},
		Extractors: scanNowExtractors,
	}
	if scanNowOnline != nil {
		// The managed-node lookup is built once (it caches its own answer).
		var managed func() bool
		if database != nil {
			managed = managedTenancyLookup(store.New(database))
		}
		seam.Online = func(ctx context.Context) dashapi.SecurityScanOnline {
			return scanNowOnline(ctx, configPath, managed)
		}
	}
	return seam
}

// scanNowCheckout is the checkout a manual run reads for root (a linked
// worktree's own tree when the project is one), root itself otherwise, as
// the CLI verbs resolve it.
func scanNowCheckout(root string) string {
	if c, ok := git.FindCheckoutRoot(root); ok && c != "" {
		return c
	}
	return root
}

// scanNowFromRun turns a scan run's coverage into a step result.
func scanNowFromRun(res secscan.Result, created int) dashapi.SecurityScanResult {
	return dashapi.SecurityScanResult{
		Outcome: string(res.Coverage.Outcome), Reason: res.Coverage.Reason, Findings: len(res.Findings), New: created,
	}
}

// scanNowFailed is a step whose run returned an error: busy when another
// scan holds the lease, failed otherwise.
func scanNowFailed(err error, busy ...error) dashapi.SecurityScanResult {
	for _, b := range busy {
		if errors.Is(err, b) {
			return dashapi.SecurityScanResult{Outcome: dashapi.SecurityScanBusy, Reason: err.Error()}
		}
	}
	return dashapi.SecurityScanResult{Outcome: string(secscan.OutcomeFailed), Reason: err.Error()}
}
