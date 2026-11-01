//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_opengrep_record.go records one Opengrep run through the one
// findings writer (secsvc.RecordRun) and says what the run proved gone.

// maxGonePaths is the store's cap on one close (store.CloseGoneSecFindings).
const maxGonePaths = 256

// codeScanGone is what a full run proves absent: this driver's open
// findings of the observer-code pack, in files the run read in full, that
// it did not report again (RecordRun keeps what it reported). Only files
// that hold such a finding are named, in chunks the store accepts. A diff
// scope hands no files (opengrep.ScanFiles), so it closes nothing.
func codeScanGone(open []secfinding.Finding, scanned []string) secsvc.Gone {
	read := map[string]bool{}
	for _, f := range scanned {
		read[f] = true
	}
	paths := map[string]bool{}
	for _, f := range open {
		if f.Engine.Driver == opengrep.DriverID && f.Rule.Pack == secrulepack.PackID && read[f.Location.RelPath] {
			paths[f.Location.RelPath] = true
		}
	}
	list := make([]string, 0, len(paths))
	for p := range paths {
		list = append(list, p)
	}
	sort.Strings(list)
	var gone secsvc.Gone
	for len(list) > 0 {
		n := min(len(list), maxGonePaths)
		g := secsvc.Gone{Pack: secrulepack.PackID, Paths: list[:n]}
		if gone.Pack == "" {
			gone = g
		} else {
			gone.Also = append(gone.Also, g)
		}
		list = list[n:]
	}
	return gone
}

// recordCodeScan writes the run's findings and scan-run row and closes
// what a complete full run proved gone.
func recordCodeScan(ctx context.Context, st *store.Store, t secscan.Target, res secscan.Result, scanned opengrep.Scanned, started time.Time, notify func()) (int, error) {
	var gone secsvc.Gone
	if len(scanned.Files) > 0 {
		open, err := st.ListSecFindings(ctx, store.SecFindingFilter{
			ProjectRootHash: secposture.ProjectRootHash(t.ProjectRoot), Status: policy.FindingStatusOpen, Limit: 1000,
		})
		if err == nil {
			gone = codeScanGone(open, scanned.Files)
		}
	}
	if res.Engine.Name == "" {
		res.Engine.Name = opengrep.DriverID
	}
	if !opengrep.EngineRan(res.Coverage) {
		// SEC-POLISH's rule (lane SEC-G2 audit finding 4): a run that never
		// executed is recorded with the one not-run reason, so the last-scan
		// time, the card's last run and the org posture's freshness and
		// outcome counts leave it out (store secScanRanSQL); the schedule
		// still reads its time. The driver's own reason stays, as the one
		// skipped part.
		res.Coverage.Skipped = append([]secscan.Skip{{Path: ".", Reason: res.Coverage.Reason}}, res.Coverage.Skipped...)
		res.Coverage.Reason = store.SecRunReasonNotRun
	}
	return secsvc.RecordRun(ctx, st, t, res, started, time.Since(started), gone, notify)
}
