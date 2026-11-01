package main

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// managed_integrity_hooks.go adds hook liveness to the managed-integrity
// report (surface-gap arc Wave 5, finding OBS-7): the tools whose captured
// sessions show their registered hooks never firing, judged by the same
// classifier as the doctor's hooks.liveness check
// (diag.HookSilentTools). Only the closed label hook_silent_surface and a
// located item per tool cross the wire, through the existing report: no new
// wire field, no orgpush.go change. Silent surfaces and session ids stay
// node-local (per-session org reach is decision D14).

// hookSilentSource reports the silent tools at now.
type hookSilentSource func(ctx context.Context, now time.Time) ([]string, error)

// storeHookSilentSource is the production source over the node store.
func storeHookSilentSource(st *store.Store) hookSilentSource {
	if st == nil {
		return nil
	}
	return func(ctx context.Context, now time.Time) ([]string, error) {
		return diag.HookSilentTools(ctx, st, now)
	}
}

// addHookLiveness adds hook_silent_surface, located on each silent tool, to
// report. With no source, or a read that fails, nothing is added: a missing
// observation is never reported as a risk.
func addHookLiveness(ctx context.Context, src hookSilentSource, now time.Time, report *orgcontract.ManagedIntegrityReport) {
	if report == nil || src == nil {
		return
	}
	tools, err := src(ctx, now)
	if err != nil || len(tools) == 0 {
		return
	}
	report.CaptureRisks = appendLabel(report.CaptureRisks, orgcontract.CaptureRiskHookSilentSurface)
	for _, t := range tools {
		report.CaptureRiskItems = append(report.CaptureRiskItems, orgcontract.CaptureRiskItem{Risk: orgcontract.CaptureRiskHookSilentSurface, Tool: t})
	}
}
