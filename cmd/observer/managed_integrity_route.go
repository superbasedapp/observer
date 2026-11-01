package main

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/routeattest"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// managed_integrity_route.go adds the per-surface route observation to the
// managed-integrity report (surface-gap arc Wave 1, finding OBS-6): the
// routable surfaces this node ran sessions on, inside
// routeattest.ObservedWindow, that never reached its proxy. It reads the same
// store query and judge as the doctor's route.observed check
// (diag.ObservedSurfaceVerdicts), so the organization and the developer see
// one verdict. Only closed "tool/surface_kind" labels cross the wire.

// routeObservationSource is the slice of the node store the step reads.
type routeObservationSource interface {
	RouteObservedSince(ctx context.Context, since time.Time) ([]store.RouteObservedRow, error)
}

// relayBypassReader reads the fail-open Windows route relay's bypass journal
// for the records at or after since (diag.RelayBypassSince in production).
type relayBypassReader func(since time.Time) diag.RelayJournal

// addRouteObservation fills report.RouteObservationVersion and
// report.UnroutedSurfaces. With no store, or a query that fails, the version
// stays 0: the organization reads "not reported", never "clean". A nil
// policy judges against the integration registry.
//
// A bypassed surface with no wire label (the registry pin test
// routeattest.TestRouteSurfaceToolsAreWireLabels keeps that from happening)
// is not dropped silently: when it is the only one, the observation is not
// reported at all, so it can never read as clean.
//
// The relay's bypass journal (finding CC-9, decision D12) is read the same
// way: a request the relay forwarded straight to the provider inside the
// window is an observed bypass. The journal names the tool but not the
// surface (a Windows CLI, VS Code and JetBrains session all read one
// settings route), so it has no closed label and counts as unlabelled: with
// no labelled bypass beside it the observation is not reported, never clean.
// An unreadable journal counts the same way. A nil relay reads nothing.
func addRouteObservation(ctx context.Context, src routeObservationSource, relay relayBypassReader, now time.Time, policy routeattest.SurfacePolicy, report *orgcontract.ManagedIntegrityReport) {
	if report == nil || src == nil {
		return
	}
	rows, err := src.RouteObservedSince(ctx, now.Add(-routeattest.ObservedWindow))
	if err != nil {
		return
	}
	var labels []string
	unlabelled := false
	for _, v := range diag.ObservedSurfaceVerdicts(rows, policy) {
		if !v.ObservedBypass() {
			continue
		}
		// An unstamped group of a single-surface tool is judged as the
		// surface its registry row names (SurfaceFacts.UnstampedAs, Wave 3),
		// so its label names that surface too.
		kind := v.Kind
		if kind == "" {
			kind = v.Facts.UnstampedAs
		}
		label, ok := orgcontract.UnroutedSurfaceLabel(v.Tool, kind)
		if !ok {
			unlabelled = true
			continue
		}
		labels = appendLabel(labels, label)
	}
	if relay != nil {
		if j := relay(now.Add(-routeattest.ObservedWindow)); j.Summary.Total() > 0 || len(j.Unreadable) > 0 {
			unlabelled = true
		}
	}
	if unlabelled && len(labels) == 0 {
		return
	}
	report.RouteObservationVersion = orgcontract.ManagedRouteObservationVersion
	report.UnroutedSurfaces = labels
	if len(labels) > 0 {
		report.CaptureRisks = appendLabel(report.CaptureRisks, orgcontract.CaptureRiskRouteBypassObserved)
	}
}
