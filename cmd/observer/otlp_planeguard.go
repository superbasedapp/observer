package main

import (
	"context"
	"log/slog"
	"sync"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/ownagent"
)

// otlp_planeguard.go keeps a developer's own agent's spans out of Plane A
// (PT-55, docs/own-agents.md "Send OpenTelemetry spans"). It wraps the Plane
// A trace handler in EVERY build and configuration, independent of
// [ingest.otel] and of the ingest.otlp component: with the vendor ingest on,
// the claim split in otlp_ingest.go already took the own-agent resources and
// this is a no-op backstop; with it off or compiled out, the own-agent
// resources it removes are dropped (logged once), never written to obs_*.
// It decides with the same claim table (internal/ownagent) the vendor ingest
// uses, minus the coding-tool row it cannot know here, which only matters
// for a resource Plane B owns anyway.

// guardPlaneA returns planeA wrapped so a resource the own-agent claim
// table keeps from Plane A never reaches it. nil stays nil (no Plane A in
// this build or configuration).
func guardPlaneA(planeA otlpingest.TraceHandler, logger *slog.Logger) otlpingest.TraceHandler {
	if planeA == nil {
		return nil
	}
	var once sync.Once
	return func(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) error {
		keep, held := withoutOwnAgentResources(req)
		if held > 0 && logger != nil {
			once.Do(func() {
				logger.Warn("otlp receiver: spans naming an own agent (sbo.agent) are never sent to AI Apps; they land on the node only with [ingest.otel] enabled and the custom-agent adapter on",
					"resources", held)
			})
		}
		if keep == nil {
			return nil
		}
		return planeA(ctx, keep)
	}
}

// withoutOwnAgentResources returns req minus every resource the claim table
// keeps from Plane A, and how many it removed. keep is nil when nothing is
// left, and req itself when nothing was removed.
func withoutOwnAgentResources(req *coltracepb.ExportTraceServiceRequest) (keep *coltracepb.ExportTraceServiceRequest, held int) {
	rss := req.GetResourceSpans()
	var kept []*tracepb.ResourceSpans
	for _, rs := range rss {
		var records [][]*commonpb.KeyValue
		for _, ss := range rs.GetScopeSpans() {
			for _, sp := range ss.GetSpans() {
				records = append(records, sp.GetAttributes())
			}
		}
		if ownagent.ClaimOTLPResource(ownagent.ReadOTLPResource(rs.GetResource().GetAttributes(), records)).Plane.KeptFromPlaneA() {
			held++
			continue
		}
		kept = append(kept, rs)
	}
	switch {
	case held == 0:
		return req, 0
	case len(kept) == 0:
		return nil, held
	}
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: kept}, held
}
