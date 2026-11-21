package main

import (
	"context"
	"sync"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// guardExport is one trace export with one resource per claim-table
// outcome the guard sees, keyed by service.name.
func guardExport() *coltracepb.ExportTraceServiceRequest {
	kv := func(k, v string) *commonpb.KeyValue {
		return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
	}
	res := func(spanAttrs []*commonpb.KeyValue, attrs ...*commonpb.KeyValue) *tracepb.ResourceSpans {
		return &tracepb.ResourceSpans{
			Resource:   &resourcepb.Resource{Attributes: attrs},
			ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{Name: "chat m", Attributes: spanAttrs}}}},
		}
	}
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{
		res(nil, kv("service.name", "own"), kv("sbo.agent", "bot")),
		res(nil, kv("service.name", "hosted"), kv("sbo.agent", "bot"), kv("sbo.tenant", "acme")),
		res([]*commonpb.KeyValue{kv("enduser.id", "u1")}, kv("service.name", "hosted-span"), kv("sbo.agent", "bot")),
		res(nil, kv("service.name", "plain")),
		res(nil, kv("service.name", "malformed"), kv("sbo.agent", "")),
		res(nil, kv("service.name", "echo"), kv("sbo.agent", "bot"), kv("sbo.emitted_by", "observer")),
	}}
}

// TestGuardPlaneA (PT-55 scope 2) runs in every build, obs-on, no_obs and
// without the vendor ingest: a resource the own-agent claim table keeps from
// Plane A (an own agent, a malformed agent name) never reaches the Plane A
// handler; a hosted app (even one naming an agent, on the resource or on a
// span), a plain app and Observer's echo pass unchanged.
func TestGuardPlaneA(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	planeA := func(_ context.Context, req *coltracepb.ExportTraceServiceRequest) error {
		mu.Lock()
		defer mu.Unlock()
		for _, rs := range req.GetResourceSpans() {
			for _, kv := range rs.GetResource().GetAttributes() {
				if kv.GetKey() == "service.name" {
					seen = append(seen, kv.GetValue().GetStringValue())
				}
			}
		}
		return nil
	}
	if guardPlaneA(nil, nil) != nil {
		t.Fatal("no Plane A handler must stay nil")
	}
	h := guardPlaneA(planeA, nil)
	if err := h(context.Background(), guardExport()); err != nil {
		t.Fatal(err)
	}
	want := []string{"hosted", "hosted-span", "plain", "echo"}
	if len(seen) != len(want) {
		t.Fatalf("Plane A saw %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("Plane A saw %v, want %v", seen, want)
		}
	}
	// An export of only own-agent resources reaches Plane A not at all.
	seen = nil
	only := &coltracepb.ExportTraceServiceRequest{ResourceSpans: guardExport().GetResourceSpans()[:1]}
	if err := h(context.Background(), only); err != nil || len(seen) != 0 {
		t.Fatalf("own-agent-only export reached Plane A: %v (err %v)", seen, err)
	}
	// An export with nothing to hold is passed through as the same value.
	plain := &coltracepb.ExportTraceServiceRequest{ResourceSpans: guardExport().GetResourceSpans()[3:4]}
	if keep, held := withoutOwnAgentResources(plain); keep != plain || held != 0 {
		t.Fatalf("plain export rewritten: held %d", held)
	}
}
