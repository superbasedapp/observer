//go:build !sbo_omit_ingest_otlp

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
)

// appSpanExport is one hosted app's export: a resource no coding-tool row
// claims, with n spans.
func appSpanExport(n int) *coltracepb.ExportTraceServiceRequest {
	spans := make([]*tracepb.Span, n)
	for i := range spans {
		spans[i] = &tracepb.Span{TraceId: bytes.Repeat([]byte{7}, 16), SpanId: []byte{1, 2, 3, 4, 5, 6, 7, byte(i + 1)}, Name: "chat"}
	}
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
			Key: "service.name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "support-chatbot"}},
		}}},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: spans}},
	}}}
}

// TestAppSpansWithAIAppsOffAreAPartialSuccess pins review E-29: with
// [ingest.otel] on and AI Apps off, an app's spans are answered as an OTLP
// partial success naming the rejected count and why, and the daemon log
// says so once, instead of a plain success that hides the loss.
func TestAppSpansWithAIAppsOffAreAPartialSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	cfg := config.Default()
	cfg.Ingest.OTel.Enabled = true
	cfg.Observability.Enabled = false
	_, traces := wireVendorOTLPIngest(ctx, cfg, database, logger, nil)
	for i := 0; i < 2; i++ {
		err := traces(ctx, appSpanExport(3))
		var p *otlpingest.PartialTraces
		if !errors.As(err, &p) || p.RejectedSpans != 3 || !strings.Contains(p.Message, "enabled = false") && !strings.Contains(p.Message, "does not include AI Apps") {
			t.Fatalf("export %d: %v", i, err)
		}
	}
	if n := strings.Count(logs.String(), "app spans were not kept"); n != 1 {
		t.Fatalf("warned %d times, want once:\n%s", n, logs.String())
	}
}

// TestPlaneAOffReasonTable: one reason per row, and none while AI Apps is
// wired.
func TestPlaneAOffReasonTable(t *testing.T) {
	on, off := config.Default(), config.Default()
	on.Observability.Enabled, off.Observability.Enabled = true, false
	wired := otlpingest.TraceHandler(func(context.Context, *coltracepb.ExportTraceServiceRequest) error { return nil })
	if r := planeAOffReason(on, wired); r != "" {
		t.Fatalf("wired: %q", r)
	}
	if !appObsCompiledIn() {
		for _, c := range []config.Config{on, off} {
			if r := planeAOffReason(c, nil); !strings.Contains(r, "does not include AI Apps") {
				t.Fatalf("not built: %q", r)
			}
		}
		return
	}
	if r := planeAOffReason(off, nil); !strings.Contains(r, "enabled = false") {
		t.Fatalf("off: %q", r)
	}
	if r := planeAOffReason(on, nil); !strings.Contains(r, "could not start") {
		t.Fatalf("failed to start: %q", r)
	}
}
