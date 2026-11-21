package otlp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func oneSpanExport() *coltracepb.ExportTraceServiceRequest {
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
			TraceId: bytes.Repeat([]byte{1}, 16), SpanId: bytes.Repeat([]byte{2}, 8), Name: "s",
		}}}},
	}}}
}

func TestTraceSwitchOffRejectsWithReasonThenForwards(t *testing.T) {
	sw := NewTraceSwitch("AI Apps is off here")
	err := sw.Handle(context.Background(), oneSpanExport())
	var pt *PartialTraces
	if !errors.As(err, &pt) || pt.RejectedSpans != 1 || pt.Message != "AI Apps is off here" {
		t.Fatalf("off: %v", err)
	}
	if sw.Handle(context.Background(), &coltracepb.ExportTraceServiceRequest{}) != nil {
		t.Fatal("an empty export was rejected")
	}
	var got atomic.Int64
	sw.Set(func(_ context.Context, req *coltracepb.ExportTraceServiceRequest) error {
		got.Add(int64(len(req.GetResourceSpans())))
		return nil
	})
	if !sw.On() {
		t.Fatal("On after Set")
	}
	if err := sw.Handle(context.Background(), oneSpanExport()); err != nil || got.Load() != 1 {
		t.Fatalf("on: %v %d", err, got.Load())
	}
	sw.Set(nil)
	if sw.On() {
		t.Fatal("On after Set(nil)")
	}
}

// TestTraceSwitchInALiveReceiver: a receiver built over the switch keeps
// its listener; installing the target turns a partial rejection into an
// accepted export with no rebind.
func TestTraceSwitchInALiveReceiver(t *testing.T) {
	sw := NewTraceSwitch("off")
	recv, err := New(Options{GRPCAddr: "127.0.0.1:0", HTTPAddr: "127.0.0.1:0", TraceHandler: sw.Handle})
	if err != nil {
		t.Fatal(err)
	}
	recv.Start()
	defer func() { _ = recv.Shutdown(context.Background()) }()
	post := func() *coltracepb.ExportTraceServiceResponse {
		t.Helper()
		body, _ := proto.Marshal(oneSpanExport())
		resp, err := http.Post("http://"+recv.HTTPAddr()+"/v1/traces", "application/x-protobuf", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		var out coltracepb.ExportTraceServiceResponse
		if err := proto.Unmarshal(buf.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return &out
	}
	if ps := post().GetPartialSuccess(); ps.GetRejectedSpans() != 1 {
		t.Fatalf("off: partial %+v", ps)
	}
	var n atomic.Int64
	sw.Set(func(context.Context, *coltracepb.ExportTraceServiceRequest) error { n.Add(1); return nil })
	if ps := post().GetPartialSuccess(); ps.GetRejectedSpans() != 0 || n.Load() != 1 {
		t.Fatalf("on: partial %+v n=%d", ps, n.Load())
	}
}
