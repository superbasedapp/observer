package otlp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

// TestReceiver_PartialTracesIsAPartialSuccess pins review E-29: a trace
// handler that refuses spans for a reason a resend cannot fix is answered,
// on both transports, with success carrying an OTLP partial success (the
// rejected count and why), not a bare 200 that hides the loss. A retry-later
// error still wins over a partial one.
func TestReceiver_PartialTracesIsAPartialSuccess(t *testing.T) {
	var ret error = &PartialTraces{RejectedSpans: 3, Message: "AI Apps is off on this machine"}
	h := func(context.Context, *coltracepb.ExportTraceServiceRequest) error { return ret }
	r, err := New(Options{HTTPAddr: "127.0.0.1:0", GRPCAddr: "127.0.0.1:0", TraceHandler: h})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	body, err := proto.Marshal(sampleTrace("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post("http://"+r.HTTPAddr()+"/v1/traces", "application/x-protobuf", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var out coltracepb.ExportTraceServiceResponse
	if resp.StatusCode != http.StatusOK || proto.Unmarshal(raw, &out) != nil {
		t.Fatalf("HTTP partial = %d %q", resp.StatusCode, raw)
	}
	if ps := out.GetPartialSuccess(); ps.GetRejectedSpans() != 3 || ps.GetErrorMessage() != "AI Apps is off on this machine" {
		t.Fatalf("HTTP partial success = %+v", ps)
	}

	conn, err := grpc.NewClient(r.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	g, err := coltracepb.NewTraceServiceClient(conn).Export(context.Background(), sampleTrace("x"))
	if err != nil || g.GetPartialSuccess().GetRejectedSpans() != 3 {
		t.Fatalf("gRPC partial = %+v %v", g, err)
	}

	ret = fmt.Errorf("busy: %w", ErrRetryLater)
	resp, err = http.Post("http://"+r.HTTPAddr()+"/v1/traces", "application/x-protobuf", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("retry-later = %d, want 503", resp.StatusCode)
	}
}

// TestTraceResponseRules pins review FR-M17: a partial success is answered
// only when the handler's error is made of *PartialTraces alone (one, several
// joined, or wrapped with words). Any other error in the join decides the
// answer, so a Plane B write error joined with a Plane A partial success is
// never hidden behind it.
func TestTraceResponseRules(t *testing.T) {
	a := &PartialTraces{RejectedSpans: 2, Message: "AI Apps is off"}
	b := &PartialTraces{RejectedSpans: 3, Message: "kept from Plane A"}
	write := errors.New("store: disk full")
	var nilPartial *PartialTraces
	cases := []struct {
		name     string
		err      error
		ok       bool
		rejected int64
		message  string
	}{
		{name: "success", err: nil, ok: true},
		{name: "one partial", err: a, ok: true, rejected: 2, message: "AI Apps is off"},
		{name: "a wrapped partial", err: fmt.Errorf("plane a: %w", a), ok: true, rejected: 2, message: "AI Apps is off"},
		{name: "partials joined add up", err: errors.Join(a, b), ok: true, rejected: 5, message: "AI Apps is off; kept from Plane A"},
		{name: "a partial joined with nothing", err: errors.Join(nil, a), ok: true, rejected: 2, message: "AI Apps is off"},
		{name: "a write error joined with a partial is not hidden", err: errors.Join(write, a), ok: false},
		{name: "a partial joined with a write error is not hidden", err: errors.Join(a, write), ok: false},
		{name: "retry later wins over a partial", err: errors.Join(fmt.Errorf("busy: %w", ErrRetryLater), a), ok: false},
		{name: "over capacity wins over a partial", err: errors.Join(ErrOverCapacity, a), ok: false},
		{name: "two wraps with a retry", err: fmt.Errorf("%w: %w", ErrRetryLater, a), ok: false},
		{name: "a plain error", err: write, ok: false},
		{name: "a typed nil partial", err: nilPartial, ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, ok := traceResponse(tc.err)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			ps := resp.GetPartialSuccess()
			if ps.GetRejectedSpans() != tc.rejected || ps.GetErrorMessage() != tc.message {
				t.Fatalf("partial success = %+v, want %d %q", ps, tc.rejected, tc.message)
			}
		})
	}
}
