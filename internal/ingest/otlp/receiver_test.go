package otlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// sample builds a minimal export with one record carrying a marker attribute.
func sample(marker string) *collogspb.ExportLogsServiceRequest {
	return &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: []*logspb.LogRecord{{
					EventName: marker,
				}},
			}},
		}},
	}
}

type capture struct {
	mu   sync.Mutex
	reqs []*collogspb.ExportLogsServiceRequest
}

func (c *capture) handler(_ context.Context, req *collogspb.ExportLogsServiceRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reqs = append(c.reqs, req)
	return nil
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reqs)
}

func TestReceiver_HTTPAndGRPCReachHandler(t *testing.T) {
	cap := &capture{}
	r, err := New(Options{
		GRPCAddr: "127.0.0.1:0",
		HTTPAddr: "127.0.0.1:0",
		Handler:  cap.handler,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	// HTTP path.
	raw, _ := proto.Marshal(sample("http-marker"))
	resp, err := http.Post("http://"+r.HTTPAddr()+"/v1/logs", "application/x-protobuf", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("http post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("http status = %d, want 200", resp.StatusCode)
	}

	// gRPC path.
	conn, err := grpc.NewClient(r.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := collogspb.NewLogsServiceClient(conn).Export(context.Background(), sample("grpc-marker")); err != nil {
		t.Fatalf("grpc export: %v", err)
	}

	// Both deliveries should have reached the handler.
	deadline := time.Now().Add(2 * time.Second)
	for cap.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cap.count() != 2 {
		t.Fatalf("handler saw %d exports, want 2", cap.count())
	}
}

// sampleTrace builds a minimal trace export with one named span.
func sampleTrace(name string) *coltracepb.ExportTraceServiceRequest {
	return &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			ScopeSpans: []*tracepb.ScopeSpans{{
				Spans: []*tracepb.Span{{TraceId: []byte{0x01}, SpanId: []byte{0x02}, Name: name}},
			}},
		}},
	}
}

// TestReceiver_TraceHTTPAndGRPCReachHandler confirms the trace receiver serves
// /v1/traces (HTTP) + the gRPC TraceService and routes to the injected
// TraceHandler — the P2 mirror of the logs path.
func TestReceiver_TraceHTTPAndGRPCReachHandler(t *testing.T) {
	var mu sync.Mutex
	var n int
	th := func(_ context.Context, _ *coltracepb.ExportTraceServiceRequest) error {
		mu.Lock()
		n++
		mu.Unlock()
		return nil
	}
	r, err := New(Options{GRPCAddr: "127.0.0.1:0", HTTPAddr: "127.0.0.1:0", TraceHandler: th})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	raw, _ := proto.Marshal(sampleTrace("http-span"))
	resp, err := http.Post("http://"+r.HTTPAddr()+"/v1/traces", "application/x-protobuf", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("http post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("http status = %d, want 200", resp.StatusCode)
	}

	conn, err := grpc.NewClient(r.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := coltracepb.NewTraceServiceClient(conn).Export(context.Background(), sampleTrace("grpc-span")); err != nil {
		t.Fatalf("grpc export: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for func() int { mu.Lock(); defer mu.Unlock(); return n }() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	got := n
	mu.Unlock()
	if got != 2 {
		t.Fatalf("trace handler saw %d exports, want 2", got)
	}
}

func TestReceiver_HTTPRejectsBadProto(t *testing.T) {
	r, err := New(Options{HTTPAddr: "127.0.0.1:0", Handler: func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	resp, err := http.Post("http://"+r.HTTPAddr()+"/v1/logs", "application/x-protobuf", bytes.NewReader([]byte("not-proto")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestNew_RefusesNonLoopback(t *testing.T) {
	_, err := New(Options{
		GRPCAddr: "0.0.0.0:4317",
		Handler:  func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
	})
	if err == nil {
		t.Fatal("expected ErrNonLoopback for 0.0.0.0 bind")
	}
}

func TestNew_AllowNonLoopbackOptIn(t *testing.T) {
	// With the explicit opt-in, a non-loopback bind is permitted (we still bind
	// to a loopback addr here so the test doesn't actually expose a port).
	r, err := New(Options{
		HTTPAddr:         "127.0.0.1:0",
		AllowNonLoopback: true,
		Handler:          func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
	})
	if err != nil {
		t.Fatalf("New with AllowNonLoopback: %v", err)
	}
	_ = r.Shutdown(context.Background())
}

// -----------------------------------------------------------------------------
// Phase 2 — additive metrics signal + outcome accounting (HTTP hook + gRPC
// StatsHandler). All additive; the node path (no MetricHandler / no OnOutcome)
// is byte-unchanged and covered by the tests above.
// -----------------------------------------------------------------------------

// sampleMetric builds a minimal metrics export with one named metric.
func sampleMetric(name string) *colmetricspb.ExportMetricsServiceRequest {
	return &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Metrics: []*metricspb.Metric{{Name: name}},
			}},
		}},
	}
}

// outcomeEvent + outcomeRec record OnOutcome callbacks for assertions.
type outcomeEvent struct {
	signal  string
	outcome Outcome
	reason  string
}

type outcomeRec struct {
	mu     sync.Mutex
	events []outcomeEvent
}

func (o *outcomeRec) hook(signal string, outcome Outcome, reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, outcomeEvent{signal, outcome, reason})
}

func (o *outcomeRec) snapshot() []outcomeEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]outcomeEvent(nil), o.events...)
}

func (o *outcomeRec) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.events)
}

// waitForCount polls until at least n events are recorded (gRPC HandleRPC(End)
// fires server-side around the time the client returns), returning whether it
// reached n.
func (o *outcomeRec) waitForCount(n int) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if o.count() >= n {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// expectExactlyOne pins the exactly-once contract for ONE request: after the
// request, the recorder must have grown from `before` to EXACTLY before+1 (so a
// double-emit is caught) and the single new event must equal want. The settle
// window lets an erroneous second (async) emit land before the count assertion.
func (o *outcomeRec) expectExactlyOne(t *testing.T, name string, before int, want outcomeEvent) {
	t.Helper()
	if !o.waitForCount(before + 1) {
		t.Errorf("%s: no new outcome event recorded (count stayed %d, want %d)", name, o.count(), before+1)
		return
	}
	time.Sleep(100 * time.Millisecond) // settle: a buggy double-emit would land here
	ev := o.snapshot()
	if len(ev) != before+1 {
		t.Errorf("%s: recorder holds %d events after the request, want EXACTLY %d (each request must emit exactly one — no double-count)", name, len(ev), before+1)
		return
	}
	if ev[before] != want {
		t.Errorf("%s: outcome = %+v, want %+v", name, ev[before], want)
	}
}

func TestReceiver_MetricHTTPAndGRPCReachHandler(t *testing.T) {
	var mu sync.Mutex
	var n int
	mh := func(_ context.Context, _ *colmetricspb.ExportMetricsServiceRequest) error {
		mu.Lock()
		n++
		mu.Unlock()
		return nil
	}
	r, err := New(Options{GRPCAddr: "127.0.0.1:0", HTTPAddr: "127.0.0.1:0", MetricHandler: mh})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	raw, _ := proto.Marshal(sampleMetric("http-metric"))
	resp, err := http.Post("http://"+r.HTTPAddr()+"/v1/metrics", "application/x-protobuf", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("http post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("http status = %d, want 200", resp.StatusCode)
	}

	conn, err := grpc.NewClient(r.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := colmetricspb.NewMetricsServiceClient(conn).Export(context.Background(), sampleMetric("grpc-metric")); err != nil {
		t.Fatalf("grpc export: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for func() int { mu.Lock(); defer mu.Unlock(); return n }() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	got := n
	mu.Unlock()
	if got != 2 {
		t.Fatalf("metric handler saw %d exports, want 2", got)
	}
}

// TestReceiver_HTTPDoesNotServeMetricsWithoutHandler pins the HTTP nil-handler
// path SEPARATELY (mutation: register /v1/metrics unconditionally → FAILS).
func TestReceiver_HTTPDoesNotServeMetricsWithoutHandler(t *testing.T) {
	r, err := New(Options{HTTPAddr: "127.0.0.1:0", Handler: func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	raw, _ := proto.Marshal(sampleMetric("x"))
	resp, err := http.Post("http://"+r.HTTPAddr()+"/v1/metrics", "application/x-protobuf", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("http post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no MetricHandler ⇒ /v1/metrics unserved)", resp.StatusCode)
	}
}

// TestReceiver_GRPCDoesNotRegisterMetricsWithoutHandler pins the gRPC nil-handler
// path SEPARATELY (mutation: register MetricsService unconditionally → FAILS).
func TestReceiver_GRPCDoesNotRegisterMetricsWithoutHandler(t *testing.T) {
	r, err := New(Options{GRPCAddr: "127.0.0.1:0", Handler: func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	conn, err := grpc.NewClient(r.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, err = colmetricspb.NewMetricsServiceClient(conn).Export(context.Background(), sampleMetric("x"))
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("metrics export code = %v, want Unimplemented (no MetricHandler ⇒ service unregistered)", status.Code(err))
	}
}

func TestNew_RejectsAllHandlersNil(t *testing.T) {
	_, err := New(Options{HTTPAddr: "127.0.0.1:0"})
	if err == nil {
		t.Fatal("New must reject an Options with all of Handler/TraceHandler/MetricHandler nil")
	}
}

// TestReceiver_HTTPOutcomeHook exercises the HTTP OUTCOME hook at every terminal
// exit: accepted, method, gzip, size, malformed, handler.
func TestReceiver_HTTPOutcomeHook(t *testing.T) {
	rec := &outcomeRec{}
	var failHandler bool
	h := func(context.Context, *collogspb.ExportLogsServiceRequest) error {
		if failHandler {
			return context.Canceled
		}
		return nil
	}
	r, err := New(Options{
		HTTPAddr:  "127.0.0.1:0",
		Handler:   h,
		OnOutcome: rec.hook,
		maxBody:   8, // tiny cap so a small body triggers a size reject
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()
	base := "http://" + r.HTTPAddr() + "/v1/logs"

	// Each closure issues ONE request; expectExactlyOne then asserts the recorder
	// grew by EXACTLY one event with the expected signal/outcome/reason — so a
	// second identical report() on any terminal path is caught by the count.
	cases := []struct {
		name string
		want outcomeEvent
		do   func()
	}{
		{"accepted", outcomeEvent{sigLogs, OutcomeAccepted, ""}, func() {
			// A valid, small body under the 8-byte cap (empty export = 0 bytes).
			resp, err := http.Post(base, "application/x-protobuf", bytes.NewReader(nil))
			if err != nil {
				t.Fatalf("post accepted: %v", err)
			}
			_ = resp.Body.Close()
		}},
		{"method", outcomeEvent{sigLogs, OutcomeRejected, ReasonMethod}, func() {
			greq, _ := http.NewRequest(http.MethodGet, base, nil)
			if gr, err := http.DefaultClient.Do(greq); err == nil {
				_ = gr.Body.Close()
			}
		}},
		{"gzip", outcomeEvent{sigLogs, OutcomeRejected, ReasonGzip}, func() {
			zreq, _ := http.NewRequest(http.MethodPost, base, bytes.NewReader([]byte("not-gzip-bytes")))
			zreq.Header.Set("Content-Encoding", "gzip")
			if zr, err := http.DefaultClient.Do(zreq); err == nil {
				_ = zr.Body.Close()
			}
		}},
		{"size", outcomeEvent{sigLogs, OutcomeRejected, ReasonSize}, func() {
			if sr, err := http.Post(base, "application/x-protobuf", bytes.NewReader(bytes.Repeat([]byte("A"), 64))); err == nil {
				_ = sr.Body.Close()
			}
		}},
		{"malformed", outcomeEvent{sigLogs, OutcomeRejected, ReasonMalformed}, func() {
			if mr, err := http.Post(base, "application/x-protobuf", bytes.NewReader([]byte{0xff})); err == nil {
				_ = mr.Body.Close()
			}
		}},
		{"handler", outcomeEvent{sigLogs, OutcomeRejected, ReasonHandler}, func() {
			failHandler = true
			if hr, err := http.Post(base, "application/x-protobuf", bytes.NewReader(nil)); err == nil {
				_ = hr.Body.Close()
			}
			failHandler = false
		}},
	}
	for _, c := range cases {
		before := rec.count()
		c.do()
		rec.expectExactlyOne(t, "http/"+c.name, before, c.want)
	}
	// Global exactly-once: total events == number of requests issued.
	if got := rec.count(); got != len(cases) {
		t.Errorf("HTTP hook fired %d times total, want EXACTLY %d (one per request)", got, len(cases))
	}
}

// badProtoCodec forces the client to send arbitrary bytes under the "proto"
// content-subtype so the server decodes them with its real proto codec — used to
// provoke a server-side decode failure the generated client could never emit.
type badProtoCodec struct{ payload []byte }

func (c badProtoCodec) Marshal(any) ([]byte, error) { return c.payload, nil }
func (c badProtoCodec) Unmarshal([]byte, any) error { return nil }
func (badProtoCodec) Name() string                  { return "proto" }

// TestReceiver_GRPCOutcomeAccounting exercises the gRPC StatsHandler accounting:
// accepted, handler, decode (pre-service malformed), size (pre-service oversized),
// each counted EXACTLY once in HandleRPC(End) with a reason derived from the
// InPayload decode-marker.
func TestReceiver_GRPCOutcomeAccounting(t *testing.T) {
	rec := &outcomeRec{}
	var failHandler bool
	mh := func(context.Context, *colmetricspb.ExportMetricsServiceRequest) error {
		if failHandler {
			return status.Error(codes.Unknown, "boom")
		}
		return nil
	}
	r, err := New(Options{
		GRPCAddr:         "127.0.0.1:0",
		MetricHandler:    mh,
		OnOutcome:        rec.hook,
		GRPCMaxRecvBytes: 16, // tiny cap so a valid message triggers a size reject
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	conn, err := grpc.NewClient(r.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	client := colmetricspb.NewMetricsServiceClient(conn)

	// Each case issues ONE RPC; expectExactlyOne asserts HandleRPC(End) fired
	// EXACTLY once for it (grew the recorder by one) with the derived reason — so
	// a second onOutcome emit per RPC is caught by the count.
	invalid := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	cases := []struct {
		name string
		want outcomeEvent
		do   func()
	}{
		{"accepted", outcomeEvent{sigMetrics, OutcomeAccepted, ""}, func() {
			// A tiny valid message under the 16-byte cap (empty export).
			if _, err := client.Export(context.Background(), &colmetricspb.ExportMetricsServiceRequest{}); err != nil {
				t.Fatalf("accepted export: %v", err)
			}
		}},
		{"handler", outcomeEvent{sigMetrics, OutcomeRejected, ReasonHandler}, func() {
			// InPayload seen ⇒ reason=handler, NOT decode (reason-stability).
			failHandler = true
			_, _ = client.Export(context.Background(), &colmetricspb.ExportMetricsServiceRequest{})
			failHandler = false
		}},
		{"decode", outcomeEvent{sigMetrics, OutcomeRejected, ReasonDecode}, func() {
			// Invalid protobuf under the proto subtype ⇒ pre-service decode
			// failure ⇒ no InPayload ⇒ reason=decode.
			_, _ = client.Export(context.Background(), &colmetricspb.ExportMetricsServiceRequest{}, grpc.ForceCodec(badProtoCodec{payload: invalid}))
		}},
		{"size", outcomeEvent{sigMetrics, OutcomeRejected, ReasonSize}, func() {
			// A valid message larger than the 16-byte recv cap ⇒ pre-service size
			// reject ⇒ ResourceExhausted, no InPayload ⇒ reason=size.
			_, _ = client.Export(context.Background(), sampleMetric(strings.Repeat("x", 128)))
		}},
	}
	for _, c := range cases {
		before := rec.count()
		c.do()
		rec.expectExactlyOne(t, "grpc/"+c.name, before, c.want)
	}
	// Global exactly-once: one HandleRPC(End) event per RPC, no double-count.
	if got := rec.count(); got != len(cases) {
		t.Errorf("gRPC HandleRPC(End) fired %d times total, want EXACTLY %d (one per RPC)", got, len(cases))
	}
}

// TestReceiver_NilOutcomeHookIsNoOp asserts the node's construction shape (nil
// OnOutcome, no MetricHandler) works: a rejected request neither panics nor
// double-counts, and valid traffic still serves.
func TestReceiver_NilOutcomeHookIsNoOp(t *testing.T) {
	r, err := New(Options{
		GRPCAddr:         "127.0.0.1:0",
		HTTPAddr:         "127.0.0.1:0",
		AllowNonLoopback: false,
		Handler:          func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
		TraceHandler:     func(context.Context, *coltracepb.ExportTraceServiceRequest) error { return nil },
	})
	if err != nil {
		t.Fatalf("New (node shape): %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	// A rejected request (bad proto) must not panic with a nil OnOutcome.
	resp, err := http.Post("http://"+r.HTTPAddr()+"/v1/logs", "application/x-protobuf", bytes.NewReader([]byte("nope")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}

	// Valid traffic still serves.
	raw, _ := proto.Marshal(sample("ok"))
	ok, err := http.Post("http://"+r.HTTPAddr()+"/v1/logs", "application/x-protobuf", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("post ok: %v", err)
	}
	_ = ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("valid status = %d, want 200", ok.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// P0-3 Phase 4 — ErrOverCapacity transport mapping (HTTP 503 / gRPC
// ResourceExhausted). All three signals, both transports, plus a control case
// per transport proving a PLAIN (non-ErrOverCapacity) handler error keeps the
// pre-existing mapping — only ErrOverCapacity gets the new treatment.
// -----------------------------------------------------------------------------

var errBoom = errors.New("boom: plain handler error")

// TestReceiver_HTTPOverCapacityMapsTo503 pins that a handler/traceHandler/
// metricHandler error which unwraps to ErrOverCapacity is translated to HTTP
// 503 (Service Unavailable) on every signal's endpoint, while a plain error
// from the same handler keeps the pre-existing 500 mapping.
func TestReceiver_HTTPOverCapacityMapsTo503(t *testing.T) {
	cases := []struct {
		name string
		path string
		body []byte
		opts func(err error) Options
	}{
		{"logs", "/v1/logs", mustMarshal(t, sample("x")), func(err error) Options {
			return Options{HTTPAddr: "127.0.0.1:0", Handler: func(context.Context, *collogspb.ExportLogsServiceRequest) error { return err }}
		}},
		{"traces", "/v1/traces", mustMarshal(t, sampleTrace("x")), func(err error) Options {
			return Options{HTTPAddr: "127.0.0.1:0", TraceHandler: func(context.Context, *coltracepb.ExportTraceServiceRequest) error { return err }}
		}},
		{"metrics", "/v1/metrics", mustMarshal(t, sampleMetric("x")), func(err error) Options {
			return Options{HTTPAddr: "127.0.0.1:0", MetricHandler: func(context.Context, *colmetricspb.ExportMetricsServiceRequest) error { return err }}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Over-capacity case: the handler's error unwraps to ErrOverCapacity.
			r, err := New(c.opts(fmt.Errorf("edge/pipeline: enqueue: %w", ErrOverCapacity)))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			r.Start()
			resp, err := http.Post("http://"+r.HTTPAddr()+c.path, "application/x-protobuf", bytes.NewReader(c.body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			_ = resp.Body.Close()
			_ = r.Shutdown(context.Background())
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("%s ErrOverCapacity status = %d, want 503", c.name, resp.StatusCode)
			}

			// Control case: a plain error must NOT get the 503 treatment.
			r2, err := New(c.opts(errBoom))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			r2.Start()
			resp2, err := http.Post("http://"+r2.HTTPAddr()+c.path, "application/x-protobuf", bytes.NewReader(c.body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			_ = resp2.Body.Close()
			_ = r2.Shutdown(context.Background())
			if resp2.StatusCode != http.StatusInternalServerError {
				t.Fatalf("%s plain-error status = %d, want 500 (only ErrOverCapacity maps to 503)", c.name, resp2.StatusCode)
			}
		})
	}
}

// mustMarshal marshals an OTLP request for use as an HTTP POST body.
func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// TestReceiver_GRPCOverCapacityMapsToResourceExhausted pins that a handler
// error which unwraps to ErrOverCapacity is translated to gRPC
// codes.ResourceExhausted on every signal's Export RPC, while a plain error
// from the same handler keeps the pre-existing (unwrapped ⇒ codes.Unknown,
// per grpc-go's default status.Convert behaviour for a non-status error)
// mapping — i.e. NOT ResourceExhausted.
func TestReceiver_GRPCOverCapacityMapsToResourceExhausted(t *testing.T) {
	cases := []struct {
		name string
		opts func(err error) Options
		call func(conn *grpc.ClientConn) error
	}{
		{"logs", func(err error) Options {
			return Options{GRPCAddr: "127.0.0.1:0", Handler: func(context.Context, *collogspb.ExportLogsServiceRequest) error { return err }}
		}, func(conn *grpc.ClientConn) error {
			_, err := collogspb.NewLogsServiceClient(conn).Export(context.Background(), sample("x"))
			return err
		}},
		{"traces", func(err error) Options {
			return Options{GRPCAddr: "127.0.0.1:0", TraceHandler: func(context.Context, *coltracepb.ExportTraceServiceRequest) error { return err }}
		}, func(conn *grpc.ClientConn) error {
			_, err := coltracepb.NewTraceServiceClient(conn).Export(context.Background(), sampleTrace("x"))
			return err
		}},
		{"metrics", func(err error) Options {
			return Options{GRPCAddr: "127.0.0.1:0", MetricHandler: func(context.Context, *colmetricspb.ExportMetricsServiceRequest) error { return err }}
		}, func(conn *grpc.ClientConn) error {
			_, err := colmetricspb.NewMetricsServiceClient(conn).Export(context.Background(), sampleMetric("x"))
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Over-capacity case.
			r, err := New(c.opts(fmt.Errorf("edge/pipeline: enqueue: %w", ErrOverCapacity)))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			r.Start()
			conn, err := grpc.NewClient(r.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			rpcErr := c.call(conn)
			_ = conn.Close()
			_ = r.Shutdown(context.Background())
			if status.Code(rpcErr) != codes.ResourceExhausted {
				t.Fatalf("%s ErrOverCapacity code = %v, want ResourceExhausted", c.name, status.Code(rpcErr))
			}

			// Control case: a plain error must NOT get ResourceExhausted.
			r2, err := New(c.opts(errBoom))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			r2.Start()
			conn2, err := grpc.NewClient(r2.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			rpcErr2 := c.call(conn2)
			_ = conn2.Close()
			_ = r2.Shutdown(context.Background())
			// Pin the EXACT real code, not just "not ResourceExhausted": a
			// plain (non-status) handler error surfaces as codes.Unknown via
			// grpc-go's default status.Convert (no interceptor here changes
			// this), so this control is non-vacuous rather than accepting any
			// other code by accident.
			if status.Code(rpcErr2) != codes.Unknown {
				t.Fatalf("%s plain-error code = %v, want Unknown (grpc-go's default status.Convert for a non-status error)", c.name, status.Code(rpcErr2))
			}
		})
	}
}

// -----------------------------------------------------------------------------
// P0-3 Phase 5 — ingress trust/security: guardLoopback empty-host fix,
// edge-only receiver token (HTTP pre-decode gate + two-part gRPC auth),
// decompression-bomb bound. All additive; the node (RequireToken false,
// OnOutcome nil) is byte-unchanged and covered by the tests above.
// edgeSecret is a shared secret with NO "tok" substring (write-filter safe).
// -----------------------------------------------------------------------------

const edgeSecret = "sbo-edge-shared-secret-9f2b34e3"

// TestGuardLoopback_EmptyHostRequiresOptIn pins the §2.6 fix: an empty host
// (":4317" = all-interfaces bind) is NO LONGER auto-loopback-safe — it now
// requires AllowNonLoopback, exactly like "0.0.0.0". "localhost" and explicit
// loopback IPs stay safe without the flag, so the node's explicit
// "127.0.0.1:4317" default is unaffected. Mutation: revert the fix (empty host
// returns nil) → the ":4317 refused without AllowNonLoopback" case FAILS.
func TestGuardLoopback_EmptyHostRequiresOptIn(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		allow   bool
		wantErr bool
	}{
		{"empty-host refused without opt-in", ":4317", false, true},
		{"empty-host allowed with opt-in", ":4317", true, false},
		{"explicit loopback ip passes (node default)", "127.0.0.1:4317", false, false},
		{"localhost passes", "localhost:4318", false, false},
		{"wildcard ip refused without opt-in", "0.0.0.0:4317", false, true},
		{"wildcard ip allowed with opt-in", "0.0.0.0:4317", true, false},
		{"ipv6 loopback passes", "[::1]:4317", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := guardLoopback(c.addr, c.allow)
			if c.wantErr && err == nil {
				t.Fatalf("guardLoopback(%q, %v) = nil, want error", c.addr, c.allow)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("guardLoopback(%q, %v) = %v, want nil", c.addr, c.allow, err)
			}
		})
	}
}

// TestReceiver_HTTPTokenGate pins the HTTP receiver-token gate: a missing/bad
// token is rejected with 401 BEFORE the decoder runs (invalid-proto + no token
// yields 401, NOT the 400 a decode-first path would produce) and the handler is
// never invoked; a correct token reaches the handler with 200. Mutation: run
// the auth check AFTER decode → the "invalid proto + no token ⇒ 401" case gets
// 400 and FAILS.
func TestReceiver_HTTPTokenGate(t *testing.T) {
	cap := &capture{}
	r, err := New(Options{
		HTTPAddr:      "127.0.0.1:0",
		Handler:       cap.handler,
		RequireToken:  true,
		ReceiverToken: edgeSecret,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()
	base := "http://" + r.HTTPAddr() + "/v1/logs"
	validBody := mustMarshal(t, sample("x"))

	do := func(body []byte, tokenVal string, setToken bool) int {
		req, _ := http.NewRequest(http.MethodPost, base, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/x-protobuf")
		if setToken {
			req.Header.Set(HeaderEdgeToken, tokenVal)
		}
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			t.Fatalf("do: %v", derr)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// (1) invalid proto + NO token ⇒ 401, proving the gate precedes decode (a
	// decode-first path would have surfaced 400 malformed).
	if code := do([]byte("not-proto"), "", false); code != http.StatusUnauthorized {
		t.Fatalf("invalid-proto + no token: status = %d, want 401 (gate must precede decode)", code)
	}
	// (2) valid proto + NO token ⇒ 401, handler untouched.
	if code := do(validBody, "", false); code != http.StatusUnauthorized {
		t.Fatalf("valid-proto + no token: status = %d, want 401", code)
	}
	// (3) valid proto + WRONG token ⇒ 401, handler untouched.
	if code := do(validBody, "wrong-secret", true); code != http.StatusUnauthorized {
		t.Fatalf("valid-proto + wrong token: status = %d, want 401", code)
	}
	if cap.count() != 0 {
		t.Fatalf("handler invoked %d times for rejected requests, want 0 (rejected pre-handler)", cap.count())
	}
	// (4) valid proto + CORRECT token ⇒ 200, handler runs.
	if code := do(validBody, edgeSecret, true); code != http.StatusOK {
		t.Fatalf("valid-proto + correct token: status = %d, want 200", code)
	}
	if cap.count() != 1 {
		t.Fatalf("handler invoked %d times after one authorized request, want 1", cap.count())
	}
}

// TestReceiver_HTTPTokenGateOffIsPassThrough pins that with RequireToken unset
// (the node), the HTTP path serves without any token header — the wrapper is a
// pure pass-through.
func TestReceiver_HTTPTokenGateOffIsPassThrough(t *testing.T) {
	cap := &capture{}
	r, err := New(Options{HTTPAddr: "127.0.0.1:0", Handler: cap.handler})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()
	resp, err := http.Post("http://"+r.HTTPAddr()+"/v1/logs", "application/x-protobuf", bytes.NewReader(mustMarshal(t, sample("x"))))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("no-token-required status = %d, want 200", resp.StatusCode)
	}
	if cap.count() != 1 {
		t.Fatalf("handler saw %d, want 1", cap.count())
	}
}

// grpcMetricCounter is a metrics handler recording invocations, standing in for
// "a WAL write happened" — an unauthenticated RPC gated pre-handler must leave
// this at 0.
type grpcMetricCounter struct {
	mu sync.Mutex
	n  int
}

func (g *grpcMetricCounter) handler(context.Context, *colmetricspb.ExportMetricsServiceRequest) error {
	g.mu.Lock()
	g.n++
	g.mu.Unlock()
	return nil
}

func (g *grpcMetricCounter) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n
}

// TestReceiver_GRPCTokenGate pins the two-part gRPC auth (R4-B2): a missing/bad
// metadata token ⇒ codes.Unauthenticated AND the handler is NOT invoked (no WAL
// write); a correct token ⇒ OK and the handler runs. Mutations: (i) stamp
// authed=true for an invalid token in TagRPC (fail-open) → the bad-token case
// stops returning Unauthenticated and FAILS; (ii) drop the interceptor gate →
// the handler runs for an unauthed RPC and the count-0 assertion FAILS.
func TestReceiver_GRPCTokenGate(t *testing.T) {
	g := &grpcMetricCounter{}
	r, err := New(Options{
		GRPCAddr:      "127.0.0.1:0",
		MetricHandler: g.handler,
		RequireToken:  true,
		ReceiverToken: edgeSecret,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	conn, err := grpc.NewClient(r.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	client := colmetricspb.NewMetricsServiceClient(conn)

	// (1) no metadata token ⇒ Unauthenticated, handler untouched.
	_, err = client.Export(context.Background(), sampleMetric("x"))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no-token RPC code = %v, want Unauthenticated", status.Code(err))
	}
	// (2) wrong token ⇒ Unauthenticated, handler untouched.
	badCtx := metadata.AppendToOutgoingContext(context.Background(), metadataEdgeTokenKey, "wrong-secret")
	_, err = client.Export(badCtx, sampleMetric("x"))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong-token RPC code = %v, want Unauthenticated", status.Code(err))
	}
	if g.count() != 0 {
		t.Fatalf("handler invoked %d times for unauthenticated RPCs, want 0 (no WAL write)", g.count())
	}
	// (3) correct token ⇒ OK, handler runs.
	okCtx := metadata.AppendToOutgoingContext(context.Background(), metadataEdgeTokenKey, edgeSecret)
	if _, err := client.Export(okCtx, sampleMetric("x")); err != nil {
		t.Fatalf("correct-token RPC: %v", err)
	}
	if g.count() != 1 {
		t.Fatalf("handler invoked %d times after one authorized RPC, want 1", g.count())
	}
}

// gzipOf returns the gzip encoding of data.
func gzipOf(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// TestReceiver_HTTPGzipDecompressedCap pins the DECOMPRESSED-size bound at its
// EXACT boundary on all three signals: a gzip body that inflates to EXACTLY the
// cap PASSES the size check (proceeds to proto-decode and is accepted 200);
// cap+1 is rejected 413 + ReasonGzip. Mutation: remove the decompressed-size
// bound → the cap+1 case is accepted and FAILS. (The exact-cap case additionally
// pins that the bound is off-by-one correct — `>` not `>=`.)
func TestReceiver_HTTPGzipDecompressedCap(t *testing.T) {
	cases := []struct {
		name string
		path string
		// valid is a real marshaled message; its length sets the exact cap so
		// gzip(valid) decompresses to precisely the cap and decodes cleanly.
		valid []byte
		opts  func(capBytes int, rec *outcomeRec) Options
	}{
		{"logs", "/v1/logs", mustMarshal(t, sample("x")), func(capBytes int, rec *outcomeRec) Options {
			return Options{HTTPAddr: "127.0.0.1:0", MaxDecompressedBytes: capBytes, OnOutcome: rec.hook, Handler: func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil }}
		}},
		{"traces", "/v1/traces", mustMarshal(t, sampleTrace("x")), func(capBytes int, rec *outcomeRec) Options {
			return Options{HTTPAddr: "127.0.0.1:0", MaxDecompressedBytes: capBytes, OnOutcome: rec.hook, TraceHandler: func(context.Context, *coltracepb.ExportTraceServiceRequest) error { return nil }}
		}},
		{"metrics", "/v1/metrics", mustMarshal(t, sampleMetric("x")), func(capBytes int, rec *outcomeRec) Options {
			return Options{HTTPAddr: "127.0.0.1:0", MaxDecompressedBytes: capBytes, OnOutcome: rec.hook, MetricHandler: func(context.Context, *colmetricspb.ExportMetricsServiceRequest) error { return nil }}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			capBytes := len(c.valid)
			if capBytes == 0 {
				t.Fatalf("%s: sample marshaled to 0 bytes — cannot pin the exact-cap boundary", c.name)
			}
			rec := &outcomeRec{}
			r, err := New(c.opts(capBytes, rec))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			r.Start()
			defer func() { _ = r.Shutdown(context.Background()) }()
			base := "http://" + r.HTTPAddr() + c.path

			post := func(gz []byte) int {
				req, _ := http.NewRequest(http.MethodPost, base, bytes.NewReader(gz))
				req.Header.Set("Content-Type", "application/x-protobuf")
				req.Header.Set("Content-Encoding", "gzip")
				resp, derr := http.DefaultClient.Do(req)
				if derr != nil {
					t.Fatalf("do: %v", derr)
				}
				_ = resp.Body.Close()
				return resp.StatusCode
			}

			// Exact cap: decompresses to len==cap ⇒ passes ⇒ 200.
			if code := post(gzipOf(t, c.valid)); code != http.StatusOK {
				t.Fatalf("%s exact-cap (%d bytes) status = %d, want 200 (off-by-one: bound must be `>` not `>=`)", c.name, capBytes, code)
			}
			// cap+1: rejected 413 + ReasonGzip.
			before := rec.count()
			if code := post(gzipOf(t, make([]byte, capBytes+1))); code != http.StatusRequestEntityTooLarge {
				t.Fatalf("%s cap+1 status = %d, want 413", c.name, code)
			}
			if !rec.waitForCount(before + 1) {
				t.Fatalf("%s: no outcome event for the cap+1 reject", c.name)
			}
			ev := rec.snapshot()
			wantSig := map[string]string{"/v1/logs": sigLogs, "/v1/traces": sigTraces, "/v1/metrics": sigMetrics}[c.path]
			if got := ev[len(ev)-1]; got != (outcomeEvent{wantSig, OutcomeRejected, ReasonGzip}) {
				t.Fatalf("%s cap+1 outcome = %+v, want {%s rejected gzip}", c.name, got, wantSig)
			}
		})
	}
}

// countingReader counts the bytes actually pulled from the underlying
// (compressed) stream — used to prove the decompressed cap BOUNDS the read
// rather than inflating the whole stream and length-checking after.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	m, err := c.r.Read(p)
	c.n += m
	return m, err
}

// TestReceiver_HTTPGzipBoundedRead proves the decompressed cap bounds the READ
// (not just a post-hoc length check) on ALL THREE signals: a body that inflates
// to 16 MiB but compresses to ~KiB is driven through the receiver's REAL http
// mux (so the correctly-registered per-signal handler runs) with a byte-counting
// spy body and a tiny (64-byte) decompressed cap; the handler rejects 413 having
// pulled far fewer compressed bytes than the whole stream. Mutation: replace the
// LimitReader with an unbounded io.ReadAll(gz) + length check on ANY of the three
// handlers → that signal's reader is drained fully (n == len(compressed)) and the
// strict `n < len(compressed)` assertion FAILS.
func TestReceiver_HTTPGzipBoundedRead(t *testing.T) {
	compressed := gzipOf(t, make([]byte, 16<<20)) // 16 MiB of zeros ⇒ ~KiB compressed
	if len(compressed) <= 4096 {
		t.Fatalf("compressed stream %d bytes is too small to distinguish a bounded read", len(compressed))
	}
	// One receiver serving all three signals, driven through its real mux so the
	// correctly-registered handler runs per path (a mutation on traces/metrics is
	// caught, not just logs).
	r, err := New(Options{
		HTTPAddr:             "127.0.0.1:0",
		MaxDecompressedBytes: 64,
		Handler:              func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
		TraceHandler:         func(context.Context, *coltracepb.ExportTraceServiceRequest) error { return nil },
		MetricHandler:        func(context.Context, *colmetricspb.ExportMetricsServiceRequest) error { return nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = r.Shutdown(context.Background()) }()

	for _, path := range []string{"/v1/logs", "/v1/traces", "/v1/metrics"} {
		t.Run(path, func(t *testing.T) {
			spy := &countingReader{r: bytes.NewReader(compressed)}
			req := httptest.NewRequest(http.MethodPost, path, spy)
			req.Header.Set("Content-Encoding", "gzip")
			// httptest.NewRequest defaults Host to "example.com", which the
			// NODE-OTLP-1 loopback Host guard now refuses. This test is about
			// the decompressed cap, so give it a Host the guard admits.
			req.Host = "127.0.0.1:4318"
			rw := httptest.NewRecorder()
			r.httpServer.Handler.ServeHTTP(rw, req)
			if rw.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("%s status = %d, want 413", path, rw.Code)
			}
			if spy.n >= len(compressed) {
				t.Fatalf("%s read %d of %d compressed bytes — the whole stream was drained, so the cap did NOT bound the read", path, spy.n, len(compressed))
			}
		})
	}
}

// TestReceiver_HTTPGzipBoundedByDefaultWhenCapUnset is the INVERSION of the old
// TestReceiver_HTTPGzipUnboundedWhenCapUnset, which pinned the very behavior
// NODE-OTLP-1 (codebase audit 2026-09-16) found to be the defect: a receiver
// with NO MaxDecompressedBytes — the NODE shape, the only shape `observer
// start` ever builds — used to io.ReadAll the gunzip stream unbounded, so a
// few-KiB hostile body could inflate without limit and OOM the daemon.
//
// An unset cap now resolves to DefaultMaxDecompressedBytes, so a gzip body that
// inflates past 256 MiB IS 413'd with ReasonGzip on every signal. Mutation:
// restore `cap == 0 ⇒ unbounded` → the body proto-decode-fails with
// ReasonMalformed instead and this FAILS. Driven directly (no listener) to keep
// the inflate off the socket.
func TestReceiver_HTTPGzipBoundedByDefaultWhenCapUnset(t *testing.T) {
	// 300 MiB of zeros — past the 256 MiB default — compresses to a few KiB.
	// ONE payload reused across all three sub-cases.
	compressed := gzipOf(t, make([]byte, 300<<20))

	// A node-shaped receiver serving all three signals with NO
	// MaxDecompressedBytes. Driven per-signal directly (no socket), so a
	// mutation un-bounding decompression in ANY ONE of the three handlers is
	// caught — a logs-only version would let a traces/metrics regression
	// survive.
	newR := func(rec *outcomeRec) *Receiver {
		return &Receiver{opts: Options{
			OnOutcome:     rec.hook,
			Handler:       func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
			TraceHandler:  func(context.Context, *coltracepb.ExportTraceServiceRequest) error { return nil },
			MetricHandler: func(context.Context, *colmetricspb.ExportMetricsServiceRequest) error { return nil },
		}}
	}
	for _, path := range []string{"/v1/logs", "/v1/traces", "/v1/metrics"} {
		t.Run(path, func(t *testing.T) {
			rec := &outcomeRec{}
			r := newR(rec)
			var handle func(http.ResponseWriter, *http.Request)
			switch path {
			case "/v1/logs":
				handle = r.handleHTTPLogs
			case "/v1/traces":
				handle = r.handleHTTPTraces
			case "/v1/metrics":
				handle = r.handleHTTPMetrics
			}
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(compressed))
			req.Header.Set("Content-Encoding", "gzip")
			rw := httptest.NewRecorder()
			handle(rw, req)

			if rw.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("%s: status = %d, want 413 — an unset cap must resolve to DefaultMaxDecompressedBytes, not to unbounded", path, rw.Code)
			}
			ev := rec.snapshot()
			if len(ev) != 1 {
				t.Fatalf("%s: want exactly one outcome event, got %d", path, len(ev))
			}
			if ev[0].reason != ReasonGzip {
				t.Fatalf("%s: reason = %q, want %q — the decompressed bound must be what rejected this", path, ev[0].reason, ReasonGzip)
			}
		})
	}
}

// TestReceiver_MaxDecompressedCapResolution is the cheap table pin for the
// three-way cap resolution the test above exercises end-to-end once: unset ⇒
// the default (NODE-OTLP-1), positive ⇒ that value, negative ⇒ the explicit
// "no bound" escape hatch. One case per branch.
func TestReceiver_MaxDecompressedCapResolution(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  int
		want int64
	}{
		{"unset defaults to the finite bound", 0, DefaultMaxDecompressedBytes},
		{"positive is honored", 64, 64},
		{"negative is the explicit no-bound escape hatch", -1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Receiver{opts: Options{MaxDecompressedBytes: tc.set}}
			if got := r.maxDecompressedCap(); got != tc.want {
				t.Errorf("maxDecompressedCap() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestReceiver_HTTPHostGuard is the NODE-OTLP-1 rebinding pin. A loopback-bound
// receiver is a SAME-MACHINE channel, so a request whose Host header names any
// other host — what a DNS-rebinding page sends — must be refused 403 with
// ReasonHost, before any body read. A loopback Host (with or without a port,
// by name or by IP, or absent entirely) passes through. A receiver the operator
// deliberately opened with AllowNonLoopback keeps serving remote exporters,
// whose Host header is a real name; that deployment's answer is the token gate,
// and `observer doctor` warns when neither is in force.
func TestReceiver_HTTPHostGuard(t *testing.T) {
	for _, tc := range []struct {
		name             string
		allowNonLoopback bool
		host             string
		wantStatus       int
		wantReason       string
	}{
		{"rebinding domain refused", false, "evil.example", http.StatusForbidden, ReasonHost},
		{"rebinding domain with port refused", false, "evil.example:4318", http.StatusForbidden, ReasonHost},
		{"public IP refused", false, "203.0.113.7:4318", http.StatusForbidden, ReasonHost},
		{"loopback IP allowed", false, "127.0.0.1:4318", http.StatusOK, ""},
		{"localhost allowed", false, "localhost:4318", http.StatusOK, ""},
		{"ipv6 loopback allowed", false, "[::1]:4318", http.StatusOK, ""},
		{"non-loopback bind serves any host", true, "collector.internal", http.StatusOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &outcomeRec{}
			r, err := New(Options{
				HTTPAddr:         "127.0.0.1:0",
				AllowNonLoopback: tc.allowNonLoopback,
				OnOutcome:        rec.hook,
				Handler:          func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer func() { _ = r.Shutdown(context.Background()) }()

			body, err := proto.Marshal(&collogspb.ExportLogsServiceRequest{})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			spy := &readCountingBody{data: body}
			req := httptest.NewRequest(http.MethodPost, "/v1/logs", spy)
			req.Host = tc.host
			rw := httptest.NewRecorder()
			r.httpServer.Handler.ServeHTTP(rw, req)

			if rw.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rw.Code, tc.wantStatus)
			}
			ev := rec.snapshot()
			if len(ev) != 1 {
				t.Fatalf("want exactly one outcome event, got %d (%+v)", len(ev), ev)
			}
			if tc.wantReason == "" {
				if ev[0].outcome != OutcomeAccepted {
					t.Fatalf("outcome = %+v, want accepted", ev[0])
				}
				return
			}
			if ev[0].reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", ev[0].reason, tc.wantReason)
			}
			// The guard must run PRE-READ: a rejected request costs no body
			// read, no gunzip, no proto.Unmarshal.
			if spy.reads != 0 {
				t.Fatalf("host guard read the body %d times before rejecting, want 0", spy.reads)
			}
		})
	}
}

// TestReceiver_HTTPHostGuardPrecedesTokenGate pins the order of the two ingress
// checks: a rebinding request that ALSO carries no token reports ReasonHost,
// not ReasonAuth. The host is the cheaper, more specific fact and the one an
// operator needs to see ("a page tried to reach my receiver"), so it is checked
// first and its reason wins.
func TestReceiver_HTTPHostGuardPrecedesTokenGate(t *testing.T) {
	rec := &outcomeRec{}
	r := &Receiver{opts: Options{
		OnOutcome:     rec.hook,
		RequireToken:  true,
		ReceiverToken: edgeSecret,
		Handler:       func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
	}}
	gated := r.withIngressGuards(sigLogs, r.handleHTTPLogs)
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(nil))
	req.Host = "evil.example"
	rw := httptest.NewRecorder()
	gated(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rw.Code)
	}
	ev := rec.snapshot()
	if len(ev) != 1 || ev[0].reason != ReasonHost {
		t.Fatalf("events = %+v, want exactly one %q reject", ev, ReasonHost)
	}
}

// TestReceiver_RequireTokenNilOutcomeNoPanic is the CRITICAL nil-safety
// regression: with RequireToken set but OnOutcome nil (the edge before it wires
// an outcome sink), the StatsHandler is installed for the token stamp — so
// HandleRPC(End) MUST nil-guard every onOutcome call or an unauthenticated RPC
// nil-panics the receiver. Both an unauthenticated and an authenticated RPC (and
// an HTTP reject) must complete without panic.
func TestReceiver_RequireTokenNilOutcomeNoPanic(t *testing.T) {
	g := &grpcMetricCounter{}
	r, err := New(Options{
		GRPCAddr:      "127.0.0.1:0",
		HTTPAddr:      "127.0.0.1:0",
		MetricHandler: g.handler,
		Handler:       func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
		RequireToken:  true,
		ReceiverToken: edgeSecret,
		// OnOutcome deliberately nil.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.Start()
	defer func() { _ = r.Shutdown(context.Background()) }()

	conn, err := grpc.NewClient(r.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	client := colmetricspb.NewMetricsServiceClient(conn)

	// Unauthenticated RPC → Unauthenticated (HandleRPC(End) runs with nil hook).
	if _, err := client.Export(context.Background(), sampleMetric("x")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauth RPC code = %v, want Unauthenticated", status.Code(err))
	}
	// Authenticated RPC → OK.
	okCtx := metadata.AppendToOutgoingContext(context.Background(), metadataEdgeTokenKey, edgeSecret)
	if _, err := client.Export(okCtx, sampleMetric("x")); err != nil {
		t.Fatalf("auth RPC: %v", err)
	}
	// HTTP reject with nil hook must not panic either.
	resp, err := http.Post("http://"+r.HTTPAddr()+"/v1/logs", "application/x-protobuf", bytes.NewReader(mustMarshal(t, sample("x"))))
	if err != nil {
		t.Fatalf("http post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("http no-token status = %d, want 401", resp.StatusCode)
	}
}

// TestNew_RejectsEmptyConfiguredToken pins Finding-1: a receiver configured with
// RequireToken but an EMPTY ReceiverToken must FAIL at construction on BOTH
// transports — otherwise ConstantTimeCompare("","")==1 and a request with a
// missing token authorizes (the gate fails OPEN). Mutation: drop the New guard →
// both empty-token constructions succeed and this FAILS.
func TestNew_RejectsEmptyConfiguredToken(t *testing.T) {
	noopLogs := func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil }
	if _, err := New(Options{RequireToken: true, ReceiverToken: "", HTTPAddr: "127.0.0.1:0", Handler: noopLogs}); err == nil {
		t.Fatal("New must reject RequireToken with an empty ReceiverToken (HTTP transport would fail open)")
	}
	if _, err := New(Options{RequireToken: true, ReceiverToken: "", GRPCAddr: "127.0.0.1:0", Handler: noopLogs}); err == nil {
		t.Fatal("New must reject RequireToken with an empty ReceiverToken (gRPC transport)")
	}
	// A correctly-configured NON-empty token still constructs fine (positive control).
	r, err := New(Options{RequireToken: true, ReceiverToken: edgeSecret, HTTPAddr: "127.0.0.1:0", Handler: noopLogs})
	if err != nil {
		t.Fatalf("New with a non-empty token: %v", err)
	}
	_ = r.Shutdown(context.Background())
}

// readCountingBody counts Read invocations to prove the HTTP token gate rejects
// BEFORE any body read / gunzip.
type readCountingBody struct {
	data  []byte
	off   int
	reads int
}

func (b *readCountingBody) Read(p []byte) (int, error) {
	b.reads++
	if b.off >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.off:])
	b.off += n
	return n, nil
}

func (b *readCountingBody) Close() error { return nil }

// TestReceiver_HTTPTokenGateRejectsBeforeBodyRead proves the gate precedes ANY
// body read or gunzip (stronger than pre-proto-decode): the wrapped handler is
// driven directly with a spy body and Content-Encoding: gzip but NO token; it
// must 401 with ZERO reads. Mutation: move the auth check to run after the body
// is read/decompressed → reads > 0 and this FAILS.
func TestReceiver_HTTPTokenGateRejectsBeforeBodyRead(t *testing.T) {
	r := &Receiver{opts: Options{
		Handler:       func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
		RequireToken:  true,
		ReceiverToken: edgeSecret,
	}}
	gated := r.withIngressGuards(sigLogs, r.handleHTTPLogs)
	body := &readCountingBody{data: gzipOf(t, make([]byte, 4096))}
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", body)
	req.Header.Set("Content-Encoding", "gzip")
	// Loopback Host so the TOKEN gate is what rejects, not the sibling
	// NODE-OTLP-1 host guard (ordering is pinned separately by
	// TestReceiver_HTTPHostGuardPrecedesTokenGate).
	req.Host = "127.0.0.1:4318"
	// No token header set.
	rw := httptest.NewRecorder()
	gated(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rw.Code)
	}
	if body.reads != 0 {
		t.Fatalf("gate read the body %d times before rejecting, want 0 (must reject pre-read)", body.reads)
	}
}

// TestReceiver_HTTPTokenGateRejectsBeforeBodyReadViaMux pins, across ALL THREE
// signal paths and through the receiver's REAL mux (not the bare handler), that
// the receiver-token gate rejects an untokened request with 401 and ZERO body
// reads. This proves BOTH that every endpoint IS wrapped with withIngressGuards (a
// mutation dropping the wrapper on the traces/metrics mux registration is caught)
// AND the pre-read ordering per endpoint. Built with all three handlers +
// RequireToken + a non-empty ReceiverToken.
func TestReceiver_HTTPTokenGateRejectsBeforeBodyReadViaMux(t *testing.T) {
	r, err := New(Options{
		HTTPAddr:      "127.0.0.1:0",
		RequireToken:  true,
		ReceiverToken: edgeSecret,
		Handler:       func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
		TraceHandler:  func(context.Context, *coltracepb.ExportTraceServiceRequest) error { return nil },
		MetricHandler: func(context.Context, *colmetricspb.ExportMetricsServiceRequest) error { return nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = r.Shutdown(context.Background()) }()

	for _, path := range []string{"/v1/logs", "/v1/traces", "/v1/metrics"} {
		t.Run(path, func(t *testing.T) {
			body := &readCountingBody{data: gzipOf(t, make([]byte, 4096))}
			req := httptest.NewRequest(http.MethodPost, path, body)
			req.Header.Set("Content-Encoding", "gzip")
			// Loopback Host so the TOKEN gate is what rejects (see above).
			req.Host = "127.0.0.1:4318"
			// No token header set.
			rw := httptest.NewRecorder()
			r.httpServer.Handler.ServeHTTP(rw, req)
			if rw.Code != http.StatusUnauthorized {
				t.Fatalf("%s status = %d, want 401", path, rw.Code)
			}
			if body.reads != 0 {
				t.Fatalf("%s gate read the body %d times before rejecting, want 0 (must reject pre-read)", path, body.reads)
			}
		})
	}
}

// countingUnaryHandler counts invocations of a gRPC UnaryHandler.
type countingUnaryHandler struct{ n int }

func (c *countingUnaryHandler) handle(context.Context, any) (any, error) {
	c.n++
	return struct{}{}, nil
}

// TestTokenGateInterceptor_Direct pins the two branches of tokenGateInterceptor
// DIRECTLY (the gRPC integration test always runs through the installed
// StatsHandler, so a stamp always exists and the acc==nil branch is never
// exercised there): (a) an UNSTAMPED context (a plain context.Background with no
// rpcAccounting value) ⇒ codes.Unauthenticated and the handler runs 0 times
// (fail-closed); (b) a context stamped authed=true (built the way TagRPC does)
// ⇒ the handler runs exactly once. Mutation: permit an absent stamp (drop the
// acc==nil check) → case (a) invokes the handler and FAILS.
func TestTokenGateInterceptor_Direct(t *testing.T) {
	// (a) missing stamp ⇒ fail-closed.
	unstamped := &countingUnaryHandler{}
	_, err := tokenGateInterceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, unstamped.handle)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing-stamp code = %v, want Unauthenticated", status.Code(err))
	}
	if unstamped.n != 0 {
		t.Fatalf("handler ran %d times for a missing stamp, want 0 (fail-closed)", unstamped.n)
	}
	// (b) authed=true stamp ⇒ handler runs once.
	authed := &countingUnaryHandler{}
	ctx := context.WithValue(context.Background(), rpcAccountingKey{}, &rpcAccounting{authed: true})
	if _, err := tokenGateInterceptor(ctx, nil, &grpc.UnaryServerInfo{}, authed.handle); err != nil {
		t.Fatalf("authed interceptor: %v", err)
	}
	if authed.n != 1 {
		t.Fatalf("handler ran %d times for an authed stamp, want 1", authed.n)
	}
}

// TestTokenAuthorized_EmptyMetadataValue pins that an EXPLICITLY EMPTY metadata
// value for the receiver-token key is NOT authorized (a non-empty want can never
// equal ""), closing the gRPC analog of the empty-token fail-open.
func TestTokenAuthorized_EmptyMetadataValue(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(metadataEdgeTokenKey, ""))
	if tokenAuthorized(ctx, edgeSecret) {
		t.Fatal("tokenAuthorized returned true for an explicitly-empty metadata token value, want false")
	}
}

// TestReceiver_HostGuardModeTriState pins the P2-3 fix: the Host-header guard
// is a TRI-STATE, not a bool derived from the bind, because the edge needs a
// third answer that AUTO cannot express.
//
// The regression this prevents: the edge passes AllowNonLoopback from its own
// config (default FALSE), so a sidecar edge bound 127.0.0.1:4318 is
// loopback-bound — and under AUTO the guard switches ON. An exporter in the
// same pod pointed at a service alias ("otel-collector:4318", an /etc/hosts or
// cluster-DNS name resolving to 127.0.0.1) then sends that alias as its Host
// and is refused 403. HostGuardOff is what the edge sets to keep serving it;
// its ingress trust is the receiver token instead.
//
// One row per (mode × bind) combination, asserted at the predicate so the
// matrix stays readable, then the two that matter re-checked end-to-end below.
func TestReceiver_HostGuardModeTriState(t *testing.T) {
	for _, tc := range []struct {
		name             string
		mode             HostGuardMode
		allowNonLoopback bool
		want             bool
	}{
		{"auto + loopback bind guards (the NODE)", HostGuardAuto, false, true},
		{"auto + opened bind does not guard", HostGuardAuto, true, false},
		{"on + loopback bind guards", HostGuardOn, false, true},
		{"on + opened bind still guards", HostGuardOn, true, true},
		{"off + loopback bind does not guard (the EDGE)", HostGuardOff, false, false},
		{"off + opened bind does not guard", HostGuardOff, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Receiver{opts: Options{HostGuard: tc.mode, AllowNonLoopback: tc.allowNonLoopback}}
			if got := r.hostGuardEnabled(); got != tc.want {
				t.Errorf("hostGuardEnabled() = %v, want %v", got, tc.want)
			}
		})
	}

	// The zero value must be AUTO: a caller that never heard of this field
	// still gets the defense. If HostGuardOff ever became the zero value the
	// node would silently lose the guard.
	var zero Options
	if zero.HostGuard != HostGuardAuto {
		t.Error("the zero HostGuardMode is not HostGuardAuto — an unset option must guard, not skip")
	}
}

// TestReceiver_EdgeShapeServesServiceAliasHost is the end-to-end half of P2-3,
// through the REAL mux: a loopback-bound receiver configured the way the edge
// configures itself (HostGuardOff + RequireToken) must ACCEPT a request whose
// Host is a service alias, while still rejecting one with a bad token. The
// node-shaped receiver in TestReceiver_HTTPHostGuard refuses the same Host —
// that contrast is the point of the tri-state.
func TestReceiver_EdgeShapeServesServiceAliasHost(t *testing.T) {
	body, err := proto.Marshal(&collogspb.ExportLogsServiceRequest{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, tc := range []struct {
		name       string
		token      string
		wantStatus int
		wantReason string
	}{
		{"correct token", edgeSecret, http.StatusOK, ""},
		{"bad token", "nope", http.StatusUnauthorized, ReasonAuth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &outcomeRec{}
			r, err := New(Options{
				HTTPAddr: "127.0.0.1:0", // loopback bind, exactly like a sidecar edge
				// AllowNonLoopback deliberately FALSE — this is the shape that
				// regressed: AUTO would guard and 403 the alias below.
				HostGuard:     HostGuardOff,
				RequireToken:  true,
				ReceiverToken: edgeSecret,
				OnOutcome:     rec.hook,
				Handler:       func(context.Context, *collogspb.ExportLogsServiceRequest) error { return nil },
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer func() { _ = r.Shutdown(context.Background()) }()

			req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
			req.Host = "otel-collector:4318" // /etc/hosts alias for 127.0.0.1
			req.Header.Set(HeaderEdgeToken, tc.token)
			rw := httptest.NewRecorder()
			r.httpServer.Handler.ServeHTTP(rw, req)

			if rw.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d — a loopback-bound EDGE must serve its exporters' service-alias Host", rw.Code, tc.wantStatus)
			}
			ev := rec.snapshot()
			if len(ev) != 1 {
				t.Fatalf("want exactly one outcome event, got %d (%+v)", len(ev), ev)
			}
			if ev[0].reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", ev[0].reason, tc.wantReason)
			}
			if tc.wantReason == "" && ev[0].outcome != OutcomeAccepted {
				t.Fatalf("outcome = %+v, want accepted", ev[0])
			}
			// Whatever happened, it must never be the HOST guard on this shape.
			if ev[0].reason == ReasonHost {
				t.Fatal("the edge shape rejected on ReasonHost — HostGuardOff was not honored")
			}
		})
	}
}
