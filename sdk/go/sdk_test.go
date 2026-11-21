package superbased

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func attrsOf(s tracetest.SpanStub) map[string]any {
	out := map[string]any{}
	for _, kv := range s.Attributes {
		out[string(kv.Key)] = kv.Value.AsInterface()
	}
	return out
}

func TestContentRules(t *testing.T) {
	setup(t)
	mem := memInit(t, Options{MaxContentChars: Int(5), Mask: func(v any, key string) (any, error) {
		switch key {
		case keyOutputValue:
			return nil, nil // dropped
		case keySystemInstructions:
			return nil, errors.New("boom") // fail safe: dropped, counted
		}
		return v, nil
	}})
	_ = WithLLMSpan(context.Background(), "chat", LLMOptions{Prompt: "hello world", System: "sys"}, func(_ context.Context, sp trace.Span) error {
		SetOutput(sp, "answer")
		return nil
	})
	a := lastSpanAttrs(t, mem)
	if a[keyInputValue] != "hello"+truncatedMark {
		t.Fatalf("input %q", a[keyInputValue])
	}
	if _, ok := a[keyOutputValue]; ok {
		t.Fatal("mask returning nil must drop the attribute")
	}
	if _, ok := a[keySystemInstructions]; ok {
		t.Fatal("a mask error must drop the attribute")
	}
	if GetDiagnostics().MaskErrors != 1 {
		t.Fatalf("mask errors %d", GetDiagnostics().MaskErrors)
	}

	setup(t)
	mem = memInit(t, Options{CaptureContent: Bool(false)})
	_ = WithLLMSpan(context.Background(), "chat", LLMOptions{Model: "m", Prompt: "secret"}, func(_ context.Context, sp trace.Span) error {
		sp.SetAttributes(attribute.String("llm.input_messages.0.message.content", "secret"), attribute.String("llm.input_messages.0.message.role", "user"))
		return nil
	})
	a = lastSpanAttrs(t, mem)
	if _, ok := a["llm.input_messages.0.message.content"]; ok || a["llm.input_messages.0.message.role"] != "user" || a[keyRequestModel] != "m" {
		t.Fatalf("capture off: %v", a)
	}
}

func TestShouldExportHook(t *testing.T) {
	setup(t)
	mem := memInit(t, Options{ShouldExport: func(s sdktrace.ReadOnlySpan) bool {
		if s.Name() == "boom" {
			panic("x")
		}
		return s.Name() != "drop"
	}})
	for _, n := range []string{"keep", "drop", "boom"} {
		_, sp := StartSpan(context.Background(), n, SpanOptions{})
		sp.End()
	}
	Flush(context.Background())
	var names []string
	for _, s := range mem.GetSpans() {
		names = append(names, s.Name)
	}
	d := GetDiagnostics()
	if strings.Join(names, ",") != "keep,boom" || d.FilteredSpans != 1 || d.ShouldExportErrors != 1 {
		t.Fatalf("%v %+v", names, d)
	}
}

func TestWithSpanStatusAndObserve(t *testing.T) {
	setup(t)
	mem := memInit(t, Options{})
	err := WithSpan(context.Background(), "fails", SpanOptions{Kind: KindTool}, func(context.Context, trace.Span) error { return errors.New("bad") })
	if err == nil {
		t.Fatal("WithSpan must return fn's error")
	}
	n, _ := Observe(context.Background(), "obs", KindChain, func(context.Context) (int, error) { return 7, nil })
	func() {
		defer func() { _ = recover() }()
		_ = WithSpan(context.Background(), "panics", SpanOptions{}, func(context.Context, trace.Span) error { panic("p") })
	}()
	Flush(context.Background())
	got := map[string]codes.Code{}
	for _, s := range mem.GetSpans() {
		got[s.Name] = s.Status.Code
	}
	if n != 7 || got["fails"] != codes.Error || got["obs"] != codes.Ok || got["panics"] != codes.Error {
		t.Fatalf("%d %v", n, got)
	}
}

func TestSetUsageNegativeWritesNothing(t *testing.T) {
	setup(t)
	mem := memInit(t, Options{})
	_ = WithLLMSpan(context.Background(), "chat", LLMOptions{}, func(_ context.Context, sp trace.Span) error {
		if err := SetUsage(sp, Usage{InputTokens: Int(5), OutputTokens: Int(-1)}); !errors.Is(err, ErrNegativeCount) {
			t.Fatalf("%v", err)
		}
		return nil
	})
	if _, ok := lastSpanAttrs(t, mem)[keyInputTokens]; ok {
		t.Fatal("nothing may be written when a count is negative")
	}
}

func TestIdentityAndScope(t *testing.T) {
	setup(t)
	mem := memInit(t, Options{User: "svc", Tags: []string{"init"}})
	ctx := PropagateAttributes(context.Background(), Attributes{User: "alice", Tags: []string{"b", "a"}, Metadata: map[string]any{"n": 1, "o": map[string]any{"z": 1, "a": 2}}})
	ctx = PropagateAttributes(ctx, Attributes{Tags: []string{"c"}, Metadata: map[string]any{"n": nil}, Clear: []string{"user"}})
	if got := CurrentAttributes(ctx); got["user"] != nil || strings.Join(got["tags"].([]string), ",") != "a,b,c" {
		t.Fatalf("%v", got)
	}
	_, sp := StartSpan(ctx, "x", SpanOptions{})
	sp.End()
	a := lastSpanAttrs(t, mem)
	if _, ok := a["sbo.metadata.n"]; ok || a["sbo.metadata.o"] != `{"a":2,"z":1}` {
		t.Fatalf("%v", a)
	}
	if strings.Join(a[keyTags].([]string), ",") != "a,b,c" {
		t.Fatalf("tags %v", a[keyTags])
	}
}

func TestAttachToHostProvider(t *testing.T) {
	setup(t)
	host := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(host)
	mem := memInit(t, Options{User: "svc", Release: "r9"})
	if GetDiagnostics().Mode != "attached" {
		t.Fatalf("mode %s", GetDiagnostics().Mode)
	}
	_, sp := host.Tracer("app").Start(context.Background(), "host span")
	sp.End()
	a := lastSpanAttrs(t, mem)
	if a[keyUser] != "svc" || a[keyResourceRelease] != "r9" || a[keySDK] != sdkMarker {
		t.Fatalf("identity not stamped in attach mode: %v", a)
	}
	// Re-init with the same settings adds no second processor.
	memInit(t, Options{User: "svc", Release: "r9", Exporter: mem})
	_, sp = host.Tracer("app").Start(context.Background(), "again")
	sp.End()
	Flush(context.Background())
	count := 0
	for _, s := range mem.GetSpans() {
		if s.Name == "again" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("a re-init exported a span %d times", count)
	}
}

func TestSamplingOwned(t *testing.T) {
	setup(t)
	mem := memInit(t, Options{SampleRate: Float(0)})
	_, sp := StartSpan(context.Background(), "x", SpanOptions{})
	sp.End()
	Flush(context.Background())
	if len(mem.GetSpans()) != 0 {
		t.Fatal("rate 0 must record nothing")
	}
	if _, err := Init(context.Background(), Options{SampleRate: Float(1.5)}); err == nil {
		t.Fatal("an explicit rate outside 0..1 is an error")
	}
}

func TestTraceContext(t *testing.T) {
	setup(t)
	memInit(t, Options{})
	ctx := PropagateAttributes(context.Background(), Attributes{User: "alice", Tags: []string{"x"}, AsBaggage: true})
	ctx, sp := StartSpan(ctx, "client", SpanOptions{})
	defer sp.End()
	h := Inject(ctx, nil)
	if h["traceparent"] == "" || !strings.Contains(h["baggage"], "sbo.user=alice") || Traceparent(ctx) != h["traceparent"] {
		t.Fatalf("%v", h)
	}
	in := map[string]string{"TraceParent": h["traceparent"], "Baggage": h["baggage"]}
	ctx2 := ContinueTrace(context.Background(), in)
	if trace.SpanContextFromContext(ctx2).TraceID() != sp.SpanContext().TraceID() {
		t.Fatal("extract lost the trace")
	}
	if CurrentAttributes(ctx2)["user"] != "alice" {
		t.Fatalf("%v", CurrentAttributes(ctx2))
	}
	if CurrentTraceID(Extract(context.Background(), map[string]string{"traceparent": "garbage"})) != "" {
		t.Fatal("a malformed header gives no remote parent")
	}
	if len(CurrentTraceID(ctx)) != 32 || len(CurrentSpanID(ctx)) != 16 || CurrentTraceID(context.Background()) != "" {
		t.Fatal("ids")
	}
}

func TestGatewayTransport(t *testing.T) {
	setup(t)
	var seen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set(HeaderRequestID, "gw-1")
	}))
	defer srv.Close()
	mem := memInit(t, Options{ServiceName: "bot"})
	ctx := PropagateAttributes(context.Background(), Attributes{User: "alice"})
	ctx, sp := StartLLMSpan(ctx, "chat", LLMOptions{})
	req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL, nil)
	req.Header.Set(HeaderUser, "kept")
	resp, err := (&http.Client{Transport: GatewayTransport(nil)}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	sp.End()
	if seen.Get(HeaderUser) != "kept" || seen.Get(HeaderService) != "bot" || !strings.HasPrefix(seen.Get(HeaderRequestID), "sdk-") {
		t.Fatalf("%v", seen)
	}
	if lastSpanAttrs(t, mem)[keyRequestID] != "gw-1" {
		t.Fatal("request_id not stamped")
	}
}

func TestShutdownAndReinit(t *testing.T) {
	setup(t)
	mem := memInit(t, Options{})
	if !Shutdown(context.Background()) || GetDiagnostics().Initialized {
		t.Fatal("shutdown")
	}
	_, sp := StartSpan(context.Background(), "after shutdown", SpanOptions{})
	sp.End()
	memInit(t, Options{Exporter: mem})
	_, sp = StartSpan(context.Background(), "after reinit", SpanOptions{})
	sp.End()
	Flush(context.Background())
	if n := len(mem.GetSpans()); n == 0 || mem.GetSpans()[n-1].Name != "after reinit" {
		t.Fatalf("%v", mem.GetSpans())
	}
	if s := CurrentSettings(); s == nil || strings.Contains(s.String(), "ik_") {
		t.Fatal("settings")
	}
}

func TestSettingsStringHidesTheKey(t *testing.T) {
	setup(t)
	s, _ := resolveSettings(mapEnv(map[string]string{"SUPERBASED_API_KEY": "ik_1.secret"}), Options{Headers: map[string]string{"X": "secret"}})
	if strings.Contains(s.String(), "secret") {
		t.Fatal(s.String())
	}
}

func TestDiagnosticsNeverCarryTheKey(t *testing.T) {
	setup(t)
	memInit(t, Options{Destination: DestinationBoth, OrgURL: "https://gw.example.com", APIKey: "ik_1.secret"})
	d := GetDiagnostics()
	if strings.Contains(strings.Join(append(d.Warnings, d.Degraded, d.LastError), " "), "secret") || d.CredentialSource != "argument" {
		t.Fatalf("%+v", d)
	}
}
