package superbased

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Version is this SDK's version (lockstep with the Python and TypeScript SDKs).
const Version = "0.2.0"

const (
	tracerName = "superbased_sdk"
	sdkMarker  = "superbased-go"
)

// runtime is what the last Init resolved, read without the lock.
type runtimeState struct {
	settings *Settings
	plan     *plan
}

var (
	mu        sync.Mutex
	provider  *sdktrace.TracerProvider
	owns      bool
	processor *switchableProcessor
	configKey string
	mode      string // "", "owned" or "attached"
	vendor    = map[string]string{}
	tracerV   atomic.Pointer[trace.Tracer]
	active    atomic.Pointer[runtimeState]
	sampler   = newSwitchableSampler()
)

func activePlan() *plan {
	if r := active.Load(); r != nil {
		return r.plan
	}
	return nil
}

// CurrentSettings are the settings the last Init resolved (nil before Init).
func CurrentSettings() *Settings {
	if r := active.Load(); r != nil {
		s := *r.settings
		return &s
	}
	return nil
}

func contentRules() (bool, int) {
	if r := active.Load(); r != nil {
		return r.settings.CaptureContent, r.settings.MaxContentChars
	}
	return true, DefaultMaxContentChars
}

// isDefaultGlobal reports whether nothing registered a tracer provider yet
// (the OpenTelemetry API's delegating default).
func isDefaultGlobal(tp trace.TracerProvider) bool {
	return fmt.Sprintf("%T", tp) == "*global.tracerProvider"
}

// Init configures tracing to export to superbased over OTLP/HTTP. It is
// idempotent: a second call with the same settings changes nothing; with
// different content, sampling or hook options it updates them in place; with
// different export targets it swaps the exporters (never a second processor).
//
// When the app already registered an OpenTelemetry SDK TracerProvider (or
// passes Options.TracerProvider), the SDK adds its span processor to it, so the
// app's and the SDK's spans land in one trace. Otherwise it creates its own
// provider and, when nothing was registered, registers it globally.
//
// Discovery (the machine's default destination) happens inside Init, bounded
// by 500 ms. Init returns an error only for a sample rate outside 0..1.
func Init(ctx context.Context, opts Options) (*Settings, error) {
	s, err := resolveSettings(osEnv, opts)
	if err != nil {
		return nil, err
	}
	p := resolvePlan(s, osEnv, explicitInputs{opts.Destination, opts.Endpoint, opts.Headers, opts.APIKey})
	if opts.SampleRate == nil {
		if bad := samplingEnvProblem(osEnv); bad != "" {
			p.warnings = append(p.warnings, bad)
		}
	}
	logPlanOnce(p)

	mu.Lock()
	defer mu.Unlock()
	v := applyVendorTracing()
	vendor = v
	active.Store(&runtimeState{settings: &s, plan: p})
	sampler.set(s.SampleRate, s.SampleParentBased)

	key := buildConfigKey(s, p, opts)
	if processor != nil && processor.current() != nil && key == configKey {
		processor.setPipeline(makePipeline(s, opts, owns))
		return CurrentSettings(), nil
	}

	if provider == nil || (opts.TracerProvider != nil && opts.TracerProvider != provider) {
		var tp *sdktrace.TracerProvider
		ownsTP := false
		if opts.TracerProvider != nil {
			tp = opts.TracerProvider
		} else if host, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
			tp = host
		} else {
			attrs := []attribute.KeyValue{}
			keys := make([]string, 0, len(s.ResourceAttrs))
			for k := range s.ResourceAttrs {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				attrs = append(attrs, attribute.String(k, s.ResourceAttrs[k]))
			}
			attrs = append(attrs, s.identity()...)
			attrs = append(attrs, attribute.String(keyServiceName, s.ServiceName))
			res, err := resource.Merge(resource.Default(), resource.NewSchemaless(attrs...))
			if err != nil {
				res = resource.NewSchemaless(attrs...)
			}
			tp = sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithSampler(sampler))
			ownsTP = true
			if isDefaultGlobal(otel.GetTracerProvider()) {
				// Nothing registered yet: register ours, so other
				// instrumentation lands in the same pipeline.
				otel.SetTracerProvider(tp)
			}
		}
		proc := &switchableProcessor{}
		tp.RegisterSpanProcessor(proc)
		if processor != nil {
			if old := processor.detach(); old != nil {
				shutdownBounded(old, s.ShutdownTimeout)
			}
			if provider != nil {
				provider.UnregisterSpanProcessor(processor)
			}
		}
		provider, owns, processor = tp, ownsTP, proc
		mode = "attached"
		if ownsTP {
			mode = "owned"
		}
	}
	delegate := buildDelegate(ctx, s, p, opts)
	processor.shutdownTimeout = s.ShutdownTimeout
	processor.setPipeline(makePipeline(s, opts, owns))
	if old := processor.swap(delegate, s.identity()); old != nil {
		shutdownBounded(old, s.ShutdownTimeout)
	}
	configKey = key
	t := provider.Tracer(tracerName, trace.WithInstrumentationVersion(Version))
	tracerV.Store(&t)
	return CurrentSettings(), nil
}

func buildConfigKey(s Settings, p *plan, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%v|%s|%s|%s|%t|%t|%s|%v|%v", s.ServiceName, s.ResourceAttrs, s.Tenant, s.User, s.SessionID, s.Quiet, s.Console, s.Release+"|"+s.Environment, s.Tags, s.Metadata)
	fmt.Fprintf(&b, "|%p|%p", opts.Exporter, opts.TracerProvider)
	ek := make([]string, 0, len(opts.Exporters))
	for k, e := range opts.Exporters {
		ek = append(ek, fmt.Sprintf("%s=%p", k, e))
	}
	sort.Strings(ek)
	b.WriteString(strings.Join(ek, ","))
	for _, t := range p.exporters {
		b.WriteString("|" + t.key())
	}
	return b.String()
}

func makePipeline(s Settings, opts Options, owned bool) *pipeline {
	return &pipeline{
		captureContent:  s.CaptureContent,
		maxContentChars: s.MaxContentChars,
		mask:            opts.Mask,
		shouldExport:    opts.ShouldExport,
		// The SDK's own provider samples at the head; attached to the host's
		// provider, the host's sampler decides what is recorded and the SDK
		// applies its rate to what it exports.
		exportRatio:       s.SampleRate,
		ratioSet:          !owned,
		dropScopePrefixes: vendorDropPrefixes(vendor),
	}
}

// buildDelegate is one batch processor (over a counting exporter) per
// destination, so a slow or down destination never delays the other, plus
// the console processor when asked. A plan with no target counts every span
// as dropped.
func buildDelegate(ctx context.Context, s Settings, p *plan, opts Options) sdktrace.SpanProcessor {
	var procs []sdktrace.SpanProcessor
	for _, t := range p.exporters {
		inner := opts.Exporters[t.name]
		if inner == nil {
			inner = opts.Exporter
		}
		if inner == nil {
			inner = newOTLPExporter(ctx, t)
		}
		if inner == nil {
			continue
		}
		procs = append(procs, sdktrace.NewBatchSpanProcessor(&countingExporter{inner: inner, quiet: s.Quiet, dest: t.name}, sdktrace.WithExportTimeout(t.timeout)))
	}
	if s.Console {
		procs = append(procs, sdktrace.NewSimpleSpanProcessor(&consoleExporter{w: stderr}))
	}
	if len(procs) == 0 {
		return discard{}
	}
	if len(procs) == 1 && len(p.exporters) == 1 {
		return procs[0]
	}
	return &fanout{procs: procs, n: int64(len(p.exporters))}
}

func newOTLPExporter(ctx context.Context, t exportTarget) sdktrace.SpanExporter {
	headers := map[string]string{}
	for k, v := range t.headers {
		headers[k] = v
	}
	loopback := isLoopbackURL(t.endpoint)
	o := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(t.endpoint),
		otlptracehttp.WithHeaders(headers),
		otlptracehttp.WithTimeout(t.timeout),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: true, InitialInterval: 100 * time.Millisecond, MaxInterval: time.Second, MaxElapsedTime: t.timeout}),
	}
	if loopback {
		// A loopback export never goes through an HTTP(S)_PROXY from the
		// environment.
		o = append(o, otlptracehttp.WithProxy(nil))
	}
	exp, err := otlptracehttp.New(ctx, o...)
	if err != nil {
		stats.mu.Lock()
		stats.lastError = clip("exporter for "+t.endpoint+": "+err.Error(), 500)
		stats.lastErrorAt = time.Now()
		stats.mu.Unlock()
		logf(slog.LevelWarn, "cannot export to %s: %v", t.endpoint, err)
		return nil
	}
	return exp
}

func tracer() trace.Tracer {
	if t := tracerV.Load(); t != nil {
		return *t
	}
	// Never crash a caller who forgot Init: the global (possibly no-op) tracer.
	return otel.Tracer(tracerName)
}

func shutdownTimeout() time.Duration {
	if s := CurrentSettings(); s != nil {
		return s.ShutdownTimeout
	}
	return DefaultShutdownTimeout
}

// Flush exports every finished span now. It is bounded by ctx's deadline when
// ctx has one, else by the Init ShutdownTimeout, and returns true when
// everything was exported in time. Call it at the end of a serverless handler.
func Flush(ctx context.Context) bool {
	mu.Lock()
	proc := processor
	mu.Unlock()
	if proc == nil || proc.current() == nil {
		return true
	}
	return flushBounded(proc, boundOf(ctx))
}

func boundOf(ctx context.Context) time.Duration {
	if ctx != nil {
		if d, ok := ctx.Deadline(); ok {
			return max(time.Until(d), time.Millisecond)
		}
	}
	return shutdownTimeout()
}

// Shutdown flushes and stops the SDK's exporters, bounded like Flush even when
// an endpoint is down. A host provider the SDK attached to keeps running. A
// later Init starts exporting again.
func Shutdown(ctx context.Context) bool {
	mu.Lock()
	proc := processor
	if proc == nil {
		mu.Unlock()
		return true
	}
	old := proc.detach()
	configKey = ""
	mu.Unlock()
	if old == nil {
		return true
	}
	ok := shutdownBounded(old, boundOf(ctx))
	maybeLogFailures(time.Now())
	return ok
}

// DestinationInfo is one export target in Diagnostics.
type DestinationInfo struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

// Diagnostics is a snapshot of the SDK's health (contract sdk-api-surface.md
// section 1). It never holds the credential.
type Diagnostics struct {
	Mode                   string            `json:"mode"` // "owned", "attached" or ""
	Initialized            bool              `json:"initialized"`
	PendingSpans           int64             `json:"pending_spans"` // once per destination
	ExportedSpans          int64             `json:"exported_spans"`
	FailedExports          int64             `json:"failed_exports"`
	DroppedSpans           int64             `json:"dropped_spans"`
	LastError              string            `json:"last_error"`
	LastErrorAt            time.Time         `json:"last_error_at"`
	SampledOutSpans        int64             `json:"sampled_out_spans"`
	FilteredSpans          int64             `json:"filtered_spans"`
	MaskErrors             int64             `json:"mask_errors"`
	ShouldExportErrors     int64             `json:"should_export_errors"`
	VendorSpansDropped     int64             `json:"vendor_spans_dropped"`
	UsageNetInputCorrected int64             `json:"usage_net_input_corrected"`
	LastHookError          string            `json:"last_hook_error"`
	AdmissionDegraded      int64             `json:"admission_degraded"`
	AdmissionLastError     string            `json:"admission_last_error"`
	AdmissionLastErrorAt   time.Time         `json:"admission_last_error_at"`
	VendorTracing          map[string]string `json:"vendor_tracing"`
	Destination            string            `json:"destination"`
	DestinationSource      string            `json:"destination_source"`
	Destinations           []DestinationInfo `json:"destinations"`
	GatewayURL             string            `json:"gateway_url"`
	Degraded               string            `json:"degraded"`
	Warnings               []string          `json:"warnings"`
	Notes                  []string          `json:"notes"`
	SignedIn               *bool             `json:"signed_in"`
	// CredentialSource is where the online credential came from: argument,
	// env, file (the machine's sign-in file), sdk_file (the SDK-held file
	// setup writes) or "".
	CredentialSource string `json:"credential_source"`
	// SDKFile is the SDK-held credential file setup writes: its path,
	// state and the refused rule (never the key).
	SDKFile SDKFileInfo `json:"sdk_file"`
	// FirstTraceLink is the first-trace link once it was written, else "".
	FirstTraceLink string `json:"first_trace_link"`
	// ServiceName is the service name Init resolved; ServiceNameSource the
	// rung that gave it: argument, env, manifest (the main module's path) or
	// default.
	ServiceName       string `json:"service_name"`
	ServiceNameSource string `json:"service_name_source"`
	// PlanRefusal is the last time the organization's plan refused AI Apps
	// ingest (an export, or any other call to the gateway), nil when never;
	// PlanRefusalAt is when. Export never fails a caller: a refused export
	// shows here, beside one warning line a minute.
	PlanRefusal   *PlanRefusalError `json:"plan_refusal"`
	PlanRefusalAt time.Time         `json:"plan_refusal_at"`
}

// GetDiagnostics returns a snapshot of the SDK's export health.
func GetDiagnostics() Diagnostics {
	var d Diagnostics
	stats.mu.Lock()
	d.PendingSpans, d.ExportedSpans, d.FailedExports, d.DroppedSpans = stats.pendingLocked(), stats.exported, stats.failedExports, stats.dropped
	d.LastError, d.LastErrorAt = stats.lastError, stats.lastErrorAt
	stats.mu.Unlock()
	c := pipeCounters
	c.mu.Lock()
	d.SampledOutSpans, d.FilteredSpans, d.MaskErrors, d.ShouldExportErrors = c.sampledOutSpans, c.filteredSpans, c.maskErrors, c.shouldExportErrors
	d.VendorSpansDropped, d.UsageNetInputCorrected, d.LastHookError = c.vendorSpansDropped, c.usageNetInputCorrected, c.lastHookError
	c.mu.Unlock()
	admitStats.mu.Lock()
	d.AdmissionDegraded, d.AdmissionLastError, d.AdmissionLastErrorAt = admitStats.degraded, admitStats.lastError, admitStats.lastErrorAt
	admitStats.mu.Unlock()
	d.PlanRefusal, d.PlanRefusalAt = planRefusalSnapshot()
	mu.Lock()
	d.Mode = mode
	d.Initialized = processor != nil && processor.current() != nil
	d.VendorTracing = map[string]string{}
	for k, v := range vendor {
		d.VendorTracing[k] = v
	}
	mu.Unlock()
	if st := CurrentSettings(); st != nil {
		d.ServiceName, d.ServiceNameSource = st.ServiceName, st.ServiceNameSource
	}
	d.Destinations = []DestinationInfo{}
	d.Warnings, d.Notes = []string{}, []string{}
	if p := activePlan(); p != nil {
		d.Destination, d.DestinationSource = p.destination, p.source
		for _, t := range p.exporters {
			d.Destinations = append(d.Destinations, DestinationInfo{t.name, t.endpoint})
		}
		d.GatewayURL, d.Degraded = p.gatewayURL, p.degraded
		d.Warnings = append(d.Warnings, p.warnings...)
		d.Notes = append(d.Notes, p.notes...)
		d.SignedIn, d.CredentialSource = p.signedIn, p.credentialFrom
		d.SDKFile = p.sdkFile
	}
	d.FirstTraceLink = firstTrace.printed()
	return d
}

// --- spans ------------------------------------------------------------------------

// SpanOptions are the options of StartSpan and WithSpan.
type SpanOptions struct {
	Kind       string // default KindChain
	Attributes []attribute.KeyValue
}

// StartSpan starts a span of the given OpenInference kind. End it with EndSpan
// (or span.End()).
func StartSpan(ctx context.Context, name string, opts SpanOptions) (context.Context, trace.Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	kind := opts.Kind
	if kind == "" {
		kind = KindChain
	}
	attrs := append([]attribute.KeyValue{attribute.String(keySpanKind, kind)}, opts.Attributes...)
	return tracer().Start(ctx, name, trace.WithAttributes(dedupe(attrs)...))
}

// dedupe keeps the last value of each key, in first-seen order.
func dedupe(attrs []attribute.KeyValue) []attribute.KeyValue {
	idx := map[attribute.Key]int{}
	out := make([]attribute.KeyValue, 0, len(attrs))
	for _, kv := range attrs {
		if i, ok := idx[kv.Key]; ok {
			out[i] = kv
			continue
		}
		idx[kv.Key] = len(out)
		out = append(out, kv)
	}
	return out
}

func statusUnset(sp trace.Span) bool {
	if ro, ok := sp.(sdktrace.ReadOnlySpan); ok {
		return ro.Status().Code == codes.Unset
	}
	return true
}

// EndSpan ends sp: with err it records the error once and sets ERROR;
// without, it sets OK unless a status was already set.
func EndSpan(sp trace.Span, err error) {
	if err != nil {
		sp.RecordError(err)
		sp.SetStatus(codes.Error, fmt.Sprintf("%T: %v", err, err))
	} else if statusUnset(sp) {
		sp.SetStatus(codes.Ok, "")
	}
	sp.End()
}

// WithSpan runs fn inside a span and returns fn's error. An error or a panic
// is recorded once and sets ERROR (the panic continues); success sets OK
// unless fn set a status.
func WithSpan(ctx context.Context, name string, opts SpanOptions, fn func(context.Context, trace.Span) error) error {
	ctx, sp := StartSpan(ctx, name, opts)
	return run(ctx, sp, fn)
}

func run(ctx context.Context, sp trace.Span, fn func(context.Context, trace.Span) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			EndSpan(sp, fmt.Errorf("panic: %v", r))
			panic(r)
		}
	}()
	err = fn(ctx, sp)
	EndSpan(sp, err)
	return err
}

// Observe runs fn inside a span of the given kind and returns its result (the
// Go form of the contract's observe decorator).
func Observe[T any](ctx context.Context, name, kind string, fn func(context.Context) (T, error)) (T, error) {
	var out T
	err := WithSpan(ctx, name, SpanOptions{Kind: kind}, func(ctx context.Context, _ trace.Span) error {
		var e error
		out, e = fn(ctx)
		return e
	})
	return out, err
}

// LLMOptions are the options of an LLM span.
type LLMOptions struct {
	Model     string
	Provider  string
	Operation string // default "chat"
	// Prompt: a string goes to input.value, a list of message objects to
	// gen_ai.input.messages (JSON), a *Prompt from GetPrompt stamps
	// sbo.prompt.* and is not request content.
	Prompt any
	// System goes to gen_ai.system_instructions.
	System     any
	Attributes []attribute.KeyValue
}

func llmAttributes(o LLMOptions) []attribute.KeyValue {
	op := o.Operation
	if op == "" {
		op = "chat"
	}
	attrs := []attribute.KeyValue{attribute.String(keyOperation, op)}
	if o.Model != "" {
		attrs = append(attrs, attribute.String(keyRequestModel, o.Model), attribute.String(keyOIModel, o.Model))
	}
	if o.Provider != "" {
		attrs = append(attrs, attribute.String(keyProvider, o.Provider), attribute.String(keyLegacySystem, o.Provider), attribute.String(keyOIProvider, o.Provider))
	}
	prompt := o.Prompt
	if p, ok := prompt.(*Prompt); ok {
		if p != nil {
			attrs = append(attrs, p.Attributes()...)
		}
		prompt = nil
	}
	if body, ok := contentBody(prompt); ok {
		key := keyInputValue
		if isMessageList(prompt) {
			key = keyInputMessages
		}
		attrs = append(attrs, attribute.String(key, body))
	}
	if body, ok := contentBody(o.System); ok {
		attrs = append(attrs, attribute.String(keySystemInstructions, body))
	}
	return append(attrs, o.Attributes...)
}

// StartLLMSpan starts an LLM span tagged in the GenAI and OpenInference
// vocabularies (gen_ai.operation.name, gen_ai.request.model, llm.model_name,
// gen_ai.provider.name, gen_ai.system, llm.provider).
func StartLLMSpan(ctx context.Context, name string, o LLMOptions) (context.Context, trace.Span) {
	return StartSpan(ctx, name, SpanOptions{Kind: KindLLM, Attributes: llmAttributes(o)})
}

// WithLLMSpan runs fn inside an LLM span (see StartLLMSpan and WithSpan).
func WithLLMSpan(ctx context.Context, name string, o LLMOptions, fn func(context.Context, trace.Span) error) error {
	ctx, sp := StartLLMSpan(ctx, name, o)
	return run(ctx, sp, fn)
}

// ToolOptions are the options of a TOOL span.
type ToolOptions struct {
	ToolName   string // default: the span name
	CallID     string
	Arguments  any // content; a non-string is JSON-encoded
	Attributes []attribute.KeyValue
}

func toolAttributes(name string, o ToolOptions) []attribute.KeyValue {
	tn := o.ToolName
	if tn == "" {
		tn = name
	}
	attrs := []attribute.KeyValue{attribute.String(keyOperation, "execute_tool"), attribute.String(keyToolName, tn), attribute.String(keyOIToolName, tn)}
	if o.CallID != "" {
		attrs = append(attrs, attribute.String(keyToolCallID, o.CallID))
	}
	if body, ok := contentBody(o.Arguments); ok {
		attrs = append(attrs, attribute.String(keyToolArguments, body))
	}
	return append(attrs, o.Attributes...)
}

// StartToolSpan starts a TOOL span (gen_ai.operation.name=execute_tool).
func StartToolSpan(ctx context.Context, name string, o ToolOptions) (context.Context, trace.Span) {
	return StartSpan(ctx, name, SpanOptions{Kind: KindTool, Attributes: toolAttributes(name, o)})
}

// WithToolSpan runs fn inside a TOOL span.
func WithToolSpan(ctx context.Context, name string, o ToolOptions, fn func(context.Context, trace.Span) error) error {
	ctx, sp := StartToolSpan(ctx, name, o)
	return run(ctx, sp, fn)
}

// RetrieverOptions are the options of a RETRIEVER span.
type RetrieverOptions struct {
	Query      any // content: gen_ai.retrieval.query.text
	Attributes []attribute.KeyValue
}

// StartRetrieverSpan starts a RETRIEVER span (gen_ai.operation.name=retrieval).
func StartRetrieverSpan(ctx context.Context, name string, o RetrieverOptions) (context.Context, trace.Span) {
	attrs := []attribute.KeyValue{attribute.String(keyOperation, "retrieval")}
	if body, ok := contentBody(o.Query); ok {
		attrs = append(attrs, attribute.String(keyRetrievalQuery, body))
	}
	return StartSpan(ctx, name, SpanOptions{Kind: KindRetriever, Attributes: append(attrs, o.Attributes...)})
}

// WithRetrieverSpan runs fn inside a RETRIEVER span.
func WithRetrieverSpan(ctx context.Context, name string, o RetrieverOptions, fn func(context.Context, trace.Span) error) error {
	ctx, sp := StartRetrieverSpan(ctx, name, o)
	return run(ctx, sp, fn)
}

// AgentOptions are the options of an AGENT span.
type AgentOptions struct {
	AgentName  string // default: the span name
	AgentID    string
	Attributes []attribute.KeyValue
}

// StartAgentSpan starts an AGENT span (gen_ai.operation.name=invoke_agent).
func StartAgentSpan(ctx context.Context, name string, o AgentOptions) (context.Context, trace.Span) {
	an := o.AgentName
	if an == "" {
		an = name
	}
	attrs := []attribute.KeyValue{attribute.String(keyOperation, "invoke_agent"), attribute.String(keyAgentName, an), attribute.String(keyOIAgentName, an)}
	if o.AgentID != "" {
		attrs = append(attrs, attribute.String(keyAgentID, o.AgentID))
	}
	return StartSpan(ctx, name, SpanOptions{Kind: KindAgent, Attributes: append(attrs, o.Attributes...)})
}

// WithAgentSpan runs fn inside an AGENT span.
func WithAgentSpan(ctx context.Context, name string, o AgentOptions, fn func(context.Context, trace.Span) error) error {
	ctx, sp := StartAgentSpan(ctx, name, o)
	return run(ctx, sp, fn)
}

// EmbeddingOptions are the options of an EMBEDDING span.
type EmbeddingOptions struct {
	Model      string
	Provider   string
	Attributes []attribute.KeyValue
}

// StartEmbeddingSpan starts an EMBEDDING span (gen_ai.operation.name=embeddings).
func StartEmbeddingSpan(ctx context.Context, name string, o EmbeddingOptions) (context.Context, trace.Span) {
	attrs := []attribute.KeyValue{attribute.String(keyOperation, "embeddings")}
	if o.Model != "" {
		attrs = append(attrs, attribute.String(keyRequestModel, o.Model))
	}
	if o.Provider != "" {
		attrs = append(attrs, attribute.String(keyProvider, o.Provider), attribute.String(keyLegacySystem, o.Provider))
	}
	return StartSpan(ctx, name, SpanOptions{Kind: KindEmbedding, Attributes: append(attrs, o.Attributes...)})
}

// WithEmbeddingSpan runs fn inside an EMBEDDING span.
func WithEmbeddingSpan(ctx context.Context, name string, o EmbeddingOptions, fn func(context.Context, trace.Span) error) error {
	ctx, sp := StartEmbeddingSpan(ctx, name, o)
	return run(ctx, sp, fn)
}

// --- setters ----------------------------------------------------------------------

// contentText is a content body as text: a string as is, anything else JSON.
func contentText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := marshalCompact(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// contentBody is a content body as an attribute value (clipped); false when
// capture is off or v is nil.
func contentBody(v any) (string, bool) {
	capture, limit := contentRules()
	if !capture || v == nil {
		return "", false
	}
	return truncateText(contentText(v), limit), true
}

// isMessageList: a list whose every element is a JSON object.
func isMessageList(v any) bool {
	if v == nil {
		return false
	}
	if _, ok := v.(string); ok {
		return false
	}
	b, err := marshalCompact(v)
	if err != nil {
		return false
	}
	arr, ok := decodeJSON(b).([]any)
	if !ok {
		return false
	}
	for _, e := range arr {
		if _, ok := e.(map[string]any); !ok {
			return false
		}
	}
	return true
}

func spanKindOf(sp trace.Span) string {
	if ro, ok := sp.(sdktrace.ReadOnlySpan); ok {
		for _, kv := range ro.Attributes() {
			if kv.Key == keySpanKind {
				return strings.ToUpper(kv.Value.Emit())
			}
		}
	}
	return ""
}

func spanHas(sp trace.Span, key string) bool {
	if ro, ok := sp.(sdktrace.ReadOnlySpan); ok {
		for _, kv := range ro.Attributes() {
			if string(kv.Key) == key {
				return true
			}
		}
	}
	return false
}

// Usage is what SetUsage records. Token counts are pointers (Int(n)) because
// zero is a real count. InputTokens is GROSS: it includes cache reads and
// writes, which are subsets of it, never addends; OutputTokens includes
// ReasoningTokens; TotalTokens is optional (ingest derives input + output).
type Usage struct {
	InputTokens, OutputTokens, TotalTokens *int
	CacheReadTokens, CacheWriteTokens      *int
	ReasoningTokens                        *int
	ResponseID, RequestID, ResponseModel   string
	FinishReasons                          []string
	CostUSD                                *float64
	Prompt, Response                       any
}

// ErrNegativeCount is returned (wrapped) by SetUsage for a negative token count.
var ErrNegativeCount = errors.New("superbased: a token count must not be negative")

var netInputWarned atomic.Bool

// SetUsage records token usage, ids and the outcome on an LLM (or embedding)
// span. A negative count returns an error and nothing is written. An
// InputTokens below CacheReadTokens + CacheWriteTokens cannot be gross: it is
// read as a NET count (Anthropic's usage.input_tokens is net), recorded as
// input + cache, counted in Diagnostics.UsageNetInputCorrected and warned about
// once per process; a TotalTokens equal to that net input + output is raised
// by the same amount.
func SetUsage(sp trace.Span, u Usage) error {
	counts := []struct {
		key, label string
		v          *int
	}{
		{keyInputTokens, "InputTokens", u.InputTokens},
		{keyOutputTokens, "OutputTokens", u.OutputTokens},
		{keyTotalTokens, "TotalTokens", u.TotalTokens},
		{keyCacheReadTokens, "CacheReadTokens", u.CacheReadTokens},
		{keyCacheWriteTokens, "CacheWriteTokens", u.CacheWriteTokens},
		{keyReasoningTokens, "ReasoningTokens", u.ReasoningTokens},
	}
	for _, c := range counts {
		if c.v != nil && *c.v < 0 {
			return fmt.Errorf("%w: %s is %d", ErrNegativeCount, c.label, *c.v)
		}
	}
	val := func(p *int) int {
		if p == nil {
			return 0
		}
		return *p
	}
	in := u.InputTokens
	total := u.TotalTokens
	if in != nil {
		cache := val(u.CacheReadTokens) + val(u.CacheWriteTokens)
		if *in < cache {
			gross := *in + cache
			pipeCounters.add(&pipeCounters.usageNetInputCorrected, "")
			if netInputWarned.CompareAndSwap(false, true) {
				logf(slog.LevelWarn, "SetUsage: InputTokens %d is below CacheReadTokens + CacheWriteTokens (%d); recorded as a net count (input + cache = %d). Pass the gross input: for Anthropic, usage.input_tokens + cache_creation_input_tokens + cache_read_input_tokens.", *in, cache, gross)
			}
			if total != nil && *total == *in+val(u.OutputTokens) {
				t := *total + cache
				total = &t
			}
			in = &gross
		}
	}
	set := func(key string, p *int) {
		if p != nil {
			sp.SetAttributes(attribute.Int(key, *p))
		}
	}
	set(keyInputTokens, in)
	set(keyOutputTokens, u.OutputTokens)
	set(keyTotalTokens, total)
	set(keyCacheReadTokens, u.CacheReadTokens)
	set(keyCacheWriteTokens, u.CacheWriteTokens)
	set(keyReasoningTokens, u.ReasoningTokens)
	if u.ResponseID != "" {
		sp.SetAttributes(attribute.String(keyResponseID, u.ResponseID))
	}
	if u.RequestID != "" {
		sp.SetAttributes(attribute.String(keyRequestID, u.RequestID))
	}
	if u.ResponseModel != "" {
		sp.SetAttributes(attribute.String(keyResponseModel, u.ResponseModel))
	}
	if u.FinishReasons != nil {
		sp.SetAttributes(attribute.StringSlice(keyFinishReasons, u.FinishReasons))
	}
	if u.CostUSD != nil {
		sp.SetAttributes(attribute.Float64(keyCost, *u.CostUSD))
	}
	if u.Prompt != nil || u.Response != nil {
		SetContent(sp, Content{Prompt: u.Prompt, Response: u.Response})
	}
	return nil
}

// Content are the bodies SetContent records.
type Content struct {
	Prompt, Response     any
	ToolArgs, ToolResult any
}

// SetContent attaches request and response bodies. The span's kind decides
// the keys: TOOL -> gen_ai.tool.call.arguments / .result; otherwise a string
// goes to input.value / output.value and a message list to
// gen_ai.input.messages / gen_ai.output.messages. No-op when content capture
// is off; each body is clipped to MaxContentChars.
func SetContent(sp trace.Span, c Content) {
	capture, limit := contentRules()
	if !capture {
		return
	}
	req, res := c.Prompt, c.Response
	if req == nil {
		req = c.ToolArgs
	}
	if res == nil {
		res = c.ToolResult
	}
	var inKey, outKey string
	if spanKindOf(sp) == KindTool {
		inKey, outKey = keyToolArguments, keyToolResult
	} else {
		inKey, outKey = keyInputValue, keyOutputValue
		if isMessageList(req) {
			inKey = keyInputMessages
		}
		if isMessageList(res) {
			outKey = keyOutputMessages
		}
	}
	if req != nil {
		sp.SetAttributes(attribute.String(inKey, truncateText(contentText(req), limit)))
	}
	if res != nil {
		sp.SetAttributes(attribute.String(outKey, truncateText(contentText(res), limit)))
	}
}

// SetInput records a span's input (input.value; a non-string is JSON-encoded).
func SetInput(sp trace.Span, v any) {
	if body, ok := contentBody(v); ok {
		sp.SetAttributes(attribute.String(keyInputValue, body))
	}
}

// SetOutput records a span's output (output.value; on a RETRIEVER span it is
// SetDocuments).
func SetOutput(sp trace.Span, v any) {
	if spanKindOf(sp) == KindRetriever {
		SetDocuments(sp, v)
		return
	}
	if body, ok := contentBody(v); ok {
		sp.SetAttributes(attribute.String(keyOutputValue, body))
	}
}

// SetToolResult records a tool call's result (gen_ai.tool.call.result).
func SetToolResult(sp trace.Span, v any) {
	if body, ok := contentBody(v); ok {
		sp.SetAttributes(attribute.String(keyToolResult, body))
	}
}

// SetDocuments records retrieved documents (gen_ai.retrieval.documents, a
// JSON array; a string element becomes {"content": s}).
func SetDocuments(sp trace.Span, docs any) {
	if docs == nil {
		return
	}
	if b, err := marshalCompact(docs); err == nil {
		if arr, ok := decodeJSON(b).([]any); ok {
			for i, d := range arr {
				if _, isObj := d.(map[string]any); !isObj {
					arr[i] = map[string]any{"content": d}
				}
			}
			docs = arr
		}
	}
	if body, ok := contentBody(docs); ok {
		sp.SetAttributes(attribute.String(keyRetrievalDocuments, body))
	}
}

// RequestParams are the model request parameters (gen_ai.request.<name>).
type RequestParams struct {
	MaxTokens        *int
	Temperature      *float64
	TopP             *float64
	TopK             *float64
	StopSequences    []string
	FrequencyPenalty *float64
	PresencePenalty  *float64
	Seed             *int
	Stream           *bool
	ReasoningLevel   string
}

// SetRequestParams records the model request parameters.
func SetRequestParams(sp trace.Span, p RequestParams) {
	k := requestParamKeys
	if p.MaxTokens != nil {
		sp.SetAttributes(attribute.Int(k["max_tokens"], *p.MaxTokens))
	}
	for name, v := range map[string]*float64{"temperature": p.Temperature, "top_p": p.TopP, "top_k": p.TopK, "frequency_penalty": p.FrequencyPenalty, "presence_penalty": p.PresencePenalty} {
		if v != nil {
			sp.SetAttributes(attribute.Float64(k[name], *v))
		}
	}
	if p.StopSequences != nil {
		sp.SetAttributes(attribute.StringSlice(k["stop_sequences"], p.StopSequences))
	}
	if p.Seed != nil {
		sp.SetAttributes(attribute.Int(k["seed"], *p.Seed))
	}
	if p.Stream != nil {
		sp.SetAttributes(attribute.Bool(k["stream"], *p.Stream))
	}
	if p.ReasoningLevel != "" {
		sp.SetAttributes(attribute.String(k["reasoning_level"], p.ReasoningLevel))
	}
}

// resetForTests forgets all SDK state (tests only).
func resetForTests() {
	mu.Lock()
	if processor != nil {
		if old := processor.detach(); old != nil {
			shutdownBounded(old, time.Second)
		}
		if provider != nil {
			provider.UnregisterSpanProcessor(processor)
		}
	}
	provider, processor, owns, configKey, mode = nil, nil, false, "", ""
	vendor = map[string]string{}
	tracerV.Store(nil)
	active.Store(nil)
	mu.Unlock()
	discoveryMu.Lock()
	discoveryCache = map[string]discovered{}
	discoveryMu.Unlock()
	loggedMu.Lock()
	logged = map[string]bool{}
	loggedMu.Unlock()
	fallbackMu.Lock()
	fallbackPlan = nil
	fallbackMu.Unlock()
	promptCache.clear()
	stats.reset()
	pipeCounters.reset()
	admitStats.reset()
	resetPlanRefusal()
	resetAdvertised()
	resetVendorForTests()
	netInputWarned.Store(false)
	firstTrace.reset()
	sampler.set(1, true)
	serviceSeen.Store(nil)
}
