package otel

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/otelident"
)

// defaultTracesPath is the OTLP/HTTP traces path a path-less endpoint URL
// posts to.
const defaultTracesPath = "/v1/traces"

// tracerName is the instrumentation scope name on every emitted span.
const tracerName = "github.com/marmutapp/superbased-observer/internal/exporter/otel"

// eventInferenceDetails is the GenAI event that carries (opt-in) prompt and
// completion content.
const eventInferenceDetails = "gen_ai.client.inference.operation.details"

// TurnSource is the row tail the exporter consumes — satisfied by *store.Store.
// Taking an interface keeps the package decoupled from the store and lets tests
// drive a controlled channel.
type TurnSource interface {
	SubscribeAPITurns(ctx context.Context, interval time.Duration, logger *slog.Logger) <-chan models.APITurn
}

// ProjectResolver resolves a project_id to its root_path — satisfied by
// *store.Store. Returns "" (no error) for an unknown id.
type ProjectResolver interface {
	ProjectRootByID(ctx context.Context, id int64) (string, error)
}

// Exporter tails api_turns and emits one gen_ai.client span per turn to an
// OTLP/HTTP endpoint. Construct with New, run with Start, drain with Stop.
type Exporter struct {
	cfg      Config
	src      TurnSource
	resolver ProjectResolver
	logger   *slog.Logger
	tp       *sdktrace.TracerProvider
	tracer   trace.Tracer

	// rootCache memoises project_id → root_path. It is touched only from the
	// single Start goroutine (export is never called concurrently), so it
	// needs no lock; project roots are immutable per id.
	rootCache map[int64]string
}

// New constructs an Exporter with a batching OTLP/HTTP trace exporter. It does
// not open a network connection — the SDK dials lazily on the first export, so
// a misconfigured or unreachable endpoint surfaces as a logged export failure,
// never a constructor error (P1). cfg env-var overrides are applied here.
func New(cfg Config, src TurnSource, resolver ProjectResolver, logger *slog.Logger) (*Exporter, error) {
	cfg = cfg.withEnvOverrides()

	tp, err := NewTracerProvider(cfg)
	if err != nil {
		return nil, fmt.Errorf("otel.New: %w", err)
	}
	return newExporter(cfg, src, resolver, logger, tp), nil
}

// NewTracerProvider builds a batching OTLP/HTTP TracerProvider from an
// ALREADY-RESOLVED Config. It does NOT apply withEnvOverrides — env-var
// resolution stays inside Exporter.New (governing only the api_turns exporter);
// a caller that must keep the endpoint scheme authoritative over OTEL_* env
// (e.g. internal/selfobs/emit's credential-bearing path) constructs its own
// Config and relies on WithEndpointURL, whose explicit scheme sets the insecure
// flag AFTER the SDK layers the env config (verified against the vendored
// otlptracehttp v1.43.0 and re-checked at v1.45.0 (T-688): NewHTTPConfig applies
// env first, then explicit options,
// and WithEndpointURL sets Traces.Insecure = scheme != "https").
//
// A full-URL Endpoint (with a scheme) is passed via WithEndpointURL so the
// scheme decides plaintext-vs-TLS; a bare host:port goes through WithEndpoint
// and WithInsecure is added only when cfg.Insecure. cfg.Headers is applied via
// WithHeaders when non-empty and cfg.HTTPClient via WithHTTPClient when non-nil.
func NewTracerProvider(cfg Config) (*sdktrace.TracerProvider, error) {
	opts := []otlptracehttp.Option{}
	if strings.Contains(cfg.Endpoint, "://") {
		opts = append(opts, otlptracehttp.WithEndpointURL(cfg.Endpoint))
		// otlptracehttp v1.45.0 sends a URL with NO path to "/" (before, the
		// default /v1/traces). Every endpoint Observer is configured with has
		// meant the default signal path, so keep it (T-688); an explicit path,
		// "/" included, is kept as written.
		if u, err := url.Parse(cfg.Endpoint); err == nil && u.Path == "" {
			opts = append(opts, otlptracehttp.WithURLPath(defaultTracesPath))
		}
	} else {
		opts = append(opts, otlptracehttp.WithEndpoint(cfg.Endpoint))
	}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
	}
	if cfg.HTTPClient != nil {
		opts = append(opts, otlptracehttp.WithHTTPClient(cfg.HTTPClient))
	}

	client, err := otlptracehttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("otel.NewTracerProvider: build OTLP exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(client),
		sdktrace.WithResource(newResource(cfg.ServiceName)),
	)
	return tp, nil
}

// newExporter wires an Exporter around an already-built TracerProvider. It is
// the seam the unit tests use to inject a synchronous in-memory provider.
func newExporter(cfg Config, src TurnSource, resolver ProjectResolver, logger *slog.Logger, tp *sdktrace.TracerProvider) *Exporter {
	return &Exporter{
		cfg:       cfg,
		src:       src,
		resolver:  resolver,
		logger:    logger,
		tp:        tp,
		tracer:    tp.Tracer(tracerName),
		rootCache: make(map[int64]string),
	}
}

// newResource builds the OTel resource carrying the service identity. It also
// stamps sbo.emitted_by="observer" so Observer's own native-console OTLP
// receiver (internal/ingest/otlp + internal/adapter/ccotel) can drop any
// telemetry we emitted, preventing a round-trip when the emit endpoint and the
// receiver share a collector (echo guard — native-console template §3.2).
func newResource(serviceName string) *resource.Resource {
	emittedBy := attribute.String(otelident.EchoAttr, otelident.EchoValue)
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName(serviceName), emittedBy),
	)
	if err != nil {
		// A schema-URL mismatch is the only error path; fall back to the bare
		// attribute set rather than failing the exporter.
		return resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName(serviceName), emittedBy)
	}
	return r
}

// Start consumes the turn tail and emits a span per turn until ctx is done (the
// tail then closes its channel and Start returns). Errors are not produced by
// the loop itself — export failures are batched and retried by the SDK — so
// Start returns nil on a clean stop; callers should still Stop to flush.
func (e *Exporter) Start(ctx context.Context) error {
	e.logger.Info("otel exporter: started",
		"endpoint", e.cfg.Endpoint, "insecure", e.cfg.Insecure,
		"emit_prompt_content", e.cfg.EmitPromptContent, "emit_user_email", e.cfg.EmitUserEmail,
		"semconv", e.cfg.SemconvStability)
	for turn := range e.src.SubscribeAPITurns(ctx, e.cfg.PollInterval, e.logger) {
		e.export(ctx, turn)
	}
	return nil
}

// Stop flushes any batched spans and shuts the TracerProvider down, bounded by
// ctx. It is safe to call after Start has returned and is idempotent.
func (e *Exporter) Stop(ctx context.Context) error {
	if err := e.tp.Shutdown(ctx); err != nil {
		return fmt.Errorf("otel.Stop: %w", err)
	}
	return nil
}

// export turns one api_turns row into a span.
func (e *Exporter) export(ctx context.Context, turn models.APITurn) {
	root := e.resolveRoot(ctx, turn.ProjectID)

	start := turn.Timestamp
	if start.IsZero() {
		start = time.Now()
	}
	end := start
	if turn.TotalResponseMS > 0 {
		end = start.Add(time.Duration(turn.TotalResponseMS) * time.Millisecond)
	}

	_, span := e.tracer.Start(
		ctx, SpanName(turn),
		trace.WithTimestamp(start),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(Attributes(turn, nil, root, e.cfg.EmitUserEmail)...),
	)
	if turn.HTTPStatus >= 400 || turn.ErrorClass != "" {
		span.SetStatus(codes.Error, turn.ErrorMessage)
	}
	if e.cfg.EmitPromptContent {
		e.addContentEvent(span, turn)
	}
	span.End(trace.WithTimestamp(end))
}

// addContentEvent attaches the opt-in inference-details event. SuperBased
// Observer does not persist raw prompt or completion bodies (the no-content-in-
// DB invariant), so the event carries the available content metadata — the
// stable prompt/message-prefix hashes and any error message — rather than the
// raw bodies the OTel convention envisions. A deployment that needs full bodies
// must capture them at the proxy before they are discarded.
func (e *Exporter) addContentEvent(span trace.Span, turn models.APITurn) {
	attrs := make([]attribute.KeyValue, 0, 3)
	if turn.SystemPromptHash != "" {
		attrs = append(attrs, attribute.String("sbo.system_prompt.hash", turn.SystemPromptHash))
	}
	if turn.MessagePrefixHash != "" {
		attrs = append(attrs, attribute.String("sbo.message_prefix.hash", turn.MessagePrefixHash))
	}
	if turn.ErrorMessage != "" {
		attrs = append(attrs, attribute.String("sbo.error.message", turn.ErrorMessage))
	}
	span.AddEvent(eventInferenceDetails, trace.WithAttributes(attrs...))
}

// resolveRoot memoises project_id → root_path lookups across the run.
func (e *Exporter) resolveRoot(ctx context.Context, id int64) string {
	if id == 0 {
		return ""
	}
	if r, ok := e.rootCache[id]; ok {
		return r
	}
	r, err := e.resolver.ProjectRootByID(ctx, id)
	if err != nil {
		e.logger.Warn("otel exporter: project root lookup failed", "project_id", id, "err", err)
		return ""
	}
	e.rootCache[id] = r
	return r
}
