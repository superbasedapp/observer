package otlp

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"

	"github.com/marmutapp/superbased-observer/internal/genaiattr"
	"github.com/marmutapp/superbased-observer/internal/ingest/hostguard"
	"github.com/marmutapp/superbased-observer/internal/otlpjson"
)

// maxBodyBytes caps an OTLP/HTTP request body to bound memory on a malformed or
// hostile request to the loopback listener.
const maxBodyBytes = 16 << 20 // 16 MiB

// DefaultMaxDecompressedBytes is the finite DECOMPRESSED gzip cap every
// receiver gets unless Options.MaxDecompressedBytes overrides it. The
// COMPRESSED body is already bounded by
// http.MaxBytesReader, but the gunzip stream is otherwise io.ReadAll'd unbounded,
// so a small hostile payload could inflate to exhaust memory (a decompression
// bomb). Sized generously at 16× maxBodyBytes so a legitimate well-compressible
// OTLP payload is unaffected.
//
// Since NODE-OTLP-1 (codebase audit 2026-09-16) this is the DEFAULT, not an
// opt-in: a caller that leaves Options.MaxDecompressedBytes unset — the NODE —
// gets this bound instead of the old unbounded io.ReadAll. The previous
// "unbounded unless the edge asks" posture meant the node's :4318 listener
// could be OOM'd by a small hostile gzip payload, and no caller ever wanted
// that behavior; it was a byte-compatibility carve-out, not a feature. A
// caller that genuinely wants no bound must now say so with a negative value
// (see Options.MaxDecompressedBytes).
const DefaultMaxDecompressedBytes = 256 << 20 // 256 MiB

// HeaderEdgeToken is the HTTP header (and, lower-cased, the gRPC metadata key)
// that carries the receiver token when Options.RequireToken is set. The edge
// always sets it; the node sets it only for an opted-in non-loopback bind
// (T-475, SR27-B5), so a loopback node never consults this header.
const HeaderEdgeToken = "X-Observer-Edge-Token" //nolint:gosec // G101: HTTP header NAME, not a credential value

// metadataEdgeTokenKey is the gRPC metadata key for the receiver token (gRPC
// metadata keys are lower-cased).
const metadataEdgeTokenKey = "x-observer-edge-token"

// ErrNonLoopback is returned by New when an address is not loopback and
// AllowNonLoopback is false (the network-posture guard, §2.2 / L3).
var ErrNonLoopback = errors.New("ingest/otlp: refusing non-loopback bind without AllowNonLoopback")

// ErrOverCapacity is a signal-neutral sentinel an injected handler MAY return to
// signal backpressure (e.g. the edge WAL is at its depth cap). When a handler's
// error unwraps to ErrOverCapacity the HTTP transport maps it to 503
// (StatusServiceUnavailable) and the gRPC transport to codes.ResourceExhausted;
// EVERY other handler error keeps the existing 500 / plain-error mapping. This is
// an ADDITIVE seam (plan §Phase 4, Blocker 5): the node's handlers never return
// ErrOverCapacity, so the node path is byte-unchanged.
var ErrOverCapacity = errors.New("ingest/otlp: over capacity")

// ErrRetryLater is a sentinel an injected handler returns when the export was
// NOT stored because of a transient condition (for example SQLite lock
// contention) and the same export is expected to succeed on a later attempt.
// The HTTP transport maps it to 503 with Retry-After and the gRPC transport to
// codes.Unavailable: both are the OTLP-retryable answers, so the exporter
// resends instead of dropping the batch (P3-10). A handler must only return it
// for writes that are idempotent on redelivery.
var ErrRetryLater = errors.New("ingest/otlp: retry later")

// writeHandlerError answers a failed HTTP export by the handler error's class.
func writeHandlerError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrOverCapacity):
		http.Error(w, "over capacity", http.StatusServiceUnavailable)
	case errors.Is(err, ErrRetryLater):
		w.Header().Set("Retry-After", "1")
		http.Error(w, "temporarily unavailable, retry", http.StatusServiceUnavailable)
	default:
		http.Error(w, "ingest failed", http.StatusInternalServerError)
	}
}

// grpcHandlerError maps a failed gRPC export by the handler error's class.
func grpcHandlerError(err error) error {
	switch {
	case errors.Is(err, ErrOverCapacity):
		return status.Error(codes.ResourceExhausted, "over capacity")
	case errors.Is(err, ErrRetryLater):
		return status.Error(codes.Unavailable, "temporarily unavailable, retry")
	default:
		return err
	}
}

// Handler ingests one decoded OTLP logs export. It is injected by the daemon
// (otlpvendor.ParseLogs → store.UpsertTurnByRequestID) so this package carries
// no dependency on the Claude Code schema or the store. A returned error is logged
// and surfaced to the client as an OTLP partial failure, but never panics the
// receiver.
type Handler func(ctx context.Context, req *collogspb.ExportLogsServiceRequest) error

// TraceHandler ingests one decoded OTLP trace export. A *PartialTraces error
// is answered as an OTLP partial success (partial.go). Optional; injected by
// the generalized-observability subsystem (internal/obs) when [observability]
// is enabled, mirroring Handler's posture. Like Handler it carries NO schema
// or store dependency — the receiver stays generic. A nil TraceHandler means
// /v1/traces and the gRPC TraceService are simply not served.
type TraceHandler func(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) error

// MetricHandler ingests one decoded OTLP metrics export. Optional; injected by a
// caller (the observer-edge, P0-3) that wants the metrics signal. Like Handler /
// TraceHandler it carries NO schema or store dependency. A nil MetricHandler
// means /v1/metrics and the gRPC MetricsService are simply not served.
type MetricHandler func(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) error

// Outcome is the terminal disposition of one received request, reported through
// Options.OnOutcome for observability accounting.
type Outcome int

const (
	// OutcomeAccepted is a request that reached and was accepted by its handler.
	OutcomeAccepted Outcome = iota
	// OutcomeRejected is a request rejected before or by the handler; the reason
	// string names why.
	OutcomeRejected
)

// Reason strings reported alongside OutcomeRejected. HTTP proto-decode failures
// report ReasonMalformed; gRPC pre-service decode failures report ReasonDecode
// (the Export methods run AFTER decode, so a decode fault never reaches them —
// it is derived from the absence of a stats.InPayload event). ReasonAuth is
// reserved for the Phase-5 token gate.
const (
	ReasonAuth = "auth"
	// ReasonHost is a request rejected by the Host-header loopback guard
	// (NODE-OTLP-1): the listener is bound loopback-only, so it is a
	// same-machine channel, and a request naming any other host is a
	// DNS-rebinding / cross-origin attempt rather than a local exporter.
	// Distinct from ReasonAuth so an operator can tell "a page tried to reach
	// my receiver" from "a collector presented a bad token".
	ReasonHost = "host"
	// ReasonOrigin is a request refused by the browser guard (F13, the
	// residual of AUDIT-NODE-OTLP-1): it carried an Origin header or a
	// Sec-Fetch-Site of cross-site / same-site, so a web page sent it, not a
	// local exporter. Distinct from ReasonHost (which catches rebinding by
	// the Host header) so an operator can tell the two apart.
	ReasonOrigin = "origin"
	// ReasonContentType is a request refused because its Content-Type is not
	// an OTLP encoding (application/x-protobuf or application/json). The
	// CORS "simple" types (text/plain, form posts, none) are exactly what a
	// page can send without a preflight, so the browser-guarded receiver
	// never decodes them.
	ReasonContentType = "content_type"
	ReasonMethod      = "method"
	ReasonGzip        = "gzip"
	ReasonMalformed   = "malformed"
	ReasonDecode      = "decode"
	ReasonSize        = "size"
	ReasonHandler     = "handler"
)

// Signal label strings for OnOutcome.
const (
	sigLogs    = "logs"
	sigTraces  = "traces"
	sigMetrics = "metrics"
)

// HostGuardMode selects the Host-header loopback guard's posture for a
// receiver (NODE-OTLP-1). It is a TRI-STATE, not a bool, because "decide from
// the bind" is a genuinely different answer from "on" and "off", and only the
// caller knows which of the three it means.
type HostGuardMode int

const (
	// HostGuardAuto (the ZERO VALUE) derives the guard from the bind: a
	// receiver bound loopback-only is a same-machine channel and gets the
	// guard; one opened with AllowNonLoopback does not, because it must serve
	// the real host names its remote exporters send. This is the NODE's
	// posture and it is the zero value so a caller that never thinks about
	// this field still gets the defense.
	HostGuardAuto HostGuardMode = iota
	// HostGuardOn always applies the guard, whatever the bind.
	HostGuardOn
	// HostGuardOff never applies it.
	//
	// This is the EDGE's setting, and the reason the tri-state exists. The
	// edge is a collector: it binds loopback in the common sidecar
	// deployment, so HostGuardAuto would switch the guard ON — and then an
	// exporter in the same pod configured against a service alias
	// ("otel-collector:4318", an /etc/hosts or DNS name that resolves to
	// 127.0.0.1) sends `Host: otel-collector:4318` and is refused 403. That
	// is a legitimate client, and the alias is not attacker-controlled the
	// way a rebinding domain is. The edge does not need the guard either: it
	// has the receiver-token gate (RequireToken), which is a stronger check
	// than a Host header and is what its threat model already relies on.
	//
	// The node cannot make the same trade on a loopback bind: it has a token
	// only when an operator opts into a non-loopback bind (T-475), which is
	// exactly why the two receivers now say what they want instead of sharing
	// one inferred answer.
	HostGuardOff
)

// OutcomeHook is the accounting callback invoked EXACTLY ONCE per terminal
// request exit (HTTP: at each handler return; gRPC: once in the StatsHandler's
// HandleRPC(*stats.End)). It must be non-blocking and is never called
// concurrently for the same request. When nil the whole accounting path is a
// silent no-op, so existing (node) callers are unaffected.
type OutcomeHook func(signal string, outcome Outcome, reason string)

// Options configures a Receiver. At least one of Handler / TraceHandler /
// MetricHandler must be set; each signal (logs / traces / metrics) is served
// only when its handler is.
type Options struct {
	// GRPCAddr / HTTPAddr are host:port binds. Empty disables that transport.
	GRPCAddr string
	HTTPAddr string
	// AllowNonLoopback permits a non-loopback bind (default false — see §2.2).
	AllowNonLoopback bool
	// HostGuard selects the Host-header loopback guard's posture
	// (NODE-OTLP-1). The zero value, HostGuardAuto, derives it from the bind;
	// see HostGuardMode for why the edge sets HostGuardOff explicitly.
	HostGuard     HostGuardMode
	Handler       Handler
	TraceHandler  TraceHandler
	MetricHandler MetricHandler
	Logger        *slog.Logger
	// OnOutcome, when set, receives one accounting event per terminal request
	// exit (nil ⇒ no-op; the node leaves it unset). gRPC events are emitted
	// EXCLUSIVELY from the StatsHandler's HandleRPC(*stats.End), HTTP events
	// EXCLUSIVELY from the HTTP handlers — no double-count.
	OnOutcome OutcomeHook

	// RequireToken enables the ingress-trust gate on BOTH transports. DEFAULT
	// OFF. The edge always sets it; the node sets it only when
	// [ingest.otel].allow_non_loopback is on (T-475, closing SR27-B5), so a
	// loopback node path (HTTP mux + gRPC server option list) is byte-unchanged. When true, a
	// request must carry HeaderEdgeToken (HTTP) / the x-observer-edge-token gRPC
	// metadata key matching ReceiverToken (constant-time compared) or it is
	// rejected before the handler runs (HTTP: pre-decode 401; gRPC: a two-part
	// TagRPC-stamp + post-decode interceptor → codes.Unauthenticated, no WAL
	// write). This is a nil-safe receiver Option, NOT a global "non-loopback
	// requires a token" rule: each caller decides (R2-B4). Edge config
	// validation adds the non-loopback-needs-a-token rule edge-side, and
	// `observer start` adds it node-side.
	RequireToken bool
	// ReceiverToken is the shared secret compared against the request token when
	// RequireToken is set. Ignored when RequireToken is false.
	ReceiverToken string
	// AcceptToken, when set (and RequireToken is set), is a SECOND way a
	// request token may authorize: a value that does not match ReceiverToken
	// is offered to it, and a true answer admits the request. The node sets
	// it to the active-ship-token check so a cloud environment's exporter can
	// carry a per-environment, short-lived, revocable ship token instead of
	// the node's one shared receiver token (CLOUDTEL-1, cloud-agents decision
	// CA-D18). nil (the edge, and every node without a ship token) keeps the
	// shared-token comparison as the only check. It runs per request, before
	// decode; it must be cheap and must not log the value.
	AcceptToken func(token string) bool

	// GRPCMaxRecvBytes, when > 0, sets grpc.MaxRecvMsgSize on the gRPC server so
	// an oversized message is rejected pre-service (a size reject) and the
	// pre-auth decode cost is bounded. Edge/test seam; the zero value leaves the
	// node's gRPC server on the grpc default, so the node server option list is
	// byte-unchanged.
	GRPCMaxRecvBytes int

	// MaxDecompressedBytes, when > 0, bounds the DECOMPRESSED gzip stream to this
	// many bytes (an over-cap inflate ⇒ 413).
	//
	// ZERO NOW MEANS THE DEFAULT, not unbounded (NODE-OTLP-1, codebase audit
	// 2026-09-16): an unset value resolves to DefaultMaxDecompressedBytes, so
	// the node's listener is bounded without having to opt in. A NEGATIVE value
	// is the explicit "no bound" escape hatch, which nothing in this repo uses
	// and which no production caller should.
	MaxDecompressedBytes int

	// maxBody, when > 0, overrides the default HTTP body cap (maxBodyBytes). It
	// is an edge/test seam; the zero value keeps the node on the 16 MiB default.
	maxBody int
}

// Receiver owns the OTLP gRPC + HTTP listeners and their lifecycle.
type Receiver struct {
	opts       Options
	grpcServer *grpc.Server
	grpcLn     net.Listener
	httpServer *http.Server
	httpLn     net.Listener
}

// New validates the options, enforces the loopback posture, and opens the
// configured listeners (so a bind conflict fails fast at construction, before
// the daemon reports itself healthy). Call Start to begin serving.
func New(opts Options) (*Receiver, error) {
	if opts.Handler == nil && opts.TraceHandler == nil && opts.MetricHandler == nil {
		return nil, errors.New("ingest/otlp: at least one of Handler / TraceHandler / MetricHandler is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.GRPCAddr == "" && opts.HTTPAddr == "" {
		return nil, errors.New("ingest/otlp: at least one of GRPCAddr/HTTPAddr is required")
	}
	// Fail-fast at construction if the token gate is enabled with an EMPTY
	// secret: an empty ReceiverToken would make ConstantTimeCompare("","")==1 —
	// a request with a missing header (HTTP) or an explicitly-empty metadata
	// value (gRPC) would authorize, i.e. the gate fails OPEN. Edge config
	// validation also forbids this, but the SHARED receiver must not fail open
	// as a reusable component.
	if opts.RequireToken && opts.ReceiverToken == "" {
		return nil, errors.New("ingest/otlp: RequireToken set but ReceiverToken is empty")
	}
	r := &Receiver{opts: opts}

	if opts.GRPCAddr != "" {
		if err := guardLoopback(opts.GRPCAddr, opts.AllowNonLoopback); err != nil {
			return nil, err
		}
		ln, err := net.Listen("tcp", opts.GRPCAddr)
		if err != nil {
			return nil, fmt.Errorf("ingest/otlp: grpc listen %s: %w", opts.GRPCAddr, err)
		}
		r.grpcLn = ln
		// Build server options additively so a caller that sets none of the
		// outcome hook / recv cap / token gate (the NODE) gets exactly
		// grpc.NewServer() with no options — byte-unchanged. The StatsHandler is
		// installed when an outcome sink OR the token gate is configured (its
		// TagRPC does both the accounting decode-mark AND the Phase-5 token
		// auth-stamp); the post-decode unary interceptor that ENFORCES the stamp
		// is installed ONLY when RequireToken (a StatsHandler alone cannot abort
		// an RPC — R4-B2).
		var serverOpts []grpc.ServerOption
		if opts.GRPCMaxRecvBytes > 0 {
			serverOpts = append(serverOpts, grpc.MaxRecvMsgSize(opts.GRPCMaxRecvBytes))
		}
		if opts.OnOutcome != nil || opts.RequireToken {
			serverOpts = append(serverOpts, grpc.StatsHandler(&outcomeStatsHandler{
				onOutcome:    opts.OnOutcome,
				requireToken: opts.RequireToken,
				token:        opts.ReceiverToken,
				accept:       opts.AcceptToken,
			}))
		}
		if opts.RequireToken {
			serverOpts = append(serverOpts, grpc.ChainUnaryInterceptor(tokenGateInterceptor))
		}
		r.grpcServer = grpc.NewServer(serverOpts...)
		if opts.Handler != nil {
			collogspb.RegisterLogsServiceServer(r.grpcServer, &logsService{handler: opts.Handler, logger: opts.Logger})
		}
		if opts.TraceHandler != nil {
			coltracepb.RegisterTraceServiceServer(r.grpcServer, &traceService{handler: opts.TraceHandler, logger: opts.Logger})
		}
		if opts.MetricHandler != nil {
			colmetricspb.RegisterMetricsServiceServer(r.grpcServer, &metricsService{handler: opts.MetricHandler, logger: opts.Logger})
		}
	}

	if opts.HTTPAddr != "" {
		if err := guardLoopback(opts.HTTPAddr, opts.AllowNonLoopback); err != nil {
			r.closeListeners()
			return nil, err
		}
		ln, err := net.Listen("tcp", opts.HTTPAddr)
		if err != nil {
			r.closeListeners()
			return nil, fmt.Errorf("ingest/otlp: http listen %s: %w", opts.HTTPAddr, err)
		}
		r.httpLn = ln
		mux := http.NewServeMux()
		if opts.Handler != nil {
			mux.HandleFunc("/v1/logs", r.withIngressGuards(sigLogs, r.handleHTTPLogs))
		}
		if opts.TraceHandler != nil {
			traces := r.withIngressGuards(sigTraces, r.handleHTTPTraces)
			mux.HandleFunc("/v1/traces", traces)
			// The Langfuse SDK exporters append this path to
			// LANGFUSE_BASE_URL (W5-2): the same handler and the same
			// guards, so a Langfuse-instrumented app points at the machine
			// unchanged. Langfuse's Basic public:secret header is never a
			// credential here (docs/sdk/langfuse.md).
			mux.HandleFunc(genaiattr.LangfuseOTLPTracesPath, traces)
		}
		if opts.MetricHandler != nil {
			mux.HandleFunc("/v1/metrics", r.withIngressGuards(sigMetrics, r.handleHTTPMetrics))
		}
		r.httpServer = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	}
	return r, nil
}

// Start begins serving on the opened listeners in background goroutines and
// returns immediately. Use Shutdown to stop.
func (r *Receiver) Start() {
	if r.grpcServer != nil {
		go func() {
			if err := r.grpcServer.Serve(r.grpcLn); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				r.opts.Logger.Warn("ingest/otlp: grpc serve ended", "err", err)
			}
		}()
		r.opts.Logger.Info("ingest/otlp: gRPC receiver listening", "addr", r.grpcLn.Addr().String(),
			"logs", r.opts.Handler != nil, "traces", r.opts.TraceHandler != nil, "metrics", r.opts.MetricHandler != nil)
	}
	if r.httpServer != nil {
		go func() {
			if err := r.httpServer.Serve(r.httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				r.opts.Logger.Warn("ingest/otlp: http serve ended", "err", err)
			}
		}()
		r.opts.Logger.Info("ingest/otlp: HTTP receiver listening", "addr", r.httpLn.Addr().String(),
			"logs", r.opts.Handler != nil, "traces", r.opts.TraceHandler != nil, "metrics", r.opts.MetricHandler != nil)
	}
}

// Shutdown gracefully stops both servers. It is safe to call once.
func (r *Receiver) Shutdown(ctx context.Context) error {
	var errs []error
	if r.grpcServer != nil {
		// GracefulStop waits for every in-flight RPC with no deadline of its
		// own: one Export blocked in a store write would hold the daemon's
		// stop until the process watchdog hard-exits (P3-28). It runs behind
		// a done channel and is cut to Stop() when ctx ends.
		done := make(chan struct{})
		go func() {
			r.grpcServer.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			// Stop closes the listeners and connections and cancels every
			// RPC's context, but grpc-go still waits for each handler to
			// return before it does, and a handler that ignores its context
			// (a write stuck in SQLite) would hold it. Stop therefore runs in
			// the background too and Shutdown returns at the deadline; both
			// goroutines end when the stuck handler returns.
			go r.grpcServer.Stop()
			errs = append(errs, fmt.Errorf("ingest/otlp: grpc graceful stop overran, stopped: %w", ctx.Err()))
		}
	}
	if r.httpServer != nil {
		if err := r.httpServer.Shutdown(ctx); err != nil {
			_ = r.httpServer.Close()
			errs = append(errs, fmt.Errorf("ingest/otlp: http shutdown: %w", err))
		}
	}
	return errors.Join(errs...)
}

// GRPCAddr / HTTPAddr report the resolved bind addresses (useful when a :0
// ephemeral port was requested, e.g. in tests). Empty when that transport is
// disabled.
func (r *Receiver) GRPCAddr() string {
	if r.grpcLn == nil {
		return ""
	}
	return r.grpcLn.Addr().String()
}

func (r *Receiver) HTTPAddr() string {
	if r.httpLn == nil {
		return ""
	}
	return r.httpLn.Addr().String()
}

func (r *Receiver) closeListeners() {
	if r.grpcLn != nil {
		_ = r.grpcLn.Close()
	}
	if r.httpLn != nil {
		_ = r.httpLn.Close()
	}
}

// withIngressGuards wraps an HTTP signal handler with the two pre-decode
// ingress checks, in order: the Host-header loopback guard (when this receiver
// is a same-machine channel — see hostGuardEnabled) and the receiver-token
// check (when RequireToken is set).
//
// Both run BEFORE the wrapped handler, so a rejected request costs no
// MaxBytesReader / gunzip / proto.Unmarshal, and each reports its own reason
// for the request's signal (ReasonHost / ReasonAuth). The token is
// constant-time compared (crypto/subtle) because it is a secret; the host is a
// plain equality test against a closed vocabulary, which is not.
//
// With NEITHER check applicable the wrapper is a pure pass-through, so a
// receiver that is both non-loopback-bound and token-less keeps its exact old
// registration — that combination is the one `observer doctor` warns about
// rather than one this package can silently fix.
func (r *Receiver) withIngressGuards(signal string, next http.HandlerFunc) http.HandlerFunc {
	hostGuard := r.hostGuardEnabled()
	browserGuard := r.browserGuardEnabled()
	if !hostGuard && !browserGuard && !r.opts.RequireToken {
		return next
	}
	want := []byte(r.opts.ReceiverToken)
	return func(w http.ResponseWriter, req *http.Request) {
		if hostGuard && !hostguard.IsLoopbackHost(req.Host) {
			http.Error(w, "forbidden", http.StatusForbidden)
			r.report(signal, OutcomeRejected, ReasonHost)
			return
		}
		if browserGuard {
			if fromBrowser(req) {
				http.Error(w, "forbidden: browser requests are not accepted", http.StatusForbidden)
				r.report(signal, OutcomeRejected, ReasonOrigin)
				return
			}
			// A non-POST falls through to the handler's method check, so
			// the outcome still names the method, not the missing type.
			if req.Method == http.MethodPost && !otlpContentType(req) {
				http.Error(w, "unsupported content type: use application/x-protobuf or application/json", http.StatusUnsupportedMediaType)
				r.report(signal, OutcomeRejected, ReasonContentType)
				return
			}
		}
		if r.opts.RequireToken {
			got := []byte(req.Header.Get(HeaderEdgeToken))
			if !tokenMatches(got, want, r.opts.AcceptToken) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				r.report(signal, OutcomeRejected, ReasonAuth)
				return
			}
		}
		next(w, req)
	}
}

// handleHTTPLogs decodes an OTLP/HTTP protobuf logs export (optionally gzipped),
// runs the handler, and replies with a marshaled ExportLogsServiceResponse.
func (r *Receiver) handleHTTPLogs(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		r.report(sigLogs, OutcomeRejected, ReasonMethod)
		return
	}
	var body io.Reader = http.MaxBytesReader(w, req.Body, r.maxBody())
	gzipped := false
	if req.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			r.report(sigLogs, OutcomeRejected, ReasonGzip)
			return
		}
		defer func() { _ = gz.Close() }()
		// Bound the DECOMPRESSED stream (the compressed body is already bounded
		// by MaxBytesReader) so a gzip bomb cannot exhaust memory: read at most
		// cap+1 bytes so an over-cap inflate is detectable without buffering the
		// whole bomb. Since NODE-OTLP-1 the cap is finite for EVERY caller — an
		// unset Options.MaxDecompressedBytes resolves to
		// DefaultMaxDecompressedBytes — so this is the normal path, not an
		// edge-only opt-in. Only an explicitly NEGATIVE cap (nothing in this
		// repo) takes the unbounded else-branch.
		if capB := r.maxDecompressedCap(); capB > 0 {
			body = io.LimitReader(gz, capB+1)
			gzipped = true
		} else {
			body = gz
		}
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		r.report(sigLogs, OutcomeRejected, readReason(err))
		return
	}
	if gzipped && int64(len(raw)) > r.maxDecompressedCap() {
		http.Error(w, "decompressed body too large", http.StatusRequestEntityTooLarge)
		r.report(sigLogs, OutcomeRejected, ReasonGzip)
		return
	}
	// A JSON body is decoded through a generic tree plus protojson, a
	// several-fold copy of its size, so it is held to the plain body cap
	// even when gzip let it inflate further (P3-39).
	if isJSON(req) && int64(len(raw)) > r.maxBody() {
		http.Error(w, "JSON body too large", http.StatusRequestEntityTooLarge)
		r.report(sigLogs, OutcomeRejected, ReasonSize)
		return
	}
	var in collogspb.ExportLogsServiceRequest
	if err := decodeBody(req, raw, &in); err != nil {
		http.Error(w, malformedText(req), http.StatusBadRequest)
		r.report(sigLogs, OutcomeRejected, ReasonMalformed)
		return
	}
	if err := r.opts.Handler(req.Context(), &in); err != nil {
		r.opts.Logger.Warn("ingest/otlp: http handler error", "err", err)
		writeHandlerError(w, err)
		r.report(sigLogs, OutcomeRejected, ReasonHandler)
		return
	}
	out, ctype, err := encodeResponse(req, &collogspb.ExportLogsServiceResponse{})
	if err != nil {
		http.Error(w, "marshal response", http.StatusInternalServerError)
		r.report(sigLogs, OutcomeRejected, ReasonHandler)
		return
	}
	w.Header().Set("Content-Type", ctype)
	_, _ = w.Write(out)
	r.report(sigLogs, OutcomeAccepted, "")
}

// handleHTTPTraces decodes an OTLP/HTTP protobuf trace export (optionally
// gzipped), runs the trace handler, and replies with a marshaled
// ExportTraceServiceResponse. Mirrors handleHTTPLogs exactly.
func (r *Receiver) handleHTTPTraces(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		r.report(sigTraces, OutcomeRejected, ReasonMethod)
		return
	}
	var body io.Reader = http.MaxBytesReader(w, req.Body, r.maxBody())
	gzipped := false
	if req.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			r.report(sigTraces, OutcomeRejected, ReasonGzip)
			return
		}
		defer func() { _ = gz.Close() }()
		// Bound the DECOMPRESSED stream (the compressed body is already bounded
		// by MaxBytesReader) so a gzip bomb cannot exhaust memory: read at most
		// cap+1 bytes so an over-cap inflate is detectable without buffering the
		// whole bomb. Since NODE-OTLP-1 the cap is finite for EVERY caller — an
		// unset Options.MaxDecompressedBytes resolves to
		// DefaultMaxDecompressedBytes — so this is the normal path, not an
		// edge-only opt-in. Only an explicitly NEGATIVE cap (nothing in this
		// repo) takes the unbounded else-branch.
		if capB := r.maxDecompressedCap(); capB > 0 {
			body = io.LimitReader(gz, capB+1)
			gzipped = true
		} else {
			body = gz
		}
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		r.report(sigTraces, OutcomeRejected, readReason(err))
		return
	}
	if gzipped && int64(len(raw)) > r.maxDecompressedCap() {
		http.Error(w, "decompressed body too large", http.StatusRequestEntityTooLarge)
		r.report(sigTraces, OutcomeRejected, ReasonGzip)
		return
	}
	// A JSON body is decoded through a generic tree plus protojson, a
	// several-fold copy of its size, so it is held to the plain body cap
	// even when gzip let it inflate further (P3-39).
	if isJSON(req) && int64(len(raw)) > r.maxBody() {
		http.Error(w, "JSON body too large", http.StatusRequestEntityTooLarge)
		r.report(sigTraces, OutcomeRejected, ReasonSize)
		return
	}
	var in coltracepb.ExportTraceServiceRequest
	if err := decodeBody(req, raw, &in); err != nil {
		http.Error(w, malformedText(req), http.StatusBadRequest)
		r.report(sigTraces, OutcomeRejected, ReasonMalformed)
		return
	}
	herr := r.opts.TraceHandler(req.Context(), &in)
	resp, ok := traceResponse(herr)
	if !ok {
		r.opts.Logger.Warn("ingest/otlp: http trace handler error", "err", herr)
		writeHandlerError(w, herr)
		r.report(sigTraces, OutcomeRejected, ReasonHandler)
		return
	}
	out, ctype, err := encodeResponse(req, resp)
	if err != nil {
		http.Error(w, "marshal response", http.StatusInternalServerError)
		r.report(sigTraces, OutcomeRejected, ReasonHandler)
		return
	}
	w.Header().Set("Content-Type", ctype)
	_, _ = w.Write(out)
	r.report(sigTraces, OutcomeAccepted, "")
}

// handleHTTPMetrics decodes an OTLP/HTTP protobuf metrics export (optionally
// gzipped), runs the metric handler, and replies with a marshaled
// ExportMetricsServiceResponse. Mirrors handleHTTPLogs / handleHTTPTraces
// exactly (P0-3 metrics signal).
func (r *Receiver) handleHTTPMetrics(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		r.report(sigMetrics, OutcomeRejected, ReasonMethod)
		return
	}
	var body io.Reader = http.MaxBytesReader(w, req.Body, r.maxBody())
	gzipped := false
	if req.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			r.report(sigMetrics, OutcomeRejected, ReasonGzip)
			return
		}
		defer func() { _ = gz.Close() }()
		// Bound the DECOMPRESSED stream (the compressed body is already bounded
		// by MaxBytesReader) so a gzip bomb cannot exhaust memory: read at most
		// cap+1 bytes so an over-cap inflate is detectable without buffering the
		// whole bomb. Since NODE-OTLP-1 the cap is finite for EVERY caller — an
		// unset Options.MaxDecompressedBytes resolves to
		// DefaultMaxDecompressedBytes — so this is the normal path, not an
		// edge-only opt-in. Only an explicitly NEGATIVE cap (nothing in this
		// repo) takes the unbounded else-branch.
		if capB := r.maxDecompressedCap(); capB > 0 {
			body = io.LimitReader(gz, capB+1)
			gzipped = true
		} else {
			body = gz
		}
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		r.report(sigMetrics, OutcomeRejected, readReason(err))
		return
	}
	if gzipped && int64(len(raw)) > r.maxDecompressedCap() {
		http.Error(w, "decompressed body too large", http.StatusRequestEntityTooLarge)
		r.report(sigMetrics, OutcomeRejected, ReasonGzip)
		return
	}
	// A JSON body is decoded through a generic tree plus protojson, a
	// several-fold copy of its size, so it is held to the plain body cap
	// even when gzip let it inflate further (P3-39).
	if isJSON(req) && int64(len(raw)) > r.maxBody() {
		http.Error(w, "JSON body too large", http.StatusRequestEntityTooLarge)
		r.report(sigMetrics, OutcomeRejected, ReasonSize)
		return
	}
	var in colmetricspb.ExportMetricsServiceRequest
	if err := decodeBody(req, raw, &in); err != nil {
		http.Error(w, malformedText(req), http.StatusBadRequest)
		r.report(sigMetrics, OutcomeRejected, ReasonMalformed)
		return
	}
	if err := r.opts.MetricHandler(req.Context(), &in); err != nil {
		r.opts.Logger.Warn("ingest/otlp: http metric handler error", "err", err)
		writeHandlerError(w, err)
		r.report(sigMetrics, OutcomeRejected, ReasonHandler)
		return
	}
	out, ctype, err := encodeResponse(req, &colmetricspb.ExportMetricsServiceResponse{})
	if err != nil {
		http.Error(w, "marshal response", http.StatusInternalServerError)
		r.report(sigMetrics, OutcomeRejected, ReasonHandler)
		return
	}
	w.Header().Set("Content-Type", ctype)
	_, _ = w.Write(out)
	r.report(sigMetrics, OutcomeAccepted, "")
}

// traceService is the gRPC TraceService implementation; Export defers to the
// injected trace handler.
type traceService struct {
	coltracepb.UnimplementedTraceServiceServer
	handler TraceHandler
	logger  *slog.Logger
}

func (s *traceService) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	err := s.handler(ctx, req)
	resp, ok := traceResponse(err)
	if !ok {
		s.logger.Warn("ingest/otlp: grpc trace handler error", "err", err)
		return nil, grpcHandlerError(err)
	}
	return resp, nil
}

// logsService is the gRPC LogsService implementation; Export defers to the
// injected handler.
type logsService struct {
	collogspb.UnimplementedLogsServiceServer
	handler Handler
	logger  *slog.Logger
}

func (s *logsService) Export(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	if err := s.handler(ctx, req); err != nil {
		s.logger.Warn("ingest/otlp: grpc handler error", "err", err)
		return nil, grpcHandlerError(err)
	}
	return &collogspb.ExportLogsServiceResponse{}, nil
}

// metricsService is the gRPC MetricsService implementation; Export defers to the
// injected metric handler.
type metricsService struct {
	colmetricspb.UnimplementedMetricsServiceServer
	handler MetricHandler
	logger  *slog.Logger
}

func (s *metricsService) Export(ctx context.Context, req *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	if err := s.handler(ctx, req); err != nil {
		s.logger.Warn("ingest/otlp: grpc metric handler error", "err", err)
		return nil, grpcHandlerError(err)
	}
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

// report invokes the outcome hook exactly once for one terminal HTTP exit; nil
// hook ⇒ silent no-op (node unaffected).
func (r *Receiver) report(signal string, outcome Outcome, reason string) {
	if r.opts.OnOutcome != nil {
		r.opts.OnOutcome(signal, outcome, reason)
	}
}

// maxBody is the effective HTTP body cap: the opts override when set, else the
// 16 MiB default.
func (r *Receiver) maxBody() int64 {
	if r.opts.maxBody > 0 {
		return int64(r.opts.maxBody)
	}
	return maxBodyBytes
}

// maxDecompressedCap is the effective DECOMPRESSED gzip cap: the opts value
// when set, DefaultMaxDecompressedBytes when UNSET (NODE-OTLP-1 — the node
// used to get no bound here at all), and 0 ("unbounded", the caller's explicit
// choice) when the opts value is negative.
func (r *Receiver) maxDecompressedCap() int64 {
	switch {
	case r.opts.MaxDecompressedBytes > 0:
		return int64(r.opts.MaxDecompressedBytes)
	case r.opts.MaxDecompressedBytes < 0:
		return 0
	default:
		return DefaultMaxDecompressedBytes
	}
}

// hostGuardEnabled reports whether the Host-header loopback check applies to
// this receiver (NODE-OTLP-1). Table-driven over HostGuardMode; AUTO branches
// on the listener's CAPABILITY, never on who constructed it — a receiver bound
// loopback-only is a SAME-MACHINE channel, so a request naming any other host
// is a rebinding attempt and is refused (the browser rail's posture, shared
// through internal/ingest/hostguard), while one opened with AllowNonLoopback
// must serve the real host names its remote exporters send.
//
// See HostGuardMode for why AUTO is not good enough for every caller: a
// loopback-bound EDGE legitimately receives an /etc/hosts service alias in the
// Host header and sets HostGuardOff, relying on its token gate instead.
func (r *Receiver) hostGuardEnabled() bool {
	switch r.opts.HostGuard {
	case HostGuardOn:
		return true
	case HostGuardOff:
		return false
	default: // HostGuardAuto — the zero value.
		return !r.opts.AllowNonLoopback
	}
}

// browserGuardEnabled reports whether the browser guard (F13) applies: the
// Origin / Sec-Fetch-Site refusal and the OTLP content-type allow-list. It is
// on for every receiver WITHOUT a token gate, because such a receiver's only
// defence is that nothing remote can reach it, and a web page in a local
// browser can: a CORS "simple" POST (text/plain, a form, no type) needs no
// preflight and would otherwise be decoded and ingested, letting the page
// forge spans, cost, user and tenant (which feed admission budgets). A
// token-gated receiver (the edge, a non-loopback node) is off: the token
// travels in a custom header, which a page can only send after a preflight
// this receiver never answers.
func (r *Receiver) browserGuardEnabled() bool {
	return !r.opts.RequireToken
}

// fromBrowser reports whether a request was sent by a web page. A browser
// stamps Origin on every cross-origin request and on every POST (a native
// exporter never sets it), and Sec-Fetch-Site names the initiator's site.
// Any Origin, including the opaque "null", is refused; Sec-Fetch-Site
// "none" (a user navigation) and "same-origin" are not by themselves a page
// of another site.
func fromBrowser(req *http.Request) bool {
	if _, ok := req.Header["Origin"]; ok {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Site"))) {
	case "cross-site", "same-site":
		return true
	}
	return false
}

// otlpContentType reports whether the request's Content-Type is one the OTLP
// encoding table accepts (internal/otlpjson.Encoding, the org gateway's
// rule): the two OTLP media types (parameters such as charset allowed), or
// NO Content-Type at all, which is protobuf, the encoding every OTLP/HTTP
// exporter defaulted to before JSON existed (review R-A13: a Plane B native
// exporter that omits the header must not be refused). Any other type is
// not. A browser cannot use the missing-type case to get in: every POST a
// page makes carries Origin, which fromBrowser refuses first.
func otlpContentType(req *http.Request) bool {
	_, err := otlpjson.Encoding(req.Header.Get("Content-Type"))
	return err == nil
}

// readReason classifies a body-read error: a MaxBytesReader overflow is a size
// reject; anything else is treated as malformed input.
func readReason(err error) string {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return ReasonSize
	}
	return ReasonMalformed
}

// outcomeStatsHandler is the gRPC accounting StatsHandler. It is installed when
// Options.OnOutcome is set OR Options.RequireToken is set (its TagRPC does both
// the accounting decode-mark AND the Phase-5 token auth-stamp); a caller that
// sets NEITHER — the node — gets no StatsHandler, so the node's gRPC server is
// byte-unchanged. The token-ENFORCING post-decode unary interceptor
// (tokenGateInterceptor) is installed ONLY when RequireToken. It performs the
// SINGLE exactly-once terminal accounting per
// RPC in HandleRPC(*stats.End) — which fires for EVERY RPC, including a
// pre-service decode/size failure that never reaches the Export method — and
// derives the reject reason from whether a stats.InPayload (successful decode)
// was seen, so a handler failure is never mis-attributed to decode.
type outcomeStatsHandler struct {
	onOutcome OutcomeHook
	// requireToken / token are the Phase-5 ingress-trust inputs. When
	// requireToken is set, TagRPC validates the metadata token at RPC creation
	// and STAMPS the result on rpcAccounting.authed (it cannot abort — R4-B2);
	// the tokenGateInterceptor reads the stamp post-decode and enforces it. When
	// requireToken is false, TagRPC stamps authed=true so the interceptor (if
	// even installed) is a no-op.
	requireToken bool
	token        string
	// accept is Options.AcceptToken (nil-safe).
	accept func(string) bool
}

// rpcAccounting is the per-RPC state carried in the TagRPC context. It tracks the
// decode marker (for outcome-reason derivation) and the Phase-5 auth stamp
// (TagRPC validates the receiver token and stamps authed; the post-decode
// tokenGateInterceptor reads it).
type rpcAccounting struct {
	method       string
	sawInPayload bool
	authed       bool
}

type rpcAccountingKey struct{}

// report invokes the outcome hook when set; nil-safe because the StatsHandler is
// now installed when RequireToken even if OnOutcome is nil (the edge may not set
// OnOutcome until a later phase), so an unconditional call would nil-panic.
func (h *outcomeStatsHandler) report(signal string, outcome Outcome, reason string) {
	if h.onOutcome != nil {
		h.onOutcome(signal, outcome, reason)
	}
}

// TagRPC allocates per-RPC accounting state AND fills the Phase-5 auth-stamp
// slot: when requireToken is set it validates the metadata receiver token at RPC
// creation (constant-time compared) and stamps authed accordingly — it does NOT
// abort, because a StatsHandler.TagRPC can only return a context (R4-B2); the
// tokenGateInterceptor enforces the stamp after decode. When requireToken is
// false, authed is stamped true so the gate is a no-op.
func (h *outcomeStatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	acc := &rpcAccounting{method: info.FullMethodName}
	if h.requireToken {
		acc.authed = tokenAuthorized(ctx, h.token, h.accept)
	} else {
		acc.authed = true
	}
	return context.WithValue(ctx, rpcAccountingKey{}, acc)
}

// HandleRPC marks a successful decode on InPayload and does the single terminal
// accounting on End.
func (h *outcomeStatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	st, _ := ctx.Value(rpcAccountingKey{}).(*rpcAccounting)
	if st == nil {
		return
	}
	switch ev := s.(type) {
	case *stats.InPayload:
		// A payload was decoded ⇒ the RPC reached (or will reach) the service
		// method; any later failure is a handler/auth fault, not a decode fault.
		st.sawInPayload = true
	case *stats.End:
		signal := signalFromFullMethod(st.method)
		if ev.Error == nil {
			h.report(signal, OutcomeAccepted, "")
			return
		}
		reason := ReasonHandler
		switch {
		case status.Code(ev.Error) == codes.Unauthenticated:
			// The tokenGateInterceptor rejected an unauthenticated RPC (post
			// decode, so sawInPayload is true — classify by the code, not the
			// decode marker).
			reason = ReasonAuth
		case !st.sawInPayload:
			// Failed BEFORE decode/service: size (over MaxRecvMsgSize) vs a
			// malformed-protobuf decode fault, distinguished by the gRPC code
			// WITHOUT parsing error text.
			if status.Code(ev.Error) == codes.ResourceExhausted {
				reason = ReasonSize
			} else {
				reason = ReasonDecode
			}
		}
		h.report(signal, OutcomeRejected, reason)
	}
}

// tokenAuthorized reports whether the incoming gRPC metadata carries a receiver
// token matching want (constant-time compared), or one accept admits. A missing
// metadata / missing key is unauthorized.
func tokenAuthorized(ctx context.Context, want string, accept func(string) bool) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	vals := md.Get(metadataEdgeTokenKey)
	if len(vals) == 0 {
		return false
	}
	return tokenMatches([]byte(vals[0]), []byte(want), accept)
}

// tokenMatches is the one token rule both transports apply: the shared
// receiver token (constant-time compared), else Options.AcceptToken when set.
// An empty presented value never reaches accept.
func tokenMatches(got, want []byte, accept func(string) bool) bool {
	if subtle.ConstantTimeCompare(got, want) == 1 {
		return true
	}
	return accept != nil && len(got) > 0 && accept(string(got))
}

// tokenGateInterceptor is the post-decode half of the two-part gRPC auth: it
// reads the auth stamp TagRPC placed on the context and, if the RPC is not
// authed, returns codes.Unauthenticated WITHOUT invoking the injected handler
// and BEFORE any WAL write. It is installed ONLY when RequireToken is set, so
// the node's gRPC server carries no interceptor. A missing stamp (no
// StatsHandler ran) is treated as unauthorized — fail-closed.
func tokenGateInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	acc, _ := ctx.Value(rpcAccountingKey{}).(*rpcAccounting)
	if acc == nil || !acc.authed {
		return nil, status.Error(codes.Unauthenticated, "invalid or missing receiver token")
	}
	return handler(ctx, req)
}

// TagConn / HandleConn are required by stats.Handler but unused here.
func (h *outcomeStatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}
func (h *outcomeStatsHandler) HandleConn(context.Context, stats.ConnStats) {}

// signalFromFullMethod maps a gRPC full method name to its OTLP signal label.
func signalFromFullMethod(m string) string {
	switch {
	case strings.Contains(m, "TraceService"):
		return sigTraces
	case strings.Contains(m, "LogsService"):
		return sigLogs
	case strings.Contains(m, "MetricsService"):
		return sigMetrics
	default:
		return ""
	}
}

// guardLoopback enforces the network posture: a bind address must resolve to
// loopback unless the operator explicitly allowed otherwise.
func guardLoopback(addr string, allow bool) error {
	if allow {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("ingest/otlp: bad addr %q: %w", addr, err)
	}
	// An EMPTY host (e.g. ":4317") binds ALL interfaces — it is NOT
	// loopback-safe and now requires AllowNonLoopback, exactly like "0.0.0.0"
	// (§2.6, Blocker 7). Only "localhost" and explicit loopback IPs stay safe
	// without the opt-in, so the node's explicit 127.0.0.1 defaults are
	// unaffected.
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: %q", ErrNonLoopback, addr)
	}
	return nil
}
