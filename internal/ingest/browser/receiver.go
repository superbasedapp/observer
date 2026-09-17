package browser

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/ingest/hostguard"
)

// maxBodyBytes caps a captured-turn request body to bound memory on a
// malformed or hostile request to the loopback listener. A single browser
// turn is small; 8 MiB is generous headroom.
const maxBodyBytes = 8 << 20 // 8 MiB

// DefaultAddr is the receiver's default loopback bind. It is deliberately
// NOT :8820 (the proxy) and NOT the dashboard mux — the browser rail gets
// its own dedicated port, mirroring the OTLP receiver's own-port posture.
const DefaultAddr = "127.0.0.1:8821"

// The capture endpoint path. Kept versioned so a future wire change can add
// /v2 without breaking older extensions.
const capturePath = "/v1/browser/capture"

// TokenHeader is the request header a client presents the shared ingress
// token in. Defense-in-depth: the listener is loopback-only AND default-off,
// but any local process could POST fabricated turns, so a correct token is
// required when one is configured (A4 /
// docs/audits/browser-m365-capture-audit-2026-07-16.md).
const TokenHeader = "X-SBO-Browser-Token" //nolint:gosec // G101: header NAME, not a credential.

// ErrNonLoopback is returned by New when an address is not loopback and
// AllowNonLoopback is false (the network-posture guard).
var ErrNonLoopback = errors.New("ingest/browser: refusing non-loopback bind without AllowNonLoopback")

// Handler ingests one raw captured-turn payload body. It is injected by the
// daemon (a closure over browserchat.Normalize → store.Ingest), so this
// package carries NO dependency on the browserchat schema or the store. A
// returned error is logged and surfaced to the client as a 500, but never
// panics the receiver.
type Handler func(ctx context.Context, body []byte) error

// Options configures a Receiver. Handler is required.
type Options struct {
	// Addr is the host:port bind. Empty defaults to DefaultAddr.
	Addr string
	// AllowNonLoopback permits a non-loopback bind (default false).
	AllowNonLoopback bool
	// Token is the shared secret a client must present in TokenHeader. When
	// non-empty every request is rejected 401 unless it matches (constant-
	// time). When "" the token gate is DISABLED — reachable only in tests /
	// callers that opt out; production wiring (cmd/observer/start.go) always
	// supplies an auto-generated token, so the loopback listener is never
	// unauthenticated in practice.
	Token   string
	Handler Handler
	Logger  *slog.Logger
}

// Receiver owns the loopback HTTP listener and its lifecycle.
type Receiver struct {
	opts       Options
	httpServer *http.Server
	httpLn     net.Listener
}

// New validates the options, enforces the loopback posture, and opens the
// listener (so a bind conflict fails fast at construction, before the daemon
// reports itself healthy). Call Start to begin serving.
func New(opts Options) (*Receiver, error) {
	if opts.Handler == nil {
		return nil, errors.New("ingest/browser: Handler is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Addr == "" {
		opts.Addr = DefaultAddr
	}
	if err := guardLoopback(opts.Addr, opts.AllowNonLoopback); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("ingest/browser: listen %s: %w", opts.Addr, err)
	}
	r := &Receiver{opts: opts, httpLn: ln}
	mux := http.NewServeMux()
	mux.HandleFunc(capturePath, r.handleCapture)
	r.httpServer = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return r, nil
}

// Start begins serving on the opened listener in a background goroutine and
// returns immediately. Use Shutdown to stop.
func (r *Receiver) Start() {
	go func() {
		if err := r.httpServer.Serve(r.httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.opts.Logger.Warn("ingest/browser: serve ended", "err", err)
		}
	}()
	r.opts.Logger.Info("ingest/browser: receiver listening", "addr", r.httpLn.Addr().String(), "path", capturePath)
}

// Shutdown gracefully stops the server. It is safe to call once.
func (r *Receiver) Shutdown(ctx context.Context) error {
	if r.httpServer != nil {
		if err := r.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("ingest/browser: shutdown: %w", err)
		}
	}
	return nil
}

// Addr reports the resolved bind address (useful when a :0 ephemeral port
// was requested, e.g. in tests).
func (r *Receiver) Addr() string {
	if r.httpLn == nil {
		return ""
	}
	return r.httpLn.Addr().String()
}

// handleCapture reads a captured-turn JSON body and runs the injected
// handler. It replies 204 on success, or an error status the client can log.
func (r *Receiver) handleCapture(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Loopback-only: reject a request whose Host header doesn't resolve to
	// loopback (a DNS-rebinding / cross-origin defense, in addition to the
	// loopback bind). Applies even when AllowNonLoopback opened the bind —
	// the capture rail is a same-machine channel.
	if !hostIsLoopback(req.Host) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Shared-token gate (defense-in-depth). Only enforced when a token is
	// configured; production wiring always supplies one.
	if r.opts.Token != "" {
		presented := req.Header.Get(TokenHeader)
		if subtle.ConstantTimeCompare([]byte(presented), []byte(r.opts.Token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	if err := r.opts.Handler(req.Context(), body); err != nil {
		r.opts.Logger.Warn("ingest/browser: handler error", "err", err)
		http.Error(w, "ingest failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// hostIsLoopback reports whether an HTTP Host header value targets loopback.
//
// The predicate itself moved to internal/ingest/hostguard when the OTLP
// receiver needed the same defense (NODE-OTLP-1, codebase audit 2026-09-16);
// this stays as the package-local spelling so the call site above reads the
// same, and so there is exactly ONE implementation to reason about.
func hostIsLoopback(host string) bool {
	return hostguard.IsLoopbackHost(host)
}

// guardLoopback enforces the network posture: a bind address must resolve to
// loopback unless the operator explicitly allowed otherwise.
func guardLoopback(addr string, allow bool) error {
	if allow {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("ingest/browser: bad addr %q: %w", addr, err)
	}
	if host == "" || host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: %q", ErrNonLoopback, addr)
	}
	return nil
}
