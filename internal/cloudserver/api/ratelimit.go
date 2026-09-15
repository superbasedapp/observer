package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// Rate limiting (plan §6 CI-P6, "per-IP/device/account rate limits; abuse
// caps"). Production uses the shared RateLimiter supplied by the cloud store;
// the small in-memory fixed-window implementation below is retained only as an
// explicit test/development backend. Keeping the HTTP policy independent from
// the counter implementation makes the security boundary testable without
// weakening the horizontally-scaled deployment contract.
//
//   - per-IP on the UNAUTHENTICATED surface (nonce, exchange, portal login —
//     the abuse points that have no verified principal yet);
//   - per-device AND per-account on the device-authenticated /v1 routes;
//   - per-account on the portal routes.

// RateLimitConfig is the fixed-window rate-limit policy. A per-dimension limit
// of 0 DISABLES that dimension (always allow) — this is how tests opt out and
// how an operator can turn a single dimension off. Window <= 0 is treated as
// the default window.
type RateLimitConfig struct {
	// Window is the fixed window each cap is measured over.
	Window time.Duration
	// IPPerWindow caps requests per client IP on the unauthenticated surface.
	IPPerWindow int
	// DevicePerWindow caps requests per device on the authenticated /v1 routes.
	DevicePerWindow int
	// AccountPerWindow caps requests per account across the authenticated /v1
	// routes AND the portal routes (one shared per-account budget).
	AccountPerWindow int
	// WebhookPerWindow caps requests per client IP on the provider-webhook
	// route ALONE. It is a separate bucket from IPPerWindow on purpose (F9):
	// WorkOS delivers from a small set of egress addresses, so sharing the
	// unauthenticated bucket would let a delivery burst starve sign-in from
	// those same addresses — and, in the direction that actually matters, would
	// let a sign-in flood make us drop account-revocation events.
	WebhookPerWindow int
	// StructuralPerWindow caps structural-snapshot uploads per DEVICE on
	// POST /v1/structural-insights ALONE (W2). Its own bucket, for the same
	// reason the webhook has one: a device draining a 30-day backlog after a
	// standing grant is granted legitimately bursts far harder than the
	// interactive surface does, and neither should be able to exhaust the
	// other's budget. The shared per-device/per-account caps in the
	// authenticate middleware still apply on top — this narrows, never widens.
	StructuralPerWindow int
}

// RateLimiter is the shared, atomic counter contract used by the HTTP policy.
// Implementations MUST atomically test-and-increment (or leave unchanged when
// limit <= 0) the tuple (bucket, key, fixed window), and MUST return an error
// when the backing store cannot make that decision. The API deliberately does
// not fall back to a local counter after an error: admission and auth fail
// closed rather than silently multiplying limits per replica.
//
// The Postgres store implements this contract for production. Tests may inject
// an in-memory implementation with NewInMemoryRateLimiter or a small fake that
// returns deterministic failures.
type RateLimiter interface {
	AllowRateLimit(ctx context.Context, bucket, key string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
}

var errRateLimiterUnavailable = errors.New("cloudserver/api: rate limiter unavailable")

// Default rate-limit caps (per window). Chosen to be generous enough that a
// normal interactive node/browser never trips them, while still bounding a
// runaway or hostile caller. The operator narrows them via SBCI_RATELIMIT_*.
const (
	defaultRateWindow  = time.Minute
	defaultRateIP      = 60
	defaultRateDevice  = 120
	defaultRateAccount = 240
	defaultRateWebhook = 60
	// A full 30-day backlog drain is 30 uploads; 90 per window leaves room for
	// several devices' first syncs plus retries without ever throttling a normal
	// node, while still bounding a runaway loop.
	defaultRateStructural = 90
	rateLimitRetrySecMin  = 1
)

// RateLimitConfigFromEnv builds a RateLimitConfig from SBCI_RATELIMIT_*, using
// the defaults for anything unset. It is the production wiring path (called by
// api.New when Options.RateLimit is nil):
//
//	SBCI_RATELIMIT_WINDOW   window duration (Go duration string, e.g. "1m", "30s"); default 1m
//	SBCI_RATELIMIT_IP       per-IP cap on the unauth surface;   default 60;  "0" disables
//	SBCI_RATELIMIT_DEVICE   per-device cap on authed /v1 routes; default 120; "0" disables
//	SBCI_RATELIMIT_ACCOUNT  per-account cap (v1 + portal);       default 240; "0" disables
//	SBCI_RATELIMIT_WEBHOOK  per-IP cap on the provider webhook;  default 60;  "0" disables
//	SBCI_RATELIMIT_STRUCTURAL per-device cap on structural uploads; default 90; "0" disables
func RateLimitConfigFromEnv() RateLimitConfig {
	cfg := RateLimitConfig{
		Window:              defaultRateWindow,
		IPPerWindow:         defaultRateIP,
		DevicePerWindow:     defaultRateDevice,
		AccountPerWindow:    defaultRateAccount,
		WebhookPerWindow:    defaultRateWebhook,
		StructuralPerWindow: defaultRateStructural,
	}
	if v := os.Getenv("SBCI_RATELIMIT_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.Window = d
		}
	}
	cfg.IPPerWindow = envIntDefault("SBCI_RATELIMIT_IP", cfg.IPPerWindow)
	cfg.DevicePerWindow = envIntDefault("SBCI_RATELIMIT_DEVICE", cfg.DevicePerWindow)
	cfg.AccountPerWindow = envIntDefault("SBCI_RATELIMIT_ACCOUNT", cfg.AccountPerWindow)
	cfg.WebhookPerWindow = envIntDefault("SBCI_RATELIMIT_WEBHOOK", cfg.WebhookPerWindow)
	cfg.StructuralPerWindow = envIntDefault("SBCI_RATELIMIT_STRUCTURAL", cfg.StructuralPerWindow)
	return cfg
}

// envIntDefault reads a non-negative integer env var, returning def when unset
// or unparseable. An explicit "0" is honored (disables the dimension).
func envIntDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

// fixedWindowLimiter is a per-key fixed-window counter. It is safe for
// concurrent use. A limit <= 0 means "unlimited" (always allow), so a
// disabled dimension costs nothing.
type fixedWindowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	now     func() time.Time
	entries map[string]*rlEntry
	// nextSweep bounds map growth: expired entries are purged lazily at most
	// once per window (cheap for a single replica; not a hot path).
	nextSweep time.Time
}

type rlEntry struct {
	count   int
	resetAt time.Time
}

func newFixedWindowLimiter(limit int, window time.Duration, now func() time.Time) *fixedWindowLimiter {
	if window <= 0 {
		window = defaultRateWindow
	}
	if now == nil {
		now = time.Now
	}
	return &fixedWindowLimiter{
		limit:   limit,
		window:  window,
		now:     now,
		entries: make(map[string]*rlEntry),
	}
}

// allow records one hit against key and reports whether it is within the cap.
// When denied it returns the duration until the window resets (Retry-After).
func (l *fixedWindowLimiter) allow(key string) (bool, time.Duration) {
	if l == nil || l.limit <= 0 {
		return true, 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	e := l.entries[key]
	if e == nil || !now.Before(e.resetAt) {
		l.entries[key] = &rlEntry{count: 1, resetAt: now.Add(l.window)}
		return true, 0
	}
	if e.count < l.limit {
		e.count++
		return true, 0
	}
	return false, e.resetAt.Sub(now)
}

// sweepLocked drops expired entries at most once per window. Caller holds mu.
func (l *fixedWindowLimiter) sweepLocked(now time.Time) {
	if now.Before(l.nextSweep) {
		return
	}
	for k, e := range l.entries {
		if !now.Before(e.resetAt) {
			delete(l.entries, k)
		}
	}
	l.nextSweep = now.Add(l.window)
}

// inMemoryRateLimiter is the test/development implementation of RateLimiter.
// Each bucket gets its own fixed-window map, so equal keys in the webhook and
// unauthenticated buckets do not share a budget. It is never selected by New
// for the normal production path (where Options.RateLimit is nil).
type inMemoryRateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]*fixedWindowLimiter
}

// NewInMemoryRateLimiter returns a process-local RateLimiter intended for unit
// tests and explicitly single-process development servers. Production callers
// should leave Options.SharedRateLimiter set to the Postgres-backed store.
func NewInMemoryRateLimiter(now func() time.Time) RateLimiter {
	if now == nil {
		now = time.Now
	}
	return &inMemoryRateLimiter{now: now, buckets: make(map[string]*fixedWindowLimiter)}
}

func (l *inMemoryRateLimiter) AllowRateLimit(_ context.Context, bucket, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	if limit <= 0 {
		return true, 0, nil
	}
	l.mu.Lock()
	counter := l.buckets[bucket]
	if counter == nil {
		counter = newFixedWindowLimiter(limit, window, l.now)
		l.buckets[bucket] = counter
	}
	l.mu.Unlock()
	ok, retry := counter.allow(key)
	return ok, retry, nil
}

// unavailableRateLimiter is a deliberate fail-closed sentinel. It catches a
// production bootstrap that forgot to wire a shared backend instead of
// reintroducing the old per-replica semantics silently.
type unavailableRateLimiter struct{}

func (unavailableRateLimiter) AllowRateLimit(context.Context, string, string, int, time.Duration) (bool, time.Duration, error) {
	return false, 0, errRateLimiterUnavailable
}

// rateLimitDimension binds one HTTP policy dimension to the shared counter
// contract. The limit is supplied on every call so the backend can implement a
// common table/function for all dimensions while the API owns policy values.
type rateLimitDimension struct {
	backend RateLimiter
	bucket  string
	limit   int
	window  time.Duration
}

func (d *rateLimitDimension) allowContext(ctx context.Context, key string) (bool, time.Duration, error) {
	if d == nil || d.limit <= 0 {
		return true, 0, nil
	}
	if d.backend == nil {
		return false, 0, errRateLimiterUnavailable
	}
	return d.backend.AllowRateLimit(ctx, d.bucket, key, d.limit, d.window)
}

// rateLimiters bundles the dimensions the Server enforces. Each is its own
// counter bucket: `webhook` shares the per-IP KEY shape with `ip` but
// deliberately NOT its budget (F9).
type rateLimiters struct {
	ip      *rateLimitDimension
	device  *rateLimitDimension
	account *rateLimitDimension
	webhook *rateLimitDimension
	// structural shares the per-DEVICE key shape with `device` but deliberately
	// not its budget (same reasoning as `webhook`).
	structural *rateLimitDimension
}

func newRateLimitersWithBackend(cfg RateLimitConfig, backend RateLimiter) *rateLimiters {
	window := cfg.Window
	if window <= 0 {
		window = defaultRateWindow
	}
	return &rateLimiters{
		ip:         &rateLimitDimension{backend: backend, bucket: "ip", limit: cfg.IPPerWindow, window: window},
		device:     &rateLimitDimension{backend: backend, bucket: "device", limit: cfg.DevicePerWindow, window: window},
		account:    &rateLimitDimension{backend: backend, bucket: "account", limit: cfg.AccountPerWindow, window: window},
		webhook:    &rateLimitDimension{backend: backend, bucket: "webhook", limit: cfg.WebhookPerWindow, window: window},
		structural: &rateLimitDimension{backend: backend, bucket: "structural", limit: cfg.StructuralPerWindow, window: window},
	}
}

// writeRateLimited emits a 429 with a Retry-After header (whole seconds, min 1).
func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int(retryAfter.Round(time.Second) / time.Second)
	if secs < rateLimitRetrySecMin {
		secs = rateLimitRetrySecMin
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded; retry later")
}

func writeRateLimitUnavailable(w http.ResponseWriter) {
	writeErr(w, http.StatusServiceUnavailable, "rate_limit_unavailable",
		"request protection is temporarily unavailable; retry later")
}

// rateLimitKey obtains the one request identity selected by the edge fence.
// A handler assembled directly in a unit test still gets a canonical direct
// peer; production requests have already passed through enforceTrustedEdge.
func rateLimitKey(r *http.Request) (string, error) {
	return edgeClientIP(r)
}

// rateLimitIP is the unauthenticated-surface middleware: one fixed-window cap
// per client IP. It fronts the nonce, exchange, and portal-login routes.
func (s *Server) rateLimitIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.rl == nil || s.rl.ip == nil || s.rl.ip.limit <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		key, err := rateLimitKey(r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_client_ip", "could not determine the client IP")
			return
		}
		ok, retry, err := s.rl.ip.allowContext(r.Context(), key)
		if err != nil {
			if s.log != nil {
				s.log.Error("cloudserver/api: IP rate limiter", "err", err)
			}
			writeRateLimitUnavailable(w)
			return
		}
		if !ok {
			writeRateLimited(w, retry)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitWebhook is the provider-webhook middleware: the same per-IP key,
// its OWN budget (F9), so neither surface can exhaust the other's. The key is
// selected by the trusted-edge middleware when production edge mode is on.
func (s *Server) rateLimitWebhook(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.rl == nil || s.rl.webhook == nil || s.rl.webhook.limit <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		key, err := rateLimitKey(r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_client_ip", "could not determine the client IP")
			return
		}
		ok, retry, err := s.rl.webhook.allowContext(r.Context(), key)
		if err != nil {
			if s.log != nil {
				s.log.Error("cloudserver/api: webhook rate limiter", "err", err)
			}
			writeRateLimitUnavailable(w)
			return
		}
		if !ok {
			writeRateLimited(w, retry)
			return
		}
		next.ServeHTTP(w, r)
	})
}
