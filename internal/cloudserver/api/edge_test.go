package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseSingleIPCanonicalizesAndRejectsAmbiguity(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "ipv4", raw: "192.0.2.1", want: "192.0.2.1", ok: true},
		{name: "ipv6 compressed", raw: "2001:0db8:0:0:0:0:0:1", want: "2001:db8::1", ok: true},
		{name: "mapped ipv4", raw: "::ffff:192.0.2.1", want: "192.0.2.1", ok: true},
		{name: "outer whitespace ipv6", raw: " 2001:db8::2 ", want: "2001:db8::2", ok: true},
		{name: "comma list", raw: "192.0.2.1, 198.51.100.1", ok: false},
		{name: "outer whitespace ipv4", raw: " 192.0.2.1 ", want: "192.0.2.1", ok: true},
		{name: "internal whitespace", raw: "192.0. 2.1", ok: false},
		{name: "scoped ipv6", raw: "fe80::1%eth0", ok: false},
		{name: "invalid", raw: "not-an-ip", ok: false},
		{name: "empty", raw: "", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSingleIP(tt.raw)
			if tt.ok {
				if err != nil || got != tt.want {
					t.Fatalf("parseSingleIP(%q) = %q, %v; want %q", tt.raw, got, err, tt.want)
				}
				return
			}
			if !errors.Is(err, errEdgeIdentity) {
				t.Fatalf("parseSingleIP(%q) error = %v; want errEdgeIdentity", tt.raw, err)
			}
		})
	}
}

func TestForwardedClientIPRejectsDuplicateAndMalformedHeaders(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
		ok     bool
	}{
		{name: "single ipv4", values: []string{"198.51.100.7"}, want: "198.51.100.7", ok: true},
		{name: "single ipv6", values: []string{"2001:db8::7"}, want: "2001:db8::7", ok: true},
		{name: "duplicate identical", values: []string{"198.51.100.7", "198.51.100.7"}, ok: false},
		{name: "duplicate conflicting", values: []string{"198.51.100.7", "198.51.100.8"}, ok: false},
		{name: "comma list", values: []string{"198.51.100.7, 198.51.100.8"}, ok: false},
		{name: "malformed", values: []string{"198.51.100.999"}, ok: false},
		{name: "missing", values: nil, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			for _, value := range tt.values {
				r.Header.Add(edgeClientIPHeader, value)
			}
			got, err := forwardedClientIP(r)
			if tt.ok {
				if err != nil || got != tt.want {
					t.Fatalf("forwardedClientIP() = %q, %v; want %q", got, err, tt.want)
				}
				return
			}
			if !errors.Is(err, errEdgeIdentity) {
				t.Fatalf("forwardedClientIP() error = %v; want errEdgeIdentity", err)
			}
		})
	}
}

func TestForwardedClientIPNeverReadsReservedCloudflareHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.Header.Set(cloudflareConnectingIPHeader, "198.51.100.7")
	if _, err := forwardedClientIP(r); !errors.Is(err, errEdgeIdentity) {
		t.Fatalf("forwardedClientIP() error=%v; want missing private header to be rejected", err)
	}
	r.Header.Set(edgeClientIPHeader, "203.0.113.7")
	got, err := forwardedClientIP(r)
	if err != nil || got != "203.0.113.7" {
		t.Fatalf("forwardedClientIP() = %q, %v; want private header value", got, err)
	}
}

func TestForwardedClientIPRejectsCaseVariantDuplicate(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	// A real net/http parser canonicalizes these keys, but the edge boundary
	// also receives requests from test/proxy adapters that may construct the
	// Header map directly. Both spellings must count toward the one-value rule.
	r.Header[edgeClientIPHeader] = []string{"203.0.113.7"}
	r.Header["x-sbci-client-ip"] = []string{"203.0.113.8"}
	if _, err := forwardedClientIP(r); !errors.Is(err, errEdgeIdentity) {
		t.Fatalf("forwardedClientIP() error=%v; want duplicate case variants rejected", err)
	}
}

func TestParseEdgeHostCanonicalizesAndRejectsURLs(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "dns", raw: "Cloud.Example", want: "cloud.example", ok: true},
		{name: "dns with port", raw: "Cloud.Example:443", want: "cloud.example", ok: true},
		{name: "maximum port", raw: "cloud.example:65535", want: "cloud.example", ok: true},
		{name: "trailing root dot", raw: "cloud.example.", want: "cloud.example", ok: true},
		{name: "url", raw: "https://cloud.example", ok: false},
		{name: "path", raw: "cloud.example/portal", ok: false},
		{name: "userinfo", raw: "user@cloud.example", ok: false},
		{name: "comma list", raw: "cloud.example, evil.example", ok: false},
		{name: "bad port", raw: "cloud.example:https", ok: false},
		{name: "zero port", raw: "cloud.example:0", ok: false},
		{name: "port above maximum", raw: "cloud.example:65536", ok: false},
		{name: "unbracketed ipv6", raw: "2001:db8::1", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEdgeHost(tt.raw)
			if tt.ok {
				if err != nil || got != tt.want {
					t.Fatalf("parseEdgeHost(%q) = %q, %v; want %q", tt.raw, got, err, tt.want)
				}
				return
			}
			if !errors.Is(err, errEdgeIdentity) {
				t.Fatalf("parseEdgeHost(%q) error=%v; want errEdgeIdentity", tt.raw, err)
			}
		})
	}
}

func TestForwardedEdgeHostRejectsDuplicateValues(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.Header.Add(edgeHostHeader, "cloud.example")
	r.Header.Add(edgeHostHeader, "cloud.example")
	if _, err := forwardedEdgeHost(r); !errors.Is(err, errEdgeIdentity) {
		t.Fatalf("forwardedEdgeHost() error=%v; want errEdgeIdentity", err)
	}
}

func TestEdgeRequestIPTrustsOnlyVerifiedPeerAndHeader(t *testing.T) {
	trusted := parseEdgeConfig(EdgeConfig{
		Enabled:          true,
		TrustedPeerCIDRs: []string{"192.0.2.0/24"},
		AuthSecret:       "edge-secret",
	})

	tests := []struct {
		name      string
		remote    string
		auth      string
		forwarded []string
		want      string
		wantErr   error
	}{
		{
			name:      "trusted peer canonicalizes ipv6",
			remote:    "192.0.2.4:443",
			auth:      "edge-secret",
			forwarded: []string{"2001:0db8:0:0::4"},
			want:      "2001:db8::4",
		},
		{
			name:      "direct origin cannot spoof",
			remote:    "198.51.100.4:443",
			auth:      "edge-secret",
			forwarded: []string{"203.0.113.4"},
			wantErr:   errEdgeUntrusted,
		},
		{
			name:      "wrong hop secret refused",
			remote:    "192.0.2.4:443",
			auth:      "wrong",
			forwarded: []string{"203.0.113.4"},
			wantErr:   errEdgeUntrusted,
		},
		{
			name:      "duplicate forwarded values refused",
			remote:    "192.0.2.4:443",
			auth:      "edge-secret",
			forwarded: []string{"203.0.113.4", "203.0.113.4"},
			wantErr:   errEdgeIdentity,
		},
		{
			name:      "comma list refused",
			remote:    "192.0.2.4:443",
			auth:      "edge-secret",
			forwarded: []string{"203.0.113.4, 203.0.113.5"},
			wantErr:   errEdgeIdentity,
		},
		{
			name:      "duplicate auth values refused",
			remote:    "192.0.2.4:443",
			auth:      "edge-secret",
			forwarded: []string{"203.0.113.4"},
			wantErr:   errEdgeUntrusted,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.test/v1/auth/nonce", nil)
			r.RemoteAddr = tt.remote
			r.Header.Set(trusted.authHeader, tt.auth)
			r.Header.Set(edgeHostHeader, "cloud.example")
			if tt.name == "duplicate auth values refused" {
				r.Header.Add(trusted.authHeader, tt.auth)
			}
			for _, value := range tt.forwarded {
				r.Header.Add(edgeClientIPHeader, value)
			}
			got, err := trusted.edgeRequestIP(r)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("edgeRequestIP() error = %v; want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("edgeRequestIP() = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestEdgeRequestIPUsesPrivateHeaderInsteadOfReservedCloudflareHeader(t *testing.T) {
	cfg := parseEdgeConfig(EdgeConfig{Enabled: true, AuthSecret: "edge-secret"})
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = "10.0.0.4:8443"
	r.Header.Set(cfg.authHeader, "edge-secret")
	r.Header.Set(edgeHostHeader, "cloud.example")
	r.Header.Set(edgeClientIPHeader, "203.0.113.7")
	// This value is deliberately malformed. It must not affect identity because
	// CF-Connecting-IP is reserved for the inbound Cloudflare edge and may be
	// rewritten on the Worker→ACA subrequest.
	r.Header.Set(cloudflareConnectingIPHeader, "not-an-ip")
	got, err := cfg.edgeRequestIP(r)
	if err != nil || got != "203.0.113.7" {
		t.Fatalf("edgeRequestIP() = %q, %v; want private client IP despite reserved header", got, err)
	}
}

func TestEdgeDisabledIgnoresForwardedHeader(t *testing.T) {
	cfg := parseEdgeConfig(EdgeConfig{})
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = "198.51.100.20:8443"
	r.Header.Set(edgeClientIPHeader, "203.0.113.20")
	r.Header.Set(cloudflareConnectingIPHeader, "198.51.100.20")
	got, err := cfg.edgeRequestIP(r)
	if err != nil || got != "198.51.100.20" {
		t.Fatalf("edgeRequestIP() = %q, %v; want direct peer 198.51.100.20", got, err)
	}
}

func TestSecretOnlyEdgeStillRequiresSyntacticDirectPeer(t *testing.T) {
	cfg := parseEdgeConfig(EdgeConfig{Enabled: true, AuthSecret: "edge-secret"})
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = "not-a-peer"
	r.Header.Set(cfg.authHeader, "edge-secret")
	r.Header.Set(edgeClientIPHeader, "203.0.113.10")
	r.Header.Set(edgeHostHeader, "cloud.example")
	if _, err := cfg.edgeRequestIP(r); !errors.Is(err, errEdgeUntrusted) {
		t.Fatalf("edgeRequestIP() error=%v; want errEdgeUntrusted", err)
	}
}

func TestEdgeHealthProbeBypassesEdgeFence(t *testing.T) {
	s := &Server{edge: parseEdgeConfig(EdgeConfig{Enabled: true, AuthSecret: "edge-secret"})}
	var called atomic.Bool
	h := s.enforceTrustedEdge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodGet, "http://example.test/healthz", nil)
	r.RemoteAddr = "not-an-ip"
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusNoContent || !called.Load() {
		t.Fatalf("health probe status=%d called=%v; want 204 and handler call", rw.Code, called.Load())
	}
}

func TestEdgeFenceRejectsDirectOriginSpoof(t *testing.T) {
	s := &Server{edge: parseEdgeConfig(EdgeConfig{
		Enabled:          true,
		TrustedPeerCIDRs: []string{"192.0.2.0/24"},
		AuthSecret:       "edge-secret",
	}), log: slog.Default()}
	h := s.enforceTrustedEdge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodGet, "http://example.test/v1/auth/nonce", nil)
	r.RemoteAddr = "127.0.0.1:8443"
	r.Header.Set(s.edge.authHeader, "edge-secret")
	r.Header.Set(edgeClientIPHeader, "203.0.113.99")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("direct origin status=%d; want 403", rw.Code)
	}
}

func TestAuthenticatedEdgeHostFeedsCanonicalHostFence(t *testing.T) {
	s := &Server{
		edge:       parseEdgeConfig(EdgeConfig{Enabled: true, AuthSecret: "edge-secret"}),
		log:        slog.Default(),
		apiHost:    "cloud.example",
		portalHost: "app.example",
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := s.enforceTrustedEdge(s.enforceCanonicalHost(inner))

	tests := []struct {
		name         string
		path         string
		incoming     string
		edgeHost     string
		addHostTwice bool
		want         int
	}{
		{name: "api origin host", path: "/v1/usage", incoming: "sbci-api.azurecontainerapps.io", edgeHost: "cloud.example", want: http.StatusNoContent},
		{name: "portal origin host", path: "/portal/api/session", incoming: "sbci-api.azurecontainerapps.io", edgeHost: "app.example", want: http.StatusNoContent},
		{name: "spoofed host rejected by canonical fence", path: "/v1/usage", incoming: "sbci-api.azurecontainerapps.io", edgeHost: "evil.example", want: http.StatusMisdirectedRequest},
		{name: "malformed host rejected", path: "/v1/usage", incoming: "sbci-api.azurecontainerapps.io", edgeHost: "https://cloud.example", want: http.StatusBadRequest},
		{name: "duplicate host rejected", path: "/v1/usage", incoming: "sbci-api.azurecontainerapps.io", edgeHost: "cloud.example", addHostTwice: true, want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://"+tt.incoming+tt.path, nil)
			r.RemoteAddr = "10.0.0.8:8443"
			r.Header.Set(s.edge.authHeader, "edge-secret")
			r.Header.Set(edgeClientIPHeader, "203.0.113.8")
			r.Header.Set(edgeHostHeader, tt.edgeHost)
			if tt.addHostTwice {
				r.Header.Add(edgeHostHeader, tt.edgeHost)
			}
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, r)
			if rw.Code != tt.want {
				t.Fatalf("status=%d; want %d, body=%s", rw.Code, tt.want, rw.Body.String())
			}
		})
	}
}

func TestAuthenticatedEdgeStripsProofHeadersBeforeInnerHandler(t *testing.T) {
	s := &Server{
		edge: parseEdgeConfig(EdgeConfig{Enabled: true, AuthSecret: "edge-secret"}),
		log:  slog.Default(),
	}
	var original *http.Request
	h := s.enforceTrustedEdge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{s.edge.authHeader, edgeHostHeader, edgeClientIPHeader, cloudflareConnectingIPHeader} {
			if values := r.Header.Values(name); len(values) != 0 {
				t.Errorf("inner handler saw proof header %q with values %q", name, values)
			}
		}
		if r.Host != "cloud.example" {
			t.Errorf("inner handler Host=%q; want cloud.example", r.Host)
		}
		if ip, err := edgeClientIP(r); err != nil || ip != "203.0.113.8" {
			t.Errorf("inner handler client IP=%q, %v; want 203.0.113.8", ip, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodGet, "http://origin.azurecontainerapps.io/v1/usage", nil)
	r.RemoteAddr = "10.0.0.8:8443"
	r.Header.Set(s.edge.authHeader, "edge-secret")
	r.Header.Set(edgeClientIPHeader, "203.0.113.8")
	r.Header.Set(cloudflareConnectingIPHeader, "198.51.100.8")
	r.Header.Set(edgeHostHeader, "cloud.example")
	original = r
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusNoContent {
		t.Fatalf("status=%d; want 204", rw.Code)
	}
	// The middleware uses the request's header map directly, so a wrapper that
	// logs after the inner handler returns cannot recover proof material either.
	for _, name := range []string{s.edge.authHeader, edgeHostHeader, edgeClientIPHeader, cloudflareConnectingIPHeader} {
		if values := original.Header.Values(name); len(values) != 0 {
			t.Fatalf("outer request retained proof header %q with values %q", name, values)
		}
	}
}

func TestDisabledEdgeStripsReservedHeadersBeforeInnerHandler(t *testing.T) {
	s := &Server{edge: parseEdgeConfig(EdgeConfig{})}
	h := s.enforceTrustedEdge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{edgeClientIPHeader, cloudflareConnectingIPHeader, edgeHostHeader, defaultEdgeAuthHeader} {
			if values := headerValuesFold(r.Header, name); len(values) != 0 {
				t.Errorf("inner handler saw reserved header %q with values %q", name, values)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodGet, "http://example.test/v1/usage", nil)
	r.RemoteAddr = "198.51.100.20:8443"
	r.Header.Set(edgeClientIPHeader, "203.0.113.20")
	r.Header.Set(cloudflareConnectingIPHeader, "203.0.113.21")
	r.Header.Set(edgeHostHeader, "evil.example")
	r.Header.Set(defaultEdgeAuthHeader, "forged")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusNoContent {
		t.Fatalf("status=%d; want 204", rw.Code)
	}
}

func TestMalformedEdgeHostUsesGenericIdentityError(t *testing.T) {
	s := &Server{
		edge: parseEdgeConfig(EdgeConfig{Enabled: true, AuthSecret: "edge-secret"}),
		log:  slog.Default(),
	}
	h := s.enforceTrustedEdge(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must not run for malformed edge host")
	}))
	r := httptest.NewRequest(http.MethodGet, "http://origin.azurecontainerapps.io/v1/usage", nil)
	r.RemoteAddr = "10.0.0.8:8443"
	r.Header.Set(s.edge.authHeader, "edge-secret")
	r.Header.Set(edgeClientIPHeader, "203.0.113.8")
	r.Header.Set(edgeHostHeader, "https://cloud.example")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d; want 400", rw.Code)
	}
	var body errorBody
	if err := json.Unmarshal(rw.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v; body=%s", err, rw.Body.String())
	}
	if body.Code != "invalid_edge_identity" {
		t.Fatalf("error code=%q; want invalid_edge_identity", body.Code)
	}
}

type failingRateLimiter struct {
	calls atomic.Int64
}

func (f *failingRateLimiter) AllowRateLimit(context.Context, string, string, int, time.Duration) (bool, time.Duration, error) {
	f.calls.Add(1)
	return false, 0, errors.New("database unavailable")
}

type recordingRateLimiter struct {
	mu      sync.Mutex
	bucket  string
	key     string
	calls   int
	allowed bool
}

func (r *recordingRateLimiter) AllowRateLimit(_ context.Context, bucket, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bucket, r.key, r.calls = bucket, key, r.calls+1
	return r.allowed, 0, nil
}

func TestTrustedEdgeUsesOneCanonicalIPForLimiter(t *testing.T) {
	backend := &recordingRateLimiter{allowed: true}
	s := &Server{
		rl:   newRateLimitersWithBackend(RateLimitConfig{IPPerWindow: 1}, backend),
		edge: parseEdgeConfig(EdgeConfig{Enabled: true, AuthSecret: "edge-secret"}),
		log:  slog.Default(),
	}
	var continued atomic.Bool
	h := s.enforceTrustedEdge(s.rateLimitIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		continued.Store(true)
		w.WriteHeader(http.StatusNoContent)
	})))
	r := httptest.NewRequest(http.MethodGet, "http://example.test/v1/auth/nonce", nil)
	r.RemoteAddr = "10.0.0.4:8443"
	r.Header.Set(s.edge.authHeader, "edge-secret")
	r.Header.Set(edgeClientIPHeader, "2001:0db8:0:0:0:0:0:4")
	r.Header.Set(edgeHostHeader, "cloud.example")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusNoContent || !continued.Load() {
		t.Fatalf("status=%d continued=%v; want 204 and continuation", rw.Code, continued.Load())
	}
	backend.mu.Lock()
	bucket, key, calls := backend.bucket, backend.key, backend.calls
	backend.mu.Unlock()
	if bucket != "ip" || key != "2001:db8::4" || calls != 1 {
		t.Fatalf("limiter call bucket=%q key=%q calls=%d; want ip/2001:db8::4/1", bucket, key, calls)
	}
}

func TestUntrustedEdgeDoesNotConsumeSpoofedLimiterKey(t *testing.T) {
	backend := &recordingRateLimiter{allowed: true}
	s := &Server{
		rl: newRateLimitersWithBackend(RateLimitConfig{IPPerWindow: 1}, backend),
		edge: parseEdgeConfig(EdgeConfig{
			Enabled:          true,
			TrustedPeerCIDRs: []string{"192.0.2.0/24"},
		}),
		log: slog.Default(),
	}
	h := s.enforceTrustedEdge(s.rateLimitIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	r := httptest.NewRequest(http.MethodGet, "http://example.test/v1/auth/nonce", nil)
	r.RemoteAddr = "198.51.100.4:8443"
	r.Header.Set(edgeClientIPHeader, "203.0.113.4")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d; want 403", rw.Code)
	}
	backend.mu.Lock()
	calls := backend.calls
	backend.mu.Unlock()
	if calls != 0 {
		t.Fatalf("limiter calls=%d; want zero for untrusted peer", calls)
	}
}

func TestRateLimitBackendErrorFailsClosedWithoutContinuation(t *testing.T) {
	f := &failingRateLimiter{}
	s := &Server{
		rl:  newRateLimitersWithBackend(RateLimitConfig{IPPerWindow: 1}, f),
		now: time.Now,
		log: slog.Default(),
	}
	var continued atomic.Bool
	h := s.rateLimitIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		continued.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodGet, "http://example.test/v1/auth/nonce", nil)
	r.RemoteAddr = "198.51.100.30:443"
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d; want 503", rw.Code)
	}
	if continued.Load() || f.calls.Load() != 1 {
		t.Fatalf("continued=%v limiter_calls=%d; want false and one call", continued.Load(), f.calls.Load())
	}
}

func TestRateLimitBackendErrorBlocksAuthAndJobRoutes(t *testing.T) {
	for _, path := range []string{"/v1/auth/nonce", "/v1/jobs"} {
		t.Run(path, func(t *testing.T) {
			f := &failingRateLimiter{}
			h := New(Options{
				RateLimit:         &RateLimitConfig{IPPerWindow: 1},
				SharedRateLimiter: f,
				Logger:            slog.Default(),
			}).Handler()
			r := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
			if path == "/v1/jobs" {
				r.Method = http.MethodPost
			}
			r.RemoteAddr = "198.51.100.40:8443"
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, r)
			if rw.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d; want 503", rw.Code)
			}
			if f.calls.Load() != 1 {
				t.Fatalf("limiter calls=%d; want one", f.calls.Load())
			}
		})
	}
}

func TestInMemoryRateLimiterAtomicUnderConcurrency(t *testing.T) {
	backend := NewInMemoryRateLimiter(time.Now)
	const workers = 64
	var wg sync.WaitGroup
	var allowed atomic.Int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _, err := backend.AllowRateLimit(context.Background(), "ip", "198.51.100.31", 1, time.Minute)
			if err != nil {
				t.Errorf("AllowRateLimit: %v", err)
				return
			}
			if ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 1 {
		t.Fatalf("allowed=%d; want exactly one atomic admission", allowed.Load())
	}
}
