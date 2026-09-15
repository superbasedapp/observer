package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// F1 (custody blocker): Gateway-Mode auth-substitution must strip EVERY
// provider-credential shape a developer request can carry — not just
// Authorization / X-Api-Key, but the Gemini X-Goog-Api-Key header and the
// Gemini ?key= query param — before the request reaches the org gateway, and
// must restore the original google credential on a custody-acked direct
// fallback.

// recordingUpstream captures the last request's headers AND URL (query
// included), unlike statusUpstream which records headers only.
type recordingUpstream struct {
	srv    *httptest.Server
	status int
	hits   int
	mu     sync.Mutex
	hdr    http.Header
	rawURL *url.URL
}

func newRecordingUpstream(t *testing.T, status int) *recordingUpstream {
	t.Helper()
	ru := &recordingUpstream{status: status}
	ru.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ru.mu.Lock()
		ru.hits++
		ru.hdr = r.Header.Clone()
		u := *r.URL
		ru.rawURL = &u
		ru.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ru.status)
		_, _ = w.Write([]byte(okChatCompletionBody))
	}))
	t.Cleanup(ru.srv.Close)
	return ru
}

func (ru *recordingUpstream) header(name string) string {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	if ru.hdr == nil {
		return ""
	}
	return ru.hdr.Get(name)
}

func (ru *recordingUpstream) queryKey() string {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	if ru.rawURL == nil {
		return ""
	}
	return ru.rawURL.Query().Get("key")
}

func (ru *recordingUpstream) count() int {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	return ru.hits
}

const (
	geminiBody = `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`
	geminiPath = "/v1beta/models/gemini-1.5-pro:generateContent"
)

// TestGatewayAuthSub_GeminiCredentialNeverReachesGateway drives a gemini-shaped
// request (X-Goog-Api-Key header + ?key= query param, the developer's Google
// credential) through Gateway Mode and asserts the gateway-bound request
// carries the virtual key and NONE of the developer credential shapes.
func TestGatewayAuthSub_GeminiCredentialNeverReachesGateway(t *testing.T) {
	gateway := newRecordingUpstream(t, http.StatusOK)

	p := mustGatewayProxy(t, Options{
		Sink:             &fakeSink{},
		VirtualKeySource: &fakeVirtualKeySource{key: "sbo-vk-secret", gen: 1},
	}, gateway.srv.URL, nil, terminalHold, false)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := doPost(t, ts.URL+geminiPath+"?key=DEV-GOOGLE-KEY", geminiBody, func(r *http.Request) {
		r.Header.Set("X-Goog-Api-Key", "DEV-GOOGLE-KEY")
	})
	_ = readBody(t, resp)
	if gateway.count() != 1 {
		t.Fatalf("gateway hits = %d, want 1", gateway.count())
	}
	if got := gateway.header("X-Api-Key"); got != "sbo-vk-secret" {
		t.Errorf("gateway X-Api-Key = %q, want the virtual key", got)
	}
	if got := gateway.header("X-Goog-Api-Key"); got != "" {
		t.Errorf("developer X-Goog-Api-Key reached the gateway: %q", got)
	}
	if got := gateway.header("Api-Key"); got != "" {
		t.Errorf("developer Api-Key reached the gateway: %q", got)
	}
	if got := gateway.queryKey(); got != "" {
		t.Errorf("developer ?key= query param reached the gateway: %q", got)
	}
}

// TestGatewayAuthSub_WebSocketUpgradeFailsClosed pins G1 (custody blocker on
// the WS path): a websocket-upgrade request that resolves to the org AI Gateway
// must NOT reach serveUpgradePassthrough, which forwards the developer's own
// Authorization / X-Api-Key untouched (it strips only hosted-identity params,
// never the gateway credential set, and never attaches the virtual key). The
// gateway data plane is HTTP request/response only, so the upgrade is refused
// fail-closed: the gateway is never dialed and no developer credential leaks.
func TestGatewayAuthSub_WebSocketUpgradeFailsClosed(t *testing.T) {
	gateway := newRecordingUpstream(t, http.StatusOK)

	p := mustGatewayProxy(t, Options{
		Sink:             &fakeSink{},
		VirtualKeySource: &fakeVirtualKeySource{key: "sbo-vk-secret", gen: 1},
	}, gateway.srv.URL, nil, terminalHold, false)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+geminiPath, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Authorization", "Bearer DEV-PROVIDER-TOKEN")
	req.Header.Set("X-Goog-Api-Key", "DEV-GOOGLE-KEY")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d (fail-closed)", resp.StatusCode, http.StatusBadGateway)
	}
	if gateway.count() != 0 {
		t.Errorf("gateway dialed %d times on a WS upgrade; must be 0 (fail-closed, no credential leak)", gateway.count())
	}
	if got := gateway.header("Authorization"); got != "" {
		t.Errorf("developer Authorization reached the gateway on the WS path: %q", got)
	}
	if got := gateway.header("X-Goog-Api-Key"); got != "" {
		t.Errorf("developer X-Goog-Api-Key reached the gateway on the WS path: %q", got)
	}
}

// TestGatewayAuthSub_DirectFallbackRestoresGoogleCredential asserts that when
// the ladder exhausts and a custody-acked direct fallback fires, the direct
// gemini provider receives the developer's ORIGINAL google credential (both the
// X-Goog-Api-Key header and the ?key= query param) restored, and never the
// virtual key.
func TestGatewayAuthSub_DirectFallbackRestoresGoogleCredential(t *testing.T) {
	gateway := newRecordingUpstream(t, http.StatusServiceUnavailable) // always fails -> exhaust
	directGemini := newRecordingUpstream(t, http.StatusOK)

	p := mustGatewayProxy(t, Options{
		GeminiUpstream:   directGemini.srv.URL,
		Sink:             &fakeSink{},
		VirtualKeySource: &fakeVirtualKeySource{key: "sbo-vk-secret", gen: 1},
	}, gateway.srv.URL, nil, terminalDirect, true)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp := doPost(t, ts.URL+geminiPath+"?key=DEV-GOOGLE-KEY", geminiBody, func(r *http.Request) {
		r.Header.Set("X-Goog-Api-Key", "DEV-GOOGLE-KEY")
	})
	_ = readBody(t, resp)

	if directGemini.count() != 1 {
		t.Fatalf("direct gemini hits = %d, want 1 (custody-acked fallback)", directGemini.count())
	}
	if got := directGemini.header("X-Goog-Api-Key"); got != "DEV-GOOGLE-KEY" {
		t.Errorf("direct gemini X-Goog-Api-Key = %q, want the restored developer credential", got)
	}
	if got := directGemini.queryKey(); got != "DEV-GOOGLE-KEY" {
		t.Errorf("direct gemini ?key= = %q, want the restored developer credential", got)
	}
	if got := directGemini.header("X-Api-Key"); got == "sbo-vk-secret" {
		t.Error("the virtual key leaked to the direct provider on custody-acked fallback")
	}
}
