package cloudclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcred"
)

// mintFakeAccessToken builds an UNSIGNED-shape JWT (header.payload.sig) with an
// exp claim so accessTokenExpiry can read it. The signature is a dummy — the
// broker never verifies it (the server does).
func mintFakeAccessToken(exp time.Time) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	h := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "kid-1"})
	p := enc(map[string]any{"sub": "user_x", "exp": exp.Unix(), "client_id": "client_x"})
	return h + "." + p + ".ZmFrZXNpZw"
}

// workosMock is a mock WorkOS authenticate endpoint counting requests per grant
// and rotating refresh tokens.
type workosMock struct {
	srv          *httptest.Server
	codeCalls    atomic.Int32
	refreshCalls atomic.Int32
	nextRefresh  string
	accessExp    time.Time
}

func newWorkOSMock(t *testing.T) *workosMock {
	t.Helper()
	m := &workosMock{nextRefresh: "refresh-1", accessExp: time.Unix(1_800_003_600, 0)}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		grant := r.Form.Get("grant_type")
		switch grant {
		case "authorization_code":
			m.codeCalls.Add(1)
			if r.Form.Get("code") == "" || r.Form.Get("code_verifier") == "" {
				http.Error(w, `{"error":"invalid_grant"}`, 400)
				return
			}
		case "refresh_token":
			m.refreshCalls.Add(1)
			if r.Form.Get("refresh_token") == "" {
				http.Error(w, `{"error":"invalid_grant"}`, 400)
				return
			}
		default:
			http.Error(w, `{"error":"unsupported_grant_type"}`, 400)
			return
		}
		// No client_secret must ever be sent (PKCE public client).
		if r.Form.Get("client_secret") != "" {
			http.Error(w, `{"error":"secret_sent"}`, 400)
			return
		}
		resp := map[string]string{
			"access_token":  mintFakeAccessToken(m.accessExp),
			"refresh_token": m.nextRefresh,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *workosMock) endpoints() WorkOSEndpoints {
	return WorkOSEndpoints{AuthorizeURL: m.srv.URL + "/authorize", TokenURL: m.srv.URL + "/authenticate"}
}

func TestGeneratePKCEChallengeMatchesVerifier(t *testing.T) {
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if p.Challenge != want {
		t.Fatalf("challenge %q != S256(verifier) %q", p.Challenge, want)
	}
	if len(p.Verifier) < 43 {
		t.Fatalf("verifier too short: %d", len(p.Verifier))
	}
}

func TestWorkOSAuthorizeURLCarriesPKCEParams(t *testing.T) {
	raw, err := WorkOSAuthorizeURL(WorkOSEndpoints{}, "client_x", "http://127.0.0.1:5555/callback", "chal", "state-1")
	if err != nil {
		t.Fatalf("WorkOSAuthorizeURL: %v", err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	for k, want := range map[string]string{
		"response_type": "code", "client_id": "client_x",
		"redirect_uri":   "http://127.0.0.1:5555/callback",
		"code_challenge": "chal", "code_challenge_method": "S256",
		"state": "state-1", "provider": "authkit",
	} {
		if q.Get(k) != want {
			t.Fatalf("authorize URL %s=%q, want %q", k, q.Get(k), want)
		}
	}
}

func TestWorkOSExchangeCodePersistsRefresh(t *testing.T) {
	m := newWorkOSMock(t)
	cred := cloudcred.Open(t.TempDir(), nil)
	access, err := WorkOSExchangeCode(context.Background(), m.srv.Client(), m.endpoints(), cred, "client_x", "the-code", "the-verifier")
	if err != nil {
		t.Fatalf("WorkOSExchangeCode: %v", err)
	}
	if access == "" {
		t.Fatal("no access token returned")
	}
	if m.codeCalls.Load() != 1 {
		t.Fatalf("expected 1 authorization_code call, got %d", m.codeCalls.Load())
	}
	got, err := cred.LoadWorkOSRefresh()
	if err != nil || got != "refresh-1" {
		t.Fatalf("refresh not persisted: got %q err %v", got, err)
	}
}

func TestWorkOSBrokerRefreshesAndCaches(t *testing.T) {
	m := newWorkOSMock(t)
	cred := cloudcred.Open(t.TempDir(), nil)
	if err := cred.SaveWorkOSRefresh("refresh-0"); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	m.accessExp = now.Add(time.Hour)
	m.nextRefresh = "refresh-rotated"

	b, err := NewWorkOSBroker(
		"client_x", cred,
		WithWorkOSEndpoints(m.endpoints()),
		WithWorkOSHTTPClient(m.srv.Client()),
		WithWorkOSClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("NewWorkOSBroker: %v", err)
	}
	ctx := context.Background()

	tok1, err := b.AccessToken(ctx)
	if err != nil || tok1 == "" {
		t.Fatalf("first AccessToken: %v", err)
	}
	if m.refreshCalls.Load() != 1 {
		t.Fatalf("expected 1 refresh call, got %d", m.refreshCalls.Load())
	}
	// Rotation persisted.
	if r, _ := cred.LoadWorkOSRefresh(); r != "refresh-rotated" {
		t.Fatalf("rotated refresh not persisted: %q", r)
	}
	// Second call within leeway is cached — no new HTTP.
	tok2, err := b.AccessToken(ctx)
	if err != nil || tok2 != tok1 {
		t.Fatalf("cached AccessToken mismatch: %v", err)
	}
	if m.refreshCalls.Load() != 1 {
		t.Fatalf("cached call must not hit WorkOS again, got %d refreshes", m.refreshCalls.Load())
	}
}

func TestWorkOSBrokerNoIdentityWhenNotLoggedIn(t *testing.T) {
	m := newWorkOSMock(t)
	cred := cloudcred.Open(t.TempDir(), nil) // no refresh stored
	b, err := NewWorkOSBroker("client_x", cred,
		WithWorkOSEndpoints(m.endpoints()), WithWorkOSHTTPClient(m.srv.Client()))
	if err != nil {
		t.Fatalf("NewWorkOSBroker: %v", err)
	}
	if _, err := b.AccessToken(context.Background()); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("expected ErrNoIdentity, got %v", err)
	}
}

func TestAccessTokenExpiryParsesJWT(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	exp := now.Add(42 * time.Minute)
	got := accessTokenExpiry(mintFakeAccessToken(exp), now)
	if got.Unix() != exp.Unix() {
		t.Fatalf("expiry = %v, want %v", got, exp)
	}
	// Opaque token ⇒ fallback now+5m.
	if fb := accessTokenExpiry("opaque", now); fb.Unix() != now.Add(5*time.Minute).Unix() {
		t.Fatalf("fallback expiry = %v", fb)
	}
}

// Guard: the broker/exchange must never send a client_secret (the mock 400s if
// one appears); this test documents that expectation explicitly.
func TestWorkOSNeverSendsClientSecret(t *testing.T) {
	m := newWorkOSMock(t)
	cred := cloudcred.Open(t.TempDir(), nil)
	if _, err := WorkOSExchangeCode(context.Background(), m.srv.Client(), m.endpoints(), cred, "client_x", "c", "v"); err != nil {
		t.Fatalf("exchange should succeed without a client secret: %v", err)
	}
	if strings.Contains("", "client_secret") { // documentation anchor
		t.Fatal("unreachable")
	}
}
