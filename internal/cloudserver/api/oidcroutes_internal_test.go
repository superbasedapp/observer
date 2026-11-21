package api

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
)

// oidcroutes_internal_test.go covers the three api rows M6.2 adds, without
// Postgres: the /oauth2 canonical-host rule, the return_to exception for the
// authorize endpoint, and the mount (including the refusal to mount an
// issuer whose identifier is not the portal origin's).

const (
	oidcPortalHost = "app.example"
	oidcAPIHost    = "cloud.example"
)

func newOIDCTestServer(t *testing.T, issuerURL string) http.Handler {
	t.Helper()
	signer, err := oidcissuer.NewLocalSigner(issuerURL, []*rsa.PrivateKey{oidctest.NewKey(t)}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := oidcissuer.New(oidcissuer.Config{Issuer: issuerURL, Store: oidctest.NewMemStore(), Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	noRedirect := ""
	s := New(Options{
		RateLimit: &RateLimitConfig{}, RootRedirectURL: &noRedirect,
		ExternalBaseURL: "https://" + oidcAPIHost, PortalBaseURL: "https://" + oidcPortalHost,
		PortalHost: oidcPortalHost, APIHost: oidcAPIHost,
		OIDCIssuer: iss,
	})
	return s.Handler()
}

func serveHost(h http.Handler, method, target, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestOIDCRoutesCanonicalHost(t *testing.T) {
	t.Parallel()
	h := newOIDCTestServer(t, "https://"+oidcPortalHost+oidcissuer.IssuerPath)
	cases := []struct {
		name, method, path, host string
		want                     int
	}{
		{"discovery on the portal host", http.MethodGet, oidcissuer.DiscoveryPath, oidcPortalHost, http.StatusOK},
		{"jwks on the portal host", http.MethodGet, oidcissuer.JWKSPath, oidcPortalHost, http.StatusOK},
		{"discovery on the api host", http.MethodGet, oidcissuer.DiscoveryPath, oidcAPIHost, http.StatusMisdirectedRequest},
		{"jwks on a stranger host", http.MethodGet, oidcissuer.JWKSPath, "evil.example", http.StatusMisdirectedRequest},
		{"token on the api host", http.MethodPost, oidcissuer.TokenPath, oidcAPIHost, http.StatusMisdirectedRequest},
		{"authorize on the api host", http.MethodGet, oidcissuer.AuthorizePath, oidcAPIHost, http.StatusMisdirectedRequest},
		{"a lookalike prefix is not the issuer", http.MethodGet, "/oauth2x", oidcPortalHost, http.StatusNotFound},
	}
	for _, tc := range cases {
		if rec := serveHost(h, tc.method, tc.path, tc.host); rec.Code != tc.want {
			t.Errorf("%s: %s %s Host=%s = %d, want %d", tc.name, tc.method, tc.path, tc.host, rec.Code, tc.want)
		}
	}
}

func TestOIDCAuthorizeWithoutSessionResumesThroughSignIn(t *testing.T) {
	t.Parallel()
	org := "0b5c3f1e-2d4a-4c6b-9e8f-1a2b3c4d5e6f"
	// The client must exist for authorize to get past the client rows.
	signer, err := oidcissuer.NewLocalSigner("https://"+oidcPortalHost+oidcissuer.IssuerPath, []*rsa.PrivateKey{oidctest.NewKey(t)}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ms := oidctest.NewMemStore()
	c, _ := oidcissuer.ClientForOrg(org, "acme", "superbased.app")
	ms.AddClient(c)
	iss, _ := oidcissuer.New(oidcissuer.Config{Issuer: "https://" + oidcPortalHost + oidcissuer.IssuerPath, Store: ms, Signer: signer})
	noRedirect := ""
	h := New(Options{
		RateLimit: &RateLimitConfig{}, RootRedirectURL: &noRedirect,
		ExternalBaseURL: "https://" + oidcAPIHost, PortalBaseURL: "https://" + oidcPortalHost, OIDCIssuer: iss,
	}).Handler()

	q := url.Values{
		"client_id": {c.ClientID}, "redirect_uri": {c.RedirectURIs[0]}, "response_type": {"code"},
		"scope": {"openid email"}, "state": {"s"}, "nonce": {"n"},
		"code_challenge": {oidcissuer.S256Challenge(strings.Repeat("v", 43))}, "code_challenge_method": {"S256"},
	}
	rec := serveHost(h, http.MethodGet, oidcissuer.AuthorizePath+"?"+q.Encode(), oidcPortalHost)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize without a session = %d %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Path != "/portal/auth/workos/start" {
		t.Fatalf("Location = %s", rec.Header().Get("Location"))
	}
	back := loc.Query().Get("return_to")
	got, ok := safeReturnPath(back)
	if !ok || got != oidcissuer.AuthorizePath+"?"+q.Encode() {
		t.Fatalf("safeReturnPath(%q) = %q, %v; want the same authorize request back", back, got, ok)
	}
}

func TestOIDCIssuerOffThePortalOriginIsNotMounted(t *testing.T) {
	t.Parallel()
	h := newOIDCTestServer(t, "https://elsewhere.example"+oidcissuer.IssuerPath)
	if rec := serveHost(h, http.MethodGet, oidcissuer.DiscoveryPath, oidcPortalHost); rec.Code != http.StatusNotFound {
		t.Fatalf("discovery for a foreign issuer identifier = %d, want 404 (not mounted)", rec.Code)
	}
}

func TestSafeReturnPathOIDCAuthorizeRow(t *testing.T) {
	t.Parallel()
	accepted := []struct{ in, want string }{
		{"/oauth2/authorize", "/oauth2/authorize"},
		{"/oauth2/authorize?state=s&client_id=org%3Ax", "/oauth2/authorize?client_id=org%3Ax&state=s"},
		{
			"/oauth2/authorize?redirect_uri=https%3A%2F%2Facme.superbased.app%2Fauth%2Foidc%2Fcallback",
			"/oauth2/authorize?redirect_uri=https%3A%2F%2Facme.superbased.app%2Fauth%2Foidc%2Fcallback",
		},
		{"/oauth2//authorize?x=1", "/oauth2/authorize?x=1"},
		// The portal rows are unchanged.
		{"/portal/privacy", "/portal/privacy"},
		{"/portal/", "/portal/"},
	}
	for _, tc := range accepted {
		if got, ok := safeReturnPath(tc.in); !ok || got != tc.want {
			t.Errorf("safeReturnPath(%q) = %q, %v; want %q", tc.in, got, ok, tc.want)
		}
	}
	rejected := []string{
		"/oauth2/authorize?x=1#frag",
		"/oauth2/authorize/?x=1",
		"/oauth2/token?x=1",
		"/oauth2/jwks.json",
		"/oauth2/authorize/../token?x=1",
		"/oauth2/%2e%2e/token?x=1",
		"/oauth2%2fauthorize?x=1",
		"//oauth2/authorize?x=1",
		"https://evil.example/oauth2/authorize?x=1",
		"/oauth2/authorize\\?x=1",
		"/oauth2/authorize?x=%zz",
		"/oauth2/authorize?x=1\r\nSet-Cookie: a=b",
		"/portal/x?next=//evil.example",
		"/portal/x?",
		"/portal/x#frag",
		"/evil",
	}
	for _, bad := range rejected {
		if got, ok := safeReturnPath(bad); ok {
			t.Errorf("safeReturnPath(%q) accepted as %q", bad, got)
		}
	}
}
