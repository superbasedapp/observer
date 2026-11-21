package oidchttp_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

func doReq(t *testing.T, is *issuerServer, method, path, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, is.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func oauthErr(t *testing.T, resp *http.Response) string {
	t.Helper()
	var b struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatalf("error body: %v", err)
	}
	return b.Error
}

func TestDiscoveryAndJWKSRoutes(t *testing.T) {
	t.Parallel()
	is, _ := newIssuerServer(t, 2)
	resp := doReq(t, is, http.MethodGet, oidcissuer.DiscoveryPath, "", nil)
	var d oidcissuer.Discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil || d.Issuer != is.issuer || d.JWKSURI != is.issuer+"/jwks.json" {
		t.Fatalf("discovery = %+v, %v", d, err)
	}
	resp = doReq(t, is, http.MethodGet, oidcissuer.JWKSPath, "", nil)
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("JWKS Cache-Control = %q", cc)
	}
	var doc oidcissuer.JWKSDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || len(doc.Keys) != 2 {
		t.Fatalf("JWKS = %+v, %v; want both replicas' keys", doc, err)
	}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" || k.Kid == "" {
			t.Errorf("JWK = %+v", k)
		}
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("the JWKS route answers CORS")
	}
}

func TestAuthorizeWithoutSessionGoesToSignIn(t *testing.T) {
	t.Parallel()
	is, _ := newIssuerServer(t, 1)
	q := url.Values{
		"client_id": {oidcissuer.ClientIDForOrg(orgA)}, "redirect_uri": {"https://acme.superbased.app/auth/oidc/callback"},
		"response_type": {"code"}, "scope": {"openid email"}, "state": {"s1"}, "nonce": {"n1"},
		"code_challenge": {oidcissuer.S256Challenge(strings.Repeat("v", 43))}, "code_challenge_method": {"S256"},
	}
	resp := doReq(t, is, http.MethodGet, oidcissuer.AuthorizePath+"?"+q.Encode(), "", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Path != "/portal/auth/workos/start" {
		t.Fatalf("Location = %s", loc)
	}
	back := loc.Query().Get("return_to")
	if !strings.HasPrefix(back, "/oauth2/authorize?") {
		t.Fatalf("return_to = %q", back)
	}
	bq, _ := url.ParseQuery(strings.TrimPrefix(back, "/oauth2/authorize?"))
	if bq.Get("state") != "s1" || bq.Get("code_challenge") != q.Get("code_challenge") {
		t.Errorf("return_to lost the request: %v", bq)
	}

	// A bad redirect URI is answered in place, never redirected, even with no
	// session.
	q.Set("redirect_uri", "https://evil.example/cb")
	resp = doReq(t, is, http.MethodGet, oidcissuer.AuthorizePath+"?"+q.Encode(), "", nil)
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" || oauthErr(t, resp) != "invalid_request" {
		t.Fatalf("mismatched redirect: status %d Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestTokenRouteRefusals(t *testing.T) {
	t.Parallel()
	is, _ := newIssuerServer(t, 1)
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {strings.Repeat("c", 43)},
		"redirect_uri": {"https://acme.superbased.app/auth/oidc/callback"}, "client_id": {oidcissuer.ClientIDForOrg(orgA)},
		"code_verifier": {strings.Repeat("v", 43)},
	}
	formCT := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	cases := []struct {
		name, path, body string
		hdr              map[string]string
		status           int
		code             string
	}{
		{"unknown code", oidcissuer.TokenPath, form.Encode(), formCT, 400, "invalid_grant"},
		{"json body", oidcissuer.TokenPath, `{"code":"x"}`, map[string]string{"Content-Type": "application/json"}, 400, "invalid_request"},
		{"query parameters", oidcissuer.TokenPath + "?" + form.Encode(), "", formCT, 400, "invalid_request"},
		{"basic credentials", oidcissuer.TokenPath, form.Encode(), map[string]string{
			"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic b3JnOng6eQ==",
		}, 401, "invalid_client"},
		{"client secret in the form", oidcissuer.TokenPath, form.Encode() + "&client_secret=s", formCT, 401, "invalid_client"},
		{"oversized body", oidcissuer.TokenPath, strings.Repeat("a", 20<<10), formCT, 400, "invalid_request"},
	}
	for _, tc := range cases {
		resp := doReq(t, is, http.MethodPost, tc.path, tc.body, tc.hdr)
		if resp.StatusCode != tc.status {
			t.Errorf("%s: status %d, want %d", tc.name, resp.StatusCode, tc.status)
			continue
		}
		if got := oauthErr(t, resp); got != tc.code {
			t.Errorf("%s: error %q, want %q", tc.name, got, tc.code)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", tc.name, resp.Header.Get("Cache-Control"))
		}
	}
}
