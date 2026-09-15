package attest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newIMDSServer returns an httptest.Server standing in for the Azure IMDS
// token endpoint. It records every request's query params and answers with a
// token whose expiry is `ttl` from now, so the test can drive caching without
// waiting on real time — the server's own request count doubles as the
// "did we actually make a network round trip" signal.
func newIMDSServer(t *testing.T, ttl time.Duration) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	var gotMetadataHeader atomic.Bool
	var gotAPIVersion, gotResource, gotClientID atomic.Value
	gotAPIVersion.Store("")
	gotResource.Store("")
	gotClientID.Store("")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Header.Get("Metadata") == "true" {
			gotMetadataHeader.Store(true)
		}
		gotAPIVersion.Store(r.URL.Query().Get("api-version"))
		gotResource.Store(r.URL.Query().Get("resource"))
		gotClientID.Store(r.URL.Query().Get("client_id"))

		expiresOn := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"tok-for-%s","expires_on":"%s"}`, r.URL.Query().Get("resource"), expiresOn)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		if !gotMetadataHeader.Load() {
			t.Error("IMDS request never carried the required Metadata: true header")
		}
		if gotAPIVersion.Load().(string) == "" {
			t.Error("IMDS request carried no api-version")
		}
	})
	return srv, &calls
}

func TestManagedIdentityTokenSourceFetchesAndCaches(t *testing.T) {
	srv, calls := newIMDSServer(t, time.Hour)
	m := &ManagedIdentityTokenSource{Endpoint: srv.URL}

	tok, err := m.Token(context.Background(), "https://management.azure.com/")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "tok-for-https://management.azure.com/" {
		t.Fatalf("token = %q", tok)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("calls after first Token = %d, want 1", got)
	}

	// Second call for the SAME audience, well inside the 1h TTL minus the 5m
	// skew — must be served from cache, no second network round trip.
	tok2, err := m.Token(context.Background(), "https://management.azure.com/")
	if err != nil {
		t.Fatalf("Token (cached): %v", err)
	}
	if tok2 != tok {
		t.Fatalf("cached token = %q, want %q", tok2, tok)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("calls after cached Token = %d, want 1 (cache should have been used)", got)
	}
}

func TestManagedIdentityTokenSourceRefetchesPastSkew(t *testing.T) {
	// TTL shorter than the 5-minute refresh skew: every call must mint fresh.
	srv, calls := newIMDSServer(t, 2*time.Minute)
	m := &ManagedIdentityTokenSource{Endpoint: srv.URL}

	if _, err := m.Token(context.Background(), "aud"); err != nil {
		t.Fatalf("Token #1: %v", err)
	}
	if _, err := m.Token(context.Background(), "aud"); err != nil {
		t.Fatalf("Token #2: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("calls = %d, want 2 (a token inside the refresh skew must not be cached)", got)
	}
}

func TestManagedIdentityTokenSourcePassesClientID(t *testing.T) {
	srv, _ := newIMDSServer(t, time.Hour)
	m := &ManagedIdentityTokenSource{Endpoint: srv.URL, ClientID: "user-assigned-identity-client-id"}

	// Route the request through a transport that inspects the outgoing query so
	// the test proves client_id was actually sent, not just accepted.
	var sawClientID string
	m.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sawClientID = r.URL.Query().Get("client_id")
		return http.DefaultTransport.RoundTrip(r)
	})}

	if _, err := m.Token(context.Background(), "aud"); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if sawClientID != "user-assigned-identity-client-id" {
		t.Fatalf("client_id sent = %q, want the configured client id", sawClientID)
	}
}

func TestManagedIdentityTokenSourceEmptyAudience(t *testing.T) {
	m := &ManagedIdentityTokenSource{}
	if _, err := m.Token(context.Background(), "   "); err == nil {
		t.Fatal("Token(empty audience) = nil error, want an error")
	}
}

func TestManagedIdentityTokenSourceNonJSONNoAccessToken(t *testing.T) {
	cases := []struct {
		name string
		body string
		code int
	}{
		{"non_2xx", `{}`, http.StatusForbidden},
		{"empty_access_token", `{"access_token":"","expires_on":"9999999999"}`, http.StatusOK},
		{"malformed_json", `not json`, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.code)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			m := &ManagedIdentityTokenSource{Endpoint: srv.URL}
			if _, err := m.Token(context.Background(), "aud"); err == nil {
				t.Fatalf("Token() with %s = nil error, want an error", c.name)
			}
		})
	}
}

func TestManagedIdentityTokenSourceUnreachable(t *testing.T) {
	m := &ManagedIdentityTokenSource{
		Endpoint:   "http://127.0.0.1:1", // nobody listens on port 1
		HTTPClient: &http.Client{Timeout: time.Second},
	}
	if _, err := m.Token(context.Background(), "aud"); err == nil {
		t.Fatal("Token() against an unreachable endpoint = nil error, want an error")
	}
}

// roundTripFunc adapts a function to http.RoundTripper for inline test doubles.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestManagedIdentityTokenSourceIsATokenSource(t *testing.T) {
	var _ TokenSource = (*ManagedIdentityTokenSource)(nil)
	if !strings.Contains(defaultIMDSEndpoint, "169.254.169.254") {
		t.Fatal("defaultIMDSEndpoint is not the well-known Azure IMDS link-local address")
	}
}
