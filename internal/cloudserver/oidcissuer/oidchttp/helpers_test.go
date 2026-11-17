package oidchttp_test

import (
	"crypto/rsa"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidchttp"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
)

// helpers_test.go holds the issuer test server shared by handlers_test.go and
// conformance_test.go. It imports nothing private: the public release drops
// conformance_test.go (it imports internal/orgserver), and the handler tests
// must still compile there.

const (
	orgA  = "0b5c3f1e-2d4a-4c6b-9e8f-1a2b3c4d5e6f"
	alice = "aaaaaaaa-0000-4000-8000-000000000001"
	// accountHeader stands in for the api package's portal-session lookup.
	accountHeader = "X-Test-Account"
	// authTimeHeader stands in for the session's authentication time.
	authTimeHeader = "X-Test-Auth-Time"
)

type issuerServer struct {
	srv    *httptest.Server
	store  *oidctest.MemStore
	clock  *oidctest.Clock
	issuer string
}

// newIssuerServer serves replicas behind one URL: each request goes to the
// replica pick names, all sharing one store.
func newIssuerServer(t *testing.T, replicas int) (*issuerServer, *atomic.Int32) {
	t.Helper()
	is := &issuerServer{store: oidctest.NewMemStore(), clock: oidctest.NewClock(time.Now().UTC().Truncate(time.Second))}
	var handlers []*oidchttp.Handler
	pick := new(atomic.Int32)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+oidcissuer.DiscoveryPath, func(w http.ResponseWriter, r *http.Request) { handlers[pick.Load()].Discovery(w, r) })
	mux.HandleFunc("GET "+oidcissuer.JWKSPath, func(w http.ResponseWriter, r *http.Request) { handlers[pick.Load()].JWKS(w, r) })
	mux.HandleFunc("GET "+oidcissuer.AuthorizePath, func(w http.ResponseWriter, r *http.Request) {
		handlers[pick.Load()].Authorize(w, r, is.session(r))
	})
	mux.HandleFunc("POST "+oidcissuer.TokenPath, func(w http.ResponseWriter, r *http.Request) { handlers[pick.Load()].Token(w, r) })
	is.srv = httptest.NewServer(mux)
	t.Cleanup(is.srv.Close)
	is.issuer = is.srv.URL + oidcissuer.IssuerPath

	c, err := oidcissuer.ClientForOrg(orgA, "acme", "superbased.app")
	if err != nil {
		t.Fatal(err)
	}
	is.store.AddClient(c)
	is.store.SetMember(alice, orgA, oidcissuer.Member{
		IsMember: true, AccountStatus: "active", OrgStatus: "active",
		RailEnabled: true, Sub: "user_alice", Email: "alice@example.com", EmailVerified: true,
	})
	for i := 0; i < replicas; i++ {
		key := oidctest.NewKey(t)
		signer, err := oidcissuer.NewLocalSigner(is.issuer, []*rsa.PrivateKey{key}, is.clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		is.store.SetKey(oidctest.ActiveKey(key, "vm", is.clock.Now().Add(-time.Hour)))
		iss, err := oidcissuer.New(oidcissuer.Config{Issuer: is.issuer, Store: is.store, Signer: signer, Now: is.clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		h, err := oidchttp.New(iss, oidchttp.Options{Logger: quietLogger()})
		if err != nil {
			t.Fatal(err)
		}
		handlers = append(handlers, h)
	}
	return is, pick
}

// session stands in for the api package's portal-session lookup: the account
// from accountHeader, its authentication time from authTimeHeader (Unix
// seconds; absent means "now" on the test clock, a session just signed in).
func (is *issuerServer) session(r *http.Request) oidcissuer.Session {
	acct := r.Header.Get(accountHeader)
	if acct == "" {
		return oidcissuer.Session{}
	}
	at := is.clock.Now()
	if v := r.Header.Get(authTimeHeader); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			at = time.Unix(n, 0).UTC()
		}
	}
	return oidcissuer.Session{AccountID: acct, AuthTime: at}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
