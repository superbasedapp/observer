package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
)

const testPortalBase = "https://app.superbased.example"

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func fixedHost(name string, err error) func() (string, error) {
	return func() (string, error) { return name, err }
}

func TestResolveOIDCServeConfig(t *testing.T) {
	t.Parallel()
	issuer := testPortalBase + oidcissuer.IssuerPath
	cases := []struct {
		name        string
		env         map[string]string
		host        func() (string, error)
		wantEnabled bool
		want        oidcServeConfig
		wantErr     string
	}{
		{name: "unset is off", env: map[string]string{}, host: fixedHost("vm-a", nil)},
		{name: "socket alone is still off", env: map[string]string{"SBCI_OIDC_SIGNER_SOCKET": "/run/x.sock"}, host: fixedHost("vm-a", nil)},
		{
			name: "issuer with defaults", env: map[string]string{"SBCI_OIDC_ISSUER": issuer}, host: fixedHost("vm-a", nil),
			wantEnabled: true, want: oidcServeConfig{issuer: issuer, socket: defaultOIDCSignerSocket, vmID: "vm-a"},
		},
		{
			name: "explicit socket and vm id", host: fixedHost("ignored", nil),
			env:         map[string]string{"SBCI_OIDC_ISSUER": issuer, "SBCI_OIDC_SIGNER_SOCKET": "/run/s.sock", "SBCI_OIDC_VM_ID": "app-2"},
			wantEnabled: true, want: oidcServeConfig{issuer: issuer, socket: "/run/s.sock", vmID: "app-2"},
		},
		{name: "issuer on another origin", env: map[string]string{"SBCI_OIDC_ISSUER": "https://cloud.superbased.example/oauth2"}, host: fixedHost("vm-a", nil), wantErr: "portal origin"},
		{name: "issuer without the path", env: map[string]string{"SBCI_OIDC_ISSUER": testPortalBase}, host: fixedHost("vm-a", nil), wantErr: "portal origin"},
		{name: "hostname unreadable", env: map[string]string{"SBCI_OIDC_ISSUER": issuer}, host: fixedHost("", errors.New("no host")), wantErr: "hostname"},
		{name: "vm id with a space", env: map[string]string{"SBCI_OIDC_ISSUER": issuer, "SBCI_OIDC_VM_ID": "app 1"}, host: fixedHost("x", nil), wantErr: "spaces"},
		{name: "vm id too long", env: map[string]string{"SBCI_OIDC_ISSUER": issuer, "SBCI_OIDC_VM_ID": strings.Repeat("v", maxVMIDLen+1)}, host: fixedHost("x", nil), wantErr: "1 to 100"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, enabled, err := resolveOIDCServeConfig(envMap(tc.env), tc.host, testPortalBase)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if enabled != tc.wantEnabled || got != tc.want {
				t.Fatalf("got (%+v, %v), want (%+v, %v)", got, enabled, tc.want, tc.wantEnabled)
			}
		})
	}
}

// newServeTestHandler builds the api handler the way serve does, with the
// issuer (or nil) serve would pass.
func newServeTestHandler(iss *oidcissuer.Issuer) http.Handler {
	noRedirect := ""
	return api.New(api.Options{
		RateLimit: &api.RateLimitConfig{}, RootRedirectURL: &noRedirect,
		ExternalBaseURL: testPortalBase, PortalBaseURL: testPortalBase,
		OIDCIssuer: iss,
	}).Handler()
}

func get(h http.Handler, path string) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

func TestServeUnconfiguredOIDCMountsNothing(t *testing.T) {
	t.Parallel()
	_, enabled, err := resolveOIDCServeConfig(envMap(nil), fixedHost("vm-a", nil), testPortalBase)
	if err != nil || enabled {
		t.Fatalf("unset env: enabled=%v err=%v, want off", enabled, err)
	}
	h := newServeTestHandler(nil)
	for _, p := range []string{oidcissuer.DiscoveryPath, oidcissuer.JWKSPath, oidcissuer.AuthorizePath} {
		if code := get(h, p); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 with the issuer unconfigured", p, code)
		}
	}
}

func TestServeConfiguredOIDCMountsTheRoutes(t *testing.T) {
	t.Parallel()
	cfg, enabled, err := resolveOIDCServeConfig(envMap(map[string]string{"SBCI_OIDC_ISSUER": testPortalBase + oidcissuer.IssuerPath}),
		fixedHost("vm-a", nil), testPortalBase)
	if err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
	signer, err := oidcissuer.NewLocalSigner(cfg.issuer, []*rsa.PrivateKey{oidctest.NewKey(t)}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := newServeOIDCIssuer(cfg, oidctest.NewMemStore(), nil, signer)
	if err != nil {
		t.Fatal(err)
	}
	h := newServeTestHandler(iss)
	for _, p := range []string{oidcissuer.DiscoveryPath, oidcissuer.JWKSPath} {
		if code := get(h, p); code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 with the issuer configured", p, code)
		}
	}
}

func TestRunOIDCMaintenanceRetriesRegistrationUntilItSucceeds(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	registerCalls := make(chan int, 8)
	sweeps := make(chan time.Time, 8)
	n := 0
	register := func(context.Context) error {
		n++
		registerCalls <- n
		if n == 1 {
			return errors.New("signer down")
		}
		return nil
	}
	sweep := func(_ context.Context, now time.Time) (int64, error) {
		sweeps <- now
		return 0, nil
	}
	clock := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	tick := make(chan time.Time)
	done := make(chan struct{})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		runOIDCMaintenance(ctx, log, register, sweep, tick, func() time.Time { return clock })
		close(done)
	}()
	if got := <-registerCalls; got != 1 {
		t.Fatalf("first register call = %d", got)
	}
	tick <- clock // retry: succeeds
	if got := <-registerCalls; got != 2 {
		t.Fatalf("second register call = %d", got)
	}
	if got := <-sweeps; !got.Equal(clock) {
		t.Fatalf("sweep at %v, want the injected clock", got)
	}
	tick <- clock // registered: sweep only
	<-sweeps
	cancel()
	<-done
	if len(registerCalls) != 0 || n != 2 {
		t.Fatalf("register called %d times, want 2 (no retry after a success)", n)
	}
}

// TestSignerIsRegisteredAsASubcommand pins that `signer oidc` is reachable.
func TestSignerIsRegisteredAsASubcommand(t *testing.T) {
	t.Parallel()
	for _, c := range newRootCmd().Commands() {
		if c.Name() != "signer" {
			continue
		}
		for _, sub := range c.Commands() {
			if sub.Name() == "oidc" {
				return
			}
		}
	}
	t.Fatal("observer-cloud has no `signer oidc` subcommand registered")
}
