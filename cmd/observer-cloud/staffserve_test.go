package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestResolveStaffServeConfig walks the staff process's configuration
// rules (ruling A3): its own host (the relying-party id, never the parent
// domain or another surface's host), its own DSN, https off loopback.
func TestResolveStaffServeConfig(t *testing.T) {
	t.Parallel()
	const dsn = "postgres://sbci_staff_svc@db/sbci"
	cases := []struct {
		name     string
		env      map[string]string
		wantErr  string
		wantHost string
		wantBase string
		wantDev  bool
	}{
		{name: "defaults", env: map[string]string{envStaffDSN: dsn}, wantHost: "staff.superbased.app", wantBase: "https://staff.superbased.app"},
		{name: "host equal to the base host", env: map[string]string{envStaffDSN: dsn, envStaffBaseURL: "https://staff.example.org/", envStaffHost: "STAFF.example.org"}, wantHost: "staff.example.org", wantBase: "https://staff.example.org"},
		{name: "no staff DSN off loopback", env: map[string]string{"SBCI_PG_DSN": dsn}, wantErr: envStaffDSN + " is required"},
		{name: "loopback falls back to the admin DSN", env: map[string]string{envStaffBaseURL: "http://localhost:8091", "SBCI_PG_DSN": dsn}, wantHost: "localhost", wantBase: "http://localhost:8091", wantDev: true},
		{name: "loopback with no DSN at all", env: map[string]string{envStaffBaseURL: "http://localhost:8091"}, wantErr: "is required"},
		{name: "plain http off loopback", env: map[string]string{envStaffDSN: dsn, envStaffBaseURL: "http://staff.superbased.app"}, wantErr: "must be https"},
		{name: "a path on the base", env: map[string]string{envStaffDSN: dsn, envStaffBaseURL: "https://staff.superbased.app/staff"}, wantErr: "must be an origin"},
		{name: "host differs from the base host", env: map[string]string{envStaffDSN: dsn, envStaffHost: "admin.superbased.app"}, wantErr: "must equal the host"},
		{name: "the parent domain", env: map[string]string{envStaffDSN: dsn, envStaffBaseURL: "https://superbased.app"}, wantErr: "registrable domain"},
		{name: "the portal host", env: map[string]string{envStaffDSN: dsn, envStaffBaseURL: "https://app.superbased.app", "SBCI_PORTAL_HOST": "app.superbased.app"}, wantErr: "SBCI_PORTAL_HOST"},
		{name: "the API host", env: map[string]string{envStaffDSN: dsn, envStaffBaseURL: "https://cloud.superbased.app", "SBCI_API_HOST": "cloud.superbased.app"}, wantErr: "SBCI_API_HOST"},
		{name: "the tenant domain", env: map[string]string{envStaffDSN: dsn, envStaffBaseURL: "https://tenants.example.co", "SBCI_TENANT_DOMAIN": "tenants.example.co"}, wantErr: "SBCI_TENANT_DOMAIN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := resolveStaffServeConfig(envOf(tc.env))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.host != tc.wantHost || c.baseURL != tc.wantBase || c.devFallback != tc.wantDev || c.listen != defaultStaffListen || c.dsn != dsn {
				t.Fatalf("config = %+v", c)
			}
		})
	}
}

// TestResolveStaffEdgeSecret walks operator ruling Staff 3 (L-83): the staff
// process authenticates its edge with SBCI_STAFF_EDGE_SHARED_SECRET (or the
// file it names), required off loopback, never equal to serve's
// SBCI_EDGE_SHARED_SECRET; the result then passes the same 32-byte format
// check serve's secret does, with refusals naming the staff variable.
func TestResolveStaffEdgeSecret(t *testing.T) {
	t.Parallel()
	staffSecret := strings.Repeat("ab", 32)
	serveSecret := strings.Repeat("cd", 32)
	files := map[string]string{"/run/secrets/staff-edge": staffSecret + "\n", "/run/secrets/serve-edge": serveSecret}
	readFile := func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("no such file")
	}
	cases := []struct {
		name     string
		env      map[string]string
		loopback bool
		want     string
		wantErr  string
	}{
		{name: "own secret", env: map[string]string{envStaffEdgeSecret: staffSecret, envEdgeSharedSecret: serveSecret}, want: staffSecret},
		{name: "own secret, serve's not visible", env: map[string]string{envStaffEdgeSecret: staffSecret}, want: staffSecret},
		{name: "own secret from a file", env: map[string]string{envStaffEdgeSecretFile: "/run/secrets/staff-edge", envEdgeSharedSecret: serveSecret}, want: staffSecret},
		{name: "the variable wins over the file", env: map[string]string{envStaffEdgeSecret: staffSecret, envStaffEdgeSecretFile: "/run/secrets/serve-edge"}, want: staffSecret},
		{name: "unset off loopback", env: map[string]string{}, wantErr: envStaffEdgeSecret + " (or " + envStaffEdgeSecretFile + ") is required"},
		{name: "only serve's secret set (the old shared posture)", env: map[string]string{envEdgeSharedSecret: serveSecret}, wantErr: "is required off loopback"},
		{name: "unset on loopback (no edge)", env: map[string]string{}, loopback: true, want: ""},
		{name: "equal to serve's", env: map[string]string{envStaffEdgeSecret: serveSecret, envEdgeSharedSecret: serveSecret}, wantErr: "equals " + envEdgeSharedSecret},
		{name: "equal to serve's through the file", env: map[string]string{envStaffEdgeSecretFile: "/run/secrets/serve-edge", envEdgeSharedSecret: serveSecret}, wantErr: "equals " + envEdgeSharedSecret},
		{name: "equal to serve's on loopback too", env: map[string]string{envStaffEdgeSecret: serveSecret, envEdgeSharedSecret: serveSecret}, loopback: true, wantErr: "equals"},
		{name: "unreadable file", env: map[string]string{envStaffEdgeSecretFile: "/missing"}, wantErr: envStaffEdgeSecretFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveStaffEdgeSecret(envOf(tc.env), readFile, tc.loopback)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), staffSecret) || strings.Contains(err.Error(), serveSecret) {
					t.Fatal("the refusal leaks a secret")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("secret = <len %d>, err = %v; want <len %d>", len(got), err, len(tc.want))
			}
		})
	}
	// The format check names the staff variable.
	if _, err := edgeConfigForOrigin("https://staff.superbased.app", "not-hex", envStaffEdgeSecret); err == nil || !strings.Contains(err.Error(), envStaffEdgeSecret) {
		t.Fatalf("malformed staff secret: err = %v, want a refusal naming %s", err, envStaffEdgeSecret)
	}
	if edge, err := edgeConfigForOrigin("https://staff.superbased.app", staffSecret, envStaffEdgeSecret); err != nil || !edge.Enabled || edge.AuthSecret != staffSecret {
		t.Fatalf("staff edge config = %+v, %v", edge, err)
	}
}

// TestLoginRules: the staff process needs a staff-only login; the customer
// serve login must never hold the staff role; the dev posture only warns.
func TestLoginRules(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	staffOnly := store.LoginMemberships{Login: "sbci_staff_svc", Staff: true}
	cases := []struct {
		name   string
		m      store.LoginMemberships
		rules  []loginRule
		strict bool
		refuse bool
	}{
		{"staff login", staffOnly, staffLoginRules, true, false},
		{"staff process on a login without the role", store.LoginMemberships{Login: "x"}, staffLoginRules, true, true},
		{"staff process on a superuser", store.LoginMemberships{Login: "postgres", Superuser: true, Staff: true, API: true, Worker: true}, staffLoginRules, true, true},
		{"staff process on the serve login", store.LoginMemberships{Login: "sbci_api_svc", Staff: true, API: true}, staffLoginRules, true, true},
		{"staff process on a worker login", store.LoginMemberships{Login: "w", Staff: true, Worker: true}, staffLoginRules, true, true},
		{"staff process, dev superuser", store.LoginMemberships{Login: "postgres", Superuser: true, Staff: true, API: true}, staffLoginRules, false, false},
		{"serve login without the role", store.LoginMemberships{Login: "sbci_api_svc", API: true}, serveLoginRules, true, false},
		{"serve login holding the role", store.LoginMemberships{Login: "sbci_api_svc", API: true, Staff: true}, serveLoginRules, true, true},
		{"single dev login holding the role", store.LoginMemberships{Login: "postgres", Superuser: true, Staff: true}, serveLoginRules, false, false},
	}
	for _, tc := range cases {
		err := checkLogin(log, "test", tc.m, tc.rules, tc.strict)
		if (err != nil) != tc.refuse {
			t.Errorf("%s: err = %v, want refuse=%v", tc.name, err, tc.refuse)
		}
	}
}

func TestRefuseStaffInServe(t *testing.T) {
	t.Parallel()
	if err := refuseStaffInServe(envOf(map[string]string{envStaffDSN: "postgres://sbci_staff_svc@db"})); err == nil {
		t.Fatal("serve accepted the staff login's DSN")
	}
	if err := refuseStaffInServe(envOf(map[string]string{"SBCI_API_PG_DSN": "postgres://sbci_api_svc@db"})); err != nil {
		t.Fatalf("serve refused a plain configuration: %v", err)
	}
}

type fakeCredStore struct {
	creds   []store.StaffCredential
	revoked []byte
	err     error
}

func (f *fakeCredStore) ListStaffCredentials(context.Context, string) ([]store.StaffCredential, error) {
	return f.creds, f.err
}

func (f *fakeCredStore) RevokeStaffCredential(_ context.Context, _ string, id []byte, _ string, _ time.Time) error {
	f.revoked = id
	return f.err
}

func TestRunStaffCredentialsAndRevoke(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	f := &fakeCredStore{creds: []store.StaffCredential{{ID: []byte{0xAB, 0xCD}, Label: "yubikey", CreatedAt: now}}}
	var out bytes.Buffer
	if err := runStaffCredentials(context.Background(), f, "s1", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "abcd  active") || !strings.Contains(out.String(), "register a backup") {
		t.Errorf("credentials output = %q", out.String())
	}

	for _, tc := range []struct {
		name  string
		flags staffRevokeFlags
		ok    bool
	}{
		{"valid", staffRevokeFlags{staffID: "s1", credential: "abcd", reason: "lost"}, true},
		{"no staff id", staffRevokeFlags{credential: "abcd", reason: "lost"}, false},
		{"not hex", staffRevokeFlags{staffID: "s1", credential: "zz", reason: "lost"}, false},
		{"no reason", staffRevokeFlags{staffID: "s1", credential: "abcd", reason: " "}, false},
	} {
		f := &fakeCredStore{}
		err := runStaffRevoke(context.Background(), f, tc.flags, now, io.Discard)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if tc.ok && !bytes.Equal(f.revoked, []byte{0xAB, 0xCD}) {
			t.Errorf("%s: revoked %x", tc.name, f.revoked)
		}
	}
	f = &fakeCredStore{err: store.ErrNotFound}
	if err := runStaffRevoke(context.Background(), f, staffRevokeFlags{staffID: "s1", credential: "abcd", reason: "lost"}, now, io.Discard); err == nil || errors.Is(err, store.ErrNotFound) || !strings.Contains(err.Error(), "no active passkey") {
		t.Errorf("not found: err = %v", err)
	}
}
