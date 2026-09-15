package main

import (
	"strings"
	"testing"
)

// TestValidatePortalCookieMode proves FC4: the server refuses to start in an
// unsafe non-Secure portal-cookie configuration. A non-Secure cookie is
// bearer-equivalent on the wire, so it is allowed only for a loopback http dev
// origin with dev-auth on; an explicit SBCI_PORTAL_SECURE=0 cannot downgrade a
// non-loopback/https origin; and the base URL must be a valid http/https origin.
func TestValidatePortalCookieMode(t *testing.T) {
	cases := []struct {
		name        string
		base        string
		secure      bool
		devAuth     bool
		explicitEnv string
		wantErr     bool
	}{
		{"https_secure_ok", "https://cloud.superbased.app", true, false, "", false},
		{"loopback_http_devauth_ok", "http://localhost:8090", false, true, "", false},
		{"loopback_ip_http_devauth_ok", "http://127.0.0.1:8090", false, true, "", false},
		{"nonloopback_http_nonsecure_err", "http://staging.example", false, false, "", true},
		{"loopback_http_no_devauth_err", "http://localhost:8090", false, false, "", true},
		{"https_explicit_off_err", "https://cloud.superbased.app", false, false, "0", true},
		{"nonloopback_explicit_off_err", "http://staging.example", false, true, "0", true},
		{"https_secure_explicit_off_downgrade_err", "https://cloud.superbased.app", true, true, "false", true},
		{"bad_scheme_err", "ftp://cloud.superbased.app", false, false, "", true},
		{"no_host_err", "https://", true, false, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validatePortalCookieMode(c.base, c.secure, c.devAuth, c.explicitEnv)
			if c.wantErr && err == nil {
				t.Fatalf("validatePortalCookieMode(%q, secure=%v, devAuth=%v, env=%q) = nil, want error",
					c.base, c.secure, c.devAuth, c.explicitEnv)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("validatePortalCookieMode(%q, ...) unexpected error: %v", c.base, err)
			}
		})
	}
}

// TestValidateTwoOriginConfig proves the F1 startup gate: once the browser
// sign-in leg is live AND both surfaces are fenced to their own names, the two
// base URLs must actually describe those names. A mismatch there is invisible
// until a real user's callback lands on a host that answers 421, so the server
// refuses to start instead.
//
// It is deliberately inert in every other configuration — that is what keeps
// the single-host staging deployment (and every existing test) unchanged.
func TestValidateTwoOriginConfig(t *testing.T) {
	const (
		portalHost = "app.superbased.app"
		apiHost    = "cloud.superbased.app"
		portalBase = "https://app.superbased.app"
		apiBase    = "https://cloud.superbased.app"
	)
	cases := []struct {
		name                                   string
		portalBase, externalBase, pHost, aHost string
		workosEnabled                          bool
		wantErr                                bool
		wantErrContains                        string
	}{
		{
			name: "correct two-origin config", portalBase: portalBase, externalBase: apiBase,
			pHost: portalHost, aHost: apiHost, workosEnabled: true,
		},
		{
			name: "hosts carrying ports still match", portalBase: portalBase + ":443", externalBase: apiBase + ":443",
			pHost: portalHost + ":443", aHost: apiHost, workosEnabled: true,
		},
		{
			// The exact pre-fix bug: the portal base was never split out, so it
			// still pointed at the API origin.
			name: "portal base still points at the api host", portalBase: apiBase, externalBase: apiBase,
			pHost: portalHost, aHost: apiHost, workosEnabled: true,
			wantErr: true, wantErrContains: "SBCI_PORTAL_BASE_URL host",
		},
		{
			name: "external base points at the portal host", portalBase: portalBase, externalBase: portalBase,
			pHost: portalHost, aHost: apiHost, workosEnabled: true,
			wantErr: true, wantErrContains: "SBCI_EXTERNAL_BASE_URL host",
		},
		{
			name: "portal base is not https", portalBase: "http://app.superbased.app", externalBase: apiBase,
			pHost: portalHost, aHost: apiHost, workosEnabled: true,
			wantErr: true, wantErrContains: "must be https",
		},
		{
			// The one-host production shape (ruling 2026-09-11): both surfaces
			// fenced to the same public name, both bases carrying it. Refusing
			// this crash-looped prod on the first SBCI_PORTAL_WORKOS=1 flip.
			name: "one-host shape: both surfaces fenced to the same name", portalBase: apiBase, externalBase: apiBase,
			pHost: apiHost, aHost: apiHost, workosEnabled: true,
		},
		{
			name: "one-host shape with the portal base on a different name", portalBase: portalBase, externalBase: apiBase,
			pHost: apiHost, aHost: apiHost, workosEnabled: true,
			wantErr: true, wantErrContains: "SBCI_PORTAL_BASE_URL host",
		},
		{
			name: "one-host shape with the external base on a different name", portalBase: apiBase, externalBase: portalBase,
			pHost: apiHost, aHost: apiHost, workosEnabled: true,
			wantErr: true, wantErrContains: "SBCI_EXTERNAL_BASE_URL host",
		},
		// --- inert configurations: nothing is validated, nothing is refused ---
		{
			name: "browser leg dark", portalBase: apiBase, externalBase: apiBase,
			pHost: portalHost, aHost: apiHost, workosEnabled: false,
		},
		{
			name: "single-host staging (no canonical hosts)", portalBase: "http://localhost:8090",
			externalBase: "http://localhost:8090", workosEnabled: true,
		},
		{
			name: "only the portal host is fenced", portalBase: apiBase, externalBase: apiBase,
			pHost: portalHost, workosEnabled: true,
		},
		{
			name: "only the api host is fenced", portalBase: apiBase, externalBase: apiBase,
			aHost: apiHost, workosEnabled: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateTwoOriginConfig(c.portalBase, c.externalBase, c.pHost, c.aHost, c.workosEnabled)
			switch {
			case c.wantErr && err == nil:
				t.Fatalf("validateTwoOriginConfig(%q, %q, %q, %q, %v) = nil, want an error",
					c.portalBase, c.externalBase, c.pHost, c.aHost, c.workosEnabled)
			case !c.wantErr && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.wantErr && c.wantErrContains != "" && !strings.Contains(err.Error(), c.wantErrContains):
				t.Fatalf("error %q does not mention %q — it must name the variable to fix", err, c.wantErrContains)
			}
		})
	}
}

// TestPortalBaseURLFallsBackToExternal pins the compatibility contract: with
// SBCI_PORTAL_BASE_URL unset the portal origin IS the API origin, so a
// single-host deployment is untouched by the two-origin split.
func TestPortalBaseURLFallsBackToExternal(t *testing.T) {
	t.Setenv("SBCI_PORTAL_BASE_URL", "")
	if got, want := portalBaseURL("http://localhost:8090"), "http://localhost:8090"; got != want {
		t.Fatalf("portalBaseURL = %q, want the external base %q", got, want)
	}
	t.Setenv("SBCI_PORTAL_BASE_URL", "https://app.superbased.app/")
	if got, want := portalBaseURL("http://localhost:8090"), "https://app.superbased.app"; got != want {
		t.Fatalf("portalBaseURL = %q, want %q (trailing slash trimmed)", got, want)
	}
}

// TestEdgeConfigForExternalOrigin pins the production fail-closed bootstrap:
// only loopback development can omit hop authentication; every public origin
// requires the exact 32-byte secret provisioned by the Azure/Cloudflare
// runbook, so a missing secret cannot silently reopen the raw ACA origin.
func TestEdgeConfigForExternalOrigin(t *testing.T) {
	secret := strings.Repeat("ab", 32)
	cases := []struct {
		name       string
		base       string
		secret     string
		wantEnable bool
		wantErr    bool
	}{
		{name: "localhost development", base: "http://localhost:8090"},
		{name: "ipv4 loopback development", base: "http://127.0.0.1:8090"},
		{name: "ipv6 loopback development", base: "http://[::1]:8090"},
		{name: "public authenticated edge", base: "https://cloud.superbased.app", secret: secret, wantEnable: true},
		{name: "public missing secret", base: "https://cloud.superbased.app", wantErr: true},
		{name: "short secret", base: "https://cloud.superbased.app", secret: "abcd", wantErr: true},
		{name: "non hex secret", base: "https://cloud.superbased.app", secret: strings.Repeat("z", 64), wantErr: true},
		{name: "whitespace wrapped secret", base: "https://cloud.superbased.app", secret: " " + secret, wantErr: true},
		{name: "origin without host", base: "https://", secret: secret, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := edgeConfigForExternalOrigin(tc.base, tc.secret)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("edgeConfigForExternalOrigin(%q, <secret len=%d>) = %+v, want error", tc.base, len(tc.secret), got)
				}
				return
			}
			if err != nil {
				t.Fatalf("edgeConfigForExternalOrigin(%q): %v", tc.base, err)
			}
			if got.Enabled != tc.wantEnable {
				t.Fatalf("Enabled=%v, want %v", got.Enabled, tc.wantEnable)
			}
			if tc.wantEnable && got.AuthSecret != tc.secret {
				t.Fatal("enabled edge did not retain the configured shared secret")
			}
		})
	}
}
