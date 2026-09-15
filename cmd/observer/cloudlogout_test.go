package main

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcred"
)

// `observer cloud logout` (plan §3 W1, D17). The command's contract is a
// two-parter: it asks the server to revoke this device's token FIRST, then
// clears local credentials — and the server half is strictly BEST-EFFORT.
// Signing out of your own machine must work offline, against a dead endpoint,
// and with an already-expired token, so no server outcome may block or fail the
// local clear.

// credCleared reports whether the credential store rooted at dir holds no API
// token for the cloud host at baseURL (the observable result of `logout`
// locally). The store is PER HOST since 2026-09-16 (cloudcred.OpenForHost), so
// the test reads the same host-scoped slot the gateway wrote.
func credCleared(t *testing.T, dir, baseURL string) bool {
	t.Helper()
	u, perr := url.Parse(baseURL)
	if perr != nil {
		t.Fatalf("parse base url: %v", perr)
	}
	_, err := cloudcred.OpenForHost(dir, strings.ToLower(u.Hostname()), nil).LoadAPIToken()
	if err == nil {
		return false
	}
	if !errors.Is(err, cloudcred.ErrNotFound) {
		t.Fatalf("LoadAPIToken: unexpected error %v", err)
	}
	return true
}

// TestCloudLogoutRevokesServerTokenThenClearsLocal is the D17 happy path: one
// server revocation, then a clean local clear.
func TestCloudLogoutRevokesServerTokenThenClearsLocal(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, _, dir := writeCloudTestConfig(t)
	if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}
	if credCleared(t, dir, f.srv.URL) {
		t.Fatal("login stored no API token; the rest of this test would be vacuous")
	}

	out, err := runCloudCmd(t, "logout", "--config", cfgPath, "--base-url", f.srv.URL)
	if err != nil {
		t.Fatalf("logout: %v\n%s", err, out)
	}
	if f.logouts != 1 {
		t.Fatalf("server saw %d logout calls, want 1 (D17: logout must revoke server-side)", f.logouts)
	}
	if !strings.Contains(out, "Server-side device token revoked") {
		t.Fatalf("logout should report the server revocation:\n%s", out)
	}
	if !credCleared(t, dir, f.srv.URL) {
		t.Fatal("logout did not clear local credentials")
	}
}

// TestCloudLogoutBestEffortSurvivesServerFailure is the whole point of
// "best-effort": a server that refuses (or is unreachable) must NOT stop the
// local sign-out, must not fail the command, and must say so in one honest line.
func TestCloudLogoutBestEffortSurvivesServerFailure(t *testing.T) {
	t.Run("server error", func(t *testing.T) {
		f := newFakeCloudServer(t)
		f.logoutStatus = 500
		cfgPath, _, dir := writeCloudTestConfig(t)
		if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
			t.Fatalf("login: %v\n%s", err, out)
		}
		out, err := runCloudCmd(t, "logout", "--config", cfgPath, "--base-url", f.srv.URL)
		if err != nil {
			t.Fatalf("logout must not fail when the server refuses: %v\n%s", err, out)
		}
		if f.logouts != 1 {
			t.Fatalf("server saw %d logout calls, want 1", f.logouts)
		}
		if !strings.Contains(out, "Warning:") {
			t.Fatalf("a failed revocation must print one warning line:\n%s", out)
		}
		if !credCleared(t, dir, f.srv.URL) {
			t.Fatal("a server failure blocked the local credential clear")
		}
	})

	t.Run("unreachable endpoint", func(t *testing.T) {
		f := newFakeCloudServer(t)
		cfgPath, _, dir := writeCloudTestConfig(t)
		if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
			t.Fatalf("login: %v\n%s", err, out)
		}
		// Point logout at a closed port: the transport error is the offline case.
		f.srv.Close()
		out, err := runCloudCmd(t, "logout", "--config", cfgPath, "--base-url", f.srv.URL)
		if err != nil {
			t.Fatalf("logout must not fail when the server is unreachable: %v\n%s", err, out)
		}
		if !strings.Contains(out, "Warning:") {
			t.Fatalf("an unreachable server must print one warning line:\n%s", out)
		}
		if !credCleared(t, dir, f.srv.URL) {
			t.Fatal("an unreachable server blocked the local credential clear")
		}
	})
}

// TestCloudLogoutMakesNoCallWithoutCredentialOrBaseURL pins the two
// preconditions: with nothing to revoke, or nowhere to revoke it, logout stays
// entirely local — no outbound request at all (the manual-only/zero-egress
// posture: a node that was never signed in makes no network call).
func TestCloudLogoutMakesNoCallWithoutCredentialOrBaseURL(t *testing.T) {
	t.Run("no stored credential", func(t *testing.T) {
		f := newFakeCloudServer(t)
		cfgPath, _, _ := writeCloudTestConfig(t)
		out, err := runCloudCmd(t, "logout", "--config", cfgPath, "--base-url", f.srv.URL)
		if err != nil {
			t.Fatalf("logout on a never-signed-in node: %v\n%s", err, out)
		}
		if f.logouts != 0 {
			t.Fatalf("server saw %d logout calls with no stored token, want 0", f.logouts)
		}
		if !strings.Contains(out, "credentials cleared") {
			t.Fatalf("logout should still confirm the local clear:\n%s", out)
		}
	})

	t.Run("no base url", func(t *testing.T) {
		t.Setenv(cloudBaseURLEnv, "")
		f := newFakeCloudServer(t)
		cfgPath, _, dir := writeCloudTestConfig(t)
		if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
			t.Fatalf("login: %v\n%s", err, out)
		}
		out, err := runCloudCmd(t, "logout", "--config", cfgPath) // no --base-url, no env
		if err != nil {
			t.Fatalf("logout without a base URL: %v\n%s", err, out)
		}
		if f.logouts != 0 {
			t.Fatalf("server saw %d logout calls with no base URL, want 0", f.logouts)
		}
		// Credentials are PER HOST (2026-09-16): with no base URL the command
		// resolves the built-in default host and signs out of THAT host, so the
		// fake server's own slot is untouched. A full local wipe is
		// `--all-hosts` (the host-less Clear), pinned right below.
		if !credCleared(t, dir, defaultCloudBaseURL) {
			t.Fatal("logout without a base URL did not clear the default host's credentials")
		}
		if credCleared(t, dir, f.srv.URL) {
			t.Fatal("logout of the default host must not clear another host's token")
		}
		out, err = runCloudCmd(t, "logout", "--config", cfgPath, "--all-hosts")
		if err != nil {
			t.Fatalf("logout --all-hosts: %v\n%s", err, out)
		}
		if !credCleared(t, dir, f.srv.URL) {
			t.Fatal("logout --all-hosts did not wipe every host's credentials")
		}
	})
}
