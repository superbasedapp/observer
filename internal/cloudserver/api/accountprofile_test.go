package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
)

// accountprofile_test.go pins the display-identity leg end to end: the WorkOS
// code exchange captures the user object the provider returns, the dev-auth
// token captures its optional email, `/portal/api/session` hands the signed-in
// browser its own profile, and an account nothing is known about gets NO
// profile key at all (so the SPA can honestly fall back to the account id).

// sessionBody is the /portal/api/session response, profile included.
type sessionBody struct {
	AccountID string `json:"account_id"`
	CSRF      string `json:"csrf_token"`
	AuthMode  string `json:"auth_mode"`
	Profile   *struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
	} `json:"profile"`
}

func readSession(t *testing.T, hc *http.Client, base string) sessionBody {
	t.Helper()
	resp, err := hc.Get(base + "/portal/api/session")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var body sessionBody
	decode(t, resp, &body)
	return body
}

// TestPortalSessionCarriesWorkOSProfile is the headline: after a real WorkOS
// callback whose token response carried a `user` object, the SPA's reload
// bootstrap returns the developer's own email and name — the thing the top bar
// renders instead of a UUID.
func TestPortalSessionCarriesWorkOSProfile(t *testing.T) {
	h := newWorkOSHarness(t, true)
	hc, _, _ := h.signIn(t, "ada")

	got := readSession(t, hc, h.srv.URL)
	if got.Profile == nil {
		t.Fatal("session carried no profile after a WorkOS sign-in that returned a user object")
	}
	if got.Profile.Email != "ada@example.test" {
		t.Errorf("profile.email = %q, want ada@example.test", got.Profile.Email)
	}
	// "first last", as the provider spells it.
	if got.Profile.DisplayName != "Ada Lovelace" {
		t.Errorf("profile.display_name = %q, want \"Ada Lovelace\"", got.Profile.DisplayName)
	}
	// The profile is ADDITIVE: the CSRF rotation semantics the bootstrap exists
	// for are untouched by it.
	if got.CSRF == "" || got.AccountID == "" || got.AuthMode != "workos" {
		t.Fatalf("bootstrap regressed alongside the profile: %+v", got)
	}
	second := readSession(t, hc, h.srv.URL)
	if second.CSRF == got.CSRF {
		t.Error("the bootstrap stopped rotating the CSRF token")
	}
	if second.Profile == nil || second.Profile.Email != got.Profile.Email {
		t.Error("the profile did not survive a second bootstrap")
	}
}

// TestPortalSessionProfileConvergesOnRelogin proves the upsert semantics from
// the outside: signing in again as the same subject refreshes the row rather
// than accumulating one per login.
func TestPortalSessionProfileConvergesOnRelogin(t *testing.T) {
	h := newWorkOSHarness(t, true)
	first, _, acctA := h.signIn(t, "grace")
	if p := readSession(t, first, h.srv.URL).Profile; p == nil || p.Email != "grace@example.test" {
		t.Fatalf("first sign-in profile = %+v", p)
	}
	second, _, acctB := h.signIn(t, "grace")
	if acctA != acctB {
		t.Fatalf("the same subject resolved to two accounts: %s / %s", acctA, acctB)
	}
	p := readSession(t, second, h.srv.URL).Profile
	if p == nil || p.Email != "grace@example.test" || p.DisplayName != "Ada Lovelace" {
		t.Fatalf("second sign-in profile = %+v", p)
	}
}

// TestPortalSessionOmitsUnknownProfile pins the honest-absence half: a dev-auth
// token with no email teaches the server nothing, so the response carries no
// `profile` key at all rather than an object of empty strings.
func TestPortalSessionOmitsUnknownProfile(t *testing.T) {
	h := newHarnessVerifier(t, identity.NewDevAuth())
	hc := devLogin(t, h.srv.URL, "dev:nameless")

	got := readSession(t, hc, h.srv.URL)
	if got.Profile != nil {
		t.Fatalf("a profile appeared for an account nothing is known about: %+v", got.Profile)
	}
	if got.AccountID == "" || got.CSRF == "" {
		t.Fatalf("bootstrap incomplete: %+v", got)
	}
}

// TestDevAuthLoginCapturesTokenEmail covers the dev-auth path's own capture:
// "dev:<subject>:<email>" carries an email, which lands in the login response
// AND in the next session bootstrap. The display name falls back to the email
// because dev-auth has no name to give.
func TestDevAuthLoginCapturesTokenEmail(t *testing.T) {
	h := newHarnessVerifier(t, identity.NewDevAuth())
	hc := devLogin(t, h.srv.URL, "dev:hopper:hopper@example.test")

	got := readSession(t, hc, h.srv.URL)
	if got.Profile == nil {
		t.Fatal("session carried no profile after a dev-auth login with an email")
	}
	if got.Profile.Email != "hopper@example.test" {
		t.Errorf("profile.email = %q, want hopper@example.test", got.Profile.Email)
	}
	if got.Profile.DisplayName != "hopper@example.test" {
		t.Errorf("profile.display_name = %q, want the email fallback", got.Profile.DisplayName)
	}
}

// devLogin POSTs a raw dev-auth broker token (portalLogin always builds
// "dev:<subject>", which cannot express the optional email suffix) and returns
// the cookie-jar client holding the session.
func devLogin(t *testing.T, base, brokerToken string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	body, _ := json.Marshal(map[string]string{"broker_token": brokerToken})
	resp, err := hc.Post(base+"/portal/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("dev login: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dev login status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	return hc
}
