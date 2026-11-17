package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth/passkey"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth/passkey/passkeytest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// staff_passkey_test.go is the Postgres half of the production passkey
// path (rulings A2, A3, A7a): the staff process (StaffHandler over an
// sbci_staff store, the go-webauthn verifier) registers two passkeys for one
// staff member with two operator codes, signs in with each, and the
// operator's revocation of one ends its session and its sign-ins while the
// other keeps working. The portal half checks the Lax cookie, the Origin
// check on cookie-authenticated mutations, and the export download fence.
// Needs Postgres (cloudtestpg; SKIPPED loudly without SBCI_TEST_PG_DSN).

func (h *staffPGHarness) passkeyRegister(code string, a *passkeytest.Authenticator) *httptest.ResponseRecorder {
	h.t.Helper()
	begin := h.do("POST", "/staff/auth/webauthn/register/begin", map[string]string{"enrolment_code": code}, nil, nil)
	if begin.Code != http.StatusOK {
		h.t.Fatalf("register/begin = %d %s", begin.Code, begin.Body)
	}
	var co struct {
		PublicKey staffauth.CreationOptions `json:"publicKey"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &co); err != nil {
		h.t.Fatal(err)
	}
	handle, err := base64.RawURLEncoding.DecodeString(co.PublicKey.User.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	cred, err := a.Register(passkeytest.Ceremony{Challenge: co.PublicKey.Challenge, Origin: staffPGOrigin, RPID: co.PublicKey.RP.ID}, handle)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.do("POST", "/staff/auth/webauthn/register/finish",
		map[string]any{"credential": json.RawMessage(cred), "label": "key"},
		[]*http.Cookie{recCookie(begin, "__Host-sbci-staff-ceremony")}, nil)
}

func (h *staffPGHarness) passkeySignIn(a *passkeytest.Authenticator) *httptest.ResponseRecorder {
	h.t.Helper()
	begin := h.do("POST", "/staff/auth/webauthn/assert/begin", nil, nil, nil)
	var ro struct {
		PublicKey staffauth.RequestOptions `json:"publicKey"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &ro); err != nil {
		h.t.Fatal(err)
	}
	cred, err := a.Assert(passkeytest.Ceremony{Challenge: ro.PublicKey.Challenge, Origin: staffPGOrigin, RPID: ro.PublicKey.RPID})
	if err != nil {
		h.t.Fatal(err)
	}
	return h.do("POST", "/staff/auth/webauthn/assert/finish",
		map[string]any{"credential": json.RawMessage(cred)},
		[]*http.Cookie{recCookie(begin, "__Host-sbci-staff-ceremony")}, nil)
}

func TestStaffPasskeysWithPostgres(t *testing.T) {
	t.Parallel()
	h := newStaffPGHarnessWith(t, passkey.New())
	ctx := context.Background()
	first, err := h.app.EnrolStaff(ctx, store.EnrolStaffInput{DisplayName: "Ops", Role: staffauth.RoleOps, Reason: "bootstrap", Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.app.EnrolStaff(ctx, store.EnrolStaffInput{StaffID: first.Staff.StaffID, Reason: "backup passkey", Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	primary, err := passkeytest.New(41, passkeytest.ES256)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := passkeytest.New(42, passkeytest.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	for code, a := range map[string]*passkeytest.Authenticator{first.RawCode: primary, second.RawCode: backup} {
		if rec := h.passkeyRegister(code, a); rec.Code != http.StatusCreated {
			t.Fatalf("register = %d %s", rec.Code, rec.Body)
		}
	}
	creds, err := h.app.ListStaffCredentials(ctx, first.Staff.StaffID)
	if err != nil || len(creds) != 2 || !creds[0].Active() || !creds[1].Active() {
		t.Fatalf("credentials = %+v, %v; want two active", creds, err)
	}

	sessions := map[*passkeytest.Authenticator]*http.Cookie{}
	for _, a := range []*passkeytest.Authenticator{primary, backup} {
		rec := h.passkeySignIn(a)
		if rec.Code != http.StatusOK {
			t.Fatalf("sign-in = %d %s", rec.Code, rec.Body)
		}
		sessions[a] = recCookie(rec, "__Host-sbci-staff")
	}

	// The operator revokes the primary (a lost key): its session ends, it no
	// longer signs in, the backup still does.
	if err := h.app.RevokeStaffCredential(ctx, first.Staff.StaffID, primary.CredentialID, "key lost", time.Now()); err != nil {
		t.Fatalf("RevokeStaffCredential: %v", err)
	}
	if err := h.app.RevokeStaffCredential(ctx, first.Staff.StaffID, primary.CredentialID, "again", time.Now()); err == nil {
		t.Fatal("a revoked credential was revoked twice")
	}
	if rec := h.do("GET", "/staff/api/me", nil, []*http.Cookie{sessions[primary]}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked credential's session = %d, want 401", rec.Code)
	}
	if rec := h.passkeySignIn(primary); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked credential sign-in = %d, want 401", rec.Code)
	}
	if rec := h.do("GET", "/staff/api/me", nil, []*http.Cookie{sessions[backup]}, nil); rec.Code != http.StatusOK {
		t.Fatalf("backup session = %d, want 200", rec.Code)
	}
	if rec := h.passkeySignIn(backup); rec.Code != http.StatusOK {
		t.Fatalf("backup sign-in = %d %s", rec.Code, rec.Body)
	}
	actions, err := h.app.ListStaffActions(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	revoked := false
	for _, a := range actions {
		revoked = revoked || (a.Verb == string(staffauth.VerbCredentialRevoked) && a.Actor == staffauth.ActorOperator && a.Reason == "key lost")
	}
	if !revoked {
		t.Error("the revocation was not logged")
	}
}

// TestPortalCookieLaxAndOriginCheck covers ruling A7a on the customer side.
func TestPortalCookieLaxAndOriginCheck(t *testing.T) {
	t.Parallel()
	h := newStaffPGHarness(t)
	rec := h.do("POST", "/portal/auth/login", map[string]string{"broker_token": "dev:portal-origin"}, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d %s", rec.Code, rec.Body)
	}
	cust := recCookie(rec, "__Host-sbci")
	if cust == nil || cust.SameSite != http.SameSiteLaxMode || !cust.Secure || !cust.HttpOnly || cust.Domain != "" {
		t.Fatalf("portal cookie = %+v, want __Host-, Secure, HttpOnly, SameSite=Lax", cust)
	}
	var lr struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, origin string
		refused      bool
	}{
		{"foreign origin", "https://evil.example", true},
		{"sibling tenant subdomain", "https://acme.example", true},
		{"null origin", "null", true},
		{"the portal origin", staffPGOrigin, false},
		{"the portal origin, other case", "HTTPS://APP.EXAMPLE", false},
		{"no Origin (a non-browser client)", "", false},
	} {
		headers := map[string]string{"X-SBCI-CSRF": lr.CSRF}
		if tc.origin != "" {
			headers["Origin"] = tc.origin
		}
		rec := h.do("POST", "/portal/api/consent", map[string]any{}, []*http.Cookie{cust}, headers)
		gotRefused := rec.Code == http.StatusForbidden && json.Valid(rec.Body.Bytes()) && containsCode(rec, "origin_mismatch")
		if gotRefused != tc.refused {
			t.Errorf("%s: POST /portal/api/consent = %d %s, refused=%v want %v", tc.name, rec.Code, rec.Body, gotRefused, tc.refused)
		}
	}
	// A GET is not origin-checked (reads stay side-effect free).
	if rec := h.do("GET", "/portal/api/overview", nil, []*http.Cookie{cust}, map[string]string{"Origin": "https://evil.example"}); rec.Code != http.StatusOK {
		t.Errorf("GET overview with a foreign Origin = %d", rec.Code)
	}
	// The export download refuses a cross-site or same-site initiator before
	// it reads anything; a same-origin fetch reaches the handler.
	for site, want := range map[string]int{"cross-site": http.StatusForbidden, "same-site": http.StatusForbidden, "same-origin": http.StatusNotFound} {
		rec := h.do("GET", "/portal/api/exports/00000000-0000-4000-8000-000000000000/download", nil, []*http.Cookie{cust}, map[string]string{"Sec-Fetch-Site": site})
		if rec.Code != want {
			t.Errorf("export download with Sec-Fetch-Site %s = %d %s, want %d", site, rec.Code, rec.Body, want)
		}
	}
}

func containsCode(rec *httptest.ResponseRecorder, code string) bool {
	var e struct {
		Code string `json:"code"`
	}
	return json.Unmarshal(rec.Body.Bytes(), &e) == nil && e.Code == code
}
