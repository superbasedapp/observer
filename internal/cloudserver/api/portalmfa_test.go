package api_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth/passkey"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth/passkey/passkeytest"
)

// portalmfa_test.go drives the C2 portal passkey second factor end to end
// over PostgreSQL, the real WebAuthn verifier (staffauth/passkey, with a
// software authenticator that builds real browser bytes), the WorkOS sign-in
// leg (a fake AuthKit) and the platform OIDC issuer.

// mfaBrowser is one browser: its client, CSRF token and the server origin.
type mfaBrowser struct {
	t    *testing.T
	p    *oidcPortal
	hc   *http.Client
	csrf string
}

func (b *mfaBrowser) do(method, path string, body any) (*http.Response, map[string]any) {
	b.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			b.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, b.p.srv.URL+path, rd)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SBCI-CSRF", b.csrf)
	resp, err := b.hc.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func (b *mfaBrowser) want(method, path string, body any, status int) map[string]any {
	b.t.Helper()
	resp, out := b.do(method, path, body)
	if resp.StatusCode != status {
		b.t.Fatalf("%s %s = %d %v, want %d", method, path, resp.StatusCode, out, status)
	}
	return out
}

// rebootstrap refreshes the CSRF token (a new session after a forced sign-in).
func (b *mfaBrowser) rebootstrap() {
	b.t.Helper()
	_, b.csrf = b.p.bootstrap(b.t, b.hc)
}

// ceremony reads a begin answer's ceremony token and options challenge.
func ceremonyOf(t *testing.T, out map[string]any) (cer, challenge, rpID string, userHandle []byte) {
	t.Helper()
	cer, _ = out["ceremony"].(string)
	opts, _ := out["options"].(map[string]any)
	challenge, _ = opts["challenge"].(string)
	if rp, ok := opts["rp"].(map[string]any); ok {
		rpID, _ = rp["id"].(string)
		if rp["name"] != "SuperBased" {
			t.Errorf("rp name = %v", rp["name"])
		}
	} else {
		rpID, _ = opts["rpId"].(string)
	}
	if u, ok := opts["user"].(map[string]any); ok {
		id, _ := u["id"].(string)
		h, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil {
			t.Fatal(err)
		}
		userHandle = h
	}
	if cer == "" || challenge == "" || rpID == "" {
		t.Fatalf("begin answer %v", out)
	}
	return cer, challenge, rpID, userHandle
}

func TestPortalPasskeySecondFactorEndToEnd(t *testing.T) {
	p := newOIDCPortalWith(t, func(o *api.Options) { o.PortalWebAuthn = passkey.New() })
	const subject = "mfa-maya"
	origin := p.srv.URL

	hc, csrf, account := p.signIn(t, subject)
	b := &mfaBrowser{t: t, p: p, hc: hc, csrf: csrf}
	m := oidcissuer.Member{
		IsMember: true, AccountStatus: "active", OrgStatus: "active", RailEnabled: true,
		Sub: "user_maya", Email: "maya@example.com", EmailVerified: true, RequireSecondFactor: true,
	}
	p.issuer.SetMember(account, reauthOrg, m)

	// 1. The org requires a second factor; Maya has none: the issuer sends
	// her to the second-factor page, resuming the authorize request.
	q, verifier := p.rpRequest(nil)
	loc := p.follow(t, hc, oidcissuer.AuthorizePath+"?"+q.Encode())
	if loc.Path != "/portal/second-factor" || !strings.HasPrefix(loc.Query().Get("return_to"), oidcissuer.AuthorizePath+"?") {
		t.Fatalf("authorize sent the browser to %s, want the second-factor page", loc)
	}
	resume := loc.Query().Get("return_to")

	// 2. The first passkey needs a fresh sign-in: an ordinary AuthKit
	// session has no authentication time.
	if out := b.want("POST", "/portal/api/mfa/passkeys/register/begin", map[string]string{"label": "laptop"}, http.StatusForbidden); out["code"] != "reauth_required" {
		t.Fatalf("first enrol without a fresh sign-in = %v", out)
	}
	state, resp := p.startFlow(t, hc, "?reauth=1&return_to="+url.QueryEscape(loc.RequestURI()))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("forced start = %d %s", resp.StatusCode, readAll(resp))
	}
	cb := p.callback(t, hc, newCode(subject), state)
	if cb.StatusCode != http.StatusSeeOther || !strings.HasPrefix(cb.Header.Get("Location"), "/portal/second-factor?") {
		t.Fatalf("forced callback = %d to %s", cb.StatusCode, cb.Header.Get("Location"))
	}
	b.rebootstrap()

	// 3. Enrol: the recovery codes come once, and this session now counts as
	// second-factored with the passkey.
	auth, err := passkeytest.New(41, passkeytest.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	cer, challenge, rpID, handle := ceremonyOf(t, b.want("POST", "/portal/api/mfa/passkeys/register/begin", map[string]string{"label": "laptop"}, http.StatusOK))
	cred, err := auth.Register(passkeytest.Ceremony{Challenge: challenge, Origin: origin, RPID: rpID}, handle)
	if err != nil {
		t.Fatal(err)
	}
	out := b.want("POST", "/portal/api/mfa/passkeys/register/finish", map[string]any{"ceremony": cer, "credential": json.RawMessage(cred)}, http.StatusCreated)
	codes, _ := out["recovery_codes"].([]any)
	if len(codes) != 10 {
		t.Fatalf("recovery codes = %v", out)
	}
	// The ceremony is single use.
	if out := b.want("POST", "/portal/api/mfa/passkeys/register/finish", map[string]any{"ceremony": cer, "credential": json.RawMessage(cred)}, http.StatusBadRequest); out["code"] != "ceremony_invalid" {
		t.Fatalf("replayed finish = %v", out)
	}

	// 4. The resumed authorize issues, with a truthful amr: a device-bound
	// key is hardware-secured.
	c := p.redeem(t, p.follow(t, hc, resume), verifier)
	if strings.Join(c.AMR, ",") != "hwk,mfa" {
		t.Fatalf("amr = %v, want hwk,mfa", c.AMR)
	}

	// 5. A new session: pending until the passkey is used. Everything but the
	// second-factor routes is refused, and the issuer will not issue even for
	// an org with no requirement.
	hc2, csrf2, _ := p.signIn(t, subject)
	b2 := &mfaBrowser{t: t, p: p, hc: hc2, csrf: csrf2}
	if out := b2.want("GET", "/portal/api/orgs", nil, http.StatusForbidden); out["code"] != "second_factor_required" {
		t.Fatalf("pending session reached orgs: %v", out)
	}
	sess := b2.want("GET", "/portal/api/session", nil, http.StatusOK)
	b2.csrf, _ = sess["csrf_token"].(string) // the bootstrap rotates it
	sf := sess["second_factor"].(map[string]any)
	if sf["pending"] != true || sf["enrolled"] != true {
		t.Fatalf("session second_factor = %v", sf)
	}
	m.RequireSecondFactor = false
	p.issuer.SetMember(account, reauthOrg, m)
	q2, verifier2 := p.rpRequest(nil)
	if loc := p.follow(t, hc2, oidcissuer.AuthorizePath+"?"+q2.Encode()); loc.Path != "/portal/second-factor" {
		t.Fatalf("pending session authorize = %s", loc)
	}
	// A pending session cannot add another passkey.
	if out := b2.want("POST", "/portal/api/mfa/passkeys/register/begin", map[string]string{}, http.StatusForbidden); out["code"] != "second_factor_required" {
		t.Fatalf("pending enrol = %v", out)
	}
	cer, challenge, rpID, _ = ceremonyOf(t, b2.want("POST", "/portal/api/mfa/assert/begin", map[string]string{}, http.StatusOK))
	// A bad signature is refused and spends the ceremony.
	bad, _ := auth.Assert(passkeytest.Ceremony{Challenge: challenge, Origin: origin, RPID: rpID, CorruptSignature: true})
	if out := b2.want("POST", "/portal/api/mfa/assert/finish", map[string]any{"ceremony": cer, "credential": json.RawMessage(bad)}, http.StatusUnauthorized); out["code"] != "webauthn_failed" {
		t.Fatalf("bad signature = %v", out)
	}
	cer, challenge, rpID, _ = ceremonyOf(t, b2.want("POST", "/portal/api/mfa/assert/begin", map[string]string{}, http.StatusOK))
	good, _ := auth.Assert(passkeytest.Ceremony{Challenge: challenge, Origin: origin, RPID: rpID})
	resume2 := oidcissuer.AuthorizePath + "?" + q2.Encode()
	out = b2.want("POST", "/portal/api/mfa/assert/finish", map[string]any{"ceremony": cer, "credential": json.RawMessage(good), "return_to": resume2}, http.StatusOK)
	next, _ := out["next"].(string)
	if !strings.HasPrefix(next, oidcissuer.AuthorizePath+"?") {
		t.Fatalf("next = %v", out)
	}
	if c := p.redeem(t, p.follow(t, hc2, next), verifier2); strings.Join(c.AMR, ",") != "hwk,mfa" {
		t.Fatalf("assertion amr = %v", c.AMR)
	}
	b2.want("GET", "/portal/api/orgs", nil, http.StatusOK)
	// An open redirect is never answered as next.
	cer, challenge, rpID, _ = ceremonyOf(t, b2.want("POST", "/portal/api/mfa/assert/begin", map[string]string{}, http.StatusOK))
	again, _ := auth.Assert(passkeytest.Ceremony{Challenge: challenge, Origin: origin, RPID: rpID})
	if out := b2.want("POST", "/portal/api/mfa/assert/finish", map[string]any{"ceremony": cer, "credential": json.RawMessage(again), "return_to": "https://evil.example/"}, http.StatusOK); out["next"] != "/portal/" {
		t.Fatalf("open redirect next = %v", out)
	}

	// 6. A recovery code unlocks the portal but is not a multi-factor
	// statement: an org that requires one still asks for the passkey; the
	// code is single use; a recovery session may not change an org's
	// requirement.
	m.RequireSecondFactor = true
	p.issuer.SetMember(account, reauthOrg, m)
	hc3, csrf3, _ := p.signIn(t, subject)
	b3 := &mfaBrowser{t: t, p: p, hc: hc3, csrf: csrf3}
	code0, _ := codes[0].(string)
	if out := b3.want("POST", "/portal/api/mfa/recover", map[string]string{"code": strings.ToUpper(code0)}, http.StatusOK); out["recovery_codes_left"] != float64(9) {
		t.Fatalf("recover = %v", out)
	}
	b3.want("GET", "/portal/api/orgs", nil, http.StatusOK)
	q3, _ := p.rpRequest(nil)
	if loc := p.follow(t, hc3, oidcissuer.AuthorizePath+"?"+q3.Encode()); loc.Path != "/portal/second-factor" {
		t.Fatalf("recovery session authorize for a requiring org = %s", loc)
	}
	hc4, csrf4, _ := p.signIn(t, subject)
	b4 := &mfaBrowser{t: t, p: p, hc: hc4, csrf: csrf4}
	if out := b4.want("POST", "/portal/api/mfa/recover", map[string]string{"code": code0}, http.StatusUnauthorized); out["code"] != "recovery_code_invalid" {
		t.Fatalf("reused code = %v", out)
	}

	// 7. Status lists the passkey; removing the last one turns the second
	// factor off (and its codes with it).
	st := b2.want("GET", "/portal/api/mfa", nil, http.StatusOK)
	keys, _ := st["passkeys"].([]any)
	if len(keys) != 1 || st["recovery_codes_left"] != float64(9) {
		t.Fatalf("status = %v", st)
	}
	id, _ := keys[0].(map[string]any)["id"].(string)
	if out := b2.want("DELETE", "/portal/api/mfa/passkeys/"+id, nil, http.StatusOK); out["passkeys_left"] != float64(0) {
		t.Fatalf("remove = %v", out)
	}
	hc5, csrf5, _ := p.signIn(t, subject)
	b5 := &mfaBrowser{t: t, p: p, hc: hc5, csrf: csrf5}
	b5.want("GET", "/portal/api/orgs", nil, http.StatusOK)
	if st := b5.want("GET", "/portal/api/mfa", nil, http.StatusOK); st["recovery_codes_left"] != float64(0) {
		t.Fatalf("codes after the last passkey = %v", st)
	}
}

// TestPortalOrgSecondFactorPolicy covers the console setting: an owner who
// signed in with a passkey may turn it on and off (each change audited); a
// session without a passkey may not; a plain member may not; a non-member
// gets 404.
func TestPortalOrgSecondFactorPolicy(t *testing.T) {
	h := newOrgsHarnessWith(t, func(o *api.Options) { o.PortalWebAuthn = passkey.New() })
	c := h.portalLogin(t, "policy-pat")
	o := createTeam(t, c, "Pat Team", "pat-team")
	path := "/portal/api/orgs/" + o.Org.OrgID + "/signin-policy"

	var v struct {
		Require   bool   `json:"require_second_factor"`
		CanChange bool   `json:"can_change"`
		Reason    string `json:"reason"`
		Code      string `json:"code"`
	}
	resp := c.get(path)
	decode(t, resp, &v)
	if v.Require || v.CanChange || v.Reason != "passkey_signin_required" {
		t.Fatalf("before a passkey: %+v", v)
	}
	resp = orgReq(t, c, "PUT", path, map[string]bool{"require_second_factor": true}, c.csrf, "")
	decode(t, resp, &v)
	if resp.StatusCode != http.StatusForbidden || v.Code != "passkey_signin_required" {
		t.Fatalf("set without a passkey = %d %+v", resp.StatusCode, v)
	}

	// Enrol a passkey (dev-auth login is a fresh sign-in).
	auth, err := passkeytest.New(52, passkeytest.ES256)
	if err != nil {
		t.Fatal(err)
	}
	auth.BackupEligible = true
	resp = orgReq(t, c, "POST", "/portal/api/mfa/passkeys/register/begin", map[string]string{"label": "phone"}, c.csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("begin = %d %s", resp.StatusCode, readAll(resp))
	}
	var begin map[string]any
	decode(t, resp, &begin)
	cer, challenge, rpID, handle := ceremonyOf(t, begin)
	cred, err := auth.Register(passkeytest.Ceremony{Challenge: challenge, Origin: c.base, RPID: rpID}, handle)
	if err != nil {
		t.Fatal(err)
	}
	resp = orgReq(t, c, "POST", "/portal/api/mfa/passkeys/register/finish", map[string]any{"ceremony": cer, "credential": json.RawMessage(cred)}, c.csrf, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("finish = %d %s", resp.StatusCode, readAll(resp))
	}
	var fin struct {
		Passkey struct {
			Synced bool `json:"synced"`
		} `json:"passkey"`
	}
	decode(t, resp, &fin)
	if !fin.Passkey.Synced {
		t.Fatal("a backup-eligible passkey is not reported as synced")
	}

	for _, want := range []bool{true, false} {
		resp = orgReq(t, c, "PUT", path, map[string]bool{"require_second_factor": want}, c.csrf, "")
		decode(t, resp, &v)
		if resp.StatusCode != http.StatusOK || v.Require != want || !v.CanChange {
			t.Fatalf("set %v = %d %+v", want, resp.StatusCode, v)
		}
	}
	var changes int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM security_audit_events WHERE event_type = 'portal_org_second_factor_changed' AND detail->>'org_id' = $1`, o.Org.OrgID).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	if changes != 2 {
		t.Fatalf("%d audit rows, want 2", changes)
	}

	// Another account: not a member.
	other := h.portalLogin(t, "policy-quinn")
	if resp := other.get(path); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("non-member read = %d", resp.StatusCode)
	}
	if resp := orgReq(t, other, "PUT", path, map[string]bool{"require_second_factor": true}, other.csrf, ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("non-member set = %d", resp.StatusCode)
	}
}
