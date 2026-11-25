package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The portal session cookie name in dev mode (PortalSecureCookie=false). Must
// match internal/cloudserver/api/portal.go's portalCookieDev.
const devCookieName = "sbci_session"

const csrfHeader = "X-SBCI-CSRF"

// newHarnessVerifier builds a portal harness with an explicit broker verifier,
// so the dev-auth-off (501) path can be exercised (built on newHarnessWith).
func newHarnessVerifier(t *testing.T, v identity.Verifier) *harness {
	t.Helper()
	// PortalSecureCookie defaults false ⇒ dev "sbci_session" cookie over http.
	return newHarnessWith(t, harnessSetup{opts: func(o *api.Options) { o.Verifier = v }})
}

// portalClient models a signed-in BROWSER: a cookie jar (the session cookie the
// server set) plus the in-memory CSRF token from login.
type portalClient struct {
	t         *testing.T
	base      string
	http      *http.Client
	csrf      string
	accountID string
}

func (h *harness) portalLogin(t *testing.T, subject string) *portalClient {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	pc := &portalClient{t: t, base: h.srv.URL, http: hc}

	body, _ := json.Marshal(map[string]string{"broker_token": "dev:" + subject})
	resp, err := hc.Post(pc.base+"/portal/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("portal login: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("portal login status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == devCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("portal login set no %q cookie; cookies=%v", devCookieName, resp.Cookies())
	}
	if !cookie.HttpOnly {
		t.Fatalf("session cookie is not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie SameSite=%v, want Lax (ruling A7a)", cookie.SameSite)
	}
	var lr struct {
		AccountID string `json:"account_id"`
		CSRF      string `json:"csrf_token"`
	}
	decode(t, resp, &lr)
	if lr.CSRF == "" || lr.AccountID == "" {
		t.Fatalf("portal login missing csrf/account: %+v", lr)
	}
	pc.csrf, pc.accountID = lr.CSRF, lr.AccountID
	return pc
}

func (c *portalClient) get(path string) *http.Response {
	c.t.Helper()
	req, _ := http.NewRequest("GET", c.base+path, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

// mutate issues a mutating request with the given CSRF header value ("" ⇒ no
// header, to exercise the missing-token path).
func (c *portalClient) mutate(method, path string, body []byte, csrf string) *http.Response {
	c.t.Helper()
	var r *http.Request
	if body == nil {
		r, _ = http.NewRequest(method, c.base+path, http.NoBody)
	} else {
		r, _ = http.NewRequest(method, c.base+path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		r.Header.Set(csrfHeader, csrf)
	}
	resp, err := c.http.Do(r)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func TestPortalLoginSetsCookieAndReadsOverview(t *testing.T) {
	h := newHarness(t)
	c := h.portalLogin(t, "portal-alice")

	resp := c.get("/portal/api/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var ov struct {
		Coverage    string         `json:"coverage_disclosure"`
		JobsByState map[string]int `json:"jobs_by_state"`
		JobsTotal   int            `json:"jobs_total"`
		Results     int            `json:"results_total"`
		Allowance   struct {
			DailyCap   int    `json:"daily_cap"`
			MonthlyCap int    `json:"monthly_cap"`
			BudgetUnit string `json:"budget_unit"`
			Evidence   int    `json:"evidence_token_budget"`
		} `json:"allowance"`
	}
	decode(t, resp, &ov)
	if ov.Coverage == "" {
		t.Fatal("overview missing coverage_disclosure string")
	}
	if ov.JobsTotal != 0 || ov.Results != 0 {
		t.Fatalf("fresh account overview not empty: %+v", ov)
	}
	// Free v5 (ruling R-AI1): token budgets, no count caps enforced.
	if ov.Allowance.DailyCap != 0 || ov.Allowance.MonthlyCap != 0 || ov.Allowance.BudgetUnit != "tokens" || ov.Allowance.Evidence != 4000 {
		t.Fatalf("unexpected allowance: %+v", ov.Allowance)
	}
}

func TestPortalNoCookieRejected(t *testing.T) {
	h := newHarness(t)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	resp, err := hc.Get(h.srv.URL + "/portal/api/overview")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-cookie overview status=%d, want 401", resp.StatusCode)
	}
}

func TestPortalCookieScopingCrossAccount(t *testing.T) {
	h := newHarness(t)
	// alice signs in on a DEVICE (creates account A + a device) and on the portal
	// (same identity ⇒ same account). bob signs into the portal only (account B).
	da := h.login(t, "scope-alice")
	pa := h.portalLogin(t, "scope-alice")
	if pa.accountID != da.accountID {
		t.Fatalf("portal + device dev subject resolved to different accounts: %s vs %s", pa.accountID, da.accountID)
	}
	pb := h.portalLogin(t, "scope-bob")

	// alice's portal cookie sees her one device.
	var dl struct {
		Devices []struct {
			ID string `json:"id"`
		} `json:"devices"`
	}
	decode(t, pa.get("/portal/api/devices"), &dl)
	if len(dl.Devices) != 1 {
		t.Fatalf("alice portal devices=%d, want 1", len(dl.Devices))
	}
	// bob's portal cookie sees NO devices (account B is empty) and cannot revoke
	// alice's device (RLS ⇒ 404, not another account's row).
	var bl struct {
		Devices []json.RawMessage `json:"devices"`
	}
	decode(t, pb.get("/portal/api/devices"), &bl)
	if len(bl.Devices) != 0 {
		t.Fatalf("bob portal devices=%d, want 0", len(bl.Devices))
	}
	if resp := pb.mutate("DELETE", "/portal/api/devices/"+dl.Devices[0].ID, nil, pb.csrf); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-account portal revoke status=%d, want 404", resp.StatusCode)
	}
}

func TestPortalCSRFRequiredOnMutation(t *testing.T) {
	h := newHarness(t)
	c := h.portalLogin(t, "csrf-carol")

	// Missing CSRF header ⇒ 403.
	if resp := c.mutate("POST", "/portal/api/deletion-requests", []byte(`{"broker_token":"dev:csrf-carol"}`), ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing-CSRF status=%d, want 403", resp.StatusCode)
	}
	// Wrong CSRF header ⇒ 403.
	if resp := c.mutate("POST", "/portal/api/deletion-requests", []byte(`{"broker_token":"dev:csrf-carol"}`), "not-the-token"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong-CSRF status=%d, want 403", resp.StatusCode)
	}
}

func TestPortalLogoutRevokesSession(t *testing.T) {
	h := newHarness(t)
	c := h.portalLogin(t, "logout-larry")

	if resp := c.mutate("POST", "/portal/auth/logout", nil, c.csrf); resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	// After logout the (revoked) session cookie no longer authenticates.
	if resp := c.get("/portal/api/overview"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-logout overview status=%d, want 401", resp.StatusCode)
	}
}

func TestPortalDeviceRevokeKillsDeviceToken(t *testing.T) {
	h := newHarness(t)
	// carol on a device (token + device) AND on the portal (same account).
	dc := h.login(t, "revoke-carol")
	pc := h.portalLogin(t, "revoke-carol")

	// The device token works before revocation.
	if resp := dc.do(dc.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke device usage status=%d, want 200", resp.StatusCode)
	}

	var dl struct {
		Devices []struct {
			ID string `json:"id"`
		} `json:"devices"`
	}
	decode(t, pc.get("/portal/api/devices"), &dl)
	if len(dl.Devices) != 1 {
		t.Fatalf("portal devices=%d, want 1", len(dl.Devices))
	}
	// Revoke the device from the PORTAL (cookie-auth + CSRF).
	if resp := pc.mutate("DELETE", "/portal/api/devices/"+dl.Devices[0].ID, nil, pc.csrf); resp.StatusCode != http.StatusOK {
		t.Fatalf("portal device revoke status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	// The device-API token (a completely separate auth path) now fails closed.
	if resp := dc.do(dc.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-revoke device usage status=%d, want 401", resp.StatusCode)
	}
}

func TestPortalDeletionRequestReauth(t *testing.T) {
	h := newHarness(t)
	// dave on a device (so the deletion skeleton has a device to revoke) + portal.
	_ = h.login(t, "del-dave")
	c := h.portalLogin(t, "del-dave")

	// Reauth credential for a DIFFERENT account ⇒ 403 mismatch.
	if resp := c.mutate("POST", "/portal/api/deletion-requests", []byte(`{"broker_token":"dev:someone-else"}`), c.csrf); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("reauth-mismatch status=%d body=%s, want 403", resp.StatusCode, readAll(resp))
	}
	// Correct reauth (same account) ⇒ 202 with an honest summary.
	resp := c.mutate("POST", "/portal/api/deletion-requests", []byte(`{"broker_token":"dev:del-dave"}`), c.csrf)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("deletion status=%d body=%s, want 202", resp.StatusCode, readAll(resp))
	}
	var dr struct {
		State          string `json:"state"`
		DevicesRevoked int    `json:"devices_revoked"`
	}
	decode(t, resp, &dr)
	if dr.State != "done" {
		t.Fatalf("deletion state=%q, want done", dr.State)
	}
	if dr.DevicesRevoked != 1 {
		t.Fatalf("devices_revoked=%d, want 1", dr.DevicesRevoked)
	}
	// The deletion skeleton revoked all sessions ⇒ this cookie is dead.
	if resp := c.get("/portal/api/overview"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-deletion overview status=%d, want 401", resp.StatusCode)
	}
}

func TestPortalConsentsAndUsage(t *testing.T) {
	h := newHarness(t)
	c := h.portalLogin(t, "cons-cathy")

	var cs struct {
		Purposes   []string `json:"purposes"`
		Generation int64    `json:"generation"`
	}
	decode(t, c.get("/portal/api/consents"), &cs)
	if cs.Purposes == nil {
		t.Fatal("consents purposes should be [] not null")
	}

	var snap store.UsageSnapshot
	decode(t, c.get("/portal/api/usage"), &snap)
	if snap.BudgetUnit != "tokens" || snap.DailyCap != 0 || snap.DailyTokenBudget <= 0 || snap.EvidenceTokenBudget != 4000 {
		t.Fatalf("usage=%+v, want the free tier's token budgets (free v5, migration 0079)", snap)
	}
	// The remaining figures every reader shows: budget minus committed, and
	// present (a pointer) even when nothing has been used yet.
	if snap.DailyTokensRemaining == nil || *snap.DailyTokensRemaining != snap.DailyTokenBudget-snap.DailyTokensUsed ||
		snap.MonthlyTokensRemaining == nil || *snap.MonthlyTokensRemaining != snap.MonthlyTokenBudget-snap.MonthlyTokensUsed {
		t.Fatalf("usage remaining = %v / %v, want budget minus used (%+v)", snap.DailyTokensRemaining, snap.MonthlyTokensRemaining, snap)
	}
	var billing struct {
		Plan *store.UsageSnapshot `json:"plan"`
	}
	decode(t, c.get("/portal/api/billing"), &billing)
	if billing.Plan == nil || billing.Plan.BudgetUnit != "tokens" || billing.Plan.DailyTokenBudget != snap.DailyTokenBudget ||
		billing.Plan.EvidenceTokenBudget != snap.EvidenceTokenBudget || billing.Plan.DailyTokensRemaining == nil {
		t.Fatalf("billing plan = %+v, want the same token budgets as usage", billing.Plan)
	}
}

func TestPortalLoginDevAuthOff501(t *testing.T) {
	h := newHarnessVerifier(t, identity.NewWorkOSPlaceholder())
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	body, _ := json.Marshal(map[string]string{"broker_token": "dev:whoever"})
	resp, err := hc.Post(h.srv.URL+"/portal/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("dev-auth-off login status=%d, want 501", resp.StatusCode)
	}
	var eb struct {
		Code string `json:"code"`
	}
	decode(t, resp, &eb)
	if eb.Code != "provider_not_configured" {
		t.Fatalf("dev-auth-off code=%q, want provider_not_configured", eb.Code)
	}
}
