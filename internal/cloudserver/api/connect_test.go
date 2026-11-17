package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachgrant"
	"github.com/marmutapp/superbased-observer/internal/cloudpop"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// connect_test.go covers the Getting started v2 connect flow (connect.go,
// portal_connect.go, store/connect.go; docs/plans/onboarding-v2-connect-flow.md;
// docs/security.md CONNECT-1) over PostgreSQL with the server bound to the
// sbci_api role: the unauthenticated create, the proof-of-possession poll and
// its replay defense, the approval page's view, Connect / Not now / decline,
// the share level the server derives, the consent receipt, the sign-in
// delivery (the same credential /v1/auth/exchange mints, one live token per
// request, three deliveries), code entry, and the two browser redirects.

// connectMachine is one machine running `observer connect`.
type connectMachine struct {
	t    *testing.T
	base string
	http *http.Client
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// connectCreated is the create answer.
type connectCreated struct {
	RequestID  string `json:"request_id"`
	UserCode   string `json:"user_code"`
	ApproveURL string `json:"approve_url"`
	VerifyURL  string `json:"verify_url"`
	ExpiresIn  int    `json:"expires_in"`
	Interval   int    `json:"interval"`
}

// connectPolled is the poll answer.
type connectPolled struct {
	Status string `json:"status"`
	Target *struct {
		OrgID       string `json:"org_id"`
		Slug        string `json:"slug"`
		Kind        string `json:"kind"`
		DisplayName string `json:"display_name"`
		ShareLevel  string `json:"share_level"`
	} `json:"target"`
	ConsentReceiptID *string `json:"consent_receipt_id"`
	Interval         int     `json:"interval"`
	SignIn           *struct {
		Token      string `json:"api_token"`
		AccountID  string `json:"account_id"`
		DeviceID   string `json:"device_id"`
		Thumbprint string `json:"thumbprint"`
		ExpiresAt  string `json:"expires_at"`
	} `json:"sign_in"`
	AttachGrant string `json:"attach_grant"`
}

// connectView is the approval page's view.
type connectView struct {
	RequestID   string `json:"request_id"`
	Status      string `json:"status"`
	UserCode    string `json:"user_code"`
	MachineName string `json:"machine_name"`
	OS          string `json:"os"`
	AgeSeconds  int64  `json:"age_seconds"`
	ExpiresIn   int64  `json:"expires_in"`
	Network     struct {
		Prefix    string `json:"prefix"`
		SameAsYou bool   `json:"same_as_you"`
	} `json:"network"`
	Choices []struct {
		OrgID       string `json:"org_id"`
		Kind        string `json:"kind"`
		DisplayName string `json:"display_name"`
		Slug        string `json:"slug"`
		Status      string `json:"status"`
		ShareLevel  string `json:"share_level"`
		Preselected bool   `json:"preselected"`
		Disclosure  struct {
			Title   string `json:"title"`
			Text    string `json:"text"`
			Version string `json:"disclosure_version"`
			SHA256  string `json:"disclosure_sha256"`
		} `json:"disclosure"`
	} `json:"choices"`
	Target *struct {
		OrgID      string `json:"org_id"`
		Kind       string `json:"kind"`
		ShareLevel string `json:"share_level"`
	} `json:"target"`
	OnlineURL string `json:"online_url"`
}

var userCodeShape = regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[0-9]{4}$`)

func newConnectMachine(t *testing.T, h orgsHarness) *connectMachine {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &connectMachine{t: t, base: h.srv.URL, http: h.srv.Client(), pub: pub, priv: priv}
}

// create is POST /v1/connect/requests with hint.
func (m *connectMachine) create(hint string) connectCreated {
	m.t.Helper()
	resp := m.post("/v1/connect/requests", map[string]string{
		"device_public_key": base64.RawURLEncoding.EncodeToString(m.pub),
		"machine_name":      "studio-mac",
		"os":                "darwin",
		"arch":              "arm64",
		"observer_version":  "1.40.0",
		"target_hint":       hint,
	})
	if resp.StatusCode != http.StatusCreated {
		m.t.Fatalf("create status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var c connectCreated
	decode(m.t, resp, &c)
	return c
}

func (m *connectMachine) post(path string, body any) *http.Response {
	m.t.Helper()
	b, _ := json.Marshal(body)
	resp, err := m.http.Post(m.base+path, "application/json", bytes.NewReader(b))
	if err != nil {
		m.t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// proof mints the poll proof: this machine's key, GET, the poll URL, and the
// request id as the bound token.
func (m *connectMachine) proof(requestID string) string {
	m.t.Helper()
	p, err := cloudpop.Create(cloudpop.CreateParams{
		PrivateKey: m.priv, Method: "GET",
		URL:         m.base + "/v1/connect/requests/" + requestID,
		AccessToken: requestID,
	})
	if err != nil {
		m.t.Fatalf("cloudpop.Create: %v", err)
	}
	return p
}

// pollWith polls with the given proof header ("" for none).
func (m *connectMachine) pollWith(requestID, proof string) *http.Response {
	m.t.Helper()
	req, _ := http.NewRequest("GET", m.base+"/v1/connect/requests/"+requestID, nil)
	if proof != "" {
		req.Header.Set("SBO-PoP", proof)
	}
	resp, err := m.http.Do(req)
	if err != nil {
		m.t.Fatalf("poll: %v", err)
	}
	return resp
}

// poll polls with a fresh proof and wants a 200.
func (m *connectMachine) poll(requestID string) connectPolled {
	m.t.Helper()
	resp := m.pollWith(requestID, m.proof(requestID))
	if resp.StatusCode != http.StatusOK {
		m.t.Fatalf("poll status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var p connectPolled
	decode(m.t, resp, &p)
	return p
}

// device turns a delivered sign-in into a signed-in device client.
func (m *connectMachine) device(p connectPolled) *testClient {
	return &testClient{
		t: m.t, base: m.base, http: m.http, priv: m.priv, pub: m.pub,
		token: p.SignIn.Token, thumbprint: p.SignIn.Thumbprint, accountID: p.SignIn.AccountID,
	}
}

func getConnectView(t *testing.T, pc *portalClient, id string) connectView {
	t.Helper()
	resp := pc.get("/portal/api/connect/requests/" + id)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("view status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var v connectView
	decode(t, resp, &v)
	return v
}

func approveConnect(t *testing.T, pc *portalClient, id string, body map[string]string) *http.Response {
	t.Helper()
	return orgReq(t, pc, "POST", "/portal/api/connect/requests/"+id+"/approve", body, pc.csrf, "")
}

func TestConnectCreateShapeAndValidation(t *testing.T) {
	h := newPlaneHarness(t, api.PersonalPlaneServing)
	m := newConnectMachine(t, h)
	c := m.create("")
	if c.RequestID == "" || !userCodeShape.MatchString(c.UserCode) || c.ExpiresIn != 900 || c.Interval != 3 ||
		c.ApproveURL != h.srv.URL+"/connect/"+c.RequestID || c.VerifyURL != h.srv.URL+"/connect" {
		t.Fatalf("create = %+v", c)
	}

	cases := []struct {
		name string
		body map[string]any
		code string
	}{
		{"unknown field", map[string]any{"device_public_key": base64.RawURLEncoding.EncodeToString(m.pub), "machine_name": "a", "os": "linux", "arch": "amd64", "observer_version": "1", "extra": 1}, "bad_request"},
		{"bad key", map[string]any{"device_public_key": "abc", "machine_name": "a", "os": "linux", "arch": "amd64", "observer_version": "1"}, "invalid_device_public_key"},
		{"blank name", map[string]any{"device_public_key": base64.RawURLEncoding.EncodeToString(m.pub), "machine_name": " ​ ", "os": "linux", "arch": "amd64", "observer_version": "1"}, "invalid_machine_name"},
		{"bad os", map[string]any{"device_public_key": base64.RawURLEncoding.EncodeToString(m.pub), "machine_name": "a", "os": "Linux", "arch": "amd64", "observer_version": "1"}, "invalid_os"},
		{"personal hint", map[string]any{"device_public_key": base64.RawURLEncoding.EncodeToString(m.pub), "machine_name": "a", "os": "linux", "arch": "amd64", "observer_version": "1", "target_hint": "u-abcdefgh"}, "invalid_target_hint"},
	}
	for _, tc := range cases {
		resp := m.post("/v1/connect/requests", tc.body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%s", tc.name, resp.StatusCode, readAll(resp))
		}
		if got := errCode(t, resp); got != tc.code {
			t.Fatalf("%s: code=%s want %s", tc.name, got, tc.code)
		}
	}
	big := strings.Repeat("a", 5000)
	if resp := m.post("/v1/connect/requests", map[string]string{"machine_name": big}); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body status=%d", resp.StatusCode)
	}
}

func TestConnectPollNeedsTheRequestKey(t *testing.T) {
	h := newPlaneHarness(t, api.PersonalPlaneServing)
	m := newConnectMachine(t, h)
	c := m.create("")

	if resp := m.pollWith(c.RequestID, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no proof: status=%d", resp.StatusCode)
	}
	other := newConnectMachine(t, h)
	if resp := m.pollWith(c.RequestID, other.proof(c.RequestID)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("another key's proof: status=%d", resp.StatusCode)
	}
	p := m.proof(c.RequestID)
	resp := m.pollWith(c.RequestID, p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pending poll status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var got connectPolled
	decode(t, resp, &got)
	if got.Status != "pending" || got.Target != nil || got.ConsentReceiptID != nil || got.SignIn != nil || got.Interval != 3 {
		t.Fatalf("pending poll = %+v", got)
	}
	if resp := m.pollWith(c.RequestID, p); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed proof: status=%d", resp.StatusCode)
	}
	if resp := m.pollWith("00000000-0000-0000-0000-000000000000", m.proof("00000000-0000-0000-0000-000000000000")); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown request: status=%d", resp.StatusCode)
	}
}

func TestConnectApprovePersonalDeliversSignIn(t *testing.T) {
	h := newPlaneHarness(t, api.PersonalPlaneServing)
	m := newConnectMachine(t, h)
	c := m.create("")
	pc := h.portalLogin(t, "connect-alice")

	v := getConnectView(t, pc, c.RequestID)
	if v.Status != "pending" || v.UserCode != c.UserCode || v.MachineName != "studio-mac" || v.OS != "darwin" ||
		v.ExpiresIn <= 0 || v.Network.Prefix != "127.0.0.0/24" || !v.Network.SameAsYou {
		t.Fatalf("view = %+v", v)
	}
	if len(v.Choices) != 1 || v.Choices[0].Kind != "personal" || !v.Choices[0].Preselected ||
		v.Choices[0].ShareLevel != "summary" || v.Choices[0].Slug != "" || v.Choices[0].Disclosure.Title != "Summary only" {
		t.Fatalf("choices = %+v (the personal dashboard is created by the view, its address never sent)", v.Choices)
	}
	personal := v.Choices[0]

	// A stale disclosure is refused; nothing changes.
	resp := approveConnect(t, pc, c.RequestID, map[string]string{
		"target_org_id": personal.OrgID, "disclosure_version": personal.Disclosure.Version, "disclosure_sha256": strings.Repeat("0", 64),
	})
	if resp.StatusCode != http.StatusConflict || errCode(t, resp) != "disclosure_changed" {
		t.Fatalf("stale disclosure: want 409 disclosure_changed")
	}
	// No CSRF: refused.
	if resp := orgReq(t, pc, "POST", "/portal/api/connect/requests/"+c.RequestID+"/approve", map[string]string{}, "", ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no CSRF: status=%d", resp.StatusCode)
	}

	resp = approveConnect(t, pc, c.RequestID, map[string]string{
		"target_org_id": personal.OrgID, "disclosure_version": personal.Disclosure.Version, "disclosure_sha256": personal.Disclosure.SHA256,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var after connectView
	decode(t, resp, &after)
	if after.Status != "approved" || after.Target == nil || after.Target.Kind != "personal" || after.UserCode != "" {
		t.Fatalf("approved view = %+v", after)
	}

	first := m.poll(c.RequestID)
	if first.Status != "approved" || first.Target == nil || first.Target.Kind != "personal" ||
		first.Target.ShareLevel != "summary" || first.Target.OrgID != personal.OrgID ||
		first.ConsentReceiptID == nil || first.SignIn == nil || first.SignIn.AccountID != pc.accountID {
		t.Fatalf("approved poll = %+v", first)
	}
	if n := countRows(t, h, `SELECT count(*) FROM connect_consents WHERE consent_id=$1::uuid AND share_level='summary' AND disclosure_sha256=$2`,
		*first.ConsentReceiptID, personal.Disclosure.SHA256); n != 1 {
		t.Fatalf("consent receipts = %d", n)
	}
	// The delivered credential is an ordinary device sign-in.
	dev := m.device(first)
	if resp := dev.do(dev.signedReq("GET", "/v1/devices", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("delivered token: status=%d body=%s", resp.StatusCode, readAll(resp))
	}

	// A re-delivery revokes the previous token: one live token per request.
	second := m.poll(c.RequestID)
	if second.SignIn == nil || second.SignIn.Token == first.SignIn.Token || second.SignIn.DeviceID != first.SignIn.DeviceID {
		t.Fatalf("second delivery = %+v", second)
	}
	if resp := dev.do(dev.signedReq("GET", "/v1/devices", nil)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("superseded token: status=%d", resp.StatusCode)
	}
	if third := m.poll(c.RequestID); third.SignIn == nil {
		t.Fatalf("third delivery = %+v", third)
	}
	resp = m.pollWith(c.RequestID, m.proof(c.RequestID))
	if resp.StatusCode != http.StatusConflict || errCode(t, resp) != "sign_in_already_delivered" {
		t.Fatalf("fourth poll: want 409 sign_in_already_delivered")
	}

	// Single use: a second answer is refused; another account cannot see it.
	resp = approveConnect(t, pc, c.RequestID, map[string]string{"target_org_id": ""})
	if resp.StatusCode != http.StatusConflict || errCode(t, resp) != "not_pending" {
		t.Fatalf("second approve: want 409 not_pending")
	}
	bob := h.portalLogin(t, "connect-bob")
	if resp := bob.get("/portal/api/connect/requests/" + c.RequestID); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("another account's view: status=%d", resp.StatusCode)
	}

	// The account home sees the machine.
	resp = pc.get("/portal/api/connect/machines")
	var home struct {
		Devices int `json:"devices"`
		Recent  []struct {
			RequestID   string `json:"request_id"`
			MachineName string `json:"machine_name"`
		} `json:"recent"`
	}
	decode(t, resp, &home)
	if home.Devices != 1 || len(home.Recent) != 1 || home.Recent[0].RequestID != c.RequestID || home.Recent[0].MachineName != "studio-mac" {
		t.Fatalf("home = %+v", home)
	}
}

func TestConnectNotNowAndDecline(t *testing.T) {
	h := newPlaneHarness(t, api.PersonalPlaneServing)
	pc := h.portalLogin(t, "connect-carol")

	m := newConnectMachine(t, h)
	c := m.create("")
	resp := approveConnect(t, pc, c.RequestID, map[string]string{"target_org_id": ""})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("not now status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	p := m.poll(c.RequestID)
	if p.Status != "approved" || p.Target != nil || p.ConsentReceiptID != nil || p.SignIn == nil {
		t.Fatalf("not now poll = %+v (signed in, nothing sent)", p)
	}
	if n := countRows(t, h, `SELECT count(*) FROM connect_consents WHERE account_id=$1::uuid`, pc.accountID); n != 0 {
		t.Fatalf("not now wrote %d consent receipts", n)
	}

	m2 := newConnectMachine(t, h)
	c2 := m2.create("")
	resp = orgReq(t, pc, "POST", "/portal/api/connect/requests/"+c2.RequestID+"/decline", map[string]string{}, pc.csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decline status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	if p := m2.poll(c2.RequestID); p.Status != "declined" || p.SignIn != nil || p.Target != nil {
		t.Fatalf("declined poll = %+v", p)
	}
}

func TestConnectExpiredRequestCannotBeApproved(t *testing.T) {
	h := newPlaneHarness(t, api.PersonalPlaneServing)
	pc := h.portalLogin(t, "connect-erin")
	m := newConnectMachine(t, h)
	c := m.create("")
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE connect_requests SET created_at = now() - interval '20 minutes', expires_at = now() - interval '5 minutes' WHERE request_id=$1::uuid`,
		c.RequestID); err != nil {
		t.Fatalf("age the request: %v", err)
	}
	if v := getConnectView(t, pc, c.RequestID); v.Status != "expired" || v.UserCode != "" || len(v.Choices) != 0 {
		t.Fatalf("expired view = %+v", v)
	}
	resp := approveConnect(t, pc, c.RequestID, map[string]string{"target_org_id": ""})
	if resp.StatusCode != http.StatusConflict || errCode(t, resp) != "not_pending" {
		t.Fatalf("approve expired: want 409 not_pending")
	}
	if p := m.poll(c.RequestID); p.Status != "expired" || p.SignIn != nil {
		t.Fatalf("expired poll = %+v", p)
	}
}

func TestConnectTeamTargetIsFullDetail(t *testing.T) {
	h := newPlaneHarness(t, api.PersonalPlaneServing)
	pc := h.portalLogin(t, "connect-dave")
	team := createTeam(t, pc, "Acme", "acme-conn")

	m := newConnectMachine(t, h)
	c := m.create("acme-conn")
	// While the team is still being set up it is not offered.
	v := getConnectView(t, pc, c.RequestID)
	for _, ch := range v.Choices {
		if ch.OrgID == team.Org.OrgID {
			t.Fatalf("a provisioning team was offered: %+v", ch)
		}
	}
	resp := approveConnect(t, pc, c.RequestID, map[string]string{"target_org_id": team.Org.OrgID, "disclosure_version": "connect-disclosure.v1", "disclosure_sha256": strings.Repeat("a", 64)})
	if resp.StatusCode != http.StatusConflict || errCode(t, resp) != "target_unavailable" {
		t.Fatalf("provisioning team: want 409 target_unavailable")
	}

	if _, err := h.pool.Exec(context.Background(), `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, team.Org.OrgID); err != nil {
		t.Fatalf("activate: %v", err)
	}
	v = getConnectView(t, pc, c.RequestID)
	var pick *struct {
		OrgID, Kind, ShareLevel, Version, SHA, Text string
		Pre                                         bool
	}
	for _, ch := range v.Choices {
		if ch.OrgID == team.Org.OrgID {
			pick = &struct {
				OrgID, Kind, ShareLevel, Version, SHA, Text string
				Pre                                         bool
			}{ch.OrgID, ch.Kind, ch.ShareLevel, ch.Disclosure.Version, ch.Disclosure.SHA256, ch.Disclosure.Text, ch.Preselected}
		} else if ch.Preselected {
			t.Fatalf("the hinted team is not the only preselected choice: %+v", v.Choices)
		}
	}
	if pick == nil || pick.Kind != "team" || pick.ShareLevel != "full" || !pick.Pre ||
		pick.Text != "Acme's admins can read full detail: prompts, responses and file paths." {
		t.Fatalf("team choice = %+v", pick)
	}
	resp = approveConnect(t, pc, c.RequestID, map[string]string{"target_org_id": pick.OrgID, "disclosure_version": pick.Version, "disclosure_sha256": pick.SHA})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve team status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	p := m.poll(c.RequestID)
	if p.Target == nil || p.Target.Kind != "team" || p.Target.ShareLevel != "full" || p.Target.Slug != "acme-conn" || p.SignIn == nil {
		t.Fatalf("team poll = %+v", p)
	}

	// A team the account does not belong to is refused.
	bob := h.portalLogin(t, "connect-bob-team")
	m2 := newConnectMachine(t, h)
	c2 := m2.create("")
	resp = approveConnect(t, bob, c2.RequestID, map[string]string{"target_org_id": team.Org.OrgID, "disclosure_version": pick.Version, "disclosure_sha256": pick.SHA})
	if resp.StatusCode != http.StatusConflict || errCode(t, resp) != "target_unavailable" {
		t.Fatalf("foreign team: want 409 target_unavailable")
	}
}

func TestConnectCodeLookup(t *testing.T) {
	h := newPlaneHarness(t, api.PersonalPlaneServing)
	pc := h.portalLogin(t, "connect-fay")
	m := newConnectMachine(t, h)
	c := m.create("")

	typed := strings.ToLower(strings.ReplaceAll(c.UserCode, "-", " "))
	resp := orgReq(t, pc, "POST", "/portal/api/connect/lookup", map[string]string{"user_code": typed}, pc.csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lookup status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var got struct {
		RequestID string `json:"request_id"`
	}
	decode(t, resp, &got)
	if got.RequestID != c.RequestID {
		t.Fatalf("lookup = %s, want %s", got.RequestID, c.RequestID)
	}
	if resp := orgReq(t, pc, "POST", "/portal/api/connect/lookup", map[string]string{"user_code": "hello"}, pc.csrf, ""); resp.StatusCode != http.StatusBadRequest || errCode(t, resp) != "code_invalid" {
		t.Fatalf("malformed code: want 400 code_invalid")
	}
	if resp := orgReq(t, pc, "POST", "/portal/api/connect/lookup", map[string]string{"user_code": "BCDF-0000"}, pc.csrf, ""); resp.StatusCode != http.StatusNotFound || errCode(t, resp) != "code_not_found" {
		t.Fatalf("unknown code: want 404 code_not_found")
	}
	// A resolved request's code no longer resolves.
	if resp := approveConnect(t, pc, c.RequestID, map[string]string{"target_org_id": ""}); resp.StatusCode != http.StatusOK {
		t.Fatalf("not now status=%d", resp.StatusCode)
	}
	if resp := orgReq(t, pc, "POST", "/portal/api/connect/lookup", map[string]string{"user_code": c.UserCode}, pc.csrf, ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("resolved code: status=%d", resp.StatusCode)
	}
}

func TestConnectBrowserRedirects(t *testing.T) {
	h := newPlaneHarness(t, api.PersonalPlaneServing)
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	cases := []struct{ path, want string }{
		{"/connect/6f1c2d3e-0000-4000-8000-000000000001", "/portal/connect/6f1c2d3e-0000-4000-8000-000000000001"},
		{"/connect?code=ktrw4821", "/portal/connect?code=KTRW-4821"},
		{"/connect?code=%3Cscript%3E", "/portal/connect"},
		{"/connect", "/portal/connect"},
	}
	for _, c := range cases {
		resp, err := hc.Get(h.srv.URL + c.path)
		if err != nil {
			t.Fatalf("GET %s: %v", c.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != c.want {
			t.Fatalf("GET %s = %d %q, want 302 %q", c.path, resp.StatusCode, resp.Header.Get("Location"), c.want)
		}
	}
}

func TestPersonalDashboardCreatedAtSignIn(t *testing.T) {
	h := newOrgsHarnessWith(t, func(o *api.Options) { o.EnsurePersonalOnSignIn = true })
	pc := h.portalLogin(t, "connect-gus")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if n := countRows(t, h, `SELECT count(*) FROM orgs WHERE created_by=$1::uuid AND kind='personal'`, pc.accountID); n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no personal org after sign-in")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Signing in again keeps the one org.
	h.portalLogin(t, "connect-gus")
	time.Sleep(200 * time.Millisecond)
	if n := countRows(t, h, `SELECT count(*) FROM orgs WHERE created_by=$1::uuid AND kind='personal'`, pc.accountID); n != 1 {
		t.Fatalf("personal orgs after a second sign-in = %d", n)
	}
}

// TestConnectAttachGrantRidesWithSignIn: with a grant key configured, an
// approval with a target hands the machine an attach grant beside each
// delivered sign-in (the same bytes every delivery), it verifies on a host
// pinning the key for the approved org only, and binds this request's device
// key; with no key, or for "Not now", no grant is sent.
func TestConnectAttachGrantRidesWithSignIn(t *testing.T) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := newOrgsHarnessWith(t, func(o *api.Options) { o.AttachGrantKey = signPriv })
	m := newConnectMachine(t, h)
	c := m.create("")
	pc := h.portalLogin(t, "grant-alice")
	v := getConnectView(t, pc, c.RequestID)
	if len(v.Choices) == 0 {
		t.Fatalf("no choices: %+v", v)
	}
	personal := v.Choices[0]
	resp := approveConnect(t, pc, c.RequestID, map[string]string{
		"target_org_id": personal.OrgID, "disclosure_version": personal.Disclosure.Version, "disclosure_sha256": personal.Disclosure.SHA256,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	first := m.poll(c.RequestID)
	if first.SignIn == nil || first.AttachGrant == "" {
		t.Fatalf("approved poll carries no attach grant: %+v", first)
	}
	keys := platformcontract.KeySet{platformcontract.NewDocumentKey(signPub)}
	claims, err := attachgrant.Verify(first.AttachGrant, attachgrant.Facts{Keys: keys, OrgID: personal.OrgID, Now: time.Now()})
	if err != nil {
		t.Fatalf("grant does not verify: %v", err)
	}
	if claims.AccountID != pc.accountID || claims.Kind != "personal" || claims.ShareLevel != "summary" ||
		claims.DeviceThumbprint != attachgrant.Thumbprint(m.pub) || claims.RequestID != c.RequestID || claims.Subject == "" {
		t.Fatalf("claims = %+v", claims)
	}
	if _, err := attachgrant.Verify(first.AttachGrant, attachgrant.Facts{Keys: keys, OrgID: "another-org", Now: time.Now()}); err == nil {
		t.Fatal("the grant verified for another org")
	}
	if second := m.poll(c.RequestID); second.AttachGrant != first.AttachGrant {
		t.Fatal("a re-delivery carried a different grant: one approval, one grant")
	}

	// "Not now": signed in, no grant.
	c2 := m.create("")
	if resp := approveConnect(t, pc, c2.RequestID, map[string]string{"target_org_id": ""}); resp.StatusCode != http.StatusOK {
		t.Fatalf("not now status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	if p := m.poll(c2.RequestID); p.SignIn == nil || p.AttachGrant != "" {
		t.Fatalf("not now poll = %+v", p)
	}

	// No key configured: no grant.
	h2 := newOrgsHarnessWith(t, nil)
	m2 := newConnectMachine(t, h2)
	c3 := m2.create("")
	pc2 := h2.portalLogin(t, "grant-bob")
	v2 := getConnectView(t, pc2, c3.RequestID)
	p2 := v2.Choices[0]
	if resp := approveConnect(t, pc2, c3.RequestID, map[string]string{
		"target_org_id": p2.OrgID, "disclosure_version": p2.Disclosure.Version, "disclosure_sha256": p2.Disclosure.SHA256,
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status=%d", resp.StatusCode)
	}
	if p := m2.poll(c3.RequestID); p.SignIn == nil || p.AttachGrant != "" {
		t.Fatalf("no key, poll = %+v", p)
	}
}
