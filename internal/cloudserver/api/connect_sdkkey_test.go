package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachgrant"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
	"github.com/marmutapp/superbased-observer/internal/sdkkeygrant"
)

// connect_sdkkey_test.go covers the AI Apps SDK quickstart's device sign-in
// on the connect flow (purpose sdk_key; connect.go, connect_keygrant.go,
// portal_connect.go, connect_sdkplan.go, store/connect.go; the SDK
// quickstart plan section 3.6; docs/security.md SDKQS-1 and SDKQS-2) over
// PostgreSQL with the server bound to the sbci_api role, and pins every wire
// body against sdk/contract/fixtures/setup (the SDKs' stubs replay those
// bodies, so a server change that breaks the SDKs fails here first).

// setupFixture is one exchange of sdk/contract/fixtures/setup.
type setupFixture struct {
	Request struct {
		Body json.RawMessage `json:"body"`
	} `json:"request"`
	Responses map[string]struct {
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
	} `json:"responses"`
}

func readSetupFixture(t *testing.T, name string) setupFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "sdk", "contract", "fixtures", "setup", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var f setupFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return f
}

// jsonShape describes a JSON value's shape: its type, and for an object each
// key's shape (an array's elements are not compared). Two bodies with the
// same shape have the same keys and the same types: values may differ.
func jsonShape(t *testing.T, raw []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return shapeOf(v)
}

func shapeOf(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+":"+shapeOf(x[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return "?"
}

// wantFixtureShape fails unless got has the shape of the fixture's named
// response, and its status.
func wantFixtureShape(t *testing.T, f setupFixture, name string, status int, got []byte) {
	t.Helper()
	want, ok := f.Responses[name]
	if !ok {
		t.Fatalf("fixture has no response %q", name)
	}
	if status != want.Status {
		t.Errorf("%s: status %d, fixture %d (body %s)", name, status, want.Status, got)
	}
	if g, w := jsonShape(t, got), jsonShape(t, want.Body); g != w {
		t.Errorf("%s: body shape\n got %s\nwant %s", name, g, w)
	}
}

// fixtureErrCode is the code of a fixture's error response.
func fixtureErrCode(t *testing.T, f setupFixture, name string) string {
	t.Helper()
	var b struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(f.Responses[name].Body, &b); err != nil || b.Code == "" {
		t.Fatalf("fixture response %s has no code: %s", name, f.Responses[name].Body)
	}
	return b.Code
}

// sdkSetup is one SDK setup run: the create body it sends and the device code
// it got back.
type sdkSetup struct {
	t          *testing.T
	base       string
	http       *http.Client
	requestID  string
	userCode   string
	deviceCode string
}

// sdkCreateBody is the fixture's create body, with a redeem hash of its own.
func sdkCreateBody(t *testing.T) map[string]any {
	t.Helper()
	f := readSetupFixture(t, "connect-create.json")
	var body map[string]any
	if err := json.Unmarshal(f.Request.Body, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func sdkPostJSON(t *testing.T, h orgsHarness, path string, body any) (int, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := h.srv.Client().Post(h.srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// newSDKSetup creates an SDK key request with the fixture body.
func newSDKSetup(t *testing.T, h orgsHarness) *sdkSetup {
	t.Helper()
	status, raw := sdkPostJSON(t, h, "/v1/connect/requests", sdkCreateBody(t))
	if status != http.StatusCreated {
		t.Fatalf("sdk create status=%d body=%s", status, raw)
	}
	var c struct {
		RequestID  string `json:"request_id"`
		UserCode   string `json:"user_code"`
		DeviceCode string `json:"device_code"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return &sdkSetup{t: t, base: h.srv.URL, http: h.srv.Client(), requestID: c.RequestID, userCode: c.UserCode, deviceCode: c.DeviceCode}
}

// pollAs polls with the given Authorization header value ("" for none) and
// returns the status and raw body.
func (p *sdkSetup) pollAs(auth string) (int, []byte) {
	p.t.Helper()
	req, _ := http.NewRequest("GET", p.base+"/v1/connect/requests/"+p.requestID, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		p.t.Fatalf("poll: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// sdkPolled is an SDK key poll answer.
type sdkPolled struct {
	Status string `json:"status"`
	Target *struct {
		OrgID       string `json:"org_id"`
		Slug        string `json:"slug"`
		Kind        string `json:"kind"`
		DisplayName string `json:"display_name"`
		ServerURL   string `json:"server_url"`
		Ready       bool   `json:"ready"`
	} `json:"target"`
	ConsentReceiptID *string `json:"consent_receipt_id"`
	Interval         int     `json:"interval"`
	KeyGrant         string  `json:"key_grant"`
}

// poll polls with the device code and wants a 200.
func (p *sdkSetup) poll() (sdkPolled, []byte) {
	p.t.Helper()
	status, raw := p.pollAs("Bearer " + p.deviceCode)
	if status != http.StatusOK {
		p.t.Fatalf("sdk poll status=%d body=%s", status, raw)
	}
	var out sdkPolled
	if err := json.Unmarshal(raw, &out); err != nil {
		p.t.Fatal(err)
	}
	return out, raw
}

// sdkView is the approval page's view of an SDK key request.
type sdkView struct {
	Purpose       string `json:"purpose"`
	Status        string `json:"status"`
	UserCode      string `json:"user_code"`
	MachineName   string `json:"machine_name"`
	Client        string `json:"client"`
	ClientVersion string `json:"client_version"`
	ProjectName   string `json:"project_name"`
	Choices       []struct {
		OrgID       string `json:"org_id"`
		Kind        string `json:"kind"`
		ShareLevel  string `json:"share_level"`
		Preselected bool   `json:"preselected"`
		Available   bool   `json:"available"`
		Refusal     *struct {
			Code       string `json:"code"`
			Message    string `json:"message"`
			UpgradeURL string `json:"upgrade_url"`
		} `json:"refusal"`
		Disclosure struct {
			Title   string `json:"title"`
			Text    string `json:"text"`
			Version string `json:"disclosure_version"`
			SHA256  string `json:"disclosure_sha256"`
		} `json:"disclosure"`
	} `json:"choices"`
	OpenURL     string `json:"open_url"`
	TargetReady *bool  `json:"target_ready"`
}

func getSDKView(t *testing.T, pc *portalClient, id string) sdkView {
	t.Helper()
	resp := pc.get("/portal/api/connect/requests/" + id)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("view status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var v sdkView
	decode(t, resp, &v)
	return v
}

func newSDKKeyHarness(t *testing.T) (orgsHarness, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newOrgsHarnessWith(t, func(o *api.Options) { o.SDKKeyGrantKey = priv }), pub
}

func activateOrg(t *testing.T, h orgsHarness, orgID string) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(), `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, orgID); err != nil {
		t.Fatalf("activate %s: %v", orgID, err)
	}
}

// TestConnectSDKKeyCreate: the fixture's create body is accepted and the
// answer has the fixture's shape (a device code beside the machine create's
// fields); a cloud with no SDK key grant key refuses the purpose; a body that
// mixes the two purposes is a bad request; a machine's create is unchanged.
func TestConnectSDKKeyCreate(t *testing.T) {
	h, _ := newSDKKeyHarness(t)
	f := readSetupFixture(t, "connect-create.json")

	status, raw := sdkPostJSON(t, h, "/v1/connect/requests", sdkCreateBody(t))
	wantFixtureShape(t, f, "created", status, raw)
	var c struct {
		UserCode   string `json:"user_code"`
		DeviceCode string `json:"device_code"`
		ExpiresIn  int    `json:"expires_in"`
		Interval   int    `json:"interval"`
	}
	_ = json.Unmarshal(raw, &c)
	if len(c.DeviceCode) != 43 || !userCodeShape.MatchString(c.UserCode) || c.ExpiresIn != 900 || c.Interval != 3 {
		t.Fatalf("created = %s", raw)
	}
	// The code is stored only as its hash.
	if n := countRows(t, h, `SELECT count(*) FROM connect_requests WHERE device_code_hash = $1 OR device_code_hash IS NULL`, c.DeviceCode); n != 0 {
		t.Fatalf("the raw device code is stored, or an SDK row has no hash (%d rows)", n)
	}
	if n := countRows(t, h, `SELECT count(*) FROM connect_requests WHERE purpose='sdk_key' AND auth_kind='device_code'
		AND client='superbased-sdk-python' AND client_version='0.2.0' AND project_name='support-bot'
		AND device_public_key IS NULL AND observer_version IS NULL AND redeem_hash IS NOT NULL`); n != 1 {
		t.Fatalf("stored sdk rows = %d", n)
	}

	// A machine's create keeps its shape: no device code.
	m := newConnectMachine(t, h)
	mc := m.post("/v1/connect/requests", map[string]string{
		"device_public_key": base64.RawURLEncoding.EncodeToString(m.pub),
		"machine_name":      "studio-mac", "os": "darwin", "arch": "arm64", "observer_version": "1.40.0",
	})
	mraw := readAll(mc)
	if mc.StatusCode != http.StatusCreated || strings.Contains(mraw, "device_code") {
		t.Fatalf("machine create = %d %s", mc.StatusCode, mraw)
	}

	cases := []struct {
		name string
		edit func(map[string]any)
		code string
	}{
		{"sdk body with a device key", func(b map[string]any) { b["device_public_key"] = base64.RawURLEncoding.EncodeToString(m.pub) }, "bad_request"},
		{"bad project", func(b map[string]any) { b["project_name"] = "Support Bot" }, fixtureErrCode(t, f, "invalid_field")},
		{"unknown client", func(b map[string]any) { b["client"] = "curl" }, "invalid_client"},
		{"unknown purpose", func(b map[string]any) { b["purpose"] = "token" }, "invalid_purpose"},
	}
	for _, tc := range cases {
		body := sdkCreateBody(t)
		tc.edit(body)
		status, raw := sdkPostJSON(t, h, "/v1/connect/requests", body)
		if status != http.StatusBadRequest || !strings.Contains(string(raw), `"code":"`+tc.code+`"`) {
			t.Errorf("%s: %d %s, want 400 %s", tc.name, status, raw, tc.code)
		}
		if tc.code == fixtureErrCode(t, f, "invalid_field") {
			wantFixtureShape(t, f, "invalid_field", status, raw)
		}
	}
	machineWithRedeem := map[string]any{
		"device_public_key": base64.RawURLEncoding.EncodeToString(m.pub), "machine_name": "a", "os": "linux",
		"arch": "amd64", "observer_version": "1", "redeem_hash": sdkCreateBody(t)["redeem_hash"],
	}
	if status, raw := sdkPostJSON(t, h, "/v1/connect/requests", machineWithRedeem); status != http.StatusBadRequest || !strings.Contains(string(raw), `"code":"bad_request"`) {
		t.Errorf("machine body with a redeem hash: %d %s", status, raw)
	}

	// No SDK key grant key: the purpose is not offered.
	off := newOrgsHarnessWith(t, nil)
	status, raw = sdkPostJSON(t, off, "/v1/connect/requests", sdkCreateBody(t))
	wantFixtureShape(t, f, "purpose_not_offered", status, raw)
	if !strings.Contains(string(raw), `"code":"`+fixtureErrCode(t, f, "purpose_not_offered")+`"`) {
		t.Fatalf("no key: %s", raw)
	}
}

// TestConnectSDKKeyPollNeedsTheDeviceCode: the request's stored auth kind
// decides: a missing, wrong or machine-style proof is refused, the code is
// the only key, and pending / declined / expired answers have the fixture's
// shape with no grant, no sign-in.
func TestConnectSDKKeyPollNeedsTheDeviceCode(t *testing.T) {
	h, _ := newSDKKeyHarness(t)
	f := readSetupFixture(t, "connect-poll.json")
	p := newSDKSetup(t, h)

	for _, auth := range []string{"", "Bearer ", "Bearer " + p.deviceCode[:42] + "x", "Basic " + p.deviceCode, p.deviceCode} {
		status, raw := p.pollAs(auth)
		if auth == "Bearer "+p.deviceCode[:42]+"x" {
			wantFixtureShape(t, f, "unauthorized", status, raw)
		}
		if status != http.StatusUnauthorized || !strings.Contains(string(raw), `"code":"`+fixtureErrCode(t, f, "unauthorized")+`"`) {
			t.Errorf("auth %q: %d %s, want 401", auth, status, raw)
		}
	}
	// A machine's proof of possession does not open a device-code request.
	m := newConnectMachine(t, h)
	if resp := m.pollWith(p.requestID, m.proof(p.requestID)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a PoP header on a device-code request: %d", resp.StatusCode)
	}
	// ... and a device code does not open a machine's request.
	mc := m.create("")
	other := &sdkSetup{t: t, base: h.srv.URL, http: h.srv.Client(), requestID: mc.RequestID}
	if status, _ := other.pollAs("Bearer " + p.deviceCode); status != http.StatusUnauthorized {
		t.Fatalf("a device code on a machine request: %d", status)
	}

	got, raw := p.poll()
	wantFixtureShape(t, f, "pending", http.StatusOK, raw)
	if got.Status != "pending" || got.Target != nil || got.KeyGrant != "" {
		t.Fatalf("pending = %s", raw)
	}
	unknown := &sdkSetup{t: t, base: h.srv.URL, http: h.srv.Client(), requestID: "00000000-0000-0000-0000-000000000000"}
	status, raw := unknown.pollAs("Bearer " + p.deviceCode)
	wantFixtureShape(t, f, "not_found", status, raw)

	pc := h.portalLogin(t, "sdk-declines")
	if resp := orgReq(t, pc, "POST", "/portal/api/connect/requests/"+p.requestID+"/decline", map[string]string{}, pc.csrf, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("decline status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	got, raw = p.poll()
	wantFixtureShape(t, f, "declined", http.StatusOK, raw)
	if got.Status != "declined" {
		t.Fatalf("declined = %s", raw)
	}

	e := newSDKSetup(t, h)
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE connect_requests SET created_at = now() - interval '20 minutes', expires_at = now() - interval '5 minutes' WHERE request_id=$1::uuid`,
		e.requestID); err != nil {
		t.Fatal(err)
	}
	got, raw = e.poll()
	wantFixtureShape(t, f, "expired", http.StatusOK, raw)
	if got.Status != "expired" {
		t.Fatalf("expired = %s", raw)
	}
}

// TestConnectSDKKeyApproveDeliversTheKeyGrant: the approval page shows the
// SDK's request with the SDK key disclosure, takes no "Not now", and sends
// the browser to the dashboard's AI apps page. The poll waits for a personal
// dashboard still being set up (approved, not ready, no grant, no delivery
// used), then hands the grant over three times (the same bytes: one
// approval, one jti), then 409. The grant verifies under the SDK key grant
// key for that organization only, binds the redeem hash and the account's
// subject, and never verifies as an attach grant. No poll carries a cloud
// sign-in, and the account home lists no machine.
func TestConnectSDKKeyApproveDeliversTheKeyGrant(t *testing.T) {
	h, signPub := newSDKKeyHarness(t)
	f := readSetupFixture(t, "connect-poll.json")
	p := newSDKSetup(t, h)
	pc := h.portalLogin(t, "sdk-alice")

	v := getSDKView(t, pc, p.requestID)
	if v.Purpose != "sdk_key" || v.Status != "pending" || v.UserCode != p.userCode || v.MachineName != "studio-mac" ||
		v.Client != "superbased-sdk-python" || v.ClientVersion != "0.2.0" || v.ProjectName != "support-bot" {
		t.Fatalf("view = %+v", v)
	}
	if len(v.Choices) != 1 || v.Choices[0].Kind != "personal" || !v.Choices[0].Available || !v.Choices[0].Preselected ||
		v.Choices[0].Disclosure.Version != "sdk-key-disclosure.v1" ||
		!strings.Contains(v.Choices[0].Disclosure.Text, "Traces need this SDK key, and nothing else.") {
		t.Fatalf("choices = %+v", v.Choices)
	}
	personal := v.Choices[0]

	// No "Not now" for an SDK key.
	resp := approveConnect(t, pc, p.requestID, map[string]string{"target_org_id": ""})
	if resp.StatusCode != http.StatusBadRequest || errCode(t, resp) != "answer_not_allowed" {
		t.Fatalf("not now on an SDK key: want 400 answer_not_allowed")
	}
	// The machine's disclosure is not the SDK key's.
	machineText := "Counts, costs"
	if strings.Contains(personal.Disclosure.Text, machineText) {
		t.Fatalf("the SDK key shows the machine's disclosure: %s", personal.Disclosure.Text)
	}

	resp = approveConnect(t, pc, p.requestID, map[string]string{
		"target_org_id": personal.OrgID, "disclosure_version": personal.Disclosure.Version, "disclosure_sha256": personal.Disclosure.SHA256,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var after sdkView
	decode(t, resp, &after)
	if after.Status != "approved" || !strings.HasPrefix(after.OpenURL, "https://u-") ||
		!strings.HasSuffix(after.OpenURL, "."+orgsTenantDomain+"/trajectories?from=connect") || after.TargetReady == nil || *after.TargetReady {
		t.Fatalf("approved view: open_url %q target_ready %v (the AI apps page, waiting while the dashboard is set up)", after.OpenURL, after.TargetReady)
	}
	if n := countRows(t, h, `SELECT count(*) FROM connect_consents WHERE org_id=$1::uuid AND disclosure_version='sdk-key-disclosure.v1' AND disclosure_sha256=$2`,
		personal.OrgID, personal.Disclosure.SHA256); n != 1 {
		t.Fatalf("consent receipts = %d", n)
	}

	// Not ready yet: approved, no grant, and no delivery used.
	for i := 0; i < 4; i++ {
		got, raw := p.poll()
		wantFixtureShape(t, f, "approved_not_ready", http.StatusOK, raw)
		if got.Status != "approved" || got.Target == nil || got.Target.Ready || got.Target.ServerURL != "" || got.KeyGrant != "" ||
			got.ConsentReceiptID == nil || strings.Contains(string(raw), "sign_in") || strings.Contains(string(raw), "attach_grant") {
			t.Fatalf("not ready poll %d = %s", i, raw)
		}
	}

	activateOrg(t, h, personal.OrgID)
	first, raw := p.poll()
	wantFixtureShape(t, f, "approved_with_grant", http.StatusOK, raw)
	if !first.Target.Ready || first.Target.ServerURL != "https://"+first.Target.Slug+"."+orgsTenantDomain || first.KeyGrant == "" ||
		strings.Contains(string(raw), "sign_in") || strings.Contains(string(raw), "attach_grant") {
		t.Fatalf("ready poll = %s", raw)
	}
	keys := platformcontract.KeySet{platformcontract.NewDocumentKey(signPub)}
	claims, err := sdkkeygrant.Verify(first.KeyGrant, sdkkeygrant.Facts{Keys: keys, Now: time.Now()})
	if err != nil {
		t.Fatalf("the grant does not verify: %v", err)
	}
	body := sdkCreateBody(t)
	if claims.OrgID != personal.OrgID || claims.Kind != "personal" || claims.AccountID != pc.accountID || claims.Subject == "" ||
		claims.RequestID != p.requestID || claims.RedeemHash != body["redeem_hash"] || claims.JTI != sdkkeygrant.JTIFor(p.requestID) ||
		claims.ExpiresAt-claims.IssuedAt != int64(sdkkeygrant.Lifetime/time.Second) {
		t.Fatalf("claims = %+v", claims)
	}
	// Another key does not verify it; the attach grant verifier refuses it.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := sdkkeygrant.Verify(first.KeyGrant, sdkkeygrant.Facts{Keys: platformcontract.KeySet{platformcontract.NewDocumentKey(otherPub)}, Now: time.Now()}); err == nil {
		t.Fatal("the grant verified under another key")
	}
	if _, err := attachgrant.Verify(first.KeyGrant, attachgrant.Facts{Keys: keys, OrgID: personal.OrgID, Now: time.Now()}); err == nil {
		t.Fatal("a key grant verified as an attach grant")
	}

	second, _ := p.poll()
	third, _ := p.poll()
	if second.KeyGrant != first.KeyGrant || third.KeyGrant != first.KeyGrant {
		t.Fatal("a re-delivery carried a different grant: one approval, one grant")
	}
	status, raw := p.pollAs("Bearer " + p.deviceCode)
	wantFixtureShape(t, f, "already_delivered", status, raw)
	if !strings.Contains(string(raw), `"code":"`+fixtureErrCode(t, f, "already_delivered")+`"`) {
		t.Fatalf("fourth poll = %d %s", status, raw)
	}

	// No device was signed in, and the account home lists no machine.
	resp = pc.get("/portal/api/connect/machines")
	var home struct {
		Devices int               `json:"devices"`
		Recent  []json.RawMessage `json:"recent"`
	}
	decode(t, resp, &home)
	if home.Devices != 0 || len(home.Recent) != 0 {
		t.Fatalf("account home after an SDK key = %+v", home)
	}
	if n := countRows(t, h, `SELECT count(*) FROM api_tokens WHERE account_id=$1::uuid`, pc.accountID); n != 0 {
		t.Fatalf("an SDK key approval minted %d cloud tokens", n)
	}
}

// TestConnectSDKKeyGrantWindow: a dashboard that becomes ready only after
// the delivery window gets no grant (the grant would be expired): 409
// key_grant_window_closed, the fixture's shape.
func TestConnectSDKKeyGrantWindow(t *testing.T) {
	h, _ := newSDKKeyHarness(t)
	p := newSDKSetup(t, h)
	pc := h.portalLogin(t, "sdk-slow")
	v := getSDKView(t, pc, p.requestID)
	personal := v.Choices[0]
	if resp := approveConnect(t, pc, p.requestID, map[string]string{
		"target_org_id": personal.OrgID, "disclosure_version": personal.Disclosure.Version, "disclosure_sha256": personal.Disclosure.SHA256,
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status=%d", resp.StatusCode)
	}
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE connect_requests SET resolved_at = now() - interval '11 minutes' WHERE request_id=$1::uuid`, p.requestID); err != nil {
		t.Fatal(err)
	}
	activateOrg(t, h, personal.OrgID)
	f := readSetupFixture(t, "connect-poll.json")
	status, raw := p.pollAs("Bearer " + p.deviceCode)
	wantFixtureShape(t, f, "window_closed", status, raw)
	if !strings.Contains(string(raw), `"code":"`+fixtureErrCode(t, f, "window_closed")+`"`) {
		t.Fatalf("late poll = %d %s", status, raw)
	}
}

// TestConnectSDKKeyTeamPlan: a team whose plan does not include AI Apps is
// listed disabled with the plan refusal's message and link and cannot be
// approved; once its plan includes AI Apps (a Business document) it is
// choosable, carries the team's SDK key disclosure, and its grant names it.
func TestConnectSDKKeyTeamPlan(t *testing.T) {
	h, signPub := newSDKKeyHarness(t)
	pc := h.portalLogin(t, "sdk-team-owner")
	team := createTeam(t, pc, "Acme", "acme-sdk")
	activateOrg(t, h, team.Org.OrgID)

	body := sdkCreateBody(t)
	body["target_hint"] = "acme-sdk"
	status, raw := sdkPostJSON(t, h, "/v1/connect/requests", body)
	if status != http.StatusCreated {
		t.Fatalf("create = %d %s", status, raw)
	}
	var c struct {
		RequestID  string `json:"request_id"`
		DeviceCode string `json:"device_code"`
	}
	_ = json.Unmarshal(raw, &c)
	p := &sdkSetup{t: t, base: h.srv.URL, http: h.srv.Client(), requestID: c.RequestID, deviceCode: c.DeviceCode}

	v := getSDKView(t, pc, p.requestID)
	var teamChoice, personalChoice int = -1, -1
	for i, ch := range v.Choices {
		switch ch.Kind {
		case "team":
			teamChoice = i
		case "personal":
			personalChoice = i
		}
	}
	if teamChoice < 0 || personalChoice < 0 {
		t.Fatalf("choices = %+v", v.Choices)
	}
	tc := v.Choices[teamChoice]
	if tc.Available || tc.Preselected || tc.Refusal == nil || tc.Refusal.Code != "plan_required" ||
		!strings.Contains(tc.Refusal.Message, "AI Apps") || !strings.HasSuffix(tc.Refusal.UpgradeURL, "/portal/orgs/"+team.Org.OrgID) {
		t.Fatalf("a team without AI Apps = %+v", tc)
	}
	if !v.Choices[personalChoice].Preselected {
		t.Fatalf("the hinted team is unavailable, so the personal dashboard is preselected: %+v", v.Choices)
	}
	resp := approveConnect(t, pc, p.requestID, map[string]string{
		"target_org_id": tc.OrgID, "disclosure_version": tc.Disclosure.Version, "disclosure_sha256": tc.Disclosure.SHA256,
	})
	if resp.StatusCode != http.StatusConflict || errCode(t, resp) != "plan_required" {
		t.Fatalf("approving a team without AI Apps: want 409 plan_required")
	}

	// The team moves to Business: AI Apps is in its plan.
	issueBusiness(t, h, team.Org.OrgID)
	v = getSDKView(t, pc, p.requestID)
	tc = v.Choices[teamChoice]
	if !tc.Available || !tc.Preselected || tc.Refusal != nil || tc.ShareLevel != "full" ||
		!strings.Contains(tc.Disclosure.Text, "Acme's admins can read what your apps send") {
		t.Fatalf("a Business team = %+v", tc)
	}
	resp = approveConnect(t, pc, p.requestID, map[string]string{
		"target_org_id": tc.OrgID, "disclosure_version": tc.Disclosure.Version, "disclosure_sha256": tc.Disclosure.SHA256,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve the team status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var after sdkView
	decode(t, resp, &after)
	if after.OpenURL != "https://acme-sdk."+orgsTenantDomain+"/trajectories?from=connect" || after.TargetReady == nil || !*after.TargetReady {
		t.Fatalf("approved team view: open_url %q ready %v", after.OpenURL, after.TargetReady)
	}
	got, raw := p.poll()
	if got.Target == nil || got.Target.Kind != "team" || got.Target.Slug != "acme-sdk" || !got.Target.Ready ||
		got.Target.ServerURL != "https://acme-sdk."+orgsTenantDomain || got.KeyGrant == "" {
		t.Fatalf("team poll = %s", raw)
	}
	claims, err := sdkkeygrant.Verify(got.KeyGrant, sdkkeygrant.Facts{Keys: platformcontract.KeySet{platformcontract.NewDocumentKey(signPub)}, Now: time.Now()})
	if err != nil || claims.OrgID != team.Org.OrgID || claims.Kind != "team" || claims.Slug != "acme-sdk" {
		t.Fatalf("team grant: %+v %v", claims, err)
	}
}

// issueBusiness stores a Business entitlement document for org, as the
// entitlements worker would after a subscription (the envelope's signature
// is not checked by the approval page: the cloud is its own issuer).
func issueBusiness(t *testing.T, h orgsHarness, orgID string) {
	t.Helper()
	now := time.Now().Unix()
	plans := entitlements.PlansOfKind(entitlements.KindTeam)
	version := 0
	for _, p := range plans {
		if p.Plan.Name == "business" && p.Plan.Version > version {
			version = p.Plan.Version
		}
	}
	b, err := entitlements.Compose("business", version, orgID, now, now-60, 0)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	raw, err := b.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO org_entitlement_docs (org_id, version, body, signature, key_id, issued_at, issued_by)
		 VALUES ($1::uuid, 1, $2, $3, $4, now(), 'system')`,
		orgID, raw, bytes.Repeat([]byte{1}, 64), strings.Repeat("k", 43)); err != nil {
		t.Fatalf("store the document: %v", err)
	}
}
