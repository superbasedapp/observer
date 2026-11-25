package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/availwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// staffavail_test.go drives the staff console's issue step and per-org Code
// security over HTTP against a real PostgreSQL, as the staff login
// (sbci_staff) with the worker's issuer run in between (lane
// fix/sr-17-staff-control), and the staff process's rate limits on that login
// (SC-1, SC-2). Skipped loudly without SBCI_TEST_PG_DSN.

// TestStaffConsoleRateLimitsOnTheStaffLogin: with the limiter on, the staff
// login can use it (SC-1: it answered 503 on every route), a signed-in staff
// member is not held to the anonymous per-IP budget (SC-2), and a cookie that
// does not resolve still is.
func TestStaffConsoleRateLimitsOnTheStaffLogin(t *testing.T) {
	t.Parallel()
	h := newStaffPGHarnessRL(t, api.StaffTestVerifier{}, &api.RateLimitConfig{Window: time.Minute, IPPerWindow: 6, AccountPerWindow: 200})
	auth := api.NewStaffTestAuthenticator(71)
	_, _, sess, _ := h.staff(staffauth.RoleSupport, auth) // four pre-session calls on the IP budget
	for i := 0; i < 20; i++ {
		if rec := h.do("GET", "/staff/api/me", nil, []*http.Cookie{sess}, nil); rec.Code != http.StatusOK {
			t.Fatalf("signed-in read %d = %d %s, want 200", i, rec.Code, rec.Body)
		}
	}
	bogus := &http.Cookie{Name: "__Host-sbci-staff", Value: "not-a-session"}
	codes := []int{}
	for i := 0; i < 4; i++ {
		codes = append(codes, h.do("GET", "/staff/api/me", nil, []*http.Cookie{bogus}, nil).Code)
	}
	if codes[0] != http.StatusUnauthorized || codes[len(codes)-1] != http.StatusTooManyRequests {
		t.Fatalf("unresolved cookie codes = %v, want 401 first and 429 once the IP budget is spent", codes)
	}
}

// availIssueKey signs envelopes for the test worker.
type availIssueKey struct{ priv ed25519.PrivateKey }

func (k availIssueKey) sign(_ context.Context, version int64, body []byte) ([]byte, string, error) {
	return pc.SignDocument(k.priv, pc.KindAvailability, pc.AvailabilityScope, version, body)
}

func TestStaffAvailabilityIssueFlowWithPostgres(t *testing.T) {
	t.Parallel()
	h := newStaffPGHarness(t)
	ctx := context.Background()
	opsAuth, suppAuth := api.NewStaffTestAuthenticator(72), api.NewStaffTestAuthenticator(73)
	_, _, ops, opsCSRF := h.staff(staffauth.RoleOps, opsAuth)
	_, _, supp, suppCSRF := h.staff(staffauth.RoleSupport, suppAuth)
	var owner string
	if err := h.pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	apiStore := mustAPIStore(t, h.pool)
	orgIDs := map[string]string{}
	for _, slug := range []string{"flow-a", "flow-b"} {
		o, err := apiStore.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{Kind: store.OrgTeam, Slug: slug, DisplayName: slug, Tenancy: store.TenancyManaged})
		if err != nil {
			t.Fatal(err)
		}
		orgIDs[slug] = o.OrgID
	}
	orgA, orgB := orgIDs["flow-a"], orgIDs["flow-b"]
	worker, err := store.NewForRole(h.pool, store.RoleWorker)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := availIssueKey{priv}
	issuer, err := availwork.NewIssuer(availwork.IssuerConfig{
		Store: worker, Signer: availwork.SignerFunc(key.sign),
		Keys: pc.KeySet{pc.NewDocumentKey(priv.Public().(ed25519.PublicKey))},
	})
	if err != nil {
		t.Fatal(err)
	}
	opsH := map[string]string{"X-SBCI-Staff-CSRF": opsCSRF}
	type componentRow struct {
		Component string          `json:"component"`
		Issued    bool            `json:"issued"`
		Next      bool            `json:"next"`
		Input     json.RawMessage `json:"input"`
		Toggle    struct {
			On    bool            `json:"on"`
			Value json.RawMessage `json:"value"`
			Error string          `json:"error"`
		} `json:"toggle"`
	}
	components := func(org string) componentRow {
		t.Helper()
		rec := h.do("GET", "/staff/api/orgs/"+org+"/components", nil, []*http.Cookie{supp}, nil)
		var out struct {
			Components []componentRow `json:"components"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("GET components = %d %s", rec.Code, rec.Body)
		}
		// The org lists every per-org component (org.security, and
		// org.aigateway since the hosted AI gateway arc); this flow
		// drives org.security only.
		for _, c := range out.Components {
			if c.Component == "org.security" {
				return c
			}
		}
		t.Fatalf("GET components has no org.security row: %s", rec.Body)
		return componentRow{}
	}
	type preview struct {
		BaseVersion  int64            `json:"base_version"`
		InputsDigest string           `json:"inputs_digest"`
		Problems     []string         `json:"problems"`
		Changes      []map[string]any `json:"changes"`
		Pending      *struct {
			State string `json:"state"`
		} `json:"pending"`
		LastRequest *struct {
			State         string `json:"state"`
			ResultVersion int64  `json:"result_version"`
		} `json:"last_request"`
	}
	getPreview := func() preview {
		t.Helper()
		rec := h.do("GET", "/staff/api/availability/preview", nil, []*http.Cookie{supp}, nil)
		var p preview
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &p) != nil {
			t.Fatalf("preview = %d %s", rec.Code, rec.Body)
		}
		return p
	}
	issue := func(p preview) {
		t.Helper()
		rec := h.do("POST", "/staff/api/availability/issue", map[string]any{"reason": "SR-17 flow", "inputs_digest": p.InputsDigest, "base_version": p.BaseVersion}, []*http.Cookie{ops}, opsH)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("issue = %d %s", rec.Code, rec.Body)
		}
		if out, err := issuer.IssueOnce(ctx); out != availwork.OutcomeIssued || err != nil {
			t.Fatalf("worker IssueOnce = %s, %v", out, err)
		}
	}

	// Off by default for both orgs; the button turns it on.
	if c := components(orgA); c.Component != "org.security" || c.Issued || c.Next || !c.Toggle.On || c.Toggle.Error != "" {
		t.Fatalf("org A before = %+v", c)
	}
	// Support can read but not change or issue.
	if rec := h.do("PUT", "/staff/api/orgs/"+orgA+"/components/org.security", map[string]any{"on": true, "reason": "support tries"}, []*http.Cookie{supp}, map[string]string{"X-SBCI-Staff-CSRF": suppCSRF}); rec.Code != http.StatusForbidden {
		t.Fatalf("support toggle = %d %s, want 403", rec.Code, rec.Body)
	}
	// ops turns it on for org A.
	rec := h.do("PUT", "/staff/api/orgs/"+orgA+"/components/org.security", map[string]any{"on": true, "reason": "SR-17 for A"}, []*http.Cookie{ops}, opsH)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), orgA) {
		t.Fatalf("toggle on = %d %s", rec.Code, rec.Body)
	}
	if rec := h.do("PUT", "/staff/api/orgs/"+orgA+"/components/org.security", map[string]any{"on": true, "reason": "again"}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusConflict {
		t.Fatalf("toggle on twice = %d, want 409 no_change", rec.Code)
	}
	for _, bad := range []struct {
		path string
		body map[string]any
		want int
	}{
		{"/staff/api/orgs/" + orgA + "/components/org.digest", map[string]any{"on": true, "reason": "r"}, http.StatusNotFound},
		{"/staff/api/orgs/00000000-0000-4000-8000-000000000000/components/org.security", map[string]any{"on": true, "reason": "r"}, http.StatusNotFound},
		{"/staff/api/orgs/" + orgA + "/components/org.security", map[string]any{"reason": "r"}, http.StatusBadRequest},
		{"/staff/api/orgs/" + orgA + "/components/org.security", map[string]any{"on": false, "reason": " "}, http.StatusBadRequest},
	} {
		if rec := h.do("PUT", bad.path, bad.body, []*http.Cookie{ops}, opsH); rec.Code != bad.want {
			t.Errorf("PUT %s %v = %d, want %d", bad.path, bad.body, rec.Code, bad.want)
		}
	}
	if c := components(orgA); c.Issued || !c.Next || c.Toggle.On {
		t.Fatalf("org A after the toggle, before an issue = %+v (next on, not issued)", c)
	}
	if c := components(orgB); c.Issued || c.Next {
		t.Fatalf("org B = %+v, want untouched", c)
	}

	// The preview shows the one change; the issue needs the current digest.
	p := getPreview()
	if p.BaseVersion != 0 || len(p.Problems) != 0 || len(p.Changes) != 1 || p.Changes[0]["key"] != "org.security" || p.Changes[0]["kind"] != "added" {
		t.Fatalf("preview = %+v", p)
	}
	if rec := h.do("POST", "/staff/api/availability/issue", map[string]any{"reason": "r", "inputs_digest": p.InputsDigest, "base_version": 0}, []*http.Cookie{supp}, map[string]string{"X-SBCI-Staff-CSRF": suppCSRF}); rec.Code != http.StatusForbidden {
		t.Fatalf("support issue = %d, want 403", rec.Code)
	}
	if rec := h.do("POST", "/staff/api/availability/issue", map[string]any{"reason": "r", "inputs_digest": strings.Repeat("0", 64), "base_version": 0}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "inputs_changed") {
		t.Fatalf("stale digest = %d %s, want 409 inputs_changed", rec.Code, rec.Body)
	}
	if rec := h.do("POST", "/staff/api/availability/issue", map[string]any{"reason": "", "inputs_digest": p.InputsDigest}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusBadRequest {
		t.Fatalf("no reason = %d, want 400", rec.Code)
	}
	rec = h.do("POST", "/staff/api/availability/issue", map[string]any{"reason": "SR-17 flow", "inputs_digest": p.InputsDigest, "base_version": 0}, []*http.Cookie{ops}, opsH)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("issue = %d %s", rec.Code, rec.Body)
	}
	if rec := h.do("POST", "/staff/api/availability/issue", map[string]any{"reason": "again", "inputs_digest": p.InputsDigest, "base_version": 0}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "issue_pending") {
		t.Fatalf("second issue = %d %s, want 409 issue_pending", rec.Code, rec.Body)
	}
	if p := getPreview(); p.Pending == nil || p.Pending.State != "pending" {
		t.Fatalf("preview while pending = %+v", p)
	}
	if out, err := issuer.IssueOnce(ctx); out != availwork.OutcomeIssued || err != nil {
		t.Fatalf("worker IssueOnce = %s, %v", out, err)
	}
	p = getPreview()
	if p.Pending != nil || p.LastRequest == nil || p.LastRequest.State != "issued" || p.BaseVersion != p.LastRequest.ResultVersion || len(p.Changes) != 0 {
		t.Fatalf("preview after the issue = %+v", p)
	}
	if rec := h.do("POST", "/staff/api/availability/issue", map[string]any{"reason": "r", "inputs_digest": p.InputsDigest, "base_version": p.BaseVersion}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "nothing_to_issue") {
		t.Fatalf("issue with no change = %d %s, want 409 nothing_to_issue", rec.Code, rec.Body)
	}
	if c := components(orgA); !c.Issued || !c.Next {
		t.Fatalf("org A after the issue = %+v", c)
	}
	if c := components(orgB); c.Issued || c.Next {
		t.Fatalf("org B after the issue = %+v, want untouched", c)
	}

	// Off again, issued, closes it.
	if rec := h.do("PUT", "/staff/api/orgs/"+orgA+"/components/org.security", map[string]any{"on": false, "reason": "SR-17 off for A"}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusOK {
		t.Fatalf("toggle off = %d %s", rec.Code, rec.Body)
	}
	issue(getPreview())
	if c := components(orgA); c.Issued || c.Next {
		t.Fatalf("org A after off = %+v", c)
	}

	// The generic PUT refuses a value the envelope would refuse (STAFF-8).
	if rec := h.do("PUT", "/staff/api/availability/org_controls/"+orgA, map[string]any{"value": map[string]any{"org": "*", "ingest": map[string]string{"mode": "pause"}}, "reason": "r"}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_input") {
		t.Fatalf("invalid org_controls value = %d %s, want 400 invalid_input", rec.Code, rec.Body)
	}
	// The log names the org and the issue requests.
	log := h.do("GET", "/staff/api/log?org="+orgA, nil, []*http.Cookie{supp}, nil)
	if !strings.Contains(log.Body.String(), `"reason":"SR-17 for A"`) || !strings.Contains(log.Body.String(), `"reason":"SR-17 off for A"`) {
		t.Fatalf("org A log = %s", log.Body)
	}
	all := h.do("GET", "/staff/api/log?verb=availability.issue_requested", nil, []*http.Cookie{supp}, nil)
	if strings.Count(all.Body.String(), `"verb":"availability.issue_requested"`) != 2 {
		t.Fatalf("issue_requested rows = %s", all.Body)
	}
}

// TestStaffAvailabilityIssueCancelWithPostgres: a pending issue request that
// no worker picks up refuses every later issue, so ops and admin can cancel
// it: fresh passkey, CSRF and a reason, only while it is pending, logged with
// the reason; support cannot.
func TestStaffAvailabilityIssueCancelWithPostgres(t *testing.T) {
	t.Parallel()
	h := newStaffPGHarness(t)
	ctx := context.Background()
	opsID, _, ops, opsCSRF := h.staff(staffauth.RoleOps, api.NewStaffTestAuthenticator(75))
	_, _, supp, suppCSRF := h.staff(staffauth.RoleSupport, api.NewStaffTestAuthenticator(76))
	adminID, _, admin, adminCSRF := h.staff(staffauth.RoleAdmin, api.NewStaffTestAuthenticator(77))
	opsH := map[string]string{"X-SBCI-Staff-CSRF": opsCSRF}
	type request struct {
		RequestID  string `json:"request_id"`
		State      string `json:"state"`
		ErrorClass string `json:"error_class"`
	}
	type preview struct {
		BaseVersion  int64    `json:"base_version"`
		InputsDigest string   `json:"inputs_digest"`
		Pending      *request `json:"pending"`
		LastRequest  *request `json:"last_request"`
	}
	getPreview := func() preview {
		t.Helper()
		rec := h.do("GET", "/staff/api/availability/preview", nil, []*http.Cookie{supp}, nil)
		var p preview
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &p) != nil {
			t.Fatalf("preview = %d %s", rec.Code, rec.Body)
		}
		return p
	}
	issue := func() string {
		t.Helper()
		p := getPreview()
		rec := h.do("POST", "/staff/api/availability/issue", map[string]any{"reason": "SR-17 cancel", "inputs_digest": p.InputsDigest, "base_version": p.BaseVersion}, []*http.Cookie{ops}, opsH)
		var out request
		if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("issue = %d %s", rec.Code, rec.Body)
		}
		return out.RequestID
	}
	cancelPath := func(id string) string { return "/staff/api/availability/issue/" + id + "/cancel" }

	// One input change, issued, and no worker: the request stays pending and
	// the next issue is refused.
	if rec := h.do("PUT", "/staff/api/availability/components/org.security", map[string]any{"value": map[string]string{"reach": "off"}, "reason": "SR-17 cancel setup"}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("input = %d %s", rec.Code, rec.Body)
	}
	id := issue()
	p := getPreview()
	if p.Pending == nil || p.Pending.RequestID != id {
		t.Fatalf("pending = %+v, want %s", p.Pending, id)
	}
	if rec := h.do("POST", "/staff/api/availability/issue", map[string]any{"reason": "blocked", "inputs_digest": p.InputsDigest, "base_version": p.BaseVersion}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "issue_pending") {
		t.Fatalf("issue while pending = %d %s, want 409 issue_pending", rec.Code, rec.Body)
	}

	// Refusals, none of which touches the request.
	staleAdmin := func() {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `UPDATE staff_sessions SET webauthn_at = webauthn_at - interval '16 minutes' WHERE staff_id = $1::uuid`, adminID); err != nil {
			t.Fatal(err)
		}
	}
	staleAdmin()
	for _, c := range []struct {
		name    string
		path    string
		body    map[string]any
		cookie  *http.Cookie
		headers map[string]string
		status  int
		code    string
	}{
		{"support", cancelPath(id), map[string]any{"reason": "support tries"}, supp, map[string]string{"X-SBCI-Staff-CSRF": suppCSRF}, http.StatusForbidden, staffauth.CodeForbiddenRole},
		{"admin, passkey older than 15 minutes", cancelPath(id), map[string]any{"reason": "stale admin"}, admin, map[string]string{"X-SBCI-Staff-CSRF": adminCSRF}, http.StatusForbidden, staffauth.CodeReauthRequired},
		{"no CSRF header", cancelPath(id), map[string]any{"reason": "no csrf"}, ops, nil, http.StatusForbidden, ""},
		{"no reason", cancelPath(id), map[string]any{}, ops, opsH, http.StatusBadRequest, "reason_required"},
		{"blank reason", cancelPath(id), map[string]any{"reason": "  "}, ops, opsH, http.StatusBadRequest, "reason_required"},
		{"malformed id", cancelPath("not-a-uuid"), map[string]any{"reason": "r"}, ops, opsH, http.StatusNotFound, "not_found"},
		{"unknown id", cancelPath("00000000-0000-4000-8000-000000000000"), map[string]any{"reason": "r"}, ops, opsH, http.StatusConflict, "not_pending"},
	} {
		rec := h.do("POST", c.path, c.body, []*http.Cookie{c.cookie}, c.headers)
		if rec.Code != c.status || (c.code != "" && !strings.Contains(rec.Body.String(), `"`+c.code+`"`)) {
			t.Errorf("%s: %d %s, want %d %s", c.name, rec.Code, rec.Body, c.status, c.code)
		}
	}
	if p := getPreview(); p.Pending == nil || p.Pending.RequestID != id {
		t.Fatalf("after the refusals the request is %+v, want still pending", p.Pending)
	}

	// ops cancels it; then it is no longer pending, and issuing works again.
	rec := h.do("POST", cancelPath(id), map[string]any{"reason": "worker loops are off"}, []*http.Cookie{ops}, opsH)
	var got request
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.RequestID != id || got.State != "failed" || got.ErrorClass != "cancelled" {
		t.Fatalf("cancel = %d %s", rec.Code, rec.Body)
	}
	if rec := h.do("POST", cancelPath(id), map[string]any{"reason": "again"}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "not_pending") {
		t.Fatalf("cancel twice = %d %s, want 409 not_pending", rec.Code, rec.Body)
	}
	if p := getPreview(); p.Pending != nil || p.LastRequest == nil || p.LastRequest.RequestID != id || p.LastRequest.State != "failed" || p.LastRequest.ErrorClass != "cancelled" {
		t.Fatalf("preview after the cancel = %+v / %+v", p.Pending, p.LastRequest)
	}
	id2 := issue()

	// A request the worker already finished cannot be cancelled.
	worker, err := store.NewForRole(h.pool, store.RoleWorker)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	issuer, err := availwork.NewIssuer(availwork.IssuerConfig{
		Store: worker, Signer: availwork.SignerFunc(availIssueKey{priv}.sign),
		Keys: pc.KeySet{pc.NewDocumentKey(priv.Public().(ed25519.PublicKey))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := issuer.IssueOnce(ctx); out != availwork.OutcomeIssued || err != nil {
		t.Fatalf("worker IssueOnce = %s, %v", out, err)
	}
	if rec := h.do("POST", cancelPath(id2), map[string]any{"reason": "too late"}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "not_pending") {
		t.Fatalf("cancel an issued request = %d %s, want 409 not_pending", rec.Code, rec.Body)
	}

	// The log: one cancel row, by ops, with its reason; the refusals wrote
	// action.refused rows, not cancels.
	log := h.do("GET", "/staff/api/log?verb=availability.issue_cancelled", nil, []*http.Cookie{supp}, nil)
	if n := strings.Count(log.Body.String(), `"verb":"availability.issue_cancelled"`); n != 1 || !strings.Contains(log.Body.String(), `"reason":"worker loops are off"`) ||
		!strings.Contains(log.Body.String(), staffauth.Actor(opsID)) {
		t.Fatalf("issue_cancelled log = %s", log.Body)
	}
}

// TestStaffRefusalsAreRateLimitedPerMember: the per-member limit runs before
// the authorization check, so a signed-in member cannot write refusal rows
// without bound.
func TestStaffRefusalsAreRateLimitedPerMember(t *testing.T) {
	t.Parallel()
	h := newStaffPGHarnessRL(t, api.StaffTestVerifier{}, &api.RateLimitConfig{Window: time.Minute, IPPerWindow: 100, AccountPerWindow: 3})
	auth := api.NewStaffTestAuthenticator(74)
	staffID, _, sess, csrf := h.staff(staffauth.RoleSupport, auth)
	codes := []int{}
	for i := 0; i < 6; i++ {
		rec := h.do("PUT", "/staff/api/availability/components/org.security",
			map[string]any{"value": map[string]string{"reach": "off"}, "reason": "support tries"},
			[]*http.Cookie{sess}, map[string]string{"X-SBCI-Staff-CSRF": csrf})
		codes = append(codes, rec.Code)
	}
	if codes[0] != http.StatusForbidden || codes[len(codes)-1] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v, want 403 refusals then 429 once the member's budget is spent", codes)
	}
	var refusals int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM staff_actions WHERE verb = 'action.refused' AND actor = $1`, staffauth.Actor(staffID)).Scan(&refusals); err != nil {
		t.Fatal(err)
	}
	if refusals > 3 {
		t.Fatalf("refusal rows = %d, want at most the member's budget (3)", refusals)
	}
}
