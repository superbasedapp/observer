package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
)

// device_orgs_test.go covers the lazy personal org's two triggers and the
// node's org discovery (device_orgs.go, portal_personal.go; D-IND-1;
// docs/security.md IND-1) over PostgreSQL with the server bound to the
// sbci_api role: device PoP on both device routes, session + CSRF + Origin on
// the console route, 201 then 200, one org and one member whoever triggers
// it, the list order (personal first, then teams oldest first), the server
// URL only for an active org, the create stage while provisioning, and every
// answer passing the cloudcontract Validate the node runs.

// newPlaneHarness is the org harness (tenant domain example.test) with the
// personal-plane switch set to plane.
func newPlaneHarness(t *testing.T, plane string) orgsHarness {
	t.Helper()
	h := newHarnessWith(t, harnessSetup{opts: func(o *api.Options) {
		o.TenantDomain = orgsTenantDomain
		o.PersonalPlane = plane
	}})
	return orgsHarness{harness: h, pool: h.store.Pool()}
}

// listDeviceOrgs is GET /v1/orgs as c, validated the way the node does.
func listDeviceOrgs(t *testing.T, c *testClient) cloudcontract.DeviceOrgList {
	t.Helper()
	resp := c.do(c.signedReq("GET", "/v1/orgs", nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/orgs status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var l cloudcontract.DeviceOrgList
	decode(t, resp, &l)
	if err := l.Validate(); err != nil {
		t.Fatalf("GET /v1/orgs answer fails the node's validation: %v (%+v)", err, l)
	}
	if l.Orgs == nil {
		t.Fatal("GET /v1/orgs answered a null orgs array")
	}
	return l
}

// ensureDevicePersonal is POST /v1/orgs/personal:ensure as c.
func ensureDevicePersonal(t *testing.T, c *testClient, wantStatus int) cloudcontract.EnsurePersonalOrgResponse {
	t.Helper()
	resp := c.do(c.signedReq("POST", "/v1/orgs/personal:ensure", nil))
	if resp.StatusCode != wantStatus {
		t.Fatalf("ensure status=%d body=%s, want %d", resp.StatusCode, readAll(resp), wantStatus)
	}
	var e cloudcontract.EnsurePersonalOrgResponse
	decode(t, resp, &e)
	if err := e.Validate(); err != nil {
		t.Fatalf("ensure answer fails the node's validation: %v (%+v)", err, e)
	}
	return e
}

func TestDeviceOrgsListAndEnsure(t *testing.T) {
	h := newPlaneHarness(t, api.PersonalPlaneServing)
	c := h.login(t, "ind-dev-alice")
	pc := h.portalLogin(t, "ind-dev-alice")
	if pc.accountID != c.accountID {
		t.Fatalf("device and portal sign-in are different accounts: %s vs %s", c.accountID, pc.accountID)
	}

	if l := listDeviceOrgs(t, c); len(l.Orgs) != 0 {
		t.Fatalf("fresh account lists %+v", l.Orgs)
	}
	// A team created first, so the personal-first order is not just age.
	team := createTeam(t, pc, "Alice Team", "alice-team")

	first := ensureDevicePersonal(t, c, http.StatusCreated)
	if !first.Created || first.Org.Kind != cloudcontract.DeviceOrgPersonal || first.Org.Tenancy != "individual" ||
		first.Org.DisplayName != "Personal" || first.Org.Status != cloudcontract.DeviceOrgProvisioning ||
		first.Org.Stage != "queued" || first.Org.ServerURL != "" || !strings.HasPrefix(first.Org.Slug, "u-") {
		t.Fatalf("first ensure = %+v", first)
	}
	again := ensureDevicePersonal(t, c, http.StatusOK)
	if again.Created || again.Org.OrgID != first.Org.OrgID {
		t.Fatalf("second ensure = %+v, want the same org, not created", again)
	}

	l := listDeviceOrgs(t, c)
	if len(l.Orgs) != 2 || l.Orgs[0].OrgID != first.Org.OrgID || l.Orgs[1].OrgID != team.Org.OrgID {
		t.Fatalf("list = %+v, want personal then the team", l.Orgs)
	}
	if tm := l.Orgs[1]; tm.Kind != cloudcontract.DeviceOrgTeam || tm.Tenancy != "managed" || tm.Stage != "queued" || tm.ServerURL != "" {
		t.Fatalf("team row = %+v", tm)
	}

	// Active: the server URL appears, the stage goes.
	if _, err := h.pool.Exec(context.Background(), `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, first.Org.OrgID); err != nil {
		t.Fatalf("activate: %v", err)
	}
	l = listDeviceOrgs(t, c)
	if p := l.Orgs[0]; p.Status != cloudcontract.DeviceOrgActive || p.ServerURL != "https://"+first.Org.Slug+"."+orgsTenantDomain || p.Stage != "" {
		t.Fatalf("active personal row = %+v", p)
	}
	if e := ensureDevicePersonal(t, c, http.StatusOK); e.Org.ServerURL != l.Orgs[0].ServerURL || e.Created {
		t.Fatalf("ensure of an active org = %+v", e)
	}

	// One org, one member, one create intent, whatever the number of calls.
	if n := countRows(t, h, `SELECT count(*) FROM orgs WHERE created_by=$1::uuid AND kind='personal'`, c.accountID); n != 1 {
		t.Fatalf("personal orgs = %d", n)
	}
	if n := countRows(t, h, `SELECT count(*) FROM org_members WHERE org_id=$1::uuid`, first.Org.OrgID); n != 1 {
		t.Fatalf("personal org members = %d", n)
	}

	// Another account sees only its own.
	bob := h.login(t, "ind-dev-bob")
	if l := listDeviceOrgs(t, bob); len(l.Orgs) != 0 {
		t.Fatalf("bob lists alice's orgs: %+v", l.Orgs)
	}
	if e := ensureDevicePersonal(t, bob, http.StatusCreated); e.Org.OrgID == first.Org.OrgID {
		t.Fatal("bob's ensure answered alice's org")
	}
}

func countRows(t *testing.T, h orgsHarness, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestDeviceOrgRoutesRequireDevicePoP(t *testing.T) {
	h := newPlaneHarness(t, api.PersonalPlaneServing)
	c := h.login(t, "ind-pop-carol")
	cases := []struct{ method, path string }{
		{"GET", "/v1/orgs"},
		{"POST", "/v1/orgs/personal:ensure"},
	}
	for _, tc := range cases {
		// No bearer.
		req, _ := http.NewRequest(tc.method, h.srv.URL+tc.path, nil)
		if resp := c.do(req); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without a bearer: %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
		// A bearer without its proof.
		req, _ = http.NewRequest(tc.method, h.srv.URL+tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+c.token)
		if resp := c.do(req); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without a proof: %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
		// A portal session is not a device credential.
		pc := h.portalLogin(t, "ind-pop-carol")
		resp := orgReq(t, pc, tc.method, tc.path, nil, pc.csrf, "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s with a portal session: %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
	// No slash alias of the ensure route.
	if resp := c.do(c.signedReq("POST", "/v1/orgs/personal/ensure", nil)); resp.StatusCode != http.StatusNotFound {
		t.Errorf("slash alias status=%d, want 404", resp.StatusCode)
	}
	if n := countRows(t, h, `SELECT count(*) FROM orgs WHERE created_by=$1::uuid`, c.accountID); n != 0 {
		t.Fatalf("refused calls created %d orgs", n)
	}
}

// personalDetail is the console's org detail body, the fields this test reads.
type personalDetail struct {
	Org struct {
		OrgID       string `json:"org_id"`
		Slug        string `json:"slug"`
		DisplayName string `json:"display_name"`
		Kind        string `json:"kind"`
		Status      string `json:"status"`
		Tenancy     string `json:"tenancy"`
		ConsoleRole string `json:"console_role"`
		Host        string `json:"host"`
	} `json:"org"`
	Can struct {
		Checkout bool `json:"checkout"`
	} `json:"can"`
}

func TestPortalEnsurePersonalOrg(t *testing.T) {
	h := newPlaneHarness(t, api.PersonalPlaneServing)
	pc := h.portalLogin(t, "ind-portal-dana")

	if resp := orgReq(t, pc, "POST", "/portal/api/orgs/personal", nil, "", ""); resp.StatusCode != http.StatusForbidden || errCode(t, resp) != "csrf_failed" {
		t.Fatalf("no CSRF: want 403 csrf_failed")
	}
	if resp := orgReq(t, pc, "POST", "/portal/api/orgs/personal", nil, pc.csrf, "https://evil.example.test"); resp.StatusCode != http.StatusForbidden || errCode(t, resp) != "origin_mismatch" {
		t.Fatalf("foreign Origin: want 403 origin_mismatch")
	}
	if resp, err := http.Post(h.srv.URL+"/portal/api/orgs/personal", "application/json", nil); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("signed out: want 401 (err %v)", err)
	}

	resp := orgReq(t, pc, "POST", "/portal/api/orgs/personal", nil, pc.csrf, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first ensure status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var d personalDetail
	decode(t, resp, &d)
	if d.Org.Kind != "personal" || d.Org.Tenancy != "individual" || d.Org.DisplayName != "Personal" || d.Org.ConsoleRole != "owner" ||
		d.Org.Status != "provisioning" || d.Org.Host != d.Org.Slug+"."+orgsTenantDomain || d.Can.Checkout {
		t.Fatalf("ensured org = %+v", d)
	}
	resp = orgReq(t, pc, "POST", "/portal/api/orgs/personal", nil, pc.csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second ensure status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var d2 personalDetail
	decode(t, resp, &d2)
	if d2.Org.OrgID != d.Org.OrgID {
		t.Fatalf("second ensure answered %s, want %s", d2.Org.OrgID, d.Org.OrgID)
	}
	// The device trigger finds the same org.
	c := h.login(t, "ind-portal-dana")
	if e := ensureDevicePersonal(t, c, http.StatusOK); e.Org.OrgID != d.Org.OrgID {
		t.Fatalf("device ensure answered %s, want the console's %s", e.Org.OrgID, d.Org.OrgID)
	}
	if n := countRows(t, h, `SELECT count(*) FROM org_members WHERE org_id=$1::uuid`, d.Org.OrgID); n != 1 {
		t.Fatalf("personal org members = %d", n)
	}
	// The team cap is untouched: the list reports zero team orgs used.
	lresp := pc.get("/portal/api/orgs")
	var list struct {
		TeamOrgs struct {
			Used int `json:"used"`
		} `json:"team_orgs"`
	}
	decode(t, lresp, &list)
	if list.TeamOrgs.Used != 0 {
		t.Fatalf("team orgs used = %d after a personal ensure, want 0", list.TeamOrgs.Used)
	}
	// The audit row is written.
	if n := countRows(t, h, `SELECT count(*) FROM security_audit_events WHERE event_type='portal_personal_org_ensured'`); n != 2 {
		t.Fatalf("portal_personal_org_ensured audit rows = %d, want 2", n)
	}
}
