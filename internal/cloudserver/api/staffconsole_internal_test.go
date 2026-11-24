package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// staffconsole_internal_test.go covers the staff console's read routes, the
// feature probe, the filtered log, the SPA mount and the staff CSP
// (staffconsole.go), with the in-memory staff store plus a console fake.

const staffTestOrg = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

// memConsoleStore adds the console reads to the in-memory staff store.
type memConsoleStore struct {
	*memStaffStore
	mu         sync.Mutex
	orgs       []store.StaffOrg
	doc        *store.StaffSignedDoc
	lastFilter *store.StaffActionFilter
}

func (m *memConsoleStore) ListStaffOrgs(context.Context) ([]store.StaffOrg, error) {
	return append([]store.StaffOrg{}, m.orgs...), nil
}

func (m *memConsoleStore) StaffOrgDetail(_ context.Context, id string) (store.StaffOrgDetail, error) {
	for _, o := range m.orgs {
		if o.OrgID == id {
			return store.StaffOrgDetail{Org: o, Grants: []store.StaffOrgGrantRow{}, Usage: []store.StaffOrgUsageDay{}, Intents: []store.StaffOrgIntent{}}, nil
		}
	}
	return store.StaffOrgDetail{}, store.ErrNotFound
}

func (m *memConsoleStore) StaffAvailabilityDocument(context.Context) (store.StaffSignedDoc, error) {
	if m.doc == nil {
		return store.StaffSignedDoc{}, store.ErrNotFound
	}
	return *m.doc, nil
}

func (m *memConsoleStore) ListStaffActionsFiltered(_ context.Context, f store.StaffActionFilter) ([]store.StaffAction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastFilter = &f
	return []store.StaffAction{{Verb: "support.signin", Reason: "filtered"}}, nil
}

// consoleHarness is a staff harness on a console store with one support
// staff member signed in.
func consoleHarness(t *testing.T, role staffauth.Role) (*staffHarness, *memConsoleStore, *http.Cookie) {
	t.Helper()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	cs := &memConsoleStore{memStaffStore: h.mem, orgs: []store.StaffOrg{{OrgID: staffTestOrg, Kind: "team", Slug: "acme", Status: "active", Members: 3}}}
	h.srv.staff.db = cs
	auth := NewStaffTestAuthenticator(9)
	h.register(staffTestSupp, role, auth)
	sess, _ := h.signIn(staffTestSupp, auth, nil)
	return h, cs, sess
}

func TestStaffConsoleOrgReads(t *testing.T) {
	t.Parallel()
	h, cs, sess := consoleHarness(t, staffauth.RoleSupport)
	get := func(path string) (int, map[string]json.RawMessage) {
		rec := h.do(staffReq{method: "GET", path: path, cookies: []*http.Cookie{sess}})
		var body map[string]json.RawMessage
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	code, body := get("/staff/api/orgs")
	if code != http.StatusOK || !strings.Contains(string(body["orgs"]), `"slug":"acme"`) {
		t.Fatalf("orgs = %d %s", code, body["orgs"])
	}
	if code, body = get("/staff/api/orgs/" + staffTestOrg); code != http.StatusOK || !strings.Contains(string(body["org"]), staffTestOrg) {
		t.Fatalf("org = %d %v", code, body)
	}
	if code, _ = get("/staff/api/orgs/00000000-0000-4000-8000-000000000000"); code != http.StatusNotFound {
		t.Errorf("unknown org = %d, want 404", code)
	}
	if code, body = get("/staff/api/availability/document"); code != http.StatusOK || string(body["document"]) != "null" {
		t.Errorf("no envelope = %d %s, want a null document", code, body["document"])
	}
	cs.doc = &store.StaffSignedDoc{Version: 4, KeyID: "k", IssuedBy: "system", Body: json.RawMessage(`{"org_controls":[]}`)}
	if code, body = get("/staff/api/availability/document"); code != http.StatusOK || !strings.Contains(string(body["document"]), `"version":4`) {
		t.Errorf("envelope = %d %s", code, body["document"])
	}
	// No session: refused.
	if rec := h.do(staffReq{method: "GET", path: "/staff/api/orgs"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("orgs without a session = %d, want 401", rec.Code)
	}
}

func TestStaffConsoleFeatures(t *testing.T) {
	t.Parallel()
	h, _, sess := consoleHarness(t, staffauth.RoleSupport)
	rec := h.do(staffReq{method: "GET", path: "/staff/api/features", cookies: []*http.Cookie{sess}})
	if rec.Code != http.StatusOK {
		t.Fatalf("features = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Features     map[string]bool        `json:"features"`
		Capabilities []staffauth.Capability `json:"capabilities"`
		Fresh        int                    `json:"fresh_window_seconds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"orgs": true, "availability_document": true,
		"support_signin": false, // no issuer configured
		// w17/portal-guardrails and w17/deletion-purge mount these routes.
		"team_allowlist": true, "deletion_queue": true,
		"plan_grant_write": false, // no route until a ruling adds one (W15-D13)
	}
	for k, v := range want {
		if got, ok := out.Features[k]; !ok || got != v {
			t.Errorf("feature %s = %v (present %v), want %v", k, got, ok, v)
		}
	}
	if len(out.Features) != len(staffFeatures) {
		t.Errorf("features = %v, want exactly the table's %d", out.Features, len(staffFeatures))
	}
	if out.Fresh != int(staffauth.FreshAssertionWindow/time.Second) {
		t.Errorf("fresh window = %d", out.Fresh)
	}
	for _, c := range out.Capabilities {
		if c.Action == staffauth.ActionWriteAvailability && c.Permitted {
			t.Error("support is shown as able to write availability")
		}
	}
}

// TestStaffConsoleNeedsConsoleStore: a staff store without the console reads
// answers 501 and the probe says the screens are off.
func TestStaffConsoleNeedsConsoleStore(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	auth := NewStaffTestAuthenticator(3)
	h.register(staffTestOps, staffauth.RoleOps, auth)
	sess, _ := h.signIn(staffTestOps, auth, nil)
	if rec := h.do(staffReq{method: "GET", path: "/staff/api/orgs", cookies: []*http.Cookie{sess}}); rec.Code != http.StatusNotImplemented {
		t.Errorf("orgs on a plain store = %d, want 501", rec.Code)
	}
	rec := h.do(staffReq{method: "GET", path: "/staff/api/features", cookies: []*http.Cookie{sess}})
	if !strings.Contains(rec.Body.String(), `"orgs":false`) {
		t.Errorf("features on a plain store = %s", rec.Body)
	}
	// The log still reads, unfiltered, and ignores the filters it cannot apply.
	if rec := h.do(staffReq{method: "GET", path: "/staff/api/log?verb=x", cookies: []*http.Cookie{sess}}); rec.Code != http.StatusOK {
		t.Errorf("log on a plain store = %d", rec.Code)
	}
}

func TestStaffConsoleLogFilters(t *testing.T) {
	t.Parallel()
	h, cs, sess := consoleHarness(t, staffauth.RoleSupport)
	rec := h.do(staffReq{method: "GET", path: "/staff/api/log?limit=20&org=" + staffTestOrg + "&verb=support.signin&before=2026-11-13T09:00:00Z", cookies: []*http.Cookie{sess}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "filtered") {
		t.Fatalf("filtered log = %d %s", rec.Code, rec.Body)
	}
	f := cs.lastFilter
	if f == nil || f.Limit != 20 || f.OrgID != staffTestOrg || f.Verb != "support.signin" || !f.Before.Equal(time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("filter = %+v", f)
	}
	cs.lastFilter = nil
	if rec := h.do(staffReq{method: "GET", path: "/staff/api/log", cookies: []*http.Cookie{sess}}); rec.Code != http.StatusOK || cs.lastFilter != nil {
		t.Errorf("unfiltered log took the filtered path: %d %+v", rec.Code, cs.lastFilter)
	}
	if rec := h.do(staffReq{method: "GET", path: "/staff/api/log?before=yesterday", cookies: []*http.Cookie{sess}}); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed before = %d, want 400", rec.Code)
	}
}

func TestStaffConsoleSPAAndCSP(t *testing.T) {
	t.Parallel()
	h := newStaffHarness(t, StaffTestVerifier{}, "")
	h.srv.staff.spa = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("staff-spa:" + r.URL.Path))
	})
	h.staff = h.srv.StaffHandler()
	cases := []struct {
		path     string
		code     int
		body     string
		location string
	}{
		{"/staff/", http.StatusOK, "staff-spa:/", ""},
		{"/staff/orgs/" + staffTestOrg, http.StatusOK, "staff-spa:/orgs/" + staffTestOrg, ""},
		{"/staff/assets/app.js", http.StatusOK, "staff-spa:/assets/app.js", ""},
		{"/staff/api/nope", http.StatusNotFound, "not_found", ""},
		{"/staff/auth/nope", http.StatusNotFound, "not_found", ""},
		{"/staff", http.StatusFound, "", "/staff/"},
	}
	onStaff := func(handler http.Handler, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "https://app.example"+path, http.NoBody))
		return rec
	}
	for _, c := range cases {
		rec := onStaff(h.staff, c.path)
		if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.body) || rec.Header().Get("Location") != c.location {
			t.Errorf("%s = %d %q loc=%q, want %d %q loc=%q", c.path, rec.Code, rec.Body, rec.Header().Get("Location"), c.code, c.body, c.location)
		}
		if got := rec.Header().Get("Content-Security-Policy"); got != staffCSP {
			t.Errorf("%s CSP = %q, want the staff policy", c.path, got)
		}
		if got := rec.Header().Get("Permissions-Policy"); got != staffPermissionsPolicy || strings.Contains(got, "paddle") {
			t.Errorf("%s Permissions-Policy = %q, want the staff policy (SC-8)", c.path, got)
		}
	}
	if strings.Contains(staffCSP, "paddle") || strings.Contains(staffCSP, "profitwell") {
		t.Error("the staff CSP allows a billing host")
	}
	// The root of the staff host redirects to the console.
	rec := onStaff(h.staff, "/")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/staff/" {
		t.Errorf("/ = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	// The customer handler never serves the staff SPA.
	if rec := onStaff(h.cust, "/staff/"); strings.Contains(rec.Body.String(), "staff-spa") {
		t.Error("the customer handler served the staff SPA")
	}
}
