package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgenrol"
)

// fakeEnrolManager records calls and answers from canned values; it never
// touches a network or a file.
type fakeEnrolManager struct {
	enrolReqs []EnrolRequest
	decisions []bool
	enrolErr  error
	pushErr   error
	leaves    int
	// shares records each ShareHistory call's confirm flag.
	shares []bool
	// resyncs records each Resync call's confirm flag.
	resyncs []bool
	// enrolled makes Overview report an existing enrolment.
	enrolled bool
	// leaveOpts / idpOpts record the switch options each call carried;
	// leaveErr makes Leave fail.
	leaveOpts []SwitchOptions
	idpOpts   []SwitchOptions
	leaveErr  error
}

func (f *fakeEnrolManager) Overview(context.Context) (EnrolmentOverview, error) {
	return EnrolmentOverview{Enrolled: f.enrolled, CredentialStore: "file"}, nil
}

func (f *fakeEnrolManager) Probe(_ context.Context, u string) (EnrolProbe, error) {
	if _, err := orgenrol.NormalizeServerURL(u); err != nil {
		return EnrolProbe{}, err
	}
	return EnrolProbe{OrgURL: u, OK: true}, nil
}

func (f *fakeEnrolManager) Enrol(_ context.Context, req EnrolRequest) (EnrolOutcome, error) {
	f.enrolReqs = append(f.enrolReqs, req)
	if f.enrolErr != nil {
		return EnrolOutcome{}, f.enrolErr
	}
	return EnrolOutcome{OrgID: "org-1", Tenancy: "individual", PendingGrant: &PendingGrant{OfferID: "o1"}}, nil
}

func (f *fakeEnrolManager) DecideGrant(_ context.Context, id string, accept bool) (GrantDecision, error) {
	if id != "o1" {
		return GrantDecision{}, orgenrol.Fail(orgenrol.CodeGone, "gone")
	}
	f.decisions = append(f.decisions, accept)
	if accept {
		return GrantDecision{Status: "accepted"}, nil
	}
	return GrantDecision{Status: "declined"}, nil
}

func (f *fakeEnrolManager) StartIdP(_ context.Context, _ string, opts SwitchOptions) (IdPStart, error) {
	f.idpOpts = append(f.idpOpts, opts)
	return IdPStart{FlowID: "f1", UserCode: "BCDF-2345"}, nil
}

func (f *fakeEnrolManager) PollIdP(_ context.Context, id string) (IdPPoll, error) {
	if id != "f1" {
		return IdPPoll{}, orgenrol.Fail(orgenrol.CodeGone, "gone")
	}
	return IdPPoll{Status: "approved", Outcome: &EnrolOutcome{OrgID: "org-1", Tenancy: "managed"}}, nil
}

func (f *fakeEnrolManager) GrantReport(context.Context) (GrantReport, error) {
	return GrantReport{State: "ungoverned"}, nil
}

func (f *fakeEnrolManager) PushNow(context.Context) (PushNowReport, error) {
	if f.pushErr != nil {
		return PushNowReport{}, f.pushErr
	}
	return PushNowReport{RowCount: 3, Message: "Pushed 3 rows"}, nil
}

func (f *fakeEnrolManager) ShareHistory(_ context.Context, confirm bool) (ShareHistoryReport, error) {
	f.shares = append(f.shares, confirm)
	return ShareHistoryReport{Eligible: 0, WouldUnlock: 42, Total: 42, Rewound: confirm}, nil
}

func (f *fakeEnrolManager) Resync(_ context.Context, confirm bool) (ResyncReport, error) {
	f.resyncs = append(f.resyncs, confirm)
	return ResyncReport{WindowDays: 30, Limit: 20000, Tables: []ResyncTable{{Table: "sessions", Queued: 7}}, Queued: 7, Manifests: 2, Confirmed: confirm}, nil
}

func (f *fakeEnrolManager) Leave(_ context.Context, opts SwitchOptions) (LeaveReport, error) {
	f.leaves++
	f.leaveOpts = append(f.leaveOpts, opts)
	if f.leaveErr != nil {
		return LeaveReport{}, f.leaveErr
	}
	return LeaveReport{WasEnrolled: true, OrgName: "Acme"}, nil
}

func enrolServer(t *testing.T, m EnrolmentManager) *Server {
	t.Helper()
	dir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(dir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	opts := Options{DB: database, ConfigPath: filepath.Join(dir, "config.toml")}
	if m != nil {
		opts.EnrolManager = m
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func enrolToken(t *testing.T, s *Server) (string, *http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/enrolment/manage", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("manage status %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Token    string            `json:"confirm_token"`
		Overview EnrolmentOverview `json:"overview"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Token == "" || body.Overview.CredentialStore != "file" {
		t.Fatalf("manage body %+v", body)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			return body.Token, c
		}
	}
	t.Fatal("no confirm cookie")
	return "", nil
}

func enrolPost(s *Server, path, body, token string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(remoteConfirmHeader, token)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

var enrolWriteRoutes = []string{
	"/api/enrolment/probe",
	"/api/enrolment/enrol",
	"/api/enrolment/grant-decision",
	"/api/enrolment/idp/start",
	"/api/enrolment/idp/poll",
	"/api/enrolment/push-now",
	"/api/enrolment/share-history",
	"/api/enrolment/resync",
	"/api/enrolment/leave",
	// The legacy alias of leave (Sol A3-02): same confirm token, same path.
	"/api/enrolment/unenroll",
}

// TestEnrolmentManageRoutesAreLocalOnly pins the route classification: every
// management route writes this machine's config/keychain or spends an
// enrolment code, so none may be remote-drivable.
func TestEnrolmentManageRoutesAreLocalOnly(t *testing.T) {
	s := enrolServer(t, &fakeEnrolManager{})
	_, capMap, _ := s.registerRoutes(nil)
	for _, p := range append([]string{"/api/enrolment/manage", "/api/enrolment/grant"}, enrolWriteRoutes...) {
		got, ok := capMap[p]
		if !ok {
			t.Fatalf("%s is not registered", p)
		}
		if got != CapabilityLocal {
			t.Errorf("%s capability = %v, want CapabilityLocal", p, got)
		}
	}
	// Contrast pin: the read-only status stays View for paired viewers.
	if got := capMap["/api/enrolment/status"]; got != CapabilityView {
		t.Errorf("/api/enrolment/status capability = %v, want CapabilityView", got)
	}
}

// TestEnrolmentWritesRequireConfirmToken: every write refuses a missing or
// mismatched token (403), a non-JSON body (415) and a non-POST (405) before
// the manager is reached.
func TestEnrolmentWritesRequireConfirmToken(t *testing.T) {
	m := &fakeEnrolManager{}
	s := enrolServer(t, m)
	tok, ck := enrolToken(t, s)
	for _, p := range enrolWriteRoutes {
		if rr := enrolPost(s, p, `{}`, "", nil); rr.Code != http.StatusForbidden {
			t.Errorf("%s without token = %d, want 403", p, rr.Code)
		}
		if rr := enrolPost(s, p, `{}`, "wrong", ck); rr.Code != http.StatusForbidden {
			t.Errorf("%s with mismatched token = %d, want 403", p, rr.Code)
		}
		req := httptest.NewRequest(http.MethodPost, p, strings.NewReader("x"))
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set(remoteConfirmHeader, tok)
		req.AddCookie(ck)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%s with text/plain = %d, want 415", p, rr.Code)
		}
		get := httptest.NewRecorder()
		s.Handler().ServeHTTP(get, httptest.NewRequest(http.MethodGet, p, nil))
		if get.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", p, get.Code)
		}
	}
	if len(m.enrolReqs) != 0 || m.leaves != 0 || len(m.shares) != 0 || len(m.resyncs) != 0 {
		t.Fatalf("a refused request reached the manager: %+v", m)
	}
}

// TestEnrolmentEnrolFlow drives enrol -> grant decision -> push-now -> leave
// with a valid token, and checks the input validation that runs before the
// manager.
func TestEnrolmentEnrolFlow(t *testing.T) {
	m := &fakeEnrolManager{}
	s := enrolServer(t, m)
	tok, ck := enrolToken(t, s)

	if rr := enrolPost(s, "/api/enrolment/enrol", `{"method":"carrier-pigeon"}`, tok, ck); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown method = %d, want 400 (%s)", rr.Code, rr.Body.String())
	}
	if rr := enrolPost(s, "/api/enrolment/enrol", `not json`, tok, ck); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON = %d, want 400", rr.Code)
	}
	if len(m.enrolReqs) != 0 {
		t.Fatal("invalid input reached the manager")
	}

	rr := enrolPost(s, "/api/enrolment/enrol", `{"method":"code","org_url":"https://org.example","token":"id.secret"}`, tok, ck)
	if rr.Code != http.StatusOK {
		t.Fatalf("enrol = %d %s", rr.Code, rr.Body.String())
	}
	var out EnrolOutcome
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil || out.PendingGrant == nil || out.PendingGrant.OfferID != "o1" {
		t.Fatalf("enrol outcome = %+v (%v)", out, err)
	}
	if strings.Contains(rr.Body.String(), "id.secret") {
		t.Fatal("the enrolment token was echoed back")
	}

	if rr := enrolPost(s, "/api/enrolment/grant-decision", `{"accept":true}`, tok, ck); rr.Code != http.StatusBadRequest {
		t.Fatalf("decision without offer_id = %d, want 400", rr.Code)
	}
	if rr := enrolPost(s, "/api/enrolment/grant-decision", `{"offer_id":"nope","accept":true}`, tok, ck); rr.Code != http.StatusGone {
		t.Fatalf("unknown offer = %d, want 410", rr.Code)
	}
	if rr := enrolPost(s, "/api/enrolment/grant-decision", `{"offer_id":"o1","accept":true}`, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("decision = %d %s", rr.Code, rr.Body.String())
	}
	if len(m.decisions) != 1 || !m.decisions[0] {
		t.Fatalf("decisions = %v", m.decisions)
	}

	if rr := enrolPost(s, "/api/enrolment/push-now", `{}`, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("push-now = %d %s", rr.Code, rr.Body.String())
	}
	if rr := enrolPost(s, "/api/enrolment/leave", `{}`, tok, ck); rr.Code != http.StatusOK || m.leaves != 1 {
		t.Fatalf("leave = %d leaves=%d", rr.Code, m.leaves)
	}
	if rr := enrolPost(s, "/api/enrolment/idp/poll", `{"flow_id":"f1"}`, tok, ck); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"approved"`) {
		t.Fatalf("idp poll = %d %s", rr.Code, rr.Body.String())
	}
}

// TestEnrolFailureStatusCoversEveryCode: every orgenrol code maps to a
// status, and the handler writes {error, message} with it.
func TestEnrolFailureStatusCoversEveryCode(t *testing.T) {
	for _, code := range orgenrol.AllCodes {
		status, ok := enrolFailureStatus[code]
		if !ok {
			t.Errorf("code %q has no HTTP status row", code)
			continue
		}
		if status == http.StatusUnauthorized {
			t.Errorf("code %q maps to 401, which the SPA reads as a lost session", code)
		}
		m := &fakeEnrolManager{enrolErr: orgenrol.Fail(code, "msg for %s", code)}
		s := enrolServer(t, m)
		tok, ck := enrolToken(t, s)
		rr := enrolPost(s, "/api/enrolment/enrol", `{"method":"code"}`, tok, ck)
		if rr.Code != status {
			t.Errorf("code %q -> HTTP %d, want %d", code, rr.Code, status)
		}
		var body map[string]string
		_ = json.NewDecoder(rr.Body).Decode(&body)
		if body["error"] != string(code) || !strings.Contains(body["message"], "msg for") {
			t.Errorf("code %q body = %v", code, body)
		}
	}
	// An unclassified error is a 500, not a guessed status.
	m := &fakeEnrolManager{pushErr: errors.New("boom")}
	s := enrolServer(t, m)
	tok, ck := enrolToken(t, s)
	if rr := enrolPost(s, "/api/enrolment/push-now", `{}`, tok, ck); rr.Code != http.StatusInternalServerError {
		t.Errorf("unclassified error = %d, want 500", rr.Code)
	}
}

// TestEnrolmentManagerNotWired: without a manager the routes say so (501)
// instead of pretending.
func TestEnrolmentManagerNotWired(t *testing.T) {
	s := enrolServer(t, nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/enrolment/manage", nil))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("manage without manager = %d, want 501", rr.Code)
	}
}

func TestUTCStampNormalisesPushLogTime(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-10-03 04:34:02", "2026-10-03T04:34:02Z"},
		{"2026-10-03T04:34:02Z", "2026-10-03T04:34:02Z"},
		{"", ""},
		{"not a time", "not a time"},
	}
	for _, c := range cases {
		if got := utcStamp(c.in); got != c.want {
			t.Errorf("utcStamp(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestLegacyUnenrollRunsTheSharedLeave (Sol A3-02): the older
// /api/enrolment/unenroll route is an alias of /api/enrolment/leave. With a
// valid confirm token it runs EnrolManager.Leave (the CLI-aligned cleanup:
// proxy routes, org bundle, parked flows, identity invalidation), never
// OrgClient.Unenroll directly, and keeps its `unenrolled` answer for old
// callers.
func TestLegacyUnenrollRunsTheSharedLeave(t *testing.T) {
	m := &fakeEnrolManager{}
	s := enrolServer(t, m)
	tok, ck := enrolToken(t, s)
	rr := enrolPost(s, "/api/enrolment/unenroll", `{}`, tok, ck)
	if rr.Code != http.StatusOK {
		t.Fatalf("unenroll = %d %s", rr.Code, rr.Body.String())
	}
	if m.leaves != 1 {
		t.Fatalf("legacy unenroll ran Leave %d times, want 1", m.leaves)
	}
	var body struct {
		Unenrolled  bool   `json:"unenrolled"`
		WasEnrolled bool   `json:"was_enrolled"`
		OrgName     string `json:"org_name"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Unenrolled || !body.WasEnrolled || body.OrgName != "Acme" {
		t.Fatalf("unenroll body = %s", rr.Body.String())
	}
}

// TestEnrolmentShareHistory (T-159): Settings > Enrolment's Share history runs
// the manager's ShareHistory (the `observer org backfill --all` performer):
// a body without confirm is the dry run, {"confirm":true} rewinds.
func TestEnrolmentShareHistory(t *testing.T) {
	m := &fakeEnrolManager{}
	s := enrolServer(t, m)
	tok, ck := enrolToken(t, s)
	rr := enrolPost(s, "/api/enrolment/share-history", `{}`, tok, ck)
	if rr.Code != http.StatusOK {
		t.Fatalf("dry run = %d %s", rr.Code, rr.Body.String())
	}
	var dry ShareHistoryReport
	if err := json.NewDecoder(rr.Body).Decode(&dry); err != nil || dry.Rewound || dry.WouldUnlock != 42 {
		t.Fatalf("dry run body = %+v (%v)", dry, err)
	}
	rr = enrolPost(s, "/api/enrolment/share-history", `{"confirm":true}`, tok, ck)
	var done ShareHistoryReport
	if err := json.NewDecoder(rr.Body).Decode(&done); rr.Code != http.StatusOK || err != nil || !done.Rewound {
		t.Fatalf("confirm = %d %+v (%v)", rr.Code, done, err)
	}
	if len(m.shares) != 2 || m.shares[0] || !m.shares[1] {
		t.Fatalf("manager saw confirm flags %v, want [false true]", m.shares)
	}
	if rr := enrolPost(s, "/api/enrolment/share-history", `not json`, tok, ck); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON = %d, want 400", rr.Code)
	}
}

// manageAuditDetails returns the remote_audit details written for route.
func manageAuditDetails(t *testing.T, s *Server, route string) []string {
	t.Helper()
	rows, err := s.opts.DB.Query(`SELECT detail FROM remote_audit WHERE route = ? ORDER BY id`, route)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

// TestEnrolmentEnrolCases (T-642): the first-time enrol route against the
// four shapes the brief names. The enrolment code never lands in the audit
// detail or the response, whichever way the enrol ends.
func TestEnrolmentEnrolCases(t *testing.T) {
	const secret = "tok-id.very-secret-part"
	body := `{"method":"code","org_url":"https://org.example","token":"` + secret + `"}`
	cases := []struct {
		name       string
		m          *fakeEnrolManager
		noToken    bool
		wantStatus int
		wantAudit  string
		wantCalls  int
	}{
		{name: "happy", m: &fakeEnrolManager{}, wantStatus: http.StatusOK, wantAudit: "org_enrol method=code org_id=org-1 tenancy=individual grant_pending=true", wantCalls: 1},
		{
			name:       "bad token",
			m:          &fakeEnrolManager{enrolErr: orgenrol.Fail(orgenrol.CodeTokenRejected, "refused")},
			wantStatus: enrolFailureStatus[orgenrol.CodeTokenRejected],
			wantAudit:  "org_enrol_failed method=code code=token_rejected",
			wantCalls:  1,
		},
		// Already enrolled: the same route re-enrols (the page's Re-enrol
		// card posts here), exactly as `observer enroll` does on an enrolled
		// machine; it is not refused.
		{name: "already enrolled", m: &fakeEnrolManager{enrolled: true}, wantStatus: http.StatusOK, wantAudit: "org_enrol method=code org_id=org-1 tenancy=individual grant_pending=true", wantCalls: 1},
		{name: "confirm token missing", m: &fakeEnrolManager{}, noToken: true, wantStatus: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := enrolServer(t, tc.m)
			tok, ck := enrolToken(t, s)
			if tc.noToken {
				tok, ck = "", nil
			}
			rr := enrolPost(s, "/api/enrolment/enrol", body, tok, ck)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if len(tc.m.enrolReqs) != tc.wantCalls {
				t.Fatalf("manager saw %d enrol calls, want %d", len(tc.m.enrolReqs), tc.wantCalls)
			}
			if tc.wantCalls > 0 && tc.m.enrolReqs[0].Token != secret {
				t.Fatalf("manager got token %q, want the posted one", tc.m.enrolReqs[0].Token)
			}
			if strings.Contains(rr.Body.String(), "very-secret") {
				t.Fatal("the enrolment code was echoed in the response")
			}
			audit := manageAuditDetails(t, s, "/api/enrolment/enrol")
			for _, d := range audit {
				if strings.Contains(d, "very-secret") || strings.Contains(d, "tok-id") {
					t.Fatalf("the enrolment code reached the audit detail: %q", d)
				}
			}
			switch {
			case tc.wantAudit == "" && len(audit) != 0:
				t.Fatalf("a refused request was audited: %v", audit)
			case tc.wantAudit != "" && (len(audit) != 1 || audit[0] != tc.wantAudit):
				t.Fatalf("audit = %v, want [%q]", audit, tc.wantAudit)
			}
		})
	}
}

// TestEnrolmentResync (T-642): Settings > Enrolment's Re-send changed rows
// runs the manager's Resync (the `observer org resync` performer): a body
// without confirm is the dry run and writes no audit row; {"confirm":true}
// queues and is audited.
func TestEnrolmentResync(t *testing.T) {
	m := &fakeEnrolManager{}
	s := enrolServer(t, m)
	tok, ck := enrolToken(t, s)
	rr := enrolPost(s, "/api/enrolment/resync", `{}`, tok, ck)
	var dry ResyncReport
	if err := json.NewDecoder(rr.Body).Decode(&dry); rr.Code != http.StatusOK || err != nil || dry.Confirmed || dry.Queued != 7 {
		t.Fatalf("dry run = %d %+v (%v)", rr.Code, dry, err)
	}
	if got := manageAuditDetails(t, s, "/api/enrolment/resync"); len(got) != 0 {
		t.Fatalf("a dry run was audited: %v", got)
	}
	rr = enrolPost(s, "/api/enrolment/resync", `{"confirm":true}`, tok, ck)
	var done ResyncReport
	if err := json.NewDecoder(rr.Body).Decode(&done); rr.Code != http.StatusOK || err != nil || !done.Confirmed {
		t.Fatalf("confirm = %d %+v (%v)", rr.Code, done, err)
	}
	if got := manageAuditDetails(t, s, "/api/enrolment/resync"); len(got) != 1 || got[0] != "org_resync queued=7 manifests=2 window_days=30" {
		t.Fatalf("audit = %v", got)
	}
	if len(m.resyncs) != 2 || m.resyncs[0] || !m.resyncs[1] {
		t.Fatalf("manager saw confirm flags %v, want [false true]", m.resyncs)
	}
	if rr := enrolPost(s, "/api/enrolment/resync", `not json`, tok, ck); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON = %d, want 400", rr.Code)
	}
}

// TestEnrolmentUnsentRowsConfirmPath pins the R3-78 confirm step's wire: a
// switch refused because rows for the current organization could not be sent
// answers 409 {error: unsent_rows, message}, and the explicit "Switch anyway"
// / "Leave anyway" reach the manager as drop_unsent on enrol, sign-in start
// and leave (whose body stays optional for the older unenroll alias).
func TestEnrolmentUnsentRowsConfirmPath(t *testing.T) {
	m := &fakeEnrolManager{enrolErr: orgenrol.Fail(orgenrol.CodeUnsentRows, "Not switched: 6 rows captured for Acme have not been sent to it yet")}
	s := enrolServer(t, m)
	tok, ck := enrolToken(t, s)

	rr := enrolPost(s, "/api/enrolment/enrol", `{"method":"code","org_url":"https://org.example","token":"id.secret"}`, tok, ck)
	if rr.Code != http.StatusConflict {
		t.Fatalf("refused switch = %d, want 409 (%s)", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "unsent_rows" || !strings.Contains(body["message"], "6 rows") {
		t.Fatalf("refusal body = %+v", body)
	}
	m.enrolErr = nil
	if rr := enrolPost(s, "/api/enrolment/enrol", `{"method":"code","org_url":"https://org.example","token":"id.secret","drop_unsent":true}`, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("switch anyway = %d %s", rr.Code, rr.Body.String())
	}
	if n := len(m.enrolReqs); n != 2 || m.enrolReqs[0].DropUnsent || !m.enrolReqs[1].DropUnsent {
		t.Fatalf("enrol requests = %+v, want refused then drop_unsent", m.enrolReqs)
	}

	if rr := enrolPost(s, "/api/enrolment/idp/start", `{"org_url":"https://org.example","drop_unsent":true}`, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("idp start = %d %s", rr.Code, rr.Body.String())
	}
	if len(m.idpOpts) != 1 || !m.idpOpts[0].DropUnsent {
		t.Fatalf("idp start options = %+v", m.idpOpts)
	}

	m.leaveErr = orgenrol.Fail(orgenrol.CodeUnsentRows, "Did not leave: 4 rows")
	if rr := enrolPost(s, "/api/enrolment/leave", `{}`, tok, ck); rr.Code != http.StatusConflict {
		t.Fatalf("refused leave = %d, want 409", rr.Code)
	}
	m.leaveErr = nil
	if rr := enrolPost(s, "/api/enrolment/leave", `{"drop_unsent":true}`, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("leave anyway = %d %s", rr.Code, rr.Body.String())
	}
	if rr := enrolPost(s, "/api/enrolment/unenroll", ``, tok, ck); rr.Code != http.StatusOK {
		t.Fatalf("legacy unenroll with no body = %d %s", rr.Code, rr.Body.String())
	}
	if rr := enrolPost(s, "/api/enrolment/leave", `not json`, tok, ck); rr.Code != http.StatusBadRequest {
		t.Fatalf("leave with a bad body = %d, want 400", rr.Code)
	}
	want := []bool{false, true, false}
	if len(m.leaveOpts) != len(want) {
		t.Fatalf("leave options = %+v, want %d calls", m.leaveOpts, len(want))
	}
	for i, w := range want {
		if m.leaveOpts[i].DropUnsent != w {
			t.Errorf("leave call %d drop_unsent = %v, want %v", i, m.leaveOpts[i].DropUnsent, w)
		}
	}
}
