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
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeEnrolment is a test double for the EnrolmentService interface.
type fakeEnrolment struct {
	state       orgclient.EnrolmentState
	statusErr   error
	payload     []byte
	unenrolled  bool
	unenrollErr error
	// invite scripting
	invite      orgclient.InviteToken
	inviteErr   error
	inviteEmail string
	inviteTTL   int
	inviteCalls int
}

func (f *fakeEnrolment) MintInviteToken(_ context.Context, email string, ttlDays int) (orgclient.InviteToken, error) {
	f.inviteCalls++
	f.inviteEmail, f.inviteTTL = email, ttlDays
	if f.inviteErr != nil {
		return orgclient.InviteToken{}, f.inviteErr
	}
	return f.invite, nil
}

func (f *fakeEnrolment) Status(context.Context) (orgclient.EnrolmentState, error) {
	return f.state, f.statusErr
}
func (f *fakeEnrolment) LastPayload(context.Context) ([]byte, error) { return f.payload, nil }
func (f *fakeEnrolment) Unenroll(context.Context) error {
	if f.unenrollErr != nil {
		return f.unenrollErr
	}
	f.unenrolled = true
	return nil
}

func newEnrolmentServer(t *testing.T, oc EnrolmentService) *Server {
	t.Helper()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	srv, err := New(Options{DB: database, OrgClient: oc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func TestEnrolmentStatus_OrgModeOff(t *testing.T) {
	srv := newEnrolmentServer(t, nil) // nil OrgClient = solo-local
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enrolment/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status code=%d", rec.Code)
	}
	var resp enrolmentStatusResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Enrolled {
		t.Errorf("solo-local should report enrolled=false, got %+v", resp)
	}

	// last-payload returns the JSON literal null.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enrolment/last-payload", nil))
	if got := rec.Body.String(); got != "null" {
		t.Errorf("last-payload (off) = %q, want null", got)
	}

	// unenroll is a no-op.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/enrolment/unenroll", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("unenroll (off) code=%d", rec.Code)
	}
}

func TestEnrolmentStatus_Enrolled(t *testing.T) {
	fake := &fakeEnrolment{
		state: orgclient.EnrolmentState{
			Enrolled: true, OrgID: "org-1", OrgName: "Acme", OrgServerURL: "https://org.acme.example",
			UserEmail: "dev@acme.example", EnrolledAt: "2026-05-26T10:00:00Z", Backend: "keychain",
			LastPush: &store.PushLogEntry{PushedAt: "2026-05-26T10:05:00Z", Status: "ok", RowCount: 12, Bytes: 480},
		},
		payload: []byte(`{"agent_version":"test","sessions":[]}`),
	}
	srv := newEnrolmentServer(t, fake)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enrolment/status", nil))
	var resp enrolmentStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Enrolled || resp.OrgName != "Acme" || resp.UserEmail != "dev@acme.example" || resp.CredentialStore != "keychain" {
		t.Fatalf("status = %+v", resp)
	}
	if resp.LastPush == nil || resp.LastPush.Status != "ok" || resp.LastPush.RowCount != 12 {
		t.Fatalf("last_push = %+v", resp.LastPush)
	}

	// last-payload is served byte-for-byte.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enrolment/last-payload", nil))
	if got := rec.Body.String(); got != string(fake.payload) {
		t.Errorf("last-payload = %q, want %q", got, fake.payload)
	}

	// unenroll calls through.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/enrolment/unenroll", nil))
	if rec.Code != http.StatusOK || !fake.unenrolled {
		t.Errorf("unenroll code=%d unenrolled=%v", rec.Code, fake.unenrolled)
	}
}

// A Status error is a 500 isolated to this endpoint — other endpoints still
// serve normally (P1: an org failure never breaks the host dashboard).
func TestEnrolmentStatus_ErrorIsolated(t *testing.T) {
	fake := &fakeEnrolment{statusErr: errors.New("keychain locked")}
	srv := newEnrolmentServer(t, fake)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enrolment/status", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status (err) code=%d, want 500", rec.Code)
	}

	// An unrelated endpoint is unaffected.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/api/status code=%d after enrolment 500, want 200", rec.Code)
	}
}

func TestEnrolmentUnenroll_MethodNotAllowed(t *testing.T) {
	srv := newEnrolmentServer(t, &fakeEnrolment{})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enrolment/unenroll", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET unenroll code=%d, want 405", rec.Code)
	}
}

// invitePost issues POST /api/enrolment/invite with the given JSON body.
func invitePost(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/enrolment/invite",
		strings.NewReader(body)))
	return rec
}

// TestEnrolmentInvite_Happy covers the loop-closing nudge: the handler proxies
// to the orgclient seam and returns a paste-ready enroll command.
func TestEnrolmentInvite_Happy(t *testing.T) {
	fake := &fakeEnrolment{
		state: orgclient.EnrolmentState{Enrolled: true, OrgServerURL: "https://org.acme.example"},
		invite: orgclient.InviteToken{
			Token: "tid.secret", TokenID: "tid", UserEmail: "mate@acme.example",
			ExpiresAt: "2026-08-07T00:00:00Z", OrgServerURL: "https://org.acme.example",
			MintedMonth: 2, MonthlyCap: 10,
		},
	}
	srv := newEnrolmentServer(t, fake)

	rec := invitePost(t, srv, `{"email":"mate@acme.example","ttl_days":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp inviteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token != "tid.secret" || resp.UserEmail != "mate@acme.example" {
		t.Fatalf("resp = %+v", resp)
	}
	if want := "observer enroll https://org.acme.example tid.secret"; resp.Command != want {
		t.Errorf("command = %q, want %q", resp.Command, want)
	}
	if resp.MintedMonth != 2 || resp.MonthlyCap != 10 {
		t.Errorf("cap counters = %d/%d, want 2/10", resp.MintedMonth, resp.MonthlyCap)
	}
	if fake.inviteEmail != "mate@acme.example" || fake.inviteTTL != 3 {
		t.Errorf("seam called with (%q, %d)", fake.inviteEmail, fake.inviteTTL)
	}
	// The one-time token must not be cached by a proxy or the browser.
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (the body carries a live credential)", got)
	}
}

// TestEnrolmentInvite_OrgModeOff pins the not-enrolled answer: 409 with an
// honest pointer, and NO call into the seam.
func TestEnrolmentInvite_OrgModeOff(t *testing.T) {
	srv := newEnrolmentServer(t, nil) // solo-local
	rec := invitePost(t, srv, `{"email":"mate@acme.example"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("code=%d body=%s, want 409", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_enrolled") {
		t.Errorf("body = %s, want a not_enrolled code", rec.Body.String())
	}
}

// TestEnrolmentInvite_RefusalsAreDistinct pins that each org-server refusal
// keeps its own status + code all the way to the UI, so the dashboard copy can
// name the actual cause (honest-disabled-copy rule) instead of a generic 500.
func TestEnrolmentInvite_RefusalsAreDistinct(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{"not enrolled", orgclient.ErrNotEnrolled, http.StatusConflict, "not_enrolled"},
		{"org disallows", orgclient.ErrInvitesDisabled, http.StatusForbidden, "member_invites"},
		{"unknown teammate", orgclient.ErrInviteTargetUnknown, http.StatusNotFound, "not_found"},
		{"cap reached", orgclient.ErrInviteCapReached, http.StatusTooManyRequests, "invite_cap_reached"},
		{"unexpected", errors.New("boom"), http.StatusInternalServerError, "boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newEnrolmentServer(t, &fakeEnrolment{inviteErr: tt.err})
			rec := invitePost(t, srv, `{"email":"mate@acme.example"}`)
			if rec.Code != tt.wantCode {
				t.Fatalf("code=%d body=%s, want %d", rec.Code, rec.Body.String(), tt.wantCode)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %s, want it to mention %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

// TestEnrolmentInvite_BadRequests pins the local validation: a non-POST is
// 405, a broken body is 400, and an empty email never reaches the org server.
func TestEnrolmentInvite_BadRequests(t *testing.T) {
	fake := &fakeEnrolment{}
	srv := newEnrolmentServer(t, fake)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enrolment/invite", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET invite code=%d, want 405", rec.Code)
	}

	if rec := invitePost(t, srv, `not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON code=%d, want 400", rec.Code)
	}
	if rec := invitePost(t, srv, `{"email":"   "}`); rec.Code != http.StatusBadRequest {
		t.Errorf("empty email code=%d, want 400", rec.Code)
	}
	if fake.inviteCalls != 0 {
		t.Errorf("invalid requests reached the org seam %d times, want 0", fake.inviteCalls)
	}
}

// TestEnrolmentStatus_PushPausedSurfacesBreaker pins the H2 dashboard surface:
// an OPEN oversized-batch circuit must appear on /api/enrolment/status so the
// Settings page can say "nothing is shipping" instead of showing a healthy
// push loop. Absent is the normal case — a merely-idle loop must NOT render the
// pause banner.
func TestEnrolmentStatus_PushPausedSurfacesBreaker(t *testing.T) {
	until := time.Date(2026, 8, 26, 18, 0, 0, 0, time.UTC)
	fake := &fakeEnrolment{
		state: orgclient.EnrolmentState{
			Enrolled: true, OrgID: "org-1", OrgName: "Acme",
			PushPaused: &store.PushBreakerState{
				Reason: "orgclient: push batch too large: serialized_bytes=250000000 limit_bytes=1048576",
				Until:  until,
			},
		},
	}
	srv := newEnrolmentServer(t, fake)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enrolment/status", nil))
	var resp enrolmentStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.PushPaused == nil {
		t.Fatal("push_paused missing while the circuit is open — the UI would show a healthy push loop")
	}
	if resp.PushPaused.Until != until.Format(time.RFC3339) {
		t.Errorf("until = %q, want %q", resp.PushPaused.Until, until.Format(time.RFC3339))
	}
	if !strings.Contains(resp.PushPaused.Reason, "limit_bytes=1048576") {
		t.Errorf("reason = %q, want the actionable diagnostic", resp.PushPaused.Reason)
	}

	// Not paused → the key is omitted entirely (no scary empty banner).
	fake.state.PushPaused = nil
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enrolment/status", nil))
	if strings.Contains(rec.Body.String(), "push_paused") {
		t.Errorf("push_paused present on a healthy node: %s", rec.Body.String())
	}
}
