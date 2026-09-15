package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// newCloudConsentTestServer mirrors newCloudAccountTestServer (cloud_account_test.go)
// but also hands back the *sql.DB so tests can seed consent receipts directly.
func newCloudConsentTestServer(t *testing.T, probe *fakeCloudProbe, runner *fakeCloudRunner) (*Server, *sql.DB) {
	t.Helper()
	srv, database := newCloudTestServer(t)
	var pf CloudSignInProbe
	if probe != nil {
		pf = probe.probe
	}
	var rf CloudCommandRunner
	if runner != nil {
		rf = runner.run
	}
	srv.opts.CloudAccount = NewCloudAccountSeams(pf, rf, nil)
	return srv, database
}

// seedCloudReceipt inserts one consent receipt directly (bypassing the CLI's
// transactional ReplaceStandingConsentGrant, which is fine for these
// read-path tests) and, when invalidate is true, immediately revokes it.
func seedCloudReceipt(t *testing.T, database *sql.DB, purpose string, mode store.CloudGrantMode, invalidate bool) store.CloudConsentReceipt {
	t.Helper()
	ctx := context.Background()
	st := store.New(database)
	id, err := st.InsertCloudConsentReceipt(ctx, store.CloudConsentReceipt{
		AccountPseudonym: "acct_test",
		UploadDigest:     "sha256:test",
		Purpose:          purpose,
		GrantMode:        mode,
	})
	if err != nil {
		t.Fatalf("seed receipt: %v", err)
	}
	if invalidate {
		if err := st.InvalidateCloudConsentReceipt(ctx, id); err != nil {
			t.Fatalf("invalidate receipt: %v", err)
		}
	}
	rows, err := st.ListCloudConsentReceipts(ctx)
	if err != nil {
		t.Fatalf("list after seed: %v", err)
	}
	for _, r := range rows {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("seeded receipt %s not found after insert", id)
	return store.CloudConsentReceipt{}
}

// postJSON POSTs body (a JSON string, "" for no body) to h and returns the
// recorded response.
func postJSON(h http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(http.MethodPost, path, nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec
}

// --- preview -----------------------------------------------------------------

// TestCloudPreview pins POST /api/cloud/preview: exact argv, the 400
// validations, truncation at cloudPreviewOutputCap, and that it is allowed
// while a sync/login is running (it makes no network call).
func TestCloudPreview(t *testing.T) {
	t.Run("unwired", func(t *testing.T) {
		srv, _ := newCloudTestServer(t)
		rec := postJSON(srv.handleCloudPreview, "/api/cloud/preview", `{"session_id":"s1","purpose":"structural_activity_insights"}`)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("unwired → %d", rec.Code)
		}
	})
	t.Run("method", func(t *testing.T) {
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := httptest.NewRecorder()
		srv.handleCloudPreview(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/preview", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET → %d", rec.Code)
		}
	})
	t.Run("missing session_id", func(t *testing.T) {
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := postJSON(srv.handleCloudPreview, "/api/cloud/preview", `{"purpose":"structural_activity_insights"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("missing session_id → %d %q", rec.Code, rec.Body.String())
		}
	})
	t.Run("invalid purpose", func(t *testing.T) {
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := postJSON(srv.handleCloudPreview, "/api/cloud/preview", `{"session_id":"s1","purpose":"cohort_benchmarking"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid purpose → %d %q", rec.Code, rec.Body.String())
		}
	})
	t.Run("ok — exact argv and passthrough output", func(t *testing.T) {
		runner := &fakeCloudRunner{output: "the literal preview bytes\n----\nupload digest: sha256:x\n"}
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudPreview, "/api/cloud/preview", `{"session_id":"sess-1","purpose":"bounded_context_enrichment"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("ok → %d %q", rec.Code, rec.Body.String())
		}
		var resp CloudPreviewResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.OK || resp.Truncated || !strings.Contains(resp.Output, "the literal preview bytes") {
			t.Fatalf("resp = %+v", resp)
		}
		if calls := runner.calls(); len(calls) != 1 || calls[0] != "preview" {
			t.Fatalf("calls = %v", calls)
		}
		want := []string{"--session", "sess-1", "--purpose", "bounded_context_enrichment"}
		got := runner.argsFor(0)
		if len(got) != len(want) {
			t.Fatalf("args = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("args = %v, want %v", got, want)
			}
		}
	})
	t.Run("runner error surfaces exit_error, ok=false", func(t *testing.T) {
		runner := &fakeCloudRunner{release: make(chan error, 1), output: "partial output\n"}
		runner.release <- errors.New("exit status 1")
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudPreview, "/api/cloud/preview", `{"session_id":"s1","purpose":"structural_activity_insights"}`)
		var resp CloudPreviewResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.OK || !strings.Contains(resp.ExitError, "exit status 1") {
			t.Fatalf("resp = %+v", resp)
		}
	})
	t.Run("truncates at the cap, keeping the head", func(t *testing.T) {
		big := strings.Repeat("a", cloudPreviewOutputCap+100)
		runner := &fakeCloudRunner{output: big}
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudPreview, "/api/cloud/preview", `{"session_id":"s1","purpose":"structural_activity_insights"}`)
		var resp CloudPreviewResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.Truncated || len(resp.Output) != cloudPreviewOutputCap || resp.Output != big[:cloudPreviewOutputCap] {
			t.Fatalf("truncated=%v len=%d", resp.Truncated, len(resp.Output))
		}
	})
	t.Run("allowed while a login is running", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
		// blockVerb "login" so the in-flight login blocks as usual while the
		// preview call below (a different verb, same runner/seams) returns
		// immediately instead of queueing behind the same release gate.
		runner := &fakeCloudRunner{release: make(chan error, 1), blockVerb: "login"}
		srv, _ := newCloudConsentTestServer(t, probe, runner)
		cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
		cloudWaitFor(t, "login spawn", func() bool { return len(runner.calls()) == 1 })

		rec := postJSON(srv.handleCloudPreview, "/api/cloud/preview", `{"session_id":"s1","purpose":"structural_activity_insights"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("preview during login → %d %q", rec.Code, rec.Body.String())
		}
		runner.release <- nil
	})
}

// --- per-session consent ------------------------------------------------------

// TestCloudConsent pins POST /api/cloud/consent's full state machine: the
// standing-grant-missing 409, the standing-grant catch-up + exact per-step
// argv, and the two up-front refusals (login/sync running).
func TestCloudConsent(t *testing.T) {
	t.Run("unwired", func(t *testing.T) {
		srv, _ := newCloudTestServer(t)
		rec := postJSON(srv.handleCloudConsent, "/api/cloud/consent", `{"session_id":"s1","purpose":"structural_activity_insights"}`)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("unwired → %d", rec.Code)
		}
	})
	t.Run("method", func(t *testing.T) {
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := httptest.NewRecorder()
		srv.handleCloudConsent(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/consent", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET → %d", rec.Code)
		}
	})
	t.Run("validation", func(t *testing.T) {
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		if rec := postJSON(srv.handleCloudConsent, "/api/cloud/consent", `{"purpose":"structural_activity_insights"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("missing session_id → %d", rec.Code)
		}
		if rec := postJSON(srv.handleCloudConsent, "/api/cloud/consent", `{"session_id":"s1","purpose":"nope"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad purpose → %d", rec.Code)
		}
	})
	t.Run("409 while a login is running", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1)}
		srv, _ := newCloudConsentTestServer(t, probe, runner)
		cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
		cloudWaitFor(t, "login spawn", func() bool { return len(runner.calls()) == 1 })

		rec := postJSON(srv.handleCloudConsent, "/api/cloud/consent", `{"session_id":"s1","purpose":"structural_activity_insights"}`)
		if rec.Code != http.StatusConflict {
			t.Fatalf("consent during login → %d", rec.Code)
		}
		if got := runner.calls(); len(got) != 1 {
			t.Fatalf("must not spawn a second command during login, calls = %v", got)
		}
		runner.release <- nil
	})
	t.Run("409 while a sync is running", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{APITokenPresent: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1)}
		srv, _ := newCloudConsentTestServer(t, probe, runner)
		cloudDoJSON[CloudSyncState](t, srv.handleCloudSync, http.MethodPost, "/api/cloud/sync")
		cloudWaitFor(t, "sync spawn", func() bool { return len(runner.calls()) == 1 })

		rec := postJSON(srv.handleCloudConsent, "/api/cloud/consent", `{"session_id":"s1","purpose":"structural_activity_insights"}`)
		if rec.Code != http.StatusConflict {
			t.Fatalf("consent during sync → %d", rec.Code)
		}
		runner.release <- nil
	})
	t.Run("records the per-session receipt only: exact argv, no standing grant minted", func(t *testing.T) {
		for _, purpose := range []string{"structural_activity_insights", "bounded_context_enrichment"} {
			runner := &fakeCloudRunner{output: "Recorded receipt rcpt_x and enqueued job job_y.\n"}
			srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
			rec := postJSON(srv.handleCloudConsent, "/api/cloud/consent",
				`{"session_id":"sess-9","purpose":"`+purpose+`"}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: code = %d %q", purpose, rec.Code, rec.Body.String())
			}
			var resp CloudConsentResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if !resp.OK || resp.ExitError != "" {
				t.Fatalf("%s: resp = %+v", purpose, resp)
			}
			calls := runner.calls()
			if len(calls) != 1 || calls[0] != "consent" {
				t.Fatalf("%s: calls = %v (exactly one per-session consent, never a standing grant)", purpose, calls)
			}
			want := []string{"--session", "sess-9", "--purpose", purpose, "--yes"}
			if got := runner.argsFor(0); !equalArgs(got, want) {
				t.Fatalf("%s: args = %v, want %v", purpose, got, want)
			}
		}
	})
	t.Run("child failure surfaces cobra's Error line, not the bare exit status", func(t *testing.T) {
		runner := &fakeCloudRunner{release: make(chan error, 1), output: "config: deprecation: k1 is deprecated\nError: no cloud base URL — pass --base-url\n"}
		runner.release <- errors.New("exit status 1")
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudConsent, "/api/cloud/consent",
			`{"session_id":"sess-9","purpose":"structural_activity_insights"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d", rec.Code)
		}
		var resp CloudConsentResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp.OK || resp.ExitError != "no cloud base URL — pass --base-url" {
			t.Fatalf("resp = %+v", resp)
		}
		if strings.Contains(resp.Output, "config: deprecation:") {
			t.Fatalf("startup notices must be stripped from every action's output, got %q", resp.Output)
		}
	})
}

// equalArgs is a small argv-equality helper for the table-driven argv
// assertions above.
func equalArgs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// --- consent grants (Settings) -------------------------------------------------

// TestCloudConsentGrants pins GET /api/cloud/consent/grants: the receipt
// shape (mode default, RFC3339 times, nullable invalidated_at, live), and
// that the grantable list passes through the injected CloudGrantableProbe
// verbatim (or an empty, never-null, list when unwired).
func TestCloudConsentGrants(t *testing.T) {
	t.Run("unwired", func(t *testing.T) {
		srv, _ := newCloudTestServer(t)
		rec := httptest.NewRecorder()
		srv.handleCloudConsentGrants(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/consent/grants", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("unwired → %d", rec.Code)
		}
	})
	t.Run("method", func(t *testing.T) {
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := postJSON(srv.handleCloudConsentGrants, "/api/cloud/consent/grants", "")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST → %d", rec.Code)
		}
	})
	t.Run("receipts and grantable", func(t *testing.T) {
		srv, database := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		seedCloudReceipt(t, database, "structural_activity_insights", store.CloudGrantStanding, false)
		seedCloudReceipt(t, database, "bounded_context_enrichment", store.CloudGrantPerUpload, false)
		seedCloudReceipt(t, database, "structural_activity_insights", store.CloudGrantStanding, true) // revoked

		srv.opts.CloudAccount.grantable = func() []CloudGrantable {
			return []CloudGrantable{
				{Purpose: "structural_activity_insights", OK: true},
				{Purpose: "bounded_context_enrichment", OK: false, Reason: "per-session only"},
			}
		}

		rec := httptest.NewRecorder()
		srv.handleCloudConsentGrants(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/consent/grants", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		var resp CloudConsentGrantsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Receipts) != 3 {
			t.Fatalf("receipts = %+v", resp.Receipts)
		}
		var sawLiveStanding, sawRevoked, sawPerUpload bool
		for _, r := range resp.Receipts {
			if r.CreatedAt == "" {
				t.Fatalf("created_at must be set: %+v", r)
			}
			switch {
			case r.Purpose == "structural_activity_insights" && r.Mode == "standing" && r.Live:
				sawLiveStanding = true
				if r.InvalidatedAt != nil {
					t.Fatalf("live receipt must have a nil invalidated_at: %+v", r)
				}
			case r.Purpose == "structural_activity_insights" && r.Mode == "standing" && !r.Live:
				sawRevoked = true
				if r.InvalidatedAt == nil || *r.InvalidatedAt == "" {
					t.Fatalf("revoked receipt must carry invalidated_at: %+v", r)
				}
			case r.Purpose == "bounded_context_enrichment" && r.Mode == "per_upload":
				sawPerUpload = true
			}
		}
		if !sawLiveStanding || !sawRevoked || !sawPerUpload {
			t.Fatalf("receipts = %+v", resp.Receipts)
		}
		if len(resp.Grantable) != 2 || resp.Grantable[0].Purpose != "structural_activity_insights" || !resp.Grantable[0].OK {
			t.Fatalf("grantable = %+v", resp.Grantable)
		}
	})
	t.Run("nil grantable probe reports an empty, never-null, list", func(t *testing.T) {
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := httptest.NewRecorder()
		srv.handleCloudConsentGrants(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/consent/grants", nil))
		if !strings.Contains(rec.Body.String(), `"grantable":[]`) {
			t.Fatalf("body = %s", rec.Body.String())
		}
	})
}

// TestCloudConsentGrantAndRevoke pins POST /api/cloud/consent/grant and
// POST /api/cloud/consent/revoke: exact argv (grant carries --yes, revoke
// does not — the CLI's revoke has no confirmation flag), validation, and the
// sync-running refusal.
func TestCloudConsentGrantAndRevoke(t *testing.T) {
	t.Run("grant: exact argv", func(t *testing.T) {
		runner := &fakeCloudRunner{output: "Recorded standing grant rcpt_x.\n"}
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudConsentGrant, "/api/cloud/consent/grant", `{"purpose":"structural_activity_insights"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		var resp CloudActionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.OK || !strings.Contains(resp.Output, "Recorded standing grant") {
			t.Fatalf("resp = %+v", resp)
		}
		calls := runner.calls()
		want := []string{"grant", "--purpose", "structural_activity_insights", "--yes"}
		if len(calls) != 1 || calls[0] != "consent" || !equalArgs(runner.argsFor(0), want) {
			t.Fatalf("calls = %v args = %v", calls, runner.argsFor(0))
		}
	})
	t.Run("revoke: exact argv, no --yes", func(t *testing.T) {
		runner := &fakeCloudRunner{output: "Revoked 1 standing grant(s).\n"}
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudConsentRevoke, "/api/cloud/consent/revoke", `{"purpose":"structural_activity_insights"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		calls := runner.calls()
		want := []string{"revoke", "--purpose", "structural_activity_insights"}
		if len(calls) != 1 || calls[0] != "consent" || !equalArgs(runner.argsFor(0), want) {
			t.Fatalf("calls = %v args = %v", calls, runner.argsFor(0))
		}
	})
	t.Run("missing purpose", func(t *testing.T) {
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		if rec := postJSON(srv.handleCloudConsentGrant, "/api/cloud/consent/grant", `{}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("grant missing purpose → %d", rec.Code)
		}
		if rec := postJSON(srv.handleCloudConsentRevoke, "/api/cloud/consent/revoke", `{}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("revoke missing purpose → %d", rec.Code)
		}
	})
	t.Run("unwired and method", func(t *testing.T) {
		srv, _ := newCloudTestServer(t)
		if rec := postJSON(srv.handleCloudConsentGrant, "/api/cloud/consent/grant", `{"purpose":"p"}`); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("grant unwired → %d", rec.Code)
		}
		if rec := postJSON(srv.handleCloudConsentRevoke, "/api/cloud/consent/revoke", `{"purpose":"p"}`); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("revoke unwired → %d", rec.Code)
		}
		wired, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := httptest.NewRecorder()
		wired.handleCloudConsentGrant(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/consent/grant", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET grant → %d", rec.Code)
		}
	})
	t.Run("409 while a sync is running", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{APITokenPresent: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1)}
		srv, _ := newCloudConsentTestServer(t, probe, runner)
		cloudDoJSON[CloudSyncState](t, srv.handleCloudSync, http.MethodPost, "/api/cloud/sync")
		cloudWaitFor(t, "sync spawn", func() bool { return len(runner.calls()) == 1 })

		if rec := postJSON(srv.handleCloudConsentGrant, "/api/cloud/consent/grant", `{"purpose":"p"}`); rec.Code != http.StatusConflict {
			t.Fatalf("grant during sync → %d", rec.Code)
		}
		if rec := postJSON(srv.handleCloudConsentRevoke, "/api/cloud/consent/revoke", `{"purpose":"p"}`); rec.Code != http.StatusConflict {
			t.Fatalf("revoke during sync → %d", rec.Code)
		}
		if got := runner.calls(); len(got) != 1 {
			t.Fatalf("must not spawn during sync, calls = %v", got)
		}
		runner.release <- nil
	})
}

// --- delete account -----------------------------------------------------------

// TestCloudDeleteAccount pins POST /api/cloud/delete-account: exact argv for
// both the hosted and --local-only shapes, and the login/sync refusals.
func TestCloudDeleteAccount(t *testing.T) {
	t.Run("hosted: --yes only", func(t *testing.T) {
		runner := &fakeCloudRunner{output: "Server-side deletion requested.\n"}
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudDeleteAccount, "/api/cloud/delete-account", `{"local_only":false}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		calls := runner.calls()
		if len(calls) != 1 || calls[0] != "delete-account" || !equalArgs(runner.argsFor(0), []string{"--yes"}) {
			t.Fatalf("calls = %v args = %v", calls, runner.argsFor(0))
		}
	})
	t.Run("local-only: --yes --local-only", func(t *testing.T) {
		runner := &fakeCloudRunner{output: "Local credentials cleared.\n"}
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudDeleteAccount, "/api/cloud/delete-account", `{"local_only":true}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		want := []string{"--yes", "--local-only"}
		if got := runner.argsFor(0); !equalArgs(got, want) {
			t.Fatalf("args = %v, want %v", got, want)
		}
	})
	t.Run("empty body defaults local_only to false", func(t *testing.T) {
		runner := &fakeCloudRunner{}
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudDeleteAccount, "/api/cloud/delete-account", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		if got := runner.argsFor(0); !equalArgs(got, []string{"--yes"}) {
			t.Fatalf("args = %v", got)
		}
	})
	t.Run("unwired and method", func(t *testing.T) {
		srv, _ := newCloudTestServer(t)
		if rec := postJSON(srv.handleCloudDeleteAccount, "/api/cloud/delete-account", `{}`); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("unwired → %d", rec.Code)
		}
		wired, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := httptest.NewRecorder()
		wired.handleCloudDeleteAccount(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/delete-account", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET → %d", rec.Code)
		}
	})
	t.Run("409 while a login is running", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1)}
		srv, _ := newCloudConsentTestServer(t, probe, runner)
		cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
		cloudWaitFor(t, "login spawn", func() bool { return len(runner.calls()) == 1 })

		rec := postJSON(srv.handleCloudDeleteAccount, "/api/cloud/delete-account", `{}`)
		if rec.Code != http.StatusConflict {
			t.Fatalf("delete-account during login → %d", rec.Code)
		}
		runner.release <- nil
	})
	t.Run("409 while a sync is running", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{APITokenPresent: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1)}
		srv, _ := newCloudConsentTestServer(t, probe, runner)
		cloudDoJSON[CloudSyncState](t, srv.handleCloudSync, http.MethodPost, "/api/cloud/sync")
		cloudWaitFor(t, "sync spawn", func() bool { return len(runner.calls()) == 1 })

		rec := postJSON(srv.handleCloudDeleteAccount, "/api/cloud/delete-account", `{}`)
		if rec.Code != http.StatusConflict {
			t.Fatalf("delete-account during sync → %d", rec.Code)
		}
		runner.release <- nil
	})
}

// TestCloudStripStartupNotices pins that only the config-deprecation startup
// lines are dropped from a preview's combined output: the JSON bytes, the
// summary and a real error line all survive verbatim, and output without any
// notice is returned untouched.
func TestCloudStripStartupNotices(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{name: "no notices untouched", in: "{\n  \"a\": 1\n}\n----\npurpose: x\n", want: "{\n  \"a\": 1\n}\n----\npurpose: x\n"},
		{name: "leading notices dropped", in: "config: deprecation: k1 is deprecated\nconfig: deprecation: the keys above …\n{\n}\n", want: "{\n}\n"},
		{name: "error line kept", in: "config: deprecation: k1\nError: --session is required\n", want: "Error: --session is required\n"},
		{name: "prefix mid-line kept", in: "note: config: deprecation: is not a startup line\n", want: "note: config: deprecation: is not a startup line\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cloudStripStartupNotices(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCloudChildError pins the exit_error derivation: the LAST cobra
// "Error: " line wins, an exec error without one is returned verbatim, and a
// nil error is "".
func TestCloudChildError(t *testing.T) {
	cases := []struct {
		name   string
		output string
		err    error
		want   string
	}{
		{name: "nil err", output: "Error: ignored\n", err: nil, want: ""},
		{name: "error line wins", output: "noise\nError: real reason\n", err: errors.New("exit status 1"), want: "real reason"},
		{name: "last error line wins", output: "Error: first\nError: second\n", err: errors.New("exit status 1"), want: "second"},
		{name: "no error line falls back", output: "just output\n", err: errors.New("signal: killed"), want: "signal: killed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cloudChildError(tc.output, tc.err); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
