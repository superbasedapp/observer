package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// --- enable / disable ---------------------------------------------------------

// TestCloudEnable pins POST /api/cloud/enable: default argv, the
// with_excerpts/background flag translation, unwired/method, and the 409
// running-action guards.
func TestCloudEnable(t *testing.T) {
	t.Run("default: exact argv", func(t *testing.T) {
		runner := &fakeCloudRunner{output: "Cloud Intelligence is on: titles (background on).\n"}
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudEnable, "/api/cloud/enable", `{"with_excerpts":false,"background":true}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		var resp CloudActionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.OK || !strings.Contains(resp.Output, "Cloud Intelligence is on") {
			t.Fatalf("resp = %+v", resp)
		}
		want := []string{"--yes", "--source", "dashboard"}
		if calls := runner.calls(); len(calls) != 1 || calls[0] != "enable" || !equalArgs(runner.argsFor(0), want) {
			t.Fatalf("calls = %v args = %v", calls, runner.argsFor(0))
		}
	})
	t.Run("with_excerpts + background off: exact argv", func(t *testing.T) {
		runner := &fakeCloudRunner{}
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudEnable, "/api/cloud/enable", `{"with_excerpts":true,"background":false}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		want := []string{"--yes", "--source", "dashboard", "--with-excerpts", "--no-background"}
		if !equalArgs(runner.argsFor(0), want) {
			t.Fatalf("args = %v, want %v", runner.argsFor(0), want)
		}
	})
	t.Run("unwired and method", func(t *testing.T) {
		srv, _ := newCloudTestServer(t)
		if rec := postJSON(srv.handleCloudEnable, "/api/cloud/enable", `{}`); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("unwired → %d", rec.Code)
		}
		wired, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := httptest.NewRecorder()
		wired.handleCloudEnable(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/enable", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET → %d", rec.Code)
		}
	})
	t.Run("409 while a sign-in or sync is running", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
		runner := &fakeCloudRunner{release: make(chan error, 2)}
		srv, _ := newCloudConsentTestServer(t, probe, runner)
		cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
		cloudWaitFor(t, "login spawn", func() bool { return len(runner.calls()) == 1 })

		if rec := postJSON(srv.handleCloudEnable, "/api/cloud/enable", `{}`); rec.Code != http.StatusConflict {
			t.Fatalf("enable during login → %d", rec.Code)
		}
		runner.release <- nil
	})
}

// TestCloudDisable pins POST /api/cloud/disable: exact argv, unwired/method,
// and the 409 running-action guard.
func TestCloudDisable(t *testing.T) {
	t.Run("exact argv", func(t *testing.T) {
		runner := &fakeCloudRunner{output: "Cloud Intelligence is off.\n"}
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		rec := postJSON(srv.handleCloudDisable, "/api/cloud/disable", `{}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		var resp CloudActionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.OK || !strings.Contains(resp.Output, "Cloud Intelligence is off") {
			t.Fatalf("resp = %+v", resp)
		}
		want := []string{"--yes", "--source", "dashboard"}
		if calls := runner.calls(); len(calls) != 1 || calls[0] != "disable" || !equalArgs(runner.argsFor(0), want) {
			t.Fatalf("calls = %v args = %v", calls, runner.argsFor(0))
		}
	})
	t.Run("unwired and method", func(t *testing.T) {
		srv, _ := newCloudTestServer(t)
		if rec := postJSON(srv.handleCloudDisable, "/api/cloud/disable", `{}`); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("unwired → %d", rec.Code)
		}
		wired, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := httptest.NewRecorder()
		wired.handleCloudDisable(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/disable", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET → %d", rec.Code)
		}
	})
	t.Run("409 while a sync is running", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{APITokenPresent: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1)}
		srv, _ := newCloudConsentTestServer(t, probe, runner)
		cloudDoJSON[CloudSyncState](t, srv.handleCloudSync, http.MethodPost, "/api/cloud/sync")
		cloudWaitFor(t, "sync spawn", func() bool { return len(runner.calls()) == 1 })

		if rec := postJSON(srv.handleCloudDisable, "/api/cloud/disable", `{}`); rec.Code != http.StatusConflict {
			t.Fatalf("disable during sync → %d", rec.Code)
		}
		runner.release <- nil
	})
}

// --- ledger --------------------------------------------------------------------

// TestCloudLedger pins GET /api/cloud/ledger: unwired/method, the empty state,
// a populated ledger's content and ordering, and the limit query parameter.
func TestCloudLedger(t *testing.T) {
	t.Run("unwired and method", func(t *testing.T) {
		srv, _ := newCloudTestServer(t)
		req := httptest.NewRequest(http.MethodGet, "/api/cloud/ledger", nil)
		rec := httptest.NewRecorder()
		srv.handleCloudLedger(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("unwired → %d", rec.Code)
		}
		wired, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec2 := httptest.NewRecorder()
		wired.handleCloudLedger(rec2, httptest.NewRequest(http.MethodPost, "/api/cloud/ledger", nil))
		if rec2.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST → %d", rec2.Code)
		}
	})
	t.Run("empty", func(t *testing.T) {
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := httptest.NewRecorder()
		srv.handleCloudLedger(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/ledger", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		var resp CloudLedgerResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.TotalReceipts != 0 || len(resp.Entries) != 0 {
			t.Fatalf("resp = %+v, want empty", resp)
		}
	})
	t.Run("populated: content-free, newest first, result attached", func(t *testing.T) {
		srv, database := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		ctx := context.Background()
		st := store.New(database)

		seedSessionAuthority(t, database, "sess-ledger", "personal")
		// Explicit CreatedAt values (rather than seedCloudReceipt's
		// time.Now()-at-insert default) so the newest-first assertion below
		// cannot flake on two inserts landing in the same clock tick.
		olderID, err := st.InsertCloudConsentReceipt(ctx, store.CloudConsentReceipt{
			AccountPseudonym: "acct_test", Purpose: "structural_activity_insights",
			UploadDigest: "sha256:older", CreatedAt: time.Now().UTC().Add(-time.Hour),
		})
		if err != nil {
			t.Fatalf("insert older receipt: %v", err)
		}
		newerID, err := st.InsertCloudConsentReceipt(ctx, store.CloudConsentReceipt{
			AccountPseudonym: "acct_test", Purpose: "bounded_context_enrichment",
			UploadDigest: "sha256:newer",
		})
		if err != nil {
			t.Fatalf("insert newer receipt: %v", err)
		}

		jobID, err := st.EnqueueCloudOutbox(ctx, store.CloudOutboxItem{
			SessionID: "sess-ledger", EvidenceContentDigest: "sha256:ec",
			UploadDigest: "sha256:older", ReceiptID: olderID,
		})
		if err != nil {
			t.Fatalf("EnqueueCloudOutbox: %v", err)
		}
		if _, err := st.UpsertCloudResult(ctx, store.CloudResult{
			SessionID: "sess-ledger", SchemaVersion: "v1", ResultJSON: `{"title":"a secret task name"}`,
			Provenance: store.CloudResultProvenance{ModelRoute: "route-x", Tokens: 7, CostUSD: 0.02},
		}); err != nil {
			t.Fatalf("UpsertCloudResult: %v", err)
		}

		rec := httptest.NewRecorder()
		srv.handleCloudLedger(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/ledger", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, "a secret task name") {
			t.Fatalf("ledger response leaked result content:\n%s", body)
		}
		var resp CloudLedgerResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.TotalReceipts != 2 || len(resp.Entries) != 2 {
			t.Fatalf("resp = %+v, want 2/2", resp)
		}
		// newest first
		if resp.Entries[0].Receipt.ID != newerID || resp.Entries[1].Receipt.ID != olderID {
			t.Fatalf("order = [%s, %s], want newest first [%s, %s]",
				resp.Entries[0].Receipt.ID, resp.Entries[1].Receipt.ID, newerID, olderID)
		}
		if !resp.Entries[1].Receipt.Live || resp.Entries[1].Receipt.Purpose != "structural_activity_insights" {
			t.Fatalf("older receipt view = %+v", resp.Entries[1].Receipt)
		}
		if len(resp.Entries[1].Items) != 1 || resp.Entries[1].Items[0].ID != jobID {
			t.Fatalf("older items = %+v, want [%s]", resp.Entries[1].Items, jobID)
		}
		if resp.Entries[1].Result == nil || resp.Entries[1].Result.ModelRoute != "route-x" || resp.Entries[1].Result.Tokens != 7 {
			t.Fatalf("older result = %+v", resp.Entries[1].Result)
		}
		if resp.Entries[0].Result != nil {
			t.Fatalf("newer entry (no outbox item) must carry no result, got %+v", resp.Entries[0].Result)
		}
	})
	t.Run("limit query parameter", func(t *testing.T) {
		srv, database := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		seedCloudReceipt(t, database, "structural_activity_insights", store.CloudGrantPerUpload, false)
		seedCloudReceipt(t, database, "structural_activity_insights", store.CloudGrantPerUpload, false)

		rec := httptest.NewRecorder()
		srv.handleCloudLedger(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/ledger?limit=1", nil))
		var resp CloudLedgerResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Entries) != 1 || resp.TotalReceipts != 2 {
			t.Fatalf("resp = %+v, want 1 entry / total 2", resp)
		}
	})
}

// --- preview by receipt_id -----------------------------------------------------

// TestCloudPreviewByReceiptID pins POST /api/cloud/preview's receipt_id path:
// a standing receipt is refused, an unknown receipt is refused, and a
// session-evidence receipt resolves to its session/purpose and echoes them.
func TestCloudPreviewByReceiptID(t *testing.T) {
	t.Run("standing receipt refused", func(t *testing.T) {
		srv, database := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rcpt := seedCloudReceipt(t, database, "structural_activity_insights", store.CloudGrantStanding, false)
		rec := postJSON(srv.handleCloudPreview, "/api/cloud/preview", `{"receipt_id":"`+rcpt.ID+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "no single upload to preview") {
			t.Fatalf("body = %q", rec.Body.String())
		}
	})
	t.Run("unknown receipt refused", func(t *testing.T) {
		srv, _ := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := postJSON(srv.handleCloudPreview, "/api/cloud/preview", `{"receipt_id":"rcpt_does_not_exist"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
	})
	t.Run("receipt with no queued upload refused", func(t *testing.T) {
		srv, database := newCloudConsentTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rcpt := seedCloudReceipt(t, database, "structural_activity_insights", store.CloudGrantPerUpload, false)
		rec := postJSON(srv.handleCloudPreview, "/api/cloud/preview", `{"receipt_id":"`+rcpt.ID+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
	})
	t.Run("session-evidence receipt resolves and echoes", func(t *testing.T) {
		runner := &fakeCloudRunner{output: "the literal preview bytes\n"}
		srv, database := newCloudConsentTestServer(t, &fakeCloudProbe{}, runner)
		ctx := context.Background()
		st := store.New(database)
		seedSessionAuthority(t, database, "sess-preview", "personal")
		rcpt := seedCloudReceipt(t, database, "bounded_context_enrichment", store.CloudGrantPerUpload, false)
		if _, err := st.EnqueueCloudOutbox(ctx, store.CloudOutboxItem{
			SessionID: "sess-preview", EvidenceContentDigest: "sha256:ec",
			UploadDigest: rcpt.UploadDigest, ReceiptID: rcpt.ID,
		}); err != nil {
			t.Fatalf("EnqueueCloudOutbox: %v", err)
		}

		rec := postJSON(srv.handleCloudPreview, "/api/cloud/preview", `{"receipt_id":"`+rcpt.ID+`"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d %q", rec.Code, rec.Body.String())
		}
		var resp CloudPreviewResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.SessionID != "sess-preview" || resp.Purpose != "bounded_context_enrichment" {
			t.Fatalf("resp = %+v", resp)
		}
		want := []string{"--session", "sess-preview", "--purpose", "bounded_context_enrichment", "--receipt-id", rcpt.ID}
		if !equalArgs(runner.argsFor(0), want) {
			t.Fatalf("args = %v, want %v", runner.argsFor(0), want)
		}
	})
}
