package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newCloudTestServer opens a migrated test DB and a dashboard Server over it.
func newCloudTestServer(t *testing.T) (*Server, *sql.DB) {
	t.Helper()
	tdir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database})
	if err != nil {
		t.Fatal(err)
	}
	return server, database
}

// seedSessionAuthority writes a session row and stamps its data-authority
// column directly (deterministic, independent of live enrolment state).
func seedSessionAuthority(t *testing.T, database *sql.DB, id, authority string) {
	t.Helper()
	ctx := context.Background()
	st := store.New(database)
	projectID, err := st.UpsertProject(ctx, "/tmp/cloud-test-"+id, "")
	if err != nil {
		t.Fatalf("upsert project for %s: %v", id, err)
	}
	if err := st.UpsertSession(ctx, models.Session{
		ID: id, ProjectID: projectID, Tool: "claude-code", Model: "claude-opus-4-8",
		StartedAt: time.Now().UTC().Add(-time.Hour), EndedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert session %s: %v", id, err)
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE sessions SET authority = ?, authority_classifier_version = 1 WHERE id = ?`,
		authority, id); err != nil {
		t.Fatalf("stamp authority %s: %v", id, err)
	}
}

// seedReconfirmationOutbox enqueues an outbox item for an eligible session and
// drives it to reconfirmation_required via a digest-mismatching rebuild. It
// returns the outbox id and the bound receipt id.
func seedReconfirmationOutbox(t *testing.T, database *sql.DB, sessionID string) (string, string) {
	t.Helper()
	ctx := context.Background()
	st := store.New(database)
	receiptID, err := st.InsertCloudConsentReceipt(ctx, store.CloudConsentReceipt{
		AccountPseudonym: "acct-test",
		Purpose:          "session_enrichment",
		Endpoint:         "https://cloud.example/v1/jobs",
		UploadDigest:     "digest-A",
	})
	if err != nil {
		t.Fatalf("insert receipt: %v", err)
	}
	outboxID, err := st.EnqueueCloudOutbox(ctx, store.CloudOutboxItem{
		SessionID:             sessionID,
		FeatureSetJSON:        `["session_enrichment"]`,
		EvidenceContentDigest: "ev-A",
		UploadDigest:          "digest-A",
		ReceiptID:             receiptID,
	})
	if err != nil {
		t.Fatalf("enqueue outbox: %v", err)
	}
	// A rebuild whose digests differ from the confirmed ones moves the item to
	// reconfirmation_required (never auto-sent).
	rebuild := func(context.Context) ([]byte, string, string, error) {
		return []byte("x"), "ev-DIFFERENT", "digest-DIFFERENT", nil
	}
	if _, _, err := st.PrepareCloudOutboxSend(ctx, outboxID, "https://cloud.example/v1/jobs", rebuild); err == nil {
		t.Fatal("expected reconfirmation error from digest mismatch, got nil")
	}
	it, ok, err := st.GetCloudOutbox(ctx, outboxID)
	if err != nil || !ok {
		t.Fatalf("get outbox: ok=%v err=%v", ok, err)
	}
	if it.State != store.CloudOutboxReconfirmationRequired {
		t.Fatalf("outbox state = %q, want reconfirmation_required", it.State)
	}
	return outboxID, receiptID
}

func TestHandleCloudStatus_Empty(t *testing.T) {
	s, _ := newCloudTestServer(t)
	rr := httptest.NewRecorder()
	s.handleCloudStatus(rr, httptest.NewRequest(http.MethodGet, "/api/cloud/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp CloudStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Active {
		t.Errorf("expected Active=false on an unconfigured node, got true: %+v", resp)
	}
	if resp.AllowanceKnown {
		t.Errorf("allowance must be unknown (server-reported at sync), got known")
	}
	if resp.Descriptor == "" {
		t.Errorf("descriptor must carry the manual-only honesty copy")
	}
	if resp.OutboxByState == nil {
		t.Errorf("outbox_by_state must be a (possibly empty) map, not null")
	}
}

func TestHandleCloudStatus_ReportsStoreFacts(t *testing.T) {
	s, database := newCloudTestServer(t)
	seedSessionAuthority(t, database, "sess-personal", "personal")
	seedReconfirmationOutbox(t, database, "sess-personal")
	// A synced result advances results + last_result_at.
	if _, err := store.New(database).UpsertCloudResult(context.Background(), store.CloudResult{
		SessionID:     "sess-personal",
		SchemaVersion: "session_enrichment.v2-candidate",
		ResultJSON:    `{"title":"AI title","taxonomy_tags":["go"]}`,
		Provenance:    store.CloudResultProvenance{ModelRoute: "luna"},
	}); err != nil {
		t.Fatalf("upsert result: %v", err)
	}

	rr := httptest.NewRecorder()
	s.handleCloudStatus(rr, httptest.NewRequest(http.MethodGet, "/api/cloud/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp CloudStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Active {
		t.Errorf("expected Active=true after seeding, got false")
	}
	if resp.ReceiptsTotal != 1 || resp.ReceiptsLive != 1 {
		t.Errorf("receipts total/live = %d/%d, want 1/1", resp.ReceiptsTotal, resp.ReceiptsLive)
	}
	if got := resp.OutboxByState["reconfirmation_required"]; got != 1 {
		t.Errorf("reconfirmation_required count = %d, want 1 (states: %+v)", got, resp.OutboxByState)
	}
	if resp.OutboxTotal != 1 {
		t.Errorf("outbox_total = %d, want 1", resp.OutboxTotal)
	}
	// A reconfirmation_required item is NOT sendable.
	if resp.SendableCount != 0 {
		t.Errorf("sendable_count = %d, want 0 (reconfirmation_required is not sendable)", resp.SendableCount)
	}
	if resp.ResultsTotal != 1 || resp.LastResultAt == "" {
		t.Errorf("results_total/last_result_at = %d/%q, want 1/non-empty", resp.ResultsTotal, resp.LastResultAt)
	}
}

func TestHandleCloudSession_PersonalWithResultAndOverride(t *testing.T) {
	s, database := newCloudTestServer(t)
	seedSessionAuthority(t, database, "sess-personal", "personal")
	_, _ = seedReconfirmationOutbox(t, database, "sess-personal")
	st := store.New(database)
	resultID, err := st.UpsertCloudResult(context.Background(), store.CloudResult{
		SessionID:     "sess-personal",
		SchemaVersion: "session_enrichment.v2-candidate",
		ResultJSON:    `{"title":"AI title","taxonomy_tags":["go","cli"]}`,
		Provenance:    store.CloudResultProvenance{ModelRoute: "luna"},
	})
	if err != nil {
		t.Fatalf("upsert result: %v", err)
	}
	if err := st.SetCloudResultOverride(context.Background(), resultID, "title", "My own title"); err != nil {
		t.Fatalf("set override: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cloud/session/sess-personal", nil)
	s.handleCloudSession(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp CloudSessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Authority != "personal" || !resp.Eligible || resp.Excluded {
		t.Errorf("authority/eligible/excluded = %q/%v/%v, want personal/true/false", resp.Authority, resp.Eligible, resp.Excluded)
	}
	if len(resp.Outbox) != 1 || resp.Outbox[0].State != "reconfirmation_required" {
		t.Fatalf("outbox = %+v, want one reconfirmation_required item", resp.Outbox)
	}
	if len(resp.Receipts) != 1 || resp.Receipts[0].Purpose != "session_enrichment" {
		t.Errorf("receipts = %+v, want one session_enrichment receipt", resp.Receipts)
	}
	if resp.Result == nil {
		t.Fatal("expected a result, got nil")
	}
	ov, ok := resp.Result.Overrides["title"]
	if !ok || ov.UserValue != "My own title" {
		t.Errorf("override title = %+v (ok=%v), want user value 'My own title'", ov, ok)
	}
	// The AI-suggested title stays in the raw result payload (override wins in
	// the UI, but the source value is still carried so the mark can show it).
	var payload map[string]any
	if err := json.Unmarshal(resp.Result.Result, &payload); err != nil {
		t.Fatalf("result payload not valid json: %v", err)
	}
	if payload["title"] != "AI title" {
		t.Errorf("ai-source title = %v, want 'AI title'", payload["title"])
	}
}

func TestHandleCloudSession_OrgExcluded(t *testing.T) {
	s, database := newCloudTestServer(t)
	seedSessionAuthority(t, database, "sess-org", "org")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cloud/session/sess-org", nil)
	s.handleCloudSession(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp CloudSessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Authority != "org" || resp.Eligible || !resp.Excluded {
		t.Errorf("authority/eligible/excluded = %q/%v/%v, want org/false/true", resp.Authority, resp.Eligible, resp.Excluded)
	}
	if resp.ExcludedReason == "" {
		t.Error("org session must carry an honest excluded reason")
	}
	if resp.Result != nil {
		t.Error("org session must not surface a personal cloud result")
	}
}

func TestHandleCloudSession_UnknownAuthorityExcluded(t *testing.T) {
	s, _ := newCloudTestServer(t)
	// No session row at all → unknown authority, ineligible, excluded.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cloud/session/does-not-exist", nil)
	s.handleCloudSession(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp CloudSessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Authority != "unknown" || resp.Eligible || !resp.Excluded {
		t.Errorf("authority/eligible/excluded = %q/%v/%v, want unknown/false/true", resp.Authority, resp.Eligible, resp.Excluded)
	}
}

// TestHandleCloudSession_CloudSessionIDIsReadOnly pins the issue "show the
// local uuid <-> cloud pseudonym mapping to the user": the handler must
// surface an already-minted pseudonym for display, but must NEVER mint one
// itself as a side effect of a read (that would be a store write hiding
// behind a GET).
func TestHandleCloudSession_CloudSessionIDIsReadOnly(t *testing.T) {
	s, database := newCloudTestServer(t)
	seedSessionAuthority(t, database, "sess-personal", "personal")

	// Before any enrollment, no pseudonym has ever been minted.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cloud/session/sess-personal", nil)
	s.handleCloudSession(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp CloudSessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.CloudSessionID != "" {
		t.Errorf("cloud_session_id = %q, want empty before enrollment (a GET must not mint one)", resp.CloudSessionID)
	}
	// The GET itself must not have minted one either — confirm directly
	// against the store, not just against what this response happened to say.
	if _, ok, err := store.New(database).LookupCloudSessionPseudonym(context.Background(), "sess-personal"); err != nil || ok {
		t.Fatalf("LookupCloudSessionPseudonym after a GET: ok=%v err=%v, want ok=false", ok, err)
	}

	// Once this device has minted a pseudonym (the real enrollment path,
	// GetOrCreateCloudSessionPseudonym), the handler must surface the SAME
	// value.
	want, err := store.New(database).GetOrCreateCloudSessionPseudonym(context.Background(), "sess-personal")
	if err != nil {
		t.Fatalf("mint pseudonym: %v", err)
	}
	if want == "" {
		t.Fatal("minted pseudonym is empty")
	}

	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/cloud/session/sess-personal", nil)
	s.handleCloudSession(rr2, req2)
	var resp2 CloudSessionResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp2.CloudSessionID != want {
		t.Errorf("cloud_session_id = %q, want %q (the pseudonym this device already minted)", resp2.CloudSessionID, want)
	}
}
