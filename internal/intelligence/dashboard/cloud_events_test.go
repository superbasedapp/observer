package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestHandleCloudStatusLastSyncNilByDefault pins the honest "never synced"
// state: LastSync is nil and ProviderState is "unknown" before any
// `observer cloud sync` has ever run.
func TestHandleCloudStatusLastSyncNilByDefault(t *testing.T) {
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
	if resp.LastSync != nil {
		t.Errorf("expected LastSync=nil before any sync, got %+v", resp.LastSync)
	}
	if resp.ProviderState != "unknown" {
		t.Errorf("expected provider_state=unknown before any sync, got %q", resp.ProviderState)
	}
}

// TestHandleCloudStatusLastSyncAndProviderState pins the field round-trip
// and the honest provider_state derivation: waiting iff the last sync
// reported waiting_provider>0; accepting iff it moved something (sent or
// results) with waiting_provider==0; unknown otherwise.
func TestHandleCloudStatusLastSyncAndProviderState(t *testing.T) {
	s, database := newCloudTestServer(t)
	st := store.New(database)
	ctx := context.Background()

	started := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	if err := st.RecordCloudSyncLast(ctx, store.CloudSyncLast{
		StartedAt: started, FinishedAt: started.Add(2 * time.Second), OK: true,
		Sent: 0, WaitingProvider: 3, Results: 0,
	}); err != nil {
		t.Fatalf("RecordCloudSyncLast (waiting): %v", err)
	}

	rr := httptest.NewRecorder()
	s.handleCloudStatus(rr, httptest.NewRequest(http.MethodGet, "/api/cloud/status", nil))
	var resp CloudStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.LastSync == nil {
		t.Fatal("expected a non-nil LastSync after recording one")
	}
	if !resp.LastSync.OK || resp.LastSync.WaitingProvider != 3 || resp.LastSync.FinishedAt == "" {
		t.Errorf("LastSync round-trip wrong: %+v", resp.LastSync)
	}
	if resp.ProviderState != "waiting" {
		t.Errorf("provider_state = %q, want waiting (waiting_provider>0)", resp.ProviderState)
	}

	// A later, cleaner sync flips the derivation to accepting.
	if err := st.RecordCloudSyncLast(ctx, store.CloudSyncLast{
		StartedAt: started.Add(time.Hour), FinishedAt: started.Add(time.Hour + time.Second), OK: true,
		Sent: 2, WaitingProvider: 0, Results: 1,
	}); err != nil {
		t.Fatalf("RecordCloudSyncLast (accepting): %v", err)
	}
	rr2 := httptest.NewRecorder()
	s.handleCloudStatus(rr2, httptest.NewRequest(http.MethodGet, "/api/cloud/status", nil))
	var resp2 CloudStatusResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp2.ProviderState != "accepting" {
		t.Errorf("provider_state = %q, want accepting", resp2.ProviderState)
	}

	// A sync that moved nothing either way (e.g. nothing sendable, no
	// results) stays honestly unknown rather than claiming "accepting".
	if err := st.RecordCloudSyncLast(ctx, store.CloudSyncLast{
		StartedAt: started.Add(2 * time.Hour), FinishedAt: started.Add(2*time.Hour + time.Second), OK: true,
	}); err != nil {
		t.Fatalf("RecordCloudSyncLast (idle): %v", err)
	}
	rr3 := httptest.NewRecorder()
	s.handleCloudStatus(rr3, httptest.NewRequest(http.MethodGet, "/api/cloud/status", nil))
	var resp3 CloudStatusResponse
	if err := json.Unmarshal(rr3.Body.Bytes(), &resp3); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp3.ProviderState != "unknown" {
		t.Errorf("provider_state = %q, want unknown (nothing moved)", resp3.ProviderState)
	}
}

// TestHandleCloudEventsDefaultWindow pins the no-`since` default: a result
// received within the default lookback window is reported; one older than
// it is not.
func TestHandleCloudEventsDefaultWindow(t *testing.T) {
	s, database := newCloudTestServer(t)
	st := store.New(database)
	ctx := context.Background()

	if _, err := st.UpsertCloudResult(ctx, store.CloudResult{
		SessionID: "sess-recent", SchemaVersion: "session_enrichment.v2-candidate",
		ResultJSON: `{"title":"Recent title"}`, ReceivedAt: time.Now().UTC().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("UpsertCloudResult (recent): %v", err)
	}
	if _, err := st.UpsertCloudResult(ctx, store.CloudResult{
		SessionID: "sess-stale", SchemaVersion: "session_enrichment.v2-candidate",
		ResultJSON: `{"title":"Stale title"}`, ReceivedAt: time.Now().UTC().Add(-cloudEventsDefaultWindow - time.Hour),
	}); err != nil {
		t.Fatalf("UpsertCloudResult (stale): %v", err)
	}

	rr := httptest.NewRecorder()
	s.handleCloudEvents(rr, httptest.NewRequest(http.MethodGet, "/api/cloud/events", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp CloudEventsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Now == "" {
		t.Error("now must be populated")
	}
	if len(resp.Results) != 1 {
		t.Fatalf("results = %d, want 1 (default window excludes the stale one): %+v", len(resp.Results), resp.Results)
	}
	if resp.Results[0].SessionID != "sess-recent" || resp.Results[0].Title != "Recent title" {
		t.Errorf("unexpected result: %+v", resp.Results[0])
	}
}

// TestHandleCloudEventsExplicitSince pins the `since` query param and that a
// superseded result never surfaces.
func TestHandleCloudEventsExplicitSince(t *testing.T) {
	s, database := newCloudTestServer(t)
	st := store.New(database)
	ctx := context.Background()

	base := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	if _, err := st.UpsertCloudResult(ctx, store.CloudResult{
		SessionID: "sess-before", SchemaVersion: "session_enrichment.v2-candidate",
		ResultJSON: `{"title":"Before"}`, ReceivedAt: base,
	}); err != nil {
		t.Fatalf("UpsertCloudResult (before): %v", err)
	}
	firstID, err := st.UpsertCloudResult(ctx, store.CloudResult{
		SessionID: "sess-after", SchemaVersion: "session_enrichment.v2-candidate",
		ResultJSON: `{"title":"stale"}`, ReceivedAt: base.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("UpsertCloudResult (after v1): %v", err)
	}
	if _, err := st.UpsertCloudResult(ctx, store.CloudResult{
		SessionID: "sess-after", SchemaVersion: "session_enrichment.v2-candidate",
		ResultJSON: `{"title":"After"}`, ReceivedAt: base.Add(time.Hour + time.Minute),
	}); err != nil {
		t.Fatalf("UpsertCloudResult (after v2): %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/cloud/events?since="+base.Format(time.RFC3339), nil)
	rr := httptest.NewRecorder()
	s.handleCloudEvents(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp CloudEventsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("results = %d, want 1 (since excludes sess-before, superseded v1 excluded): %+v", len(resp.Results), resp.Results)
	}
	got := resp.Results[0]
	if got.SessionID != "sess-after" || got.Title != "After" {
		t.Errorf("unexpected result: %+v", got)
	}
	if got.ResultID == firstID {
		t.Errorf("returned the superseded result id %q", firstID)
	}
}
