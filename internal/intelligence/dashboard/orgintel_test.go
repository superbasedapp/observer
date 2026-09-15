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

// TestHandleSessionOrgIntel_EnrichedResult seeds one node-local org_intel_cache
// row and asserts GET /api/session/<id>/org-intel renders it as the newest
// result with its content intact.
func TestHandleSessionOrgIntel_EnrichedResult(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()

	st := store.New(database)
	ctx := context.Background()
	// Two pulls for the same session; the newer one must win (DESC order).
	if err := st.UpsertOrgIntelResult(ctx, store.OrgIntelResult{
		SessionID: "sIntel",
		JobID:     "job-old",
		Title:     "stale title",
		FetchedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("seed old: %v", err)
	}
	if err := st.UpsertOrgIntelResult(ctx, store.OrgIntelResult{
		SessionID:     "sIntel",
		JobID:         "job-new",
		Title:         "Refactored the cache layer",
		Description:   "The session split the store seam and added a privacy sentinel.",
		TaxonomyTags:  []string{"refactor", "storage"},
		SuggestedTags: []string{"cleanup"},
		Limitations:   []string{"metadata only"},
		Confidence:    "high",
		SchemaVersion: "session_enrichment.v2",
		FetchedAt:     time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("seed new: %v", err)
	}

	srv := &Server{opts: Options{DB: database}}
	req := httptest.NewRequest(http.MethodGet, "/api/session/sIntel/org-intel", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp orgIntelWire
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body %s", err, rec.Body.String())
	}
	if !resp.Enriched || resp.Result == nil {
		t.Fatalf("expected enriched result, got %+v", resp)
	}
	if resp.Result.JobID != "job-new" {
		t.Fatalf("expected newest job (job-new) to win, got %q", resp.Result.JobID)
	}
	if resp.Result.Title != "Refactored the cache layer" {
		t.Fatalf("title = %q", resp.Result.Title)
	}
	if len(resp.Result.TaxonomyTags) != 2 || resp.Result.Confidence != "high" {
		t.Fatalf("result content = %+v", resp.Result)
	}
}

// TestHandleSessionOrgIntel_HonestEmpty asserts a session with no cached result
// answers enriched=false with a reason, not an error.
func TestHandleSessionOrgIntel_HonestEmpty(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()

	srv := &Server{opts: Options{DB: database}}
	req := httptest.NewRequest(http.MethodGet, "/api/session/sNone/org-intel", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp orgIntelWire
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body %s", err, rec.Body.String())
	}
	if resp.Enriched || resp.Result != nil {
		t.Fatalf("expected honest empty, got %+v", resp)
	}
	if resp.Reason == "" {
		t.Fatalf("expected a reason on the empty response")
	}
}
