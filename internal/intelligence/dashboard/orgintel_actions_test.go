package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeOrgIntel is a scripted org-plane manager for the handler tests.
type fakeOrgIntel struct {
	enrichErr   error
	enrichShown string
	ledgerID    int64
}

func (f *fakeOrgIntel) Status(*http.Request) (OrgIntelStatus, error) { return OrgIntelStatus{}, nil }

func (f *fakeOrgIntel) Accept(*http.Request, string) (OrgIntelStatus, error) {
	return OrgIntelStatus{}, nil
}

func (f *fakeOrgIntel) Withdraw(*http.Request) (OrgIntelStatus, error) { return OrgIntelStatus{}, nil }

func (f *fakeOrgIntel) Session(_ *http.Request, id string) (OrgIntelSessionView, error) {
	if id == "missing" {
		return OrgIntelSessionView{}, fmt.Errorf("%w: no session", ErrOrgIntelNotFound)
	}
	return OrgIntelSessionView{
		SessionID: id, Authority: "org", Class: "individual",
		Actions: OrgIntelActionsView{Preview: true, Enrich: true, NeedsPreview: true},
	}, nil
}

func (f *fakeOrgIntel) Preview(_ *http.Request, id string) (OrgIntelPreview, error) {
	return OrgIntelPreview{SessionID: id, EvidenceLevel: "titles", UploadDigest: "sha256:up", Bytes: `{"x":1}`}, nil
}

func (f *fakeOrgIntel) Enrich(_ *http.Request, id, shown string) (OrgIntelEnrichResult, error) {
	f.enrichShown = shown
	if f.enrichErr != nil {
		return OrgIntelEnrichResult{}, f.enrichErr
	}
	return OrgIntelEnrichResult{Submission: OrgIntelSubmissionView{SessionID: id, State: "submitted"}, Queued: true, Sent: true, Message: "Sent."}, nil
}

func (f *fakeOrgIntel) Ledger(_ *http.Request, id int64) (OrgIntelLedger, error) {
	f.ledgerID = id
	return OrgIntelLedger{Rows: []OrgIntelSubmissionView{{ID: 1, State: "submitted"}}}, nil
}

func confirmedPost(path, body string) *http.Request {
	r := loopbackRequest(http.MethodPost, path)
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(remoteConfirmHeader, "tok")
	r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: "tok"})
	return r
}

// TestOrgIntelActionRoutes: each route answers through the manager, enrich
// needs the confirm token and passes the shown digest through, and the typed
// refusals map onto their statuses.
func TestOrgIntelActionRoutes(t *testing.T) {
	fake := &fakeOrgIntel{}
	s := newRemoteTestServer(t, Options{OrgIntel: fake})
	h := s.guardedHandler("127.0.0.1:8081")
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	rec := serve(loopbackRequest(http.MethodGet, "/api/intel/session/s1"))
	var sess struct {
		ConfirmToken string              `json:"confirm_token"`
		Session      OrgIntelSessionView `json:"session"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &sess) != nil || sess.ConfirmToken == "" || !sess.Session.Actions.NeedsPreview || sess.Session.Enriched {
		t.Fatalf("session = %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(loopbackRequest(http.MethodGet, "/api/intel/session/missing")); rec.Code != http.StatusNotFound {
		t.Fatalf("missing session = %d", rec.Code)
	}
	if rec := serve(loopbackRequest(http.MethodGet, "/api/intel/preview?session_id=s1")); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "sha256:up") {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(loopbackRequest(http.MethodGet, "/api/intel/preview")); rec.Code != http.StatusBadRequest {
		t.Fatalf("preview without id = %d", rec.Code)
	}

	// Enrich without the confirm token is refused before the manager runs.
	bare := loopbackRequest(http.MethodPost, "/api/intel/enrich")
	bare.Body = io.NopCloser(strings.NewReader(`{"session_id":"s1"}`))
	bare.Header.Set("Content-Type", "application/json")
	if rec := serve(bare); rec.Code != http.StatusForbidden {
		t.Fatalf("unconfirmed enrich = %d", rec.Code)
	}
	if rec := serve(confirmedPost("/api/intel/enrich", `{"session_id":"s1","upload_digest":"sha256:up"}`)); rec.Code != http.StatusOK || fake.enrichShown != "sha256:up" {
		t.Fatalf("enrich = %d %s (shown %q)", rec.Code, rec.Body.String(), fake.enrichShown)
	}
	for _, c := range []struct {
		err    error
		status int
		code   string
	}{
		{fmt.Errorf("%w: changed", ErrOrgIntelPreviewRequired), http.StatusConflict, "preview_required"},
		{fmt.Errorf("%w: off", ErrOrgIntelConflict), http.StatusConflict, "not_applicable"},
	} {
		fake.enrichErr = c.err
		rec := serve(confirmedPost("/api/intel/enrich", `{"session_id":"s1"}`))
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != c.status || body["error"] != c.code {
			t.Fatalf("enrich err %v = %d %v", c.err, rec.Code, body)
		}
	}

	if rec := serve(loopbackRequest(http.MethodGet, "/api/intel/ledger?id=7")); rec.Code != http.StatusOK || fake.ledgerID != 7 {
		t.Fatalf("ledger = %d (id %d)", rec.Code, fake.ledgerID)
	}
	if rec := serve(loopbackRequest(http.MethodGet, "/api/intel/ledger?id=x")); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad ledger id = %d", rec.Code)
	}
}

// TestOrgIntelResultsFollowIntelVisibility: when the organization hides the
// `intel` subsection on a MANAGED node, the org-plane session read is refused
// by the guard and the older /api/session/<id>/org-intel sub-route shows
// nothing either. (On an individual node `intel` is a floor, T-379.)
func TestOrgIntelResultsFollowIntelVisibility(t *testing.T) {
	s := newRemoteTestServer(t, Options{
		OrgIntel:   &fakeOrgIntel{},
		Governance: governedProviderAs(t, true, []string{"intel"}, nil),
	})
	if err := store.New(s.opts.DB).UpsertOrgIntelResult(context.Background(), store.OrgIntelResult{
		SessionID: "s1", JobID: "j1", Title: "Org title", Confidence: "high",
		SchemaVersion: "session_enrichment.v2", FetchedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	h := s.guardedHandler("127.0.0.1:8081")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/intel/session/s1"))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "governance_hidden") {
		t.Fatalf("hidden session read = %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/session/s1/org-intel"))
	var w orgIntelWire
	if err := json.Unmarshal(rec.Body.Bytes(), &w); err != nil || w.Enriched || w.Result != nil {
		t.Fatalf("hidden org-intel sub-route = %d %s", rec.Code, rec.Body.String())
	}
}
