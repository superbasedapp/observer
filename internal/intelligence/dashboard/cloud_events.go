package dashboard

import (
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloud_events.go serves GET /api/cloud/events (value-upgrade plan §W3
// "background by default", docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md):
// a small poll the Sessions-page uses to notice a newly-arrived enrichment
// result without a full page reload, so the developer sees "N session(s)
// named by Cloud Intelligence" shortly after the background loop's
// `observer cloud consent` + the next `observer cloud sync` land a title —
// without ever making the browser wait on a sync itself. Read-only over
// internal/store.ListCloudResultsSince, the FF1 "one store seam per
// database" seam (this file never selects against cloud_results directly).
// Class V (a store-derived read), same as GET /api/cloud/status.

// CloudEventResultView is one enrichment result GET /api/cloud/events
// reports. Content-free beyond the AI title, which is the same field the
// Sessions list and session header already render (LoadCloudEnrichedTitles /
// GetCloudSessionResult) — still node-local, never uploaded.
type CloudEventResultView struct {
	ResultID   string `json:"result_id"`
	SessionID  string `json:"session_id"`
	Title      string `json:"title"`
	ReceivedAt string `json:"received_at"`
}

// CloudEventsResponse is GET /api/cloud/events's payload.
type CloudEventsResponse struct {
	Results []CloudEventResultView `json:"results"`
	Now     string                 `json:"now"`
}

// cloudEventsDefaultWindow is how far back GET /api/cloud/events looks when
// `since` is absent — long enough that a page opened mid-poll-interval still
// sees the most recent result, short enough that it never resurfaces stale
// history as if it just happened.
const cloudEventsDefaultWindow = 15 * time.Minute

// cloudEventsLimit bounds one poll's response.
const cloudEventsLimit = 50

// handleCloudEvents serves GET /api/cloud/events?since=<RFC3339>. `since`
// absent, empty, or unparsable defaults to the last cloudEventsDefaultWindow.
func (s *Server) handleCloudEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	since := time.Now().UTC().Add(-cloudEventsDefaultWindow)
	if raw := r.URL.Query().Get("since"); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			since = t
		}
	}
	st := store.New(s.db())
	results, err := st.ListCloudResultsSince(ctx, since, cloudEventsLimit)
	if err != nil {
		http.Error(w, "list cloud results: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := CloudEventsResponse{Now: time.Now().UTC().Format(time.RFC3339)}
	for _, res := range results {
		resp.Results = append(resp.Results, CloudEventResultView{
			ResultID:   res.ResultID,
			SessionID:  res.SessionID,
			Title:      res.Title,
			ReceivedAt: cloudRFC3339(res.ReceivedAt),
		})
	}
	writeJSON(w, resp)
}
