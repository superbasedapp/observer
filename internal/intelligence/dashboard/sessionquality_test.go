package dashboard

import (
	"net/http"
	"testing"
)

// TestSessionQualityEndpoint pins /api/session/<id>/quality: the honest
// unscored body (no score fields, never a zero), 404 for an unknown session,
// POST scoring + persisting the full breakdown, the persisted read-back, and
// 405 for other methods. The steps share one server and run in order.
func TestSessionQualityEndpoint(t *testing.T) {
	s, _ := newTagTestServer(t)

	steps := []struct {
		name       string
		method     string
		path       string
		wantCode   int
		wantScored bool
		// wantFields must be present; absentFields must be missing.
		wantFields   []string
		absentFields []string
	}{
		{
			name:   "unscored session answers scored=false with no score fields",
			method: http.MethodGet, path: "/api/session/sess-a/quality",
			wantCode: http.StatusOK, wantScored: false,
			wantFields:   []string{"session_id", "current_action_count", "weights", "auto"},
			absentFields: []string{"quality_score", "error_rate", "redundancy_ratio", "scored_at", "exploration_efficiency"},
		},
		{
			name:   "unknown session is 404",
			method: http.MethodGet, path: "/api/session/nope/quality",
			wantCode: http.StatusNotFound,
		},
		{
			name:   "POST scores and persists the full breakdown",
			method: http.MethodPost, path: "/api/session/sess-a/quality",
			wantCode: http.StatusOK, wantScored: true,
			wantFields: []string{
				"quality_score", "redundancy_ratio", "error_rate",
				"exploration_efficiency", "continuity_score", "scored_at", "scored_action_count",
			},
		},
		{
			name:   "GET reads the persisted score back",
			method: http.MethodGet, path: "/api/session/sess-a/quality",
			wantCode: http.StatusOK, wantScored: true,
			wantFields: []string{"quality_score", "scored_at", "scored_action_count"},
		},
		{
			name:   "a sibling session stays unscored",
			method: http.MethodGet, path: "/api/session/sess-b/quality",
			wantCode: http.StatusOK, wantScored: false,
			absentFields: []string{"quality_score"},
		},
		{
			name:   "PUT is not allowed",
			method: http.MethodPut, path: "/api/session/sess-a/quality",
			wantCode: http.StatusMethodNotAllowed,
		},
	}
	for _, st := range steps {
		code, body := doJSON(t, s, st.method, st.path, "")
		if code != st.wantCode {
			t.Fatalf("%s: status %d, want %d", st.name, code, st.wantCode)
		}
		if code != http.StatusOK {
			continue
		}
		if got, _ := body["scored"].(bool); got != st.wantScored {
			t.Errorf("%s: scored=%v, want %v (body %v)", st.name, got, st.wantScored, body)
		}
		for _, f := range st.wantFields {
			if _, ok := body[f]; !ok {
				t.Errorf("%s: missing field %q (body %v)", st.name, f, body)
			}
		}
		for _, f := range st.absentFields {
			if _, ok := body[f]; ok {
				t.Errorf("%s: field %q must be absent, got %v", st.name, f, body[f])
			}
		}
		if n, _ := body["current_action_count"].(float64); n != 1 {
			t.Errorf("%s: current_action_count=%v, want 1", st.name, body["current_action_count"])
		}
	}

	// The weights echo the scorer's formula; they must sum to 1.
	_, body := doJSON(t, s, http.MethodGet, "/api/session/sess-a/quality", "")
	w, _ := body["weights"].(map[string]any)
	sum := 0.0
	for _, k := range []string{"redundancy", "error", "exploration", "continuity"} {
		v, _ := w[k].(float64)
		sum += v
	}
	if sum < 0.999 || sum > 1.001 {
		t.Errorf("weights sum to %v, want 1 (%v)", sum, w)
	}
	if n, _ := body["scored_action_count"].(float64); n != 1 {
		t.Errorf("scored_action_count=%v, want 1", body["scored_action_count"])
	}
}
