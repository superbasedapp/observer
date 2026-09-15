package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestCloudProgressListAndDetailAgree(t *testing.T) {
	s, database := newCloudTestServer(t)
	seedSessionAuthority(t, database, "progress-session", "personal")
	// The Sessions list excludes marker-only sessions; give this fixture real
	// captured activity so it exercises the same row the detail panel reads.
	if _, err := database.ExecContext(context.Background(), `INSERT INTO actions
		(session_id, project_id, timestamp, action_type, tool)
		SELECT id, project_id, started_at, 'tool_call', 'codex' FROM sessions WHERE id = ?`, "progress-session"); err != nil {
		t.Fatal(err)
	}
	id, _ := seedReconfirmationOutbox(t, database, "progress-session")
	for _, state := range []string{"pending", "sending", "sent", "failed_retryable", "reconfirmation_required", "failed_terminal", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			if _, err := database.ExecContext(context.Background(), `UPDATE cloud_outbox SET state = ? WHERE id = ?`, state, id); err != nil {
				t.Fatal(err)
			}
			detail := httptest.NewRecorder()
			s.handleCloudSession(detail, httptest.NewRequest(http.MethodGet, "/api/cloud/session/progress-session", nil))
			var d CloudSessionResponse
			if err := json.Unmarshal(detail.Body.Bytes(), &d); err != nil {
				t.Fatal(err)
			}
			if d.Progress == nil || d.Progress.State != state {
				t.Fatalf("detail = %+v, want %s", d.Progress, state)
			}
			list := httptest.NewRecorder()
			s.handleSessions(list, httptest.NewRequest(http.MethodGet, "/api/sessions", nil))
			if list.Code != http.StatusOK {
				t.Fatalf("list status %d: %s", list.Code, list.Body.String())
			}
			var payload struct {
				Rows []struct {
					ID       string                         `json:"id"`
					Progress *store.CloudEnrichmentProgress `json:"cloud_enrichment"`
				} `json:"rows"`
			}
			if err := json.Unmarshal(list.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if len(payload.Rows) != 1 || payload.Rows[0].Progress == nil || payload.Rows[0].Progress.State != state {
				t.Fatalf("list = %+v, want %s", payload.Rows, state)
			}
		})
	}
}
