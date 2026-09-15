package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestSessionAccountsSummarySortPagination(t *testing.T) {
	const sid = "account-page"
	srv := newSortFixture(t, sid)
	st := store.New(srv.db())
	var obs []models.ToolAccountObservation
	for _, tc := range []struct{ id, email string }{{"msg_0", "z@example.invalid"}, {"msg_1", "a@example.invalid"}, {"msg_2", "a@example.invalid"}, {"msg_2", "z@example.invalid"}} {
		obs = append(obs, models.ToolAccountObservation{SessionID: sid, Tool: models.ToolClaudeCode, BindingKind: "message", BindingID: tc.id, Role: "assistant", Email: tc.email, Source: "fixture", Scope: "test", Stage: "activity", ObservedAt: time.Now()})
	}
	if err := st.RecordToolAccounts(context.Background(), obs); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"?sort_by=account&limit=1", "?sort_by=account&sort_dir=desc&limit=1", "?tail=1", "?limit=1&offset=5"} {
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/session/"+sid+"/messages"+query, nil))
		if rr.Code != 200 {
			t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
		}
		var response struct {
			Total    int `json:"total"`
			Messages []struct {
				Account models.MessageAccount `json:"account"`
			} `json:"messages"`
			Summary struct {
				Observed, Unknown, Conflicts int
				Accounts                     []models.ToolAccountEvidence
			} `json:"account_summary"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Total != 6 || len(response.Messages) != 1 || response.Summary.Observed != 2 || response.Summary.Unknown != 3 || response.Summary.Conflicts != 1 || len(response.Summary.Accounts) != 2 {
			t.Fatalf("bad full timeline summary: %s", rr.Body.String())
		}
		if query == "?sort_by=account&limit=1" && response.Messages[0].Account.Label != "a@example.invalid" {
			t.Fatalf("bad account sort: %s", rr.Body.String())
		}
		if query == "?sort_by=account&sort_dir=desc&limit=1" && response.Messages[0].Account.Label != "z@example.invalid" {
			t.Fatalf("bad reverse account sort: %s", rr.Body.String())
		}
	}
}
