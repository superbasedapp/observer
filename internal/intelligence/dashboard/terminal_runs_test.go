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

func TestTerminalRunsHistoryEmpty(t *testing.T) {
	_, h := newManageServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/runs", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/terminal/runs = %d", rec.Code)
	}
	var resp struct {
		Runs []any `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Runs == nil {
		t.Error("runs must be a (possibly empty) array, never null")
	}
}

// TestTerminalRunsHistoryShowsOrigin pins lane cli-2: the run history
// carries who started each run and an agent's parent session, and omits
// both for a run recorded before migration 220.
func TestTerminalRunsHistoryShowsOrigin(t *testing.T) {
	s, h := newManageServer(t)
	st := store.New(s.opts.DB)
	at := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	for _, r := range []store.TerminalRun{
		{RunID: "run-agent", Tool: "codex", Kind: "fresh", LaunchedAt: at, Initiator: "agent", ParentSessionID: "sess-parent"},
		{RunID: "run-old", Tool: "codex", Kind: "fresh", LaunchedAt: at.Add(-time.Hour)},
	} {
		if err := st.InsertTerminalRun(context.Background(), r); err != nil {
			t.Fatalf("InsertTerminalRun: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/runs", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var resp struct {
		Runs []map[string]any `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byID := map[string]map[string]any{}
	for _, r := range resp.Runs {
		byID[r["run_id"].(string)] = r
	}
	if a := byID["run-agent"]; a["initiator"] != "agent" || a["parent_session_id"] != "sess-parent" {
		t.Fatalf("agent run = %v", a)
	}
	if o := byID["run-old"]; o["initiator"] != nil || o["parent_session_id"] != nil {
		t.Fatalf("a run with no recorded origin carries one: %v", o)
	}
}
