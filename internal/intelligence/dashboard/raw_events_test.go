package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleSessionRawEventsReadsSourceJSONL(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()

	dir := t.TempDir()
	source := filepath.Join(dir, "session.jsonl")
	body := strings.Join([]string{
		`{"timestamp":"2026-07-15T00:00:00Z","type":"turn_context","payload":{"type":"context","turn_id":"t1"}}`,
		`{"timestamp":"2026-07-15T00:00:01Z","type":"event_msg","payload":{"type":"agent_message","message":"not an indexed tool row"}}`,
		`{"timestamp":"2026-07-15T00:00:02Z","type":"response_item","payload":{"type":"function_call","call_id":"call_1","name":"exec_command"}}`,
		``,
	}, "\n")
	if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-07-15T00:00:00Z') RETURNING id`,
		dir).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, started_at)
		 VALUES ('raw-sess', 'codex', ?, '2026-07-15T00:00:00Z')`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id)
		 VALUES ('raw-sess', ?, '2026-07-15T00:00:02Z', 'run_command', 'codex', ?, 'call_1')`,
		projectID, source); err != nil {
		t.Fatal(err)
	}

	srv := &Server{opts: Options{DB: database}}
	req := httptest.NewRequest(http.MethodGet, "/api/session/raw-sess/raw-events?limit=10", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionDetail(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp rawEventsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.SessionID != "raw-sess" || resp.Tool != "codex" {
		t.Fatalf("session/tool = %q/%q", resp.SessionID, resp.Tool)
	}
	if resp.Total != 3 || len(resp.Rows) != 3 {
		t.Fatalf("rows total=%d len=%d want 3/3: %+v", resp.Total, len(resp.Rows), resp.Rows)
	}
	if len(resp.Sources) != 1 || resp.Sources[0].Path != source || resp.Sources[0].Rows != 3 || resp.Sources[0].Error != "" {
		t.Fatalf("sources = %+v", resp.Sources)
	}
	if resp.Rows[1].PayloadType != "agent_message" {
		t.Errorf("row 2 payload_type = %q want agent_message", resp.Rows[1].PayloadType)
	}
	if !strings.Contains(resp.Rows[1].Excerpt, "not an indexed tool row") {
		t.Errorf("row 2 excerpt = %q", resp.Rows[1].Excerpt)
	}
	if resp.Rows[2].EventID != "call_1" {
		t.Errorf("row 3 event_id = %q want call_1", resp.Rows[2].EventID)
	}
}

// TestIsRawJSONLSource pins the source_file filter: an absolute path on the
// daemon's own OS with a .json/.jsonl extension. The Windows rows are the
// regression: a C:\ transcript path used to be dropped by a SQL `LIKE '/%'`
// filter, so a Windows daemon showed zero raw events for every session.
func TestIsRawJSONLSource(t *testing.T) {
	windows := filepath.Separator == '\\'
	tests := []struct {
		name               string
		path               string
		wantWin, wantPOSIX bool
	}{
		{"posix jsonl", "/home/dev/.claude/projects/p/s.jsonl", false, true},
		{"posix json upper-case ext", "/home/dev/.codex/s.JSON", false, true},
		{"windows jsonl", `C:\Users\dev\.claude\projects\p\s.jsonl`, true, false},
		{"windows slash jsonl", "C:/Users/dev/.codex/sessions/s.jsonl", true, false},
		{"absolute but not a transcript", filepath.Join(t.TempDir(), "state.db"), false, false},
		{"relative path", "sessions/s.jsonl", false, false},
		{"non-path marker", "proxy", false, false},
		{"empty", "", false, false},
		// Ledger CLOUDSESS-12: a UNC, device or extended-length path is
		// never opened, on any OS (a Windows UNC open leaks the owner's
		// NTLM hash to the named host).
		{"UNC share", `\\attacker.example@SSL\share\s.jsonl`, false, false},
		{"forward-slash UNC share", "//attacker.example/share/s.jsonl", false, false},
		{"extended-length path", `\\?\C:\Users\dev\s.jsonl`, false, false},
		{"device path", `\\.\pipe\s.jsonl`, false, false},
		{"cloud-session synthetic key", "cloud-session:9f86d081884c7d65", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.wantPOSIX
			if windows {
				want = tc.wantWin
			}
			if got := isRawJSONLSource(tc.path); got != want {
				t.Errorf("isRawJSONLSource(%q) = %v, want %v", tc.path, got, want)
			}
		})
	}
}
