package invariant

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

var update = flag.Bool("update", false, "rewrite golden files instead of comparing")

// endpoints are the headline single-user dashboard reads whose responses
// must not move when org-mode code lands. Params are fixed so the golden
// is a pure function of the seeded corpus; days windows are wide enough
// that the (recent) seed always falls inside them.
var endpoints = []struct {
	name string // golden file base name
	path string
}{
	{"overview", "/api/status"},
	{"sessions", "/api/sessions?limit=50&days=30"},
	{"actions", "/api/actions?limit=100&days=30"},
	{"tools", "/api/tools?days=30"},
	{"cost", "/api/cost?days=30&group_by=model"},
}

func TestSingleUserDashboardInvariant(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "inv.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	seed(ctx, t, store.New(database))

	// DBPath is cosmetic (header display + a stat for db_size_bytes) and is
	// not used to open anything — pin it to a fixed value so /api/status's
	// db_path / db_size_bytes are reproducible regardless of the temp dir.
	srv, err := dashboard.New(dashboard.Options{DB: database, DBPath: "/inv/observer.db"})
	if err != nil {
		t.Fatalf("dashboard.New: %v", err)
	}
	handler := srv.Handler()

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ep.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s: status %d, body=%s", ep.path, rec.Code, rec.Body.String())
			}
			assertSchemaVersionIsHead(t, rec.Body.Bytes())
			got := canonicalize(t, rec.Body.Bytes())

			golden := filepath.Join("golden", ep.name+".json")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatalf("write golden %s: %v", golden, err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden %s: %v (run `go test ./tests/invariant -update` to create it)", golden, err)
			}
			if string(got) != string(want) {
				t.Errorf("%s response diverged from golden %s.\n--- got ---\n%s\n--- want ---\n%s",
					ep.path, golden, got, want)
			}
		})
	}
}

// assertSchemaVersionIsHead checks a response's top-level schema_version, when
// it has one, against the node lineage head. The golden tokenises the value,
// so this is where a wrong version is still caught.
func assertSchemaVersionIsHead(t *testing.T, body []byte) {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		return // not an object; canonicalize reports undecodable bodies
	}
	raw, ok := top["schema_version"]
	if !ok {
		return
	}
	if got, want := raw, float64(db.LatestSchemaVersion()); got != want {
		t.Errorf("schema_version = %v, want the node lineage head %v", got, want)
	}
}

// seed writes a fixed, reproducible corpus: two projects, three sessions
// across three tools, a spread of action types (incl. a failure), token
// usage rows, and proxy-accurate api_turns. Timestamps are relative to a
// recent base (so they sit inside any days>=1 window) with distinct
// per-row offsets (so list ordering is total); the canonicaliser tokenises
// the absolute values out of the response.
func seed(ctx context.Context, t *testing.T, st *store.Store) {
	t.Helper()
	const (
		alpha = "/inv/project-alpha"
		beta  = "/inv/project-beta"
	)
	base := time.Now().UTC().Add(-2 * time.Hour)
	at := func(min int) time.Time { return base.Add(time.Duration(min) * time.Minute) }

	events := []models.ToolEvent{
		{SourceFile: "cc.jsonl", SourceEventID: "cc-1", SessionID: "sess-cc-1", ProjectRoot: alpha, Timestamp: at(0), Tool: models.ToolClaudeCode, Model: "claude-opus-4-7", ActionType: models.ActionReadFile, Target: "main.go", Success: true},
		{SourceFile: "cc.jsonl", SourceEventID: "cc-2", SessionID: "sess-cc-1", ProjectRoot: alpha, Timestamp: at(1), Tool: models.ToolClaudeCode, Model: "claude-opus-4-7", ActionType: models.ActionEditFile, Target: "main.go", Success: true},
		{SourceFile: "cc.jsonl", SourceEventID: "cc-3", SessionID: "sess-cc-1", ProjectRoot: alpha, Timestamp: at(2), Tool: models.ToolClaudeCode, Model: "claude-opus-4-7", ActionType: models.ActionRunCommand, Target: "go test ./...", Success: false, ErrorMessage: "exit 1"},
		{SourceFile: "cur.jsonl", SourceEventID: "cur-1", SessionID: "sess-cur-1", ProjectRoot: alpha, Timestamp: at(10), Tool: models.ToolCursor, Model: "claude-sonnet-4-5", ActionType: models.ActionSearchText, Target: "TODO", Success: true},
		{SourceFile: "cur.jsonl", SourceEventID: "cur-2", SessionID: "sess-cur-1", ProjectRoot: alpha, Timestamp: at(11), Tool: models.ToolCursor, Model: "claude-sonnet-4-5", ActionType: models.ActionWriteFile, Target: "notes.md", Success: true},
		{SourceFile: "cdx.jsonl", SourceEventID: "cdx-1", SessionID: "sess-cdx-1", ProjectRoot: beta, Timestamp: at(20), Tool: models.ToolCodex, Model: "gpt-5-codex", ActionType: models.ActionReadFile, Target: "lib.rs", Success: true},
		{SourceFile: "cdx.jsonl", SourceEventID: "cdx-2", SessionID: "sess-cdx-1", ProjectRoot: beta, Timestamp: at(21), Tool: models.ToolCodex, Model: "gpt-5-codex", ActionType: models.ActionRunCommand, Target: "cargo build", Success: true},
	}

	tokens := []models.TokenEvent{
		{SourceFile: "cc.jsonl", SourceEventID: "cc-tok-1", SessionID: "sess-cc-1", ProjectRoot: alpha, Timestamp: at(2), Tool: models.ToolClaudeCode, Model: "claude-opus-4-7", InputTokens: 1200, OutputTokens: 800, CacheReadTokens: 4000, Source: "jsonl", Reliability: "unreliable"},
		{SourceFile: "cur.jsonl", SourceEventID: "cur-tok-1", SessionID: "sess-cur-1", ProjectRoot: alpha, Timestamp: at(11), Tool: models.ToolCursor, Model: "claude-sonnet-4-5", InputTokens: 500, OutputTokens: 300, Source: "jsonl", Reliability: "unreliable"},
		{SourceFile: "cdx.jsonl", SourceEventID: "cdx-tok-1", SessionID: "sess-cdx-1", ProjectRoot: beta, Timestamp: at(21), Tool: models.ToolCodex, Model: "gpt-5-codex", InputTokens: 900, OutputTokens: 600, Source: "jsonl", Reliability: "unreliable"},
	}

	if _, err := st.Ingest(ctx, events, tokens, store.IngestOptions{}); err != nil {
		t.Fatalf("seed Ingest: %v", err)
	}

	// Proxy-accurate api_turns drive the SourceAuto cost rollup.
	turns := []models.APITurn{
		{SessionID: "sess-cc-1", ProjectID: 1, Timestamp: at(2), Provider: "anthropic", Model: "claude-opus-4-7", RequestID: "req-cc-1", InputTokens: 1200, OutputTokens: 800, CacheReadTokens: 4000, MessageCount: 3, ToolUseCount: 2, CostUSD: 0.0421},
		{SessionID: "sess-cdx-1", ProjectID: 2, Timestamp: at(21), Provider: "openai", Model: "gpt-5-codex", RequestID: "req-cdx-1", InputTokens: 900, OutputTokens: 600, MessageCount: 2, ToolUseCount: 1, CostUSD: 0.0188},
	}
	for _, turn := range turns {
		if _, err := st.InsertAPITurn(ctx, turn); err != nil {
			t.Fatalf("seed InsertAPITurn: %v", err)
		}
	}
}

// canonicalize decodes the JSON body, tokenises every absolute timestamp
// to a stable placeholder, and re-marshals with sorted map keys so the
// golden is reproducible across machines and wall-clock dates.
func canonicalize(t *testing.T, body []byte) []byte {
	t.Helper()
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("unmarshal response: %v\nbody=%s", err, body)
	}
	v = normalize(v)
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal canonical: %v", err)
	}
	return append(out, '\n')
}

func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			// uptime_seconds counts wall-clock seconds since process
			// start (added to /api/status by usability-arc P1.9) —
			// volatile by definition, like the timestamps tokenised
			// below. DELETE it rather than pin it: the field's
			// PRESENCE is timing-dependent too (omitted when a fast
			// test run rounds uptime to 0), so a value placeholder
			// still left the golden flaky across hosts (caught by the
			// first post-lint-unblock CI run, 2026-06-11).
			if k == "uptime_seconds" {
				delete(x, k)
				continue
			}
			// host_os is runtime.GOOS (added to /api/status so the
			// terminal key bar labels ⌃/⌥ from the DAEMON's platform
			// rather than the browser's — the browser is usually a
			// phone that is not the machine being typed into).
			// TOKENISED, not deleted, unlike uptime_seconds above: the
			// value differs per host, but the field's PRESENCE does
			// not, so pinning presence still catches an accidental
			// removal — the same reason timestamps are tokenised
			// rather than dropped.
			if k == "host_os" {
				x[k] = "<GOOS>"
				continue
			}
			// host_name is os.Hostname (added to /api/status by T-425 so
			// a remote node dashboard can always name the machine it
			// shows; D-337). Machine-specific like host_os, so it is
			// TOKENISED for the same reason: the value differs per host
			// but the field's presence pins the T-425 contract.
			if k == "host_name" {
				x[k] = "<HOSTNAME>"
				continue
			}
			// schema_version is the node lineage head, which moves with
			// every agent migration. TOKENISED so a new migration needs no
			// golden edit (lane TESTDB, item 9); its value is checked against
			// the lineage head in TestSingleUserDashboardInvariant instead.
			if k == "schema_version" {
				x[k] = "<SCHEMA_VERSION>"
				continue
			}
			x[k] = normalize(val)
		}
		return x
	case []any:
		for i, val := range x {
			x[i] = normalize(val)
		}
		return x
	case string:
		if isTimestamp(x) {
			return "<TS>"
		}
		return x
	default:
		return x
	}
}

func isTimestamp(s string) bool {
	if len(s) < 20 { // shortest RFC3339 is "2006-01-02T15:04:05Z"
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return true
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}
