package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xuri/excelize/v2"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	// Seed minimal data.
	st := store.New(database)
	root := t.TempDir()
	// Timestamp is relative-to-now so the seeded action always falls
	// within any "last N days" query window. Hardcoded dates here turn
	// into time bombs as the clock advances past the test window — the
	// previous 2026-04-16 seed silently broke TestAPITimeseriesActions
	// and TestAPITools once the test ran past 2026-05-16.
	base := time.Now().UTC().Add(-time.Hour)
	_, err = st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sA",
		ProjectRoot: root, Timestamp: base, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}

	s, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	return s, root
}

// TestIndexHTML_Served confirms `/` serves the React SPA shell after
// the Phase 8 cutover. The legacy `static/index.html` is gone; the
// rendered HTML now comes from the Vite build embedded under
// internal/intelligence/dashboard/webapp/dist.
func TestIndexHTML_Served(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET /: %d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), "<title>SuperBased</title>") {
		t.Errorf("missing title: %s", body)
	}
	if !strings.Contains(string(body), `<div id="root"></div>`) {
		t.Errorf("missing React root marker: %s", body)
	}
}

// TestAPIWatcherHealth_OrphanCursorFiltered pins the v1.4.25 fix: a
// parse_cursors row whose path no current adapter recognises (older
// adapter versions tracked broader patterns) gets tagged
// orphan_unmatched and excluded from the behind_count. Without this
// the user-visible banner would show such rows forever — Rescan
// can't process them, so they'd never close.
func TestAPIWatcherHealth_OrphanCursorFiltered(t *testing.T) {
	s, root := newTestServer(t)

	// Seed two parse_cursors rows. One file lives in t.TempDir() (the
	// "real" file the predicate will accept) and is on-disk so a
	// stat() succeeds; the other is fictional and the predicate
	// rejects it as orphan.
	realPath := filepath.Join(root, "rollout-real.jsonl")
	if err := writeFile(realPath, "x"); err != nil {
		t.Fatal(err)
	}
	orphanPath := filepath.Join(root, "GitHub Copilot Chat.log")
	if err := writeFile(orphanPath, "yyyy"); err != nil {
		t.Fatal(err)
	}

	// Both at offset 0 so file_size > byte_offset → both LOOK behind.
	if _, err := s.opts.DB.ExecContext(
		context.Background(),
		`INSERT INTO parse_cursors (source_file, byte_offset, last_parsed) VALUES (?, 0, ?), (?, 0, ?)`,
		realPath, time.Now().Format(time.RFC3339Nano),
		orphanPath, time.Now().Format(time.RFC3339Nano),
	); err != nil {
		t.Fatal(err)
	}

	// Predicate accepts only the rollout pattern.
	s.opts.RecognizesSessionFile = func(p string) bool {
		return strings.HasPrefix(filepath.Base(p), "rollout-")
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health/watcher", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["behind_count"].(float64) != 1 {
		t.Errorf("behind_count: %v want 1 (orphan must NOT be counted)", got["behind_count"])
	}
	if got["orphan_count"].(float64) != 1 {
		t.Errorf("orphan_count: %v want 1", got["orphan_count"])
	}
	files := got["files"].([]any)
	if len(files) != 2 {
		t.Fatalf("files: %d want 2 (both still listed, only counts differ)", len(files))
	}
	// Find the orphan and verify the flag.
	var orphanFlagged bool
	for _, fAny := range files {
		f := fAny.(map[string]any)
		if strings.HasSuffix(f["path"].(string), "GitHub Copilot Chat.log") {
			orphanFlagged = f["orphan_unmatched"] == true
		}
	}
	if !orphanFlagged {
		t.Error("orphan row should carry orphan_unmatched=true")
	}
}

// writeFile is a tiny helper for the orphan test.
func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

// TestAPIWatcherHealth_SuspectedMisrouted pins the v1.4.51
// suspected_misrouted heuristic: a parse_cursors row whose cursor
// reached EOF on a non-trivial file but the actions table has zero
// rows for that source_file gets flagged as a suspected pre-v1.4.51
// misroute. The operator-driven recovery is
// `observer scan --force --adapter <name>`.
func TestAPIWatcherHealth_SuspectedMisrouted(t *testing.T) {
	s, root := newTestServer(t)

	// A non-trivial file (well above the 1KB threshold) the predicate
	// will accept.
	bigPath := filepath.Join(root, "rollout-suspect.jsonl")
	body := strings.Repeat("padding line\n", 200) // ~2.4 KB
	if err := writeFile(bigPath, body); err != nil {
		t.Fatal(err)
	}
	// Cursor seeded at EOF: byte_offset == file size → caught up.
	if _, err := s.opts.DB.ExecContext(
		context.Background(),
		`INSERT INTO parse_cursors (source_file, byte_offset, last_parsed) VALUES (?, ?, ?)`,
		bigPath, len(body), time.Now().Format(time.RFC3339Nano),
	); err != nil {
		t.Fatal(err)
	}
	// Crucially: no rows inserted into actions for this source_file.
	// That's the pre-v1.4.51 fingerprint (claude-code "parsed" a
	// Codex file, advanced cursor to EOF, emitted nothing).

	s.opts.RecognizesSessionFile = func(p string) bool {
		return strings.HasPrefix(filepath.Base(p), "rollout-")
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health/watcher", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["suspected_misrouted_count"].(float64) != 1 {
		t.Errorf("suspected_misrouted_count: %v want 1", got["suspected_misrouted_count"])
	}
	files := got["files"].([]any)
	var flagged bool
	for _, fAny := range files {
		f := fAny.(map[string]any)
		if f["suspected_misrouted"] == true {
			flagged = true
			if reason, ok := f["misroute_reason"].(string); !ok || reason == "" {
				t.Errorf("suspected_misrouted row missing misroute_reason: %v", f)
			}
		}
	}
	if !flagged {
		t.Error("expected at least one row with suspected_misrouted=true")
	}
}

// TestAPIWatcherHealth_SmallFileNotFlaggedAsSuspect pins the
// 1KB-min-bytes guard — empty/stub session files (cursor at EOF, no
// actions) must NOT be flagged because real sessions sometimes start
// with a session_meta line and nothing else when the user closes
// the IDE immediately.
func TestAPIWatcherHealth_SmallFileNotFlaggedAsSuspect(t *testing.T) {
	s, root := newTestServer(t)

	smallPath := filepath.Join(root, "rollout-stub.jsonl")
	body := "stub" // 4 bytes
	if err := writeFile(smallPath, body); err != nil {
		t.Fatal(err)
	}
	if _, err := s.opts.DB.ExecContext(
		context.Background(),
		`INSERT INTO parse_cursors (source_file, byte_offset, last_parsed) VALUES (?, ?, ?)`,
		smallPath, len(body), time.Now().Format(time.RFC3339Nano),
	); err != nil {
		t.Fatal(err)
	}
	s.opts.RecognizesSessionFile = func(p string) bool { return true }

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health/watcher", nil)
	s.Handler().ServeHTTP(rr, req)
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["suspected_misrouted_count"].(float64) != 0 {
		t.Errorf("suspected_misrouted_count: %v want 0 (file below 1KB threshold)", got["suspected_misrouted_count"])
	}
}

func TestAPIStatus(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	counts, ok := got["counts"].(map[string]any)
	if !ok {
		t.Fatalf("missing counts map: %+v", got)
	}
	if counts["sessions"] == nil || counts["actions"] == nil {
		t.Errorf("missing session/action counts: %+v", counts)
	}
}

// TestAPIStatusCarriesHostOS pins the DAEMON's OS on /api/status.
//
// The dashboard's on-screen terminal key bar labels its modifier keys from
// this field (⌃/⌥ on darwin, Ctrl/Alt elsewhere): the vocabulary describes
// the machine whose PTY is being typed into, and the browser is very often a
// phone that is NOT that machine. The field must therefore always be present
// and must be runtime.GOOS of the serving process — never a client guess.
func TestAPIStatusCarriesHostOS(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	hostOS, ok := got["host_os"].(string)
	if !ok {
		t.Fatalf("host_os missing from /api/status: %+v", got)
	}
	if hostOS != runtime.GOOS {
		t.Errorf("host_os = %q, want %q (runtime.GOOS of the daemon)", hostOS, runtime.GOOS)
	}
}

func TestAPICodexSupport_ChatGPTJSONLOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	now := time.Now().UTC()
	_, err = st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "codex.jsonl", SourceEventID: "e1", SessionID: "codex-s1",
		ProjectRoot: t.TempDir(), Timestamp: now.Add(-5 * time.Minute),
		Tool: models.ToolCodex, ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, []models.TokenEvent{{
		SessionID: "codex-s1", Timestamp: now.Add(-4 * time.Minute), Tool: models.ToolCodex,
		Model: "gpt-5", InputTokens: 100, OutputTokens: 20, Source: models.TokenSourceJSONL,
		Reliability: models.ReliabilityApproximate, SourceFile: "codex.jsonl", SourceEventID: "tok1",
	}}, store.IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}

	codexHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(codexHome, "auth.json"), []byte(`{"auth_mode":"chatgpt"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)

	s, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/codex/support?days=30", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["auth_mode"] != "chatgpt" {
		t.Fatalf("auth_mode: %v", got["auth_mode"])
	}
	if got["mode"] != "jsonl_only" {
		t.Fatalf("mode: %v", got["mode"])
	}
	if got["compression_mode"] != "unavailable" {
		t.Fatalf("compression_mode: %v", got["compression_mode"])
	}
	if got["linked_api_turn_count"].(float64) != 0 {
		t.Fatalf("linked_api_turn_count: %v", got["linked_api_turn_count"])
	}
	summary := got["summary"].(string)
	if !strings.Contains(summary, "ChatGPT-auth") {
		t.Fatalf("summary missing ChatGPT explanation: %q", summary)
	}
}

func TestAPICodexSupport_ChatGPTProxyUnlinked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	now := time.Now().UTC()
	_, err = st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "codex.jsonl", SourceEventID: "e1", SessionID: "codex-s1",
		ProjectRoot: t.TempDir(), Timestamp: now.Add(-5 * time.Minute),
		Tool: models.ToolCodex, ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, []models.TokenEvent{{
		SessionID: "codex-s1", Timestamp: now.Add(-4 * time.Minute), Tool: models.ToolCodex,
		Model: "gpt-5.5", InputTokens: 100, OutputTokens: 20, Source: models.TokenSourceJSONL,
		Reliability: models.ReliabilityApproximate, SourceFile: "codex.jsonl", SourceEventID: "tok1",
	}}, store.IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		Timestamp:                  now.Add(-3 * time.Minute),
		Provider:                   models.ProviderOpenAI,
		Model:                      "gpt-5.5",
		CompressionOriginalBytes:   4000,
		CompressionCompressedBytes: 900,
		CompressionCount:           1,
	}); err != nil {
		t.Fatal(err)
	}

	codexHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(codexHome, "auth.json"), []byte(`{"auth_mode":"chatgpt"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)

	s, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/codex/support?days=30", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["mode"] != "proxy_unlinked+jsonl" {
		t.Fatalf("mode: %v", got["mode"])
	}
	if got["compression_mode"] != "live_unlinked" {
		t.Fatalf("compression_mode: %v", got["compression_mode"])
	}
	if got["unlinked_api_turn_count"].(float64) != 1 {
		t.Fatalf("unlinked_api_turn_count: %v", got["unlinked_api_turn_count"])
	}
}

func TestAPICodexSupport_ProxyLinked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()
	_, err = st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "codex.jsonl", SourceEventID: "e1", SessionID: "codex-s1",
		ProjectRoot: root, Timestamp: now.Add(-10 * time.Minute),
		Tool: models.ToolCodex, ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, []models.TokenEvent{{
		SessionID: "codex-s1", Timestamp: now.Add(-9 * time.Minute), Tool: models.ToolCodex,
		Model: "gpt-5", InputTokens: 100, OutputTokens: 20, Source: models.TokenSourceJSONL,
		Reliability: models.ReliabilityApproximate, SourceFile: "codex.jsonl", SourceEventID: "tok1",
	}}, store.IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "codex-s1", Timestamp: now.Add(-8 * time.Minute),
		Provider: models.ProviderOpenAI, Model: "gpt-5", InputTokens: 100, OutputTokens: 20,
	}); err != nil {
		t.Fatal(err)
	}

	s, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/codex/support?days=30", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["mode"] != "proxy+jsonl" {
		t.Fatalf("mode: %v", got["mode"])
	}
	if got["compression_mode"] != "live" {
		t.Fatalf("compression_mode: %v", got["compression_mode"])
	}
	if got["linked_api_turn_count"].(float64) != 1 {
		t.Fatalf("linked_api_turn_count: %v", got["linked_api_turn_count"])
	}
}

func TestAPICost_Shape(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cost?days=30&group_by=model", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("cost: %d  body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["group_by"] == nil {
		t.Errorf("missing group_by: %+v", got)
	}
}

// TestAPICost_TotalCompression verifies that when api_turns carries
// compression stats, /api/cost surfaces them in the total_compression
// block and at least one row's compression.original_bytes > 0.
func TestAPICost_TotalCompression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	turn := models.APITurn{
		SessionID:                  "sA",
		Timestamp:                  time.Now().UTC().Add(-time.Hour),
		Provider:                   models.ProviderAnthropic,
		Model:                      "claude-sonnet-4",
		InputTokens:                100,
		OutputTokens:               50,
		CompressionOriginalBytes:   10000,
		CompressionCompressedBytes: 3000,
		CompressionCount:           2,
		CompressionDroppedCount:    1,
		CompressionMarkerCount:     1,
	}
	if _, err := st.InsertAPITurn(context.Background(), turn); err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cost?days=30&group_by=model", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("cost: %d  body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	tc, ok := got["total_compression"].(map[string]any)
	if !ok {
		t.Fatalf("missing total_compression: %+v", got)
	}
	orig, _ := tc["original_bytes"].(float64)
	compressed, _ := tc["compressed_bytes"].(float64)
	if int(orig) != 10000 {
		t.Errorf("original_bytes: got %v want 10000", tc["original_bytes"])
	}
	if int(compressed) != 3000 {
		t.Errorf("compressed_bytes: got %v want 3000", tc["compressed_bytes"])
	}
	rows, _ := got["rows"].([]any)
	if len(rows) == 0 {
		t.Fatalf("no rows in cost summary: %+v", got)
	}
	row0, _ := rows[0].(map[string]any)
	rc, ok := row0["compression"].(map[string]any)
	if !ok {
		t.Fatalf("row[0] missing compression: %+v", row0)
	}
	if int(rc["original_bytes"].(float64)) != 10000 {
		t.Errorf("row compression original_bytes: %v", rc["original_bytes"])
	}
}

// TestAPICompressionEvents seeds two compression_events rows and an
// owning api_turn, then verifies /api/compression/events returns them
// with derived saved_bytes and joined model. Pins the contract behind
// the new "Recent compression events" table on the Compression tab.
func TestAPICompressionEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	now := time.Now().UTC()
	turn := models.APITurn{
		SessionID: "s1", Timestamp: now.Add(-time.Hour),
		Provider: models.ProviderAnthropic, Model: "claude-sonnet-4",
		InputTokens: 100, OutputTokens: 50,
		CompressionOriginalBytes:   30000,
		CompressionCompressedBytes: 8000,
		CompressionEvents: []models.CompressionEvent{
			{Mechanism: "json", OriginalBytes: 20000, CompressedBytes: 5000, MsgIndex: 3},
			{Mechanism: "drop", OriginalBytes: 10000, CompressedBytes: 0, MsgIndex: 5, ImportanceScore: 0.12},
		},
	}
	for i := range turn.CompressionEvents {
		turn.CompressionEvents[i].Timestamp = turn.Timestamp
	}
	if _, err := st.InsertAPITurn(context.Background(), turn); err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/compression/events?days=30", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("/api/compression/events: %d  body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if int(got["total"].(float64)) != 2 {
		t.Fatalf("total: got %v want 2", got["total"])
	}
	rows, _ := got["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows: got %d want 2", len(rows))
	}
	// Rows ordered by timestamp DESC, id DESC — the second event
	// inserted (drop) lands first.
	first := rows[0].(map[string]any)
	if first["mechanism"] != "drop" {
		t.Errorf("first row mechanism: got %v want drop", first["mechanism"])
	}
	// `drop` is a lossy-eviction mechanism (compressed_bytes == 0 by
	// construction). Its bytes are reported as EVICTED, never as saved,
	// and never priced — otherwise the row would read as a fake
	// "10 KB / 100% saved / $X".
	if lossy, _ := first["lossy"].(bool); !lossy {
		t.Errorf("first lossy: got %v want true", first["lossy"])
	}
	if int(first["evicted_bytes"].(float64)) != 10000 {
		t.Errorf("first evicted_bytes: got %v want 10000", first["evicted_bytes"])
	}
	if int(first["saved_bytes"].(float64)) != 0 {
		t.Errorf("first saved_bytes: got %v want 0 (evicted, not saved)", first["saved_bytes"])
	}
	if first["model"] != "claude-sonnet-4" {
		t.Errorf("first model: got %v want claude-sonnet-4", first["model"])
	}
	// Evicted bytes are never priced as savings — $ must be 0.
	if dropUSD, _ := first["saved_usd_est"].(float64); dropUSD != 0 {
		t.Errorf("first saved_usd_est: got %v want 0 (evicted content is not priced)", dropUSD)
	}

	// The `json` event is a genuine (compressing) mechanism — it keeps
	// its real saved_bytes and priced $, and is not flagged lossy.
	second := rows[1].(map[string]any)
	if second["mechanism"] != "json" {
		t.Fatalf("second row mechanism: got %v want json", second["mechanism"])
	}
	if lossy, _ := second["lossy"].(bool); lossy {
		t.Errorf("second lossy: got true want false (json compresses)")
	}
	if int(second["saved_bytes"].(float64)) != 15000 {
		t.Errorf("second saved_bytes: got %v want 15000", second["saved_bytes"])
	}
	jsonUSD, _ := second["saved_usd_est"].(float64)
	wantJSONUSD := (15000.0 / 4) * 3.0 / 1_000_000
	if !approxEqual(jsonUSD, wantJSONUSD, 1e-9) {
		t.Errorf("second saved_usd_est: got %v want %v", jsonUSD, wantJSONUSD)
	}

	// Mechanism filter: only json
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/compression/events?days=30&mechanism=json", nil)
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != 200 {
		t.Fatalf("filtered: %d", rr2.Code)
	}
	var got2 map[string]any
	json.NewDecoder(rr2.Body).Decode(&got2)
	if int(got2["total"].(float64)) != 1 {
		t.Errorf("filtered total: got %v want 1", got2["total"])
	}
}

// TestAPICompressionTimeseries verifies the per-day per-mechanism
// rollup shape — feeds the "Savings by mechanism" stacked-bar chart.
func TestAPICompressionTimeseries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	now := time.Now().UTC()
	turn := models.APITurn{
		SessionID: "s1", Timestamp: now.Add(-2 * time.Hour),
		Provider: models.ProviderAnthropic, Model: "claude-sonnet-4",
		CompressionEvents: []models.CompressionEvent{
			{Mechanism: "json", Timestamp: now.Add(-2 * time.Hour), OriginalBytes: 10000, CompressedBytes: 3000},
			{Mechanism: "json", Timestamp: now.Add(-2 * time.Hour), OriginalBytes: 5000, CompressedBytes: 1000},
			{Mechanism: "drop", Timestamp: now.Add(-2 * time.Hour), OriginalBytes: 8000, CompressedBytes: 0},
		},
	}
	if _, err := st.InsertAPITurn(context.Background(), turn); err != nil {
		t.Fatal(err)
	}
	srv, _ := New(Options{DB: database, DBPath: path})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/compression/timeseries?bucket=day&days=30", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("/api/compression/timeseries: %d  body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	json.NewDecoder(rr.Body).Decode(&got)
	series, _ := got["series"].([]any)
	if len(series) != 1 {
		t.Fatalf("series: got %d want 1", len(series))
	}
	point := series[0].(map[string]any)
	by, _ := point["by_mechanism"].(map[string]any)
	jsonStats, _ := by["json"].(map[string]any)
	if int(jsonStats["count"].(float64)) != 2 {
		t.Errorf("json count: got %v want 2", jsonStats["count"])
	}
	// 10000+5000-3000-1000 = 11000 saved by json
	if int(jsonStats["saved_bytes"].(float64)) != 11000 {
		t.Errorf("json saved_bytes: got %v want 11000", jsonStats["saved_bytes"])
	}
	// `drop` is a lossy-eviction mechanism: its bytes are reported as
	// evicted, not saved, and are excluded from the point totals. A
	// per-mechanism grouping otherwise renders every drop row as
	// "8 KB / 100% saved" because compressed_bytes is 0 by construction.
	dropStats, _ := by["drop"].(map[string]any)
	if lossy, _ := dropStats["lossy"].(bool); !lossy {
		t.Errorf("drop lossy: got %v want true", dropStats["lossy"])
	}
	if int(dropStats["saved_bytes"].(float64)) != 0 {
		t.Errorf("drop saved_bytes: got %v want 0 (evicted, not saved)", dropStats["saved_bytes"])
	}
	if int(dropStats["evicted_bytes"].(float64)) != 8000 {
		t.Errorf("drop evicted_bytes: got %v want 8000", dropStats["evicted_bytes"])
	}
	if dropUSD, _ := dropStats["saved_usd_est"].(float64); dropUSD != 0 {
		t.Errorf("drop saved_usd_est: got %v want 0 (evicted content is not priced)", dropUSD)
	}

	// Per-mechanism $ saved is priced via the cost engine —
	// claude-sonnet-4 is in baked-in pricing at $3 / 1M input tokens
	// (matches TestAPICost_CompressionSavingsDerived). Tokens =
	// saved_bytes / 4; $ = tokens × input_rate / 1M.
	jsonUSD, _ := jsonStats["saved_usd_est"].(float64)
	wantJSONUSD := (11000.0 / 4) * 3.0 / 1_000_000
	if !approxEqual(jsonUSD, wantJSONUSD, 1e-9) {
		t.Errorf("json saved_usd_est: got %v want %v", jsonUSD, wantJSONUSD)
	}
	// Point totals exclude the lossy drop bytes/$: total_saved_usd_est
	// is json-only, and the evicted bytes surface as total_evicted_bytes.
	totalUSD, _ := point["total_saved_usd_est"].(float64)
	if !approxEqual(totalUSD, wantJSONUSD, 1e-9) {
		t.Errorf("total_saved_usd_est: got %v want %v (drop excluded)", totalUSD, wantJSONUSD)
	}
	if int(point["total_saved_bytes"].(float64)) != 11000 {
		t.Errorf("total_saved_bytes: got %v want 11000 (drop excluded)", point["total_saved_bytes"])
	}
	if int(point["total_evicted_bytes"].(float64)) != 8000 {
		t.Errorf("total_evicted_bytes: got %v want 8000", point["total_evicted_bytes"])
	}
	// total_count still includes the drop event — it is compression
	// activity, just not a saving.
	if int(point["total_count"].(float64)) != 3 {
		t.Errorf("total_count: got %v want 3", point["total_count"])
	}
}

func approxEqual(a, b, eps float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= eps
}

// TestAPIToolsBreakdown seeds two tools with action-type variety and
// asserts /api/tools/breakdown returns per-tool by_type counts.
// Pins the contract behind the action-type-mix chart on Tools tab.
func TestAPIToolsBreakdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()
	events := []models.ToolEvent{
		// claude-code: 2 read, 1 edit
		{
			SourceFile: "f1", SourceEventID: "1", SessionID: "sA", ProjectRoot: root,
			Timestamp: now.Add(-time.Hour), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		},
		{
			SourceFile: "f1", SourceEventID: "2", SessionID: "sA", ProjectRoot: root,
			Timestamp: now.Add(-50 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
		},
		{
			SourceFile: "f1", SourceEventID: "3", SessionID: "sA", ProjectRoot: root,
			Timestamp: now.Add(-40 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionEditFile, Target: "a.go", Success: true,
		},
		// cursor: 2 edit
		{
			SourceFile: "f2", SourceEventID: "4", SessionID: "sB", ProjectRoot: root,
			Timestamp: now.Add(-30 * time.Minute), Tool: models.ToolCursor,
			ActionType: models.ActionEditFile, Target: "c.go", Success: true,
		},
		{
			SourceFile: "f2", SourceEventID: "5", SessionID: "sB", ProjectRoot: root,
			Timestamp: now.Add(-20 * time.Minute), Tool: models.ToolCursor,
			ActionType: models.ActionEditFile, Target: "d.go", Success: true,
		},
	}
	if _, err := st.Ingest(context.Background(), events, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/tools/breakdown?days=30", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("/api/tools/breakdown: %d  body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	rows, _ := got["tools"].([]any)
	if len(rows) != 2 {
		t.Fatalf("expected 2 tools: got %d", len(rows))
	}
	// claude-code should be first (3 actions vs cursor's 2).
	first := rows[0].(map[string]any)
	if first["tool"] != "claude-code" {
		t.Errorf("ordering: got first=%v want claude-code", first["tool"])
	}
	if int(first["total"].(float64)) != 3 {
		t.Errorf("claude-code total: %v want 3", first["total"])
	}
	bt, _ := first["by_type"].(map[string]any)
	if int(bt["read_file"].(float64)) != 2 {
		t.Errorf("claude-code read_file: %v want 2", bt["read_file"])
	}
	if int(bt["edit_file"].(float64)) != 1 {
		t.Errorf("claude-code edit_file: %v want 1", bt["edit_file"])
	}

	// WP-T5 additive dimensions. by_type above is the pre-WP-T5 contract
	// and must keep working untouched; these are the like-to-like ones.
	cats, _ := got["categories"].([]any)
	if len(cats) != len(tooltax.Categories()) {
		t.Errorf("categories: got %d entries want %d", len(cats), len(tooltax.Categories()))
	} else if cats[0] != tooltax.Categories()[0] {
		t.Errorf("categories order: got %v want tooltax display order", cats)
	}
	surfaces, _ := got["surfaces"].([]any)
	if len(surfaces) != len(tooltax.Surfaces())+1 {
		t.Errorf("surfaces: got %v want the canonical surfaces + %q", surfaces, SurfaceUnresolved)
	}

	// jsonInt reads a numeric member without asserting on a possibly
	// absent key — a wrong taxonomy answer must fail as a diff, not as a
	// nil-interface panic that hides the rest of the assertions.
	jsonInt := func(m map[string]any, key string) int {
		v, ok := m[key].(float64)
		if !ok {
			return -1
		}
		return int(v)
	}
	byCat, _ := first["by_category"].(map[string]any)
	// 2 read + 1 edit are all category "file".
	if len(byCat) != 1 || jsonInt(byCat, tooltax.CategoryFile) != 3 {
		t.Errorf("claude-code by_category: %v want {file: 3}", byCat)
	}
	// These fixtures carry no raw_tool_name, so the surface is honestly
	// unresolved rather than guessed to be a builtin.
	bySurface, _ := first["by_surface"].(map[string]any)
	if len(bySurface) != 1 || jsonInt(bySurface, SurfaceUnresolved) != 3 {
		t.Errorf("claude-code by_surface: %v want {%s: 3}", bySurface, SurfaceUnresolved)
	}
	cov, _ := first["coverage"].(map[string]any)
	if jsonInt(cov, "observed_categories") != 1 {
		t.Errorf("coverage.observed_categories: %v want 1", cov["observed_categories"])
	}
	if jsonInt(cov, "canonical_categories") != len(tooltax.Categories()) {
		t.Errorf("coverage.canonical_categories: %v want %d",
			cov["canonical_categories"], len(tooltax.Categories()))
	}
	if cov["vocabulary_declared"] != true {
		t.Errorf("coverage.vocabulary_declared: %v want true", cov["vocabulary_declared"])
	}
	if jsonInt(cov, "expressible_categories") != tooltax.CoverageDepth("claude-code") {
		t.Errorf("coverage.expressible_categories: %v want %d",
			cov["expressible_categories"], tooltax.CoverageDepth("claude-code"))
	}
	// observed(1) is the file category, which claude-code declares, so
	// nothing here is beyond the vocabulary. The key must still be
	// present: it is what stops a client formatting observed and
	// expressible as one ratio (see TestCoverageObservedMayExceedDeclared
	// for the case where observed legitimately exceeds expressible).
	if jsonInt(cov, "observed_beyond_declared") != 0 {
		t.Errorf("coverage.observed_beyond_declared: %v want 0", cov["observed_beyond_declared"])
	}
}

// TestAPICost_CompressionSavingsDerived seeds an api_turn with known
// compression byte deltas and asserts the cost engine derives
// tokens_saved_est (=saved_bytes/4) and cost_saved_usd_est
// (=tokens_saved × model_input_rate) onto the row + total_compression.
// Pins the new headline metrics on the redesigned Compression tab.
func TestAPICost_CompressionSavingsDerived(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	// claude-sonnet-4 is in the baked-in pricing table at $3 / 1M input
	// (as of 2026-04). Verify we look up correctly and compute.
	turn := models.APITurn{
		SessionID: "s1", Timestamp: time.Now().UTC().Add(-time.Hour),
		Provider: models.ProviderAnthropic, Model: "claude-sonnet-4",
		InputTokens:                100,
		OutputTokens:               50,
		CompressionOriginalBytes:   40000,
		CompressionCompressedBytes: 8000, // saved 32000 bytes
		CompressionCount:           4,
		CompressionDroppedCount:    2,
		CompressionMarkerCount:     2,
	}
	if _, err := st.InsertAPITurn(context.Background(), turn); err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}
	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cost?days=30&group_by=model", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("/api/cost: %d  body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	tc, ok := got["total_compression"].(map[string]any)
	if !ok {
		t.Fatalf("missing total_compression: %+v", got)
	}
	// 32000 saved bytes / 4 = 8000 tokens
	if int(tc["tokens_saved_est"].(float64)) != 8000 {
		t.Errorf("total_compression.tokens_saved_est: got %v want 8000", tc["tokens_saved_est"])
	}
	// 8000 × $3/1M = $0.024 (claude-sonnet-4 input rate)
	usd, _ := tc["cost_saved_usd_est"].(float64)
	if usd <= 0 {
		t.Errorf("total_compression.cost_saved_usd_est: got %v want > 0 (model has known pricing)", usd)
	}
	rows, _ := got["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row: got %d", len(rows))
	}
	row := rows[0].(map[string]any)
	rc, _ := row["compression"].(map[string]any)
	if int(rc["tokens_saved_est"].(float64)) != 8000 {
		t.Errorf("row[0].compression.tokens_saved_est: got %v want 8000", rc["tokens_saved_est"])
	}
}

// TestAPICost_TokenMathReconciles seeds api_turns with known per-bucket
// token counts and asserts the /api/cost summary sums them correctly,
// per-row and in the total_tokens aggregate. Pins the contract behind
// the user-visible "Net In / Cache R / Cache W / Output" cost-table
// columns and the cost-summary line.
func TestAPICost_TokenMathReconciles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	now := time.Now().UTC()
	turns := []models.APITurn{
		{
			SessionID: "s1", Timestamp: now.Add(-2 * time.Hour),
			Provider: models.ProviderAnthropic, Model: "claude-sonnet-4",
			InputTokens: 1000, CacheReadTokens: 4000,
			CacheCreationTokens: 200, OutputTokens: 500,
		},
		{
			SessionID: "s1", Timestamp: now.Add(-time.Hour),
			Provider: models.ProviderAnthropic, Model: "claude-sonnet-4",
			InputTokens: 2000, CacheReadTokens: 6000,
			CacheCreationTokens: 100, OutputTokens: 800,
		},
	}
	for _, tu := range turns {
		if _, err := st.InsertAPITurn(context.Background(), tu); err != nil {
			t.Fatalf("InsertAPITurn: %v", err)
		}
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cost?days=30&group_by=model", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("/api/cost: %d  body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	tt, ok := got["total_tokens"].(map[string]any)
	if !ok {
		t.Fatalf("missing total_tokens: %+v", got)
	}
	// 1000 + 2000 = 3000 net input
	if int(tt["input"].(float64)) != 3000 {
		t.Errorf("total_tokens.input: got %v want 3000", tt["input"])
	}
	// 4000 + 6000 = 10000 cache read
	if int(tt["cache_read"].(float64)) != 10000 {
		t.Errorf("total_tokens.cache_read: got %v want 10000", tt["cache_read"])
	}
	// 200 + 100 = 300 cache creation
	if int(tt["cache_creation"].(float64)) != 300 {
		t.Errorf("total_tokens.cache_creation: got %v want 300", tt["cache_creation"])
	}
	// 500 + 800 = 1300 output
	if int(tt["output"].(float64)) != 1300 {
		t.Errorf("total_tokens.output: got %v want 1300", tt["output"])
	}
	// Per-row tokens should reconcile too — single row since both turns
	// are the same model.
	rows, _ := got["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row (one model): got %d", len(rows))
	}
	row := rows[0].(map[string]any)
	rt := row["tokens"].(map[string]any)
	if int(rt["input"].(float64)) != 3000 ||
		int(rt["cache_read"].(float64)) != 10000 ||
		int(rt["cache_creation"].(float64)) != 300 ||
		int(rt["output"].(float64)) != 1300 {
		t.Errorf("row[0].tokens mismatch: %+v", rt)
	}
	if int(row["turn_count"].(float64)) != 2 {
		t.Errorf("row[0].turn_count: got %v want 2", row["turn_count"])
	}
}

// TestAPIExportXLSX_Sheets seeds minimal data and verifies the export
// endpoint returns a non-empty xlsx with the expected sheet names.
// Catches regressions where a sheet writer panics or excelize fails to
// render the workbook.
func TestAPIExportXLSX_Sheets(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/export.xlsx?days=30", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("/api/export.xlsx: %d  body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); !strings.Contains(got, "spreadsheetml") {
		t.Errorf("Content-Type: got %q want xlsx", got)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("Content-Disposition: got %q", cd)
	}
	body := rr.Body.Bytes()
	if len(body) < 1024 {
		t.Fatalf("xlsx body suspiciously small: %d bytes", len(body))
	}
	// xlsx is a zip — check the magic.
	if body[0] != 'P' || body[1] != 'K' {
		t.Errorf("body doesn't start with PK zip magic: %q", body[:8])
	}
	// Open the workbook from the response bytes and assert the expected
	// sheet names exist.
	f, err := excelize.OpenReader(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("excelize.OpenReader: %v", err)
	}
	defer f.Close()
	want := map[string]bool{
		"Overview": false, "Cost": false, "Sessions": false,
		"Actions": false, "Tools": false, "Compression": false,
		"Discovery — stale rereads": false, "Discovery — repeated commands": false,
		"Patterns": false,
	}
	for _, name := range f.GetSheetList() {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for k, ok := range want {
		if !ok {
			t.Errorf("missing sheet: %q", k)
		}
	}
}

// Phase 8 cutover (2026-05-16) removed the legacy vanilla-JS
// SPA whose static markup these regression guards asserted on:
//
//   - TestIndexHTML_HasSavingsSection (compression anchors / ids)
//   - TestIndexHTML_CostPanelExposesAllTokenBuckets (Net Input /
//     Cache Read / Cache Write / Output literal text and the JS
//     `tokens.cache_read` / `tokens.cache_creation` template
//     literals)
//
// The React build renders all of that client-side from the API,
// so the markers don't appear in server-rendered HTML. The
// data-correctness intent (every billing bucket is exposed
// separately, never collapsed) lives on in the API tests:
// TestAPICost_TokenMathReconciles, TestAPICompressionTimeseries,
// TestAPICost_TotalCompression, TestAPIToolsBreakdown.

func TestAPISessions_ReturnsRows(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("sessions: %d", rr.Code)
	}
	var got struct {
		Rows  []map[string]any `json:"rows"`
		Page  int              `json:"page"`
		Limit int              `json:"limit"`
		Total int              `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Total != 1 {
		t.Fatalf("expected total=1, got %d", got.Total)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 session row, got %d", len(got.Rows))
	}
	if got.Page != 1 || got.Limit != 10 {
		t.Errorf("page/limit: got %d/%d want 1/10", got.Page, got.Limit)
	}
	// Regression guard for A4: total_actions must reflect the count of
	// actions joined live, not the never-written sessions.total_actions
	// stored column. Fixture seeds exactly one ToolEvent for "sA".
	if got.Rows[0]["total_actions"].(float64) != 1 {
		t.Errorf("total_actions: got %v want 1 (seed has one action)",
			got.Rows[0]["total_actions"])
	}
}

// TestAPISessions_HidesMarkerOnlySessions pins the fix for the empty
// Windows-CC probe sessions: a session whose only action is a lifecycle /
// meta marker (instructions_loaded, config_change, …) with no token_usage
// or api_turns is contentless and must not surface on /api/sessions. The
// store still physically holds the rows (store.Ingest bootstraps them
// because these markers can precede a real session) — the filter lives at
// the read layer, so we assert the rows exist in the DB but are excluded
// from both the list and the pagination total. The real "sA" session
// (seeded with a read_file action) must still appear.
func TestAPISessions_HidesMarkerOnlySessions(t *testing.T) {
	s, root := newTestServer(t)
	st := store.New(s.opts.DB)
	base := time.Now().UTC().Add(-time.Hour)

	// Two probe sessions: one instructions_loaded-only, one config_change-only.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "sIL:instructions_loaded:/r/CLAUDE.md",
			SessionID: "sIL", ProjectRoot: root, Timestamp: base, Tool: models.ToolClaudeCode,
			ActionType: models.ActionInstructionsLoaded, Target: "/r/CLAUDE.md", Success: true,
		},
		{
			SourceFile: "f", SourceEventID: "sCfg:config_change",
			SessionID: "sCfg", ProjectRoot: root, Timestamp: base, Tool: models.ToolClaudeCode,
			ActionType: models.ActionConfigChange, Target: "settings.json", Success: true,
		},
	}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// Sanity: the probe sessions ARE in the DB (filter, not non-insertion).
	var seeded int
	if err := s.opts.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE id IN ('sIL','sCfg')`).Scan(&seeded); err != nil {
		t.Fatal(err)
	}
	if seeded != 2 {
		t.Fatalf("expected both probe sessions persisted, got %d", seeded)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("sessions: %d", rr.Code)
	}
	var got struct {
		Rows  []map[string]any `json:"rows"`
		Total int              `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Total != 1 {
		t.Fatalf("total: got %d want 1 (only the real session, probes hidden)", got.Total)
	}
	if len(got.Rows) != 1 || got.Rows[0]["id"] != "sA" {
		t.Fatalf("rows: got %v want exactly [sA]", got.Rows)
	}
}

// TestAPISessions_AttachesTokensAndCost pins the per-session token/cost
// rollup wired into /api/sessions. When an api_turns row exists for a
// session, total_tokens, cost_usd, and cost_reliability should be
// populated; sessions with no token data render zeroed fields the
// frontend renders as "—".
func TestAPISessions_AttachesTokensAndCost(t *testing.T) {
	s, _ := newTestServer(t)

	// Seed one api_turn for the existing "sA" session. newTestServer
	// already wrote the session via the action; we just attach billing
	// data on top.
	st := store.New(s.opts.DB)
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sA", Provider: models.ProviderAnthropic,
		Model:        "claude-sonnet-4-6",
		InputTokens:  1_000_000,
		OutputTokens: 50_000,
		Timestamp:    time.Date(2026, 4, 16, 10, 0, 5, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows []struct {
			ID                  string  `json:"id"`
			InputTokens         int64   `json:"input_tokens"`
			OutputTokens        int64   `json:"output_tokens"`
			CacheReadTokens     int64   `json:"cache_read_tokens"`
			CacheCreationTokens int64   `json:"cache_creation_tokens"`
			TotalTokens         int64   `json:"total_tokens"`
			CostUSD             float64 `json:"cost_usd"`
			CostReliability     string  `json:"cost_reliability"`
		} `json:"rows"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 session, got %d", len(got.Rows))
	}
	row := got.Rows[0]
	if row.ID != "sA" {
		t.Fatalf("session id = %q want sA", row.ID)
	}
	wantTokens := int64(1_000_000 + 50_000)
	if row.TotalTokens != wantTokens {
		t.Errorf("total_tokens = %d want %d", row.TotalTokens, wantTokens)
	}
	// v1.4.51 — per-bucket token fields. Verify the breakdown matches
	// the InputTokens / OutputTokens we seeded, and that the cache
	// buckets stay zero when no cache traffic was recorded.
	if row.InputTokens != 1_000_000 {
		t.Errorf("input_tokens = %d want 1_000_000", row.InputTokens)
	}
	if row.OutputTokens != 50_000 {
		t.Errorf("output_tokens = %d want 50_000", row.OutputTokens)
	}
	if row.CacheReadTokens != 0 || row.CacheCreationTokens != 0 {
		t.Errorf("cache buckets should be zero (no cache traffic seeded): R=%d W=%d",
			row.CacheReadTokens, row.CacheCreationTokens)
	}
	if row.CostReliability != "accurate" {
		t.Errorf("cost_reliability = %q want accurate (proxy row)", row.CostReliability)
	}
	if row.CostUSD <= 0 {
		t.Errorf("cost_usd = %f, want > 0 (claude-sonnet-4-6 is priced)", row.CostUSD)
	}
}

// TestAPISessionsCalendar_CostHonorsToolFilter pins audit Finding E: the
// /api/sessions/calendar per-day cost must be scoped by ?tool=X to match the
// per-day session count (which already filters on sessions.tool). Pre-fix the
// cost Summary call omitted Tool, so a tool-filtered calendar rendered tool-X
// session counts beside ALL-tools cost (overstated per-tool spend on the
// heatmap).
func TestAPISessionsCalendar_CostHonorsToolFilter(t *testing.T) {
	s, root := newTestServer(t)
	st := store.New(s.opts.DB)
	now := time.Now().UTC()

	// sA already exists (claude-code, 1 action). Attach a costed turn.
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sA", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 1_000_000, OutputTokens: 50_000,
		Timestamp: now,
	}); err != nil {
		t.Fatal(err)
	}

	// A second session on a DIFFERENT tool (codex) with its own costed turn.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "cdx1", SessionID: "sCdx",
		ProjectRoot: root, Timestamp: now, Tool: models.ToolCodex,
		ActionType: models.ActionReadFile, Target: "c.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sCdx", Provider: models.ProviderOpenAI,
		Model: "gpt-5.1", InputTokens: 500_000, OutputTokens: 20_000,
		Timestamp: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Sum cost + session_count across all returned day cells (robust to a
	// midnight-boundary split between the seeded rows).
	sumCalendar := func(tool string) (cost float64, sessions int) {
		u := "/api/sessions/calendar?days=2"
		if tool != "" {
			u += "&tool=" + tool
		}
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, u, nil))
		if rr.Code != 200 {
			t.Fatalf("GET %s: %d body=%s", u, rr.Code, rr.Body.String())
		}
		var got struct {
			Cells []struct {
				CostUSD      float64 `json:"cost_usd"`
				SessionCount int     `json:"session_count"`
			} `json:"cells"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		for _, c := range got.Cells {
			cost += c.CostUSD
			sessions += c.SessionCount
		}
		return cost, sessions
	}

	allCost, allSessions := sumCalendar("")
	codexCost, codexSessions := sumCalendar(models.ToolCodex)

	if allSessions != 2 {
		t.Fatalf("all-tools session count = %d want 2", allSessions)
	}
	if codexSessions != 1 {
		t.Fatalf("codex session count = %d want 1 (count already filters by tool)", codexSessions)
	}
	if codexCost <= 0 {
		t.Fatalf("codex calendar cost = %f want > 0 (gpt-5.1 is priced)", codexCost)
	}
	// The regression guard: pre-fix codexCost == allCost (tool ignored on the
	// cost rollup). Post-fix the codex-only cost must EXCLUDE the claude-code
	// turn, so it is strictly less than the all-tools total.
	if codexCost >= allCost {
		t.Errorf("codex calendar cost = %f must be < all-tools cost %f (tool filter ignored on cost?)",
			codexCost, allCost)
	}
}

// TestAPISessions_DurationSecondsFromActions pins the v1.4.51 elapsed
// computation. A session with two actions 10 minutes apart should
// report duration_seconds ≈ 600 even when ended_at is NULL (open
// session — backend uses MAX(actions.timestamp) as the fallback).
func TestAPISessions_DurationSecondsFromActions(t *testing.T) {
	s, _ := newTestServer(t)

	// newTestServer seeded "sA" with one action; add a second action
	// 10 minutes later so duration_seconds resolves to 600.
	st := store.New(s.opts.DB)
	root := s.opts.DBPath // any non-empty stand-in for project root
	startTs := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	endTs := startTs.Add(10 * time.Minute)
	// First action at startTs, second 10 minutes later. The first
	// becomes started_at via UpsertSession's MIN-merge; the second
	// becomes MAX(actions.timestamp).
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "dur1", SessionID: "sDur",
			ProjectRoot: root, Timestamp: startTs,
			Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
			Target: "a.go", Success: true,
		},
		{
			SourceFile: "f", SourceEventID: "dur2", SessionID: "sDur",
			ProjectRoot: root, Timestamp: endTs,
			Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
			Target: "b.go", Success: true,
		},
	}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows []struct {
			ID              string `json:"id"`
			DurationSeconds int64  `json:"duration_seconds"`
			LastSeenAt      string `json:"last_seen_at"`
		} `json:"rows"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range got.Rows {
		if r.ID != "sDur" {
			continue
		}
		found = true
		if r.LastSeenAt == "" {
			t.Errorf("last_seen_at should fall back to MAX(actions.timestamp), got empty")
		}
		// Allow ±1s for any rounding inside RFC3339 parse.
		if r.DurationSeconds < 599 || r.DurationSeconds > 601 {
			t.Errorf("duration_seconds = %d want ≈ 600", r.DurationSeconds)
		}
	}
	if !found {
		t.Errorf("session sDur not in /api/sessions response")
	}
}

// TestAPISessions_HasProjectField pins the response contract for the
// fix that ties to issue #1 + #2 (project column + project filter):
// handleSessions must return the session's project root_path on every
// row so the frontend can render the column. Pre-fix the field was
// absent and every row in the dashboard table looked identical to the
// user, hiding cross-project sessions.
func TestAPISessions_HasProjectField(t *testing.T) {
	s, root := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) == 0 {
		t.Fatal("expected at least one session row")
	}
	proj, ok := got.Rows[0]["project"].(string)
	if !ok {
		t.Fatalf("project field missing or wrong type: %+v", got.Rows[0])
	}
	if proj != root {
		t.Errorf("project: got %q want %q", proj, root)
	}
}

// TestAPISessions_ProjectFilter verifies that ?project=<root> scopes the
// result to a single project root.
func TestAPISessions_ProjectFilter(t *testing.T) {
	s, root := newTestServer(t)

	// Match — filter on the seeded project's root.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/sessions?limit=10&project="+root, nil)
	s.Handler().ServeHTTP(rr, req)
	var got struct {
		Rows  []map[string]any `json:"rows"`
		Total int              `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Total != 1 {
		t.Errorf("filtered total: got %d want 1", got.Total)
	}

	// Miss — filter on a non-existent root.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet,
		"/api/sessions?limit=10&project=/does/not/exist", nil)
	s.Handler().ServeHTTP(rr, req)
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Total != 0 {
		t.Errorf("non-matching project filter: got total=%d want 0", got.Total)
	}
}

// TestAPISessions_DaysFilter pins the v1.4.28 fix: the global days
// window now applies to /api/sessions. Pre-fix the Sessions tab
// rendered everything regardless of the dropdown, so 30-day windows
// still showed 60+ day old rows.
func TestAPISessions_DaysFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()
	recent := now.Add(-3 * 24 * time.Hour)
	old := now.Add(-60 * 24 * time.Hour)

	// Two sessions: one 3 days ago, one 60 days ago. Both same project.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f1", SourceEventID: "e1", SessionID: "sRecent",
			ProjectRoot: root, Timestamp: recent, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		},
		{
			SourceFile: "f2", SourceEventID: "e2", SessionID: "sOld",
			ProjectRoot: root, Timestamp: old, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
		},
	}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}

	check := func(query string, wantTotal int) {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/sessions?"+query, nil)
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", query, rr.Code, rr.Body.String())
		}
		var got struct {
			Total int `json:"total"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Total != wantTotal {
			t.Errorf("%s: total=%d want %d", query, got.Total, wantTotal)
		}
	}

	check("limit=10", 2)         // no filter → both sessions visible.
	check("limit=10&days=7", 1)  // 7-day window → only sRecent.
	check("limit=10&days=30", 1) // 30-day window → still only sRecent.
	check("limit=10&days=90", 2) // 90-day window → both back.
}

// TestAPIActions_WindowContract exercises the sub-day / custom-window
// wire contract (hours / since / until) on /api/actions end-to-end,
// proving no day-truncation on the hours path and that `until` is
// honored as an upper bound.
func TestAPIActions_WindowContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()
	twoHours := now.Add(-2 * time.Hour)
	twoDays := now.Add(-2 * 24 * time.Hour)
	sixtyDays := now.Add(-60 * 24 * time.Hour)

	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f1", SourceEventID: "e1", SessionID: "s1",
			ProjectRoot: root, Timestamp: twoHours, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		},
		{
			SourceFile: "f2", SourceEventID: "e2", SessionID: "s1",
			ProjectRoot: root, Timestamp: twoDays, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
		},
		{
			SourceFile: "f3", SourceEventID: "e3", SessionID: "s1",
			ProjectRoot: root, Timestamp: sixtyDays, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "c.go", Success: true,
		},
	}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}

	total := func(query string) int {
		t.Helper()
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/actions?"+query, nil))
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", query, rr.Code, rr.Body.String())
		}
		var got struct {
			Total int `json:"total"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got.Total
	}

	if n := total(""); n != 3 {
		t.Errorf("no filter: total=%d want 3", n)
	}
	// hours=6 must catch the 2-hour-ago action a plain day window would
	// still catch — but critically NOT round down to a day. hours=1
	// excludes the 2-hour-ago row, which day=1 could never express.
	if n := total("hours=6"); n != 1 {
		t.Errorf("hours=6: total=%d want 1", n)
	}
	if n := total("hours=1"); n != 0 {
		t.Errorf("hours=1: total=%d want 0 (sub-day precision)", n)
	}
	if n := total("days=7"); n != 2 {
		t.Errorf("days=7: total=%d want 2", n)
	}
	// since = 3 days ago → 2-hour + 2-day rows.
	since := now.Add(-3 * 24 * time.Hour).Format(time.RFC3339)
	if n := total("since=" + since); n != 2 {
		t.Errorf("since=3d: total=%d want 2", n)
	}
	// until = 1 day ago with a wide lower bound → excludes the recent
	// 2-hour row, keeps the 2-day and 60-day rows.
	until := now.Add(-1 * 24 * time.Hour).Format(time.RFC3339)
	if n := total("days=90&until=" + until); n != 2 {
		t.Errorf("days=90&until=1d: total=%d want 2", n)
	}
	// since+until closed window bracketing only the 2-day row.
	lo := now.Add(-3 * 24 * time.Hour).Format(time.RFC3339)
	hi := now.Add(-1 * 24 * time.Hour).Format(time.RFC3339)
	if n := total("since=" + lo + "&until=" + hi); n != 1 {
		t.Errorf("since=3d&until=1d: total=%d want 1", n)
	}

	// Precedence: the new `since` wins over a legacy from_date when both
	// are present. from_date in the future would day-grained-exclude
	// everything, but since it's gated off, all 3 in-window rows return.
	ninety := now.Add(-90 * 24 * time.Hour).Format(time.RFC3339)
	if n := total("since=" + ninety + "&from_date=2099-01-01"); n != 3 {
		t.Errorf("since wins over from_date: total=%d want 3 (from_date ignored)", n)
	}
	// Compat: legacy `days` still ANDs with from_date (days is not a
	// "new" param), so a future from_date excludes everything.
	if n := total("days=90&from_date=2099-01-01"); n != 0 {
		t.Errorf("days ANDs from_date: total=%d want 0", n)
	}
}

// TestAPISessions_WindowIncludesRecentActivityOnOldSession pins audit Finding
// B: /api/sessions must reconcile its window with the cost engine, which
// windows by turn/token TIMESTAMP. A session that STARTED before the window but
// has RECENT turns contributes to /api/cost, so it must also appear here (and
// in the pagination total) — otherwise the Sessions tab under-counts vs the
// Cost tab. A session that started old AND has no recent activity stays
// excluded.
func TestAPISessions_WindowIncludesRecentActivityOnOldSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()
	old := now.Add(-45 * 24 * time.Hour)

	// Both sessions started 45 days ago (outside a 7-day window).
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f1", SourceEventID: "e1", SessionID: "sActive",
			ProjectRoot: root, Timestamp: old, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		},
		{
			SourceFile: "f2", SourceEventID: "e2", SessionID: "sStale",
			ProjectRoot: root, Timestamp: old, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
		},
	}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	// Only sActive has a RECENT turn (today) — the cost engine counts it in a
	// 7-day window, so the Sessions tab must too.
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sActive", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 100_000, OutputTokens: 5_000,
		Timestamp: now,
	}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions?limit=50&days=7", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows []struct {
			ID string `json:"id"`
		} `json:"rows"`
		Total int `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range got.Rows {
		ids[r.ID] = true
	}
	if !ids["sActive"] {
		t.Errorf("sActive (started 45d ago, recent turn) must appear in the 7-day window to match /api/cost; rows=%v", ids)
	}
	if ids["sStale"] {
		t.Errorf("sStale (started 45d ago, no recent activity) must NOT appear in the 7-day window; rows=%v", ids)
	}
	// total counts the same WHERE, so it must include sActive and exclude sStale.
	if got.Total != 1 {
		t.Errorf("total=%d want 1 (sActive in-window via recent turn, sStale excluded)", got.Total)
	}
}

// TestAPISessions_SortByCostIsGlobalAcrossPages pins audit Finding C
// (Variant 1): sorting by cost must be GLOBAL across the whole filtered set,
// not page-local. Pre-fix the server returned one started_at-ordered page and
// the frontend sorted only those rows, so "sort by cost desc" surfaced the most
// expensive of the VISIBLE page, never the most expensive session on a later
// page. With server-side sort, page 1 of sort_by=cost&desc is the globally most
// expensive session even though it started oldest (last by the default order).
func TestAPISessions_SortByCostIsGlobalAcrossPages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()

	// Three sessions. Default order is started_at DESC: cheap, mid, expensive.
	// Cost order is the inverse: the OLDEST session is the priciest, so a
	// page-local sort over the first started_at page would never surface it.
	seed := func(id string, startedAt time.Time, inputTokens int64) {
		if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
			SourceFile: "f-" + id, SourceEventID: "e-" + id, SessionID: id,
			ProjectRoot: root, Timestamp: startedAt, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: id, Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: inputTokens, OutputTokens: 0,
			Timestamp: startedAt,
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed("sCheap", now.Add(-1*time.Hour), 10_000)
	seed("sMid", now.Add(-2*time.Hour), 100_000)
	seed("sExpensive", now.Add(-3*time.Hour), 5_000_000)

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}

	get := func(query string) (ids []string, total int, pageCost float64) {
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions?"+query, nil))
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", query, rr.Code, rr.Body.String())
		}
		var got struct {
			Rows []struct {
				ID string `json:"id"`
			} `json:"rows"`
			Total       int     `json:"total"`
			PageCostUSD float64 `json:"page_cost_usd"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		for _, row := range got.Rows {
			ids = append(ids, row.ID)
		}
		return ids, got.Total, got.PageCostUSD
	}

	// Default order (no sort) is started_at DESC: the most RECENT session.
	if ids, _, _ := get("limit=1&page=1"); len(ids) != 1 || ids[0] != "sCheap" {
		t.Fatalf("default page 1 = %v, want [sCheap] (most recent by started_at)", ids)
	}

	// sort_by=cost desc page 1 must be the GLOBAL max — sExpensive — even
	// though it started oldest (it sits on the LAST default page).
	ids, total, pageCost := get("limit=1&page=1&sort_by=cost&sort_dir=desc")
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(ids) != 1 || ids[0] != "sExpensive" {
		t.Fatalf("cost-desc page 1 = %v, want [sExpensive] (global max across pages)", ids)
	}
	if pageCost <= 0 {
		t.Errorf("page_cost_usd = %v, want > 0 (the expensive session's cost)", pageCost)
	}

	// Subsequent pages descend: mid then cheap.
	if ids, _, _ := get("limit=1&page=2&sort_by=cost&sort_dir=desc"); len(ids) != 1 || ids[0] != "sMid" {
		t.Errorf("cost-desc page 2 = %v, want [sMid]", ids)
	}
	if ids, _, _ := get("limit=1&page=3&sort_by=cost&sort_dir=desc"); len(ids) != 1 || ids[0] != "sCheap" {
		t.Errorf("cost-desc page 3 = %v, want [sCheap]", ids)
	}

	// Ascending flips the order: page 1 is the cheapest.
	if ids, _, _ := get("limit=1&page=1&sort_by=cost&sort_dir=asc"); len(ids) != 1 || ids[0] != "sCheap" {
		t.Errorf("cost-asc page 1 = %v, want [sCheap]", ids)
	}
}

// TestAPISessionDetail_CopilotOutputShadowDeduped pins the session-detail side
// of the copilot output-only shadow dedup: the panel's token bucket must count
// the turn's output ONCE (152), not twice (304), and the spurious shadow model
// must not appear in the per-model breakdown.
func TestAPISessionDetail_CopilotOutputShadowDeduped(t *testing.T) {
	s, root := newTestServer(t)
	now := time.Now().UTC()
	st := store.New(s.opts.DB)
	// Bootstrap a copilot-cli session.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "cp1", SessionID: "sCp",
		ProjectRoot: root, Timestamp: now, Tool: models.ToolCopilotCLI,
		ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	// Two token rows for the same turn: full-usage (Tier-1) + output-only
	// shadow (Tier-3), different models like the live adapter emits.
	insTok := func(model string, in, out int64, src, evid string) {
		if _, err := s.opts.DB.ExecContext(context.Background(),
			`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, source, reliability, source_file, source_event_id)
			 VALUES (?, ?, 'copilot-cli', ?, ?, ?, ?, 'approximate', 'f', ?)`,
			"sCp", now.Format(time.RFC3339Nano), model, in, out, src, evid); err != nil {
			t.Fatal(err)
		}
	}
	insTok("claude-haiku-4-5-20251001", 16267, 152, "otel", "log:null:1")
	insTok("claude-haiku-4.5", 0, 152, "jsonl", "evt:token")

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/sCp", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Tokens   map[string]int64 `json:"tokens"`
		PerModel []struct {
			Model  string `json:"model"`
			Output int64  `json:"output"`
		} `json:"per_model"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Tokens["output"] != 152 {
		t.Errorf("token bucket output = %d, want 152 (shadow deduped, not 304)", got.Tokens["output"])
	}
	if got.Tokens["input"] != 16267 {
		t.Errorf("token bucket input = %d, want 16267", got.Tokens["input"])
	}
	if len(got.PerModel) != 1 || got.PerModel[0].Model != "claude-haiku-4-5-20251001" {
		t.Errorf("per_model = %+v, want only the full-usage model claude-haiku-4-5-20251001", got.PerModel)
	}
}

// TestAPIProjects covers the /api/projects endpoint introduced for the
// project-filter dropdown on the toolbar.
func TestAPIProjects(t *testing.T) {
	s, root := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) == 0 {
		t.Fatal("expected at least one project row")
	}
	first := got.Rows[0]
	if first["root_path"] != root {
		t.Errorf("root_path: got %v want %q", first["root_path"], root)
	}
	if first["session_count"].(float64) != 1 {
		t.Errorf("session_count: got %v want 1", first["session_count"])
	}
	if first["action_count"].(float64) != 1 {
		t.Errorf("action_count: got %v want 1", first["action_count"])
	}
}

// TestAPISessionDetail covers the new /api/session/<id> endpoint.
func TestAPISessionDetail(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["id"] != "sA" {
		t.Errorf("id: %v", got["id"])
	}
	if got["tool"] != "claude-code" {
		t.Errorf("tool: %v", got["tool"])
	}
	if got["total_actions"].(float64) != 1 {
		t.Errorf("total_actions: %v", got["total_actions"])
	}
	if _, ok := got["tokens"].(map[string]any); !ok {
		t.Errorf("tokens: missing or wrong shape: %v", got["tokens"])
	}
	if _, ok := got["tool_breakdown"].([]any); !ok {
		t.Errorf("tool_breakdown: missing or wrong shape: %v", got["tool_breakdown"])
	}
	// sA has no ended_at; last_activity_at must fall back to the action's
	// timestamp (COALESCE) so the frontend Elapsed figure is start→last
	// activity, not start→now (the 583h bug).
	if _, hasEnded := got["ended_at"]; hasEnded {
		t.Errorf("fixture sA unexpectedly has ended_at: %v", got["ended_at"])
	}
	la, ok := got["last_activity_at"].(string)
	if !ok || la == "" {
		t.Errorf("last_activity_at: missing/empty for open session: %v", got["last_activity_at"])
	}
}

// TestAPISessionDetail_CursorContextBudget guards the honest no-billed-tokens
// fallback: a cursor session with no token_usage (not proxied + turn cancelled)
// surfaces the carried context budget parsed from prompt_context actions plus a
// note explaining the empty bill — and never fabricates a cost.
func TestAPISessionDetail_CursorContextBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	ts := time.Now().UTC().Add(-time.Hour)

	// Cursor session with two prompt_context budget rows and NO token_usage.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "pc1", SessionID: "sCB",
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolCursor,
			ActionType: models.ActionPromptContext,
			Target:     "Rules — 15580 tokens, 61924 chars", Success: true,
		},
		{
			SourceFile: "f", SourceEventID: "pc2", SessionID: "sCB",
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolCursor,
			ActionType: models.ActionPromptContext,
			Target:     "Tool definitions — 7339 tokens, 29154 chars", Success: true,
		},
	}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	s, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/sCB", nil))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Tokens              map[string]int64 `json:"tokens"`
		ContextBudgetTokens int64            `json:"context_budget_tokens"`
		TokensNote          string           `json:"tokens_note"`
		CostUSD             float64          `json:"cost_usd"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ContextBudgetTokens != 15580+7339 {
		t.Errorf("context_budget_tokens = %d, want %d", got.ContextBudgetTokens, 15580+7339)
	}
	if !strings.Contains(got.TokensNote, "Cursor") {
		t.Errorf("tokens_note missing cursor explanation: %q", got.TokensNote)
	}
	if got.CostUSD != 0 {
		t.Errorf("context budget must not fabricate cost: cost_usd=%v", got.CostUSD)
	}
}

// TestAPISessionDetail_ModelFallsBackToTokenUsage guards the cursor model-gap
// fix (2026-06-18). sessions.model is populated only from an ingested event's
// model, which is empty for every cursor session and nearly all claude-code
// sessions (their hook events carry no model). The detail endpoint must fall
// back to the dominant token_usage model so the dashboard still shows one —
// and when sessions.model IS set it must win over the fallback.
func TestAPISessionDetail_ModelFallsBackToTokenUsage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	ts := time.Date(2026, 4, 28, 6, 50, 0, 0, time.UTC)

	// Session sFB: one cursor action carrying NO model (so sessions.model
	// stays empty — the live cursor shape) plus two token_usage rows; opus
	// has the larger token volume so it's the dominant bucket.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sFB",
		ProjectRoot: root, Timestamp: ts, Tool: models.ToolCursor,
		ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, tu := range []struct {
		eid, model string
		in, out    int64
	}{
		{"tk1", "claude-haiku-4-5", 100, 200},
		{"tk2", "claude-opus-4-7", 5_000, 9_000}, // larger volume → dominant
	} {
		if _, err := database.ExecContext(context.Background(),
			`INSERT INTO token_usage (session_id, source_file, source_event_id, timestamp, tool, model,
				input_tokens, output_tokens, source, reliability)
			 VALUES ('sFB', 'f-tu', ?, ?, 'cursor', ?, ?, ?, 'hook', 'accurate')`,
			tu.eid, ts.Format(time.RFC3339Nano), tu.model, tu.in, tu.out); err != nil {
			t.Fatal(err)
		}
	}

	// Precondition: sessions.model is empty.
	var sm string
	if err := database.QueryRowContext(context.Background(),
		`SELECT COALESCE(model,'') FROM sessions WHERE id='sFB'`).Scan(&sm); err != nil {
		t.Fatal(err)
	}
	if sm != "" {
		t.Fatalf("precondition: sessions.model should be empty, got %q", sm)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	modelOf := func(id string) string {
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/"+id, nil))
		if rr.Code != 200 {
			t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
		}
		var got struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got.Model
	}

	if m := modelOf("sFB"); m != "claude-opus-4-7" {
		t.Errorf("model fallback: got %q, want claude-opus-4-7 (dominant token_usage model)", m)
	}

	// An explicit sessions.model must win over the token_usage fallback.
	if _, err := database.ExecContext(context.Background(),
		`UPDATE sessions SET model='explicit-model' WHERE id='sFB'`); err != nil {
		t.Fatal(err)
	}
	if m := modelOf("sFB"); m != "explicit-model" {
		t.Errorf("explicit sessions.model: got %q, want explicit-model (must win)", m)
	}
}

// TestAPISessionDetail_ZeroActionsWithTokens guards the NULL-scan regression
// exposed once the FK-787 retention fix let actions actually prune: a session
// whose actions were all deleted but whose token_usage rows survive (retention
// never prunes token_usage) has zero rows in the action-aggregate query, where
// SUM(CASE…) over an empty set is NULL. Scanning that into int 500'd the whole
// detail endpoint. The COALESCE(...,0) fix must let it render 200 with tokens.
func TestAPISessionDetail_ZeroActionsWithTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)

	// A session with ONLY a token_usage row and no actions — the post-prune
	// shape (token ingest upserts the session; it creates no action rows).
	if _, err := st.Ingest(context.Background(), nil, []models.TokenEvent{{
		SourceFile: "j", SourceEventID: "tok-1", SessionID: "sZero",
		ProjectRoot: t.TempDir(), Timestamp: time.Date(2026, 4, 28, 6, 50, 0, 0, time.UTC),
		Tool: models.ToolCursor, Model: "default",
		InputTokens: 1000, OutputTokens: 200,
		Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate,
	}}, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	var na int
	if err := database.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM actions WHERE session_id='sZero'`).Scan(&na); err != nil {
		t.Fatal(err)
	}
	if na != 0 {
		t.Fatalf("setup: expected 0 actions, got %d", na)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/sZero", nil))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s (NULL-scan regression — SUM over zero actions)", rr.Code, rr.Body.String())
	}
	var got struct {
		TotalActions   int    `json:"total_actions"`
		SuccessActions int    `json:"success_actions"`
		FailureActions int    `json:"failure_actions"`
		Model          string `json:"model"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.TotalActions != 0 || got.SuccessActions != 0 || got.FailureActions != 0 {
		t.Errorf("action counts: got total=%d success=%d failure=%d, want all 0", got.TotalActions, got.SuccessActions, got.FailureActions)
	}
	if got.Model != "default" {
		t.Errorf("model: got %q, want default (renders despite zero actions)", got.Model)
	}
}

// TestAPISessionDetail_CostSurvivesUnattributedProxy is the regression
// guard for the cost_usd:0 polish item: the per-session cost lookup must
// still surface real cost when proxy api_turns rows for the same logical
// turn landed with NULL session_id (pre-pidbridge era) and would
// otherwise dedup the session-attributed JSONL row out of the rollup.
//
// Setup mirrors the live failure mode: session sA owns a token_usage row
// at minute T with model M and tokens P. An api_turn with session_id=""
// also exists at minute T with the same model+tokens — the cost engine's
// SourceAuto fingerprint dedup matches the JSONL row against the
// NULL-session proxy fingerprint and drops it, leaving sA with no row in
// the GroupBySession rollup. Pre-fix: cost_usd=0. Post-fix: cost is
// computed directly off the session's own token_usage row via
// engine.Compute, so it lands non-zero.
func TestAPISessionDetail_CostSurvivesUnattributedProxy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	ts := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)

	// Create session sA via Ingest (also inserts one action).
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sA",
		ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// JSONL token_usage row for sA — model+tokens with known pricing so
	// engine.Compute returns a positive value.
	if _, err := st.InsertTokenEvents(context.Background(), []models.TokenEvent{{
		SourceFile: "tu", SourceEventID: "tu-e1", SessionID: "sA",
		Timestamp: ts, Tool: string(models.ToolClaudeCode),
		Model:               "claude-sonnet-4-6",
		InputTokens:         1000,
		OutputTokens:        2000,
		CacheReadTokens:     500,
		CacheCreationTokens: 250,
		Source:              "jsonl",
		Reliability:         "approximate",
	}}); err != nil {
		t.Fatal(err)
	}

	// Proxy api_turn at the same minute with the SAME tokens but NULL
	// session_id — matches the JSONL fingerprint, would dedup the JSONL
	// row out of the GroupBySession rollup pre-fix.
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID:           "",
		Timestamp:           ts,
		Provider:            models.ProviderAnthropic,
		Model:               "claude-sonnet-4-6",
		InputTokens:         1000,
		OutputTokens:        2000,
		CacheReadTokens:     500,
		CacheCreationTokens: 250,
	}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	costUSD, _ := got["cost_usd"].(float64)
	if costUSD <= 0 {
		t.Errorf("cost_usd: got %v, want > 0 (token_usage row for sA "+
			"with priced model claude-sonnet-4-6 should yield positive "+
			"cost even when a NULL-session proxy row shares its fingerprint)",
			got["cost_usd"])
	}
	// Spot-check the math: pricing for claude-sonnet-4-6 is
	// {Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75} per
	// million tokens. Expected = 1000*3/1e6 + 2000*15/1e6 +
	// 500*0.30/1e6 + 250*3.75/1e6 = 0.003 + 0.030 + 0.00015 + 0.0009375
	// = 0.0341 (approximately).
	want := 0.0341
	if costUSD < want*0.99 || costUSD > want*1.01 {
		t.Errorf("cost_usd: got %v, want ≈ %v (claude-sonnet-4-6 pricing × seeded tokens)",
			costUSD, want)
	}
}

// TestAPISessionMessages_GroupsByMessageID pins the v1.4.17 per-message
// timeline endpoint. Multiple tool calls under the same upstream
// message.id collapse into a single row whose tool_call_count == N
// and tool_calls array carries the N entries; user_prompt actions
// surface as their own message rows.
func TestAPISessionMessages_GroupsByMessageID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	ts := time.Date(2026, 4, 28, 6, 50, 0, 0, time.UTC)

	// One assistant turn (msg_A) emits two tool calls AND has a
	// token_usage row. Plus one user_prompt action with no token data.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "u1", SessionID: "sA",
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionUserPrompt, Target: "do X", Success: true,
			RawToolInput: "do X with a much longer explanation than fits in target",
			MessageID:    "user_evt_1",
		},
		{
			SourceFile: "f", SourceEventID: "toolu_1", SessionID: "sA",
			ProjectRoot: root, Timestamp: ts.Add(time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "main.go", Success: true,
			MessageID: "msg_A",
		},
		{
			SourceFile: "f", SourceEventID: "toolu_2", SessionID: "sA",
			ProjectRoot: root, Timestamp: ts.Add(2 * time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "ls -la", Success: true,
			RawToolInput: "[\"powershell.exe\",\"-Command\",\"Get-ChildItem -Recurse -Force C:\\\\Users\\\\marmu\\\\.codex\\\\sessions\"]",
			MessageID:    "msg_A",
		},
	}, []models.TokenEvent{
		{
			SourceFile: "f", SourceEventID: "msg_A", SessionID: "sA",
			Timestamp: ts.Add(time.Second), Tool: models.ToolClaudeCode,
			Model: "claude-opus-4-7", InputTokens: 100, OutputTokens: 500,
			MessageID: "msg_A",
			Source:    models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
		},
	}, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	var runCmdActionID int64
	if err := database.QueryRowContext(
		context.Background(),
		`SELECT id FROM actions WHERE session_id = ? AND source_event_id = ?`,
		"sA", "toolu_2",
	).Scan(&runCmdActionID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(
		context.Background(),
		`INSERT INTO action_excerpts (action_id, tool_name, target, excerpt, error_message)
		 VALUES (?, ?, ?, ?, ?)`,
		runCmdActionID, "Bash", "ls -la", "total 64\n-rw-r--r-- main.go", "",
	); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA/messages", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Messages []struct {
			MessageID     string `json:"message_id"`
			Role          string `json:"role"`
			Input         int64  `json:"input"`
			Output        int64  `json:"output"`
			ToolCallCount int    `json:"tool_call_count"`
			ToolCalls     []struct {
				ActionType string `json:"action_type"`
				Target     string `json:"target"`
				FullText   string `json:"full_text"`
				Excerpt    string `json:"excerpt"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 2 {
		t.Fatalf("messages: got %d want 2 (user_evt_1 + msg_A)", len(got.Messages))
	}
	// User prompt row: no tokens, action_type=user_prompt.
	user := got.Messages[0]
	if user.MessageID != "user_evt_1" {
		t.Errorf("first message: got id=%q want user_evt_1", user.MessageID)
	}
	if user.Role != "user" {
		t.Errorf("first message role: got %q want user", user.Role)
	}
	if user.ToolCallCount != 1 || got.Messages[0].ToolCalls[0].ActionType != "user_prompt" {
		t.Errorf("first message tool calls: %+v", user.ToolCalls)
	}
	if got.Messages[0].ToolCalls[0].FullText != "do X with a much longer explanation than fits in target" {
		t.Errorf("user full_text: got %q", got.Messages[0].ToolCalls[0].FullText)
	}
	// Assistant row: tokens populated, two tool calls grouped.
	asst := got.Messages[1]
	if asst.MessageID != "msg_A" {
		t.Errorf("second message: got id=%q want msg_A", asst.MessageID)
	}
	if asst.Role != "assistant" {
		t.Errorf("second message role: got %q want assistant", asst.Role)
	}
	if asst.Input != 100 || asst.Output != 500 {
		t.Errorf("second message tokens: got in=%d out=%d want 100/500", asst.Input, asst.Output)
	}
	if asst.ToolCallCount != 2 {
		t.Errorf("second message tool_call_count: got %d want 2 (read_file + run_command)", asst.ToolCallCount)
	}
	if got.Messages[1].ToolCalls[1].Excerpt != "total 64\n-rw-r--r-- main.go" {
		t.Errorf("run_command excerpt: got %q", got.Messages[1].ToolCalls[1].Excerpt)
	}
	if got.Messages[1].ToolCalls[1].FullText != "powershell.exe -Command Get-ChildItem -Recurse -Force C:\\Users\\marmu\\.codex\\sessions" {
		t.Errorf("run_command full_text: got %q", got.Messages[1].ToolCalls[1].FullText)
	}
}

// TestAPISessionMessages_BrowserChatInlineBody pins the browser-capture
// message rendering contract: for a browserchat *-web session the
// assistant_message row surfaces raw_tool_output inline as full_text
// (the on-screen answer), the paired user_prompt row surfaces the prompt
// as full_text, and the per-turn API-call metadata (request_url /
// id_source / granularity / prompt+response token estimates) is extracted
// onto the tool_call row. Also asserts the negation: a coding-agent
// (non-*-web) assistant_message row does NOT inline raw_tool_output —
// full_text stays the target preview — so coding-agent rendering is
// unchanged.
func TestAPISessionMessages_BrowserChatInlineBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := "browser://chatgpt.com"
	ts := time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC)
	longResp := strings.Repeat("A", fullTextInlineMax+500)

	// Browser session (chatgpt-web): user_prompt (MessageID "user:m1",
	// prompt in raw_tool_input) + assistant_message (MessageID "m1",
	// response in raw_tool_output, API-call detail in metadata) + a
	// token estimate row keyed on "m1".
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "b1:user", SessionID: "sW",
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolChatGPTWeb,
			ActionType: models.ActionUserPrompt, Target: "How do I sort a slice?",
			Success:      true,
			RawToolName:  "chatgpt.user_prompt",
			RawToolInput: "How do I sort a slice in Go with a custom comparator?",
			MessageID:    "user:m1",
		},
		{
			SourceFile: "f", SourceEventID: "b1", SessionID: "sW",
			ProjectRoot: root, Timestamp: ts.Add(2 * time.Second), Tool: models.ToolChatGPTWeb,
			ActionType: models.ActionAssistantMessage, Target: "gpt-5",
			Success:     true,
			DurationMs:  1500,
			RawToolName: "chatgpt.assistant_text",
			ToolOutput:  longResp,
			MessageID:   "m1",
			Metadata: &models.ActionMetadata{
				RequestURL:        "/backend-api/conversation",
				IDSource:          "resume",
				Granularity:       "full",
				PromptTokensEst:   12,
				ResponseTokensEst: 340,
			},
		},
	}, []models.TokenEvent{
		{
			SourceFile: "f", SourceEventID: "m1:tok", SessionID: "sW",
			Timestamp: ts.Add(2 * time.Second), Tool: models.ToolChatGPTWeb,
			Model: "gpt-5", InputTokens: 12, OutputTokens: 340,
			MessageID: "m1",
			Source:    models.TokenSourceEstimated, Reliability: models.ReliabilityUnreliable,
		},
	}, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// Coding-agent control session (claude-code): an assistant_message
	// whose raw_tool_output (model narration) must NOT be inlined.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f2", SourceEventID: "c1", SessionID: "sC",
			ProjectRoot: t.TempDir(), Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionAssistantMessage, Target: "Sure, let me help.",
			Success:     true,
			RawToolName: "claude.assistant_text",
			ToolOutput:  "Sure, let me help. Here is a very long narration body that should stay collapsed.",
			MessageID:   "cm1",
		},
	}, []models.TokenEvent{
		{
			SourceFile: "f2", SourceEventID: "cm1", SessionID: "sC",
			Timestamp: ts, Tool: models.ToolClaudeCode,
			Model: "claude-opus-4-8", InputTokens: 50, OutputTokens: 80,
			MessageID: "cm1",
			Source:    models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
		},
	}, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}

	type tcRow struct {
		ActionType        string `json:"action_type"`
		Target            string `json:"target"`
		FullText          string `json:"full_text"`
		FullTextElided    bool   `json:"full_text_elided"`
		HasFullOutput     bool   `json:"has_full_output"`
		RequestURL        string `json:"request_url"`
		IDSource          string `json:"id_source"`
		Granularity       string `json:"granularity"`
		PromptTokensEst   int64  `json:"prompt_tokens_est"`
		ResponseTokensEst int64  `json:"response_tokens_est"`
	}
	fetch := func(sid string) []struct {
		Role      string  `json:"role"`
		ToolCalls []tcRow `json:"tool_calls"`
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/session/"+sid+"/messages", nil)
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
		}
		var got struct {
			Messages []struct {
				Role      string  `json:"role"`
				ToolCalls []tcRow `json:"tool_calls"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got.Messages
	}

	// --- Browser session assertions ---
	wmsgs := fetch("sW")
	var userTC, asstTC *tcRow
	for i := range wmsgs {
		for j := range wmsgs[i].ToolCalls {
			tc := &wmsgs[i].ToolCalls[j]
			switch tc.ActionType {
			case "user_prompt":
				userTC = tc
			case "assistant_message":
				asstTC = tc
			}
		}
	}
	if userTC == nil || asstTC == nil {
		t.Fatalf("browser session missing rows: user=%v asst=%v (msgs=%+v)", userTC, asstTC, wmsgs)
	}
	if userTC.FullText != "How do I sort a slice in Go with a custom comparator?" {
		t.Errorf("user full_text: got %q", userTC.FullText)
	}
	// Assistant body inlined from raw_tool_output, capped + elided.
	if len(asstTC.FullText) != fullTextInlineMax {
		t.Errorf("assistant full_text length: got %d want %d (capped)", len(asstTC.FullText), fullTextInlineMax)
	}
	if !asstTC.FullTextElided {
		t.Errorf("assistant full_text_elided: got false, want true (body exceeded cap)")
	}
	if !asstTC.HasFullOutput {
		t.Errorf("assistant has_full_output: got false, want true")
	}
	if asstTC.RequestURL != "/backend-api/conversation" || asstTC.IDSource != "resume" ||
		asstTC.Granularity != "full" {
		t.Errorf("assistant metadata: url=%q id=%q gran=%q", asstTC.RequestURL, asstTC.IDSource, asstTC.Granularity)
	}
	if asstTC.PromptTokensEst != 12 || asstTC.ResponseTokensEst != 340 {
		t.Errorf("assistant token estimates: prompt=%d response=%d want 12/340", asstTC.PromptTokensEst, asstTC.ResponseTokensEst)
	}

	// --- Coding-agent control: assistant_message NOT inlined ---
	cmsgs := fetch("sC")
	var cAsst *tcRow
	for i := range cmsgs {
		for j := range cmsgs[i].ToolCalls {
			if cmsgs[i].ToolCalls[j].ActionType == "assistant_message" {
				cAsst = &cmsgs[i].ToolCalls[j]
			}
		}
	}
	if cAsst == nil {
		t.Fatalf("control session missing assistant_message row (msgs=%+v)", cmsgs)
	}
	if cAsst.FullText != "Sure, let me help." {
		t.Errorf("control assistant full_text: got %q, want the target preview (raw_tool_output must NOT be inlined)", cAsst.FullText)
	}
	// The metadata keys are browser-only; absent here.
	if cAsst.RequestURL != "" || cAsst.Granularity != "" {
		t.Errorf("control assistant carried browser metadata: url=%q gran=%q", cAsst.RequestURL, cAsst.Granularity)
	}
}

// TestAPISessionMessages_CodexTurnVsInferenceGrouping pins the
// v1.7.24 migration-032 dashboard contract: codex token rows have
// per-event message_id + turn-grouping turn_id. The default
// /messages endpoint rolls them up by turn_id (one assistant row per
// user-turn, summing per-inference tokens). With ?detail=inference,
// the endpoint groups by message_id instead so each codex token_count
// event surfaces as its own row.
func TestAPISessionMessages_CodexTurnVsInferenceGrouping(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	ts := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)

	// One assistant function_call action keyed to the turn, plus two
	// codex token_count rows for the same turn — one row per model
	// inference (the v1.7.24+ contract). MessageID is per-event; TurnID
	// groups them back to "turn-2".
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "fc_1", SessionID: "sCx",
		ProjectRoot: root, Timestamp: ts, Tool: models.ToolCodex,
		ActionType: models.ActionRunCommand, Target: "ls", Success: true,
		MessageID: "turn-2",
	}}, []models.TokenEvent{
		{
			SourceFile: "rollout.jsonl", SourceEventID: "tk:rollout.jsonl:L7",
			SessionID: "sCx", ProjectRoot: root, Timestamp: ts,
			Tool: models.ToolCodex, Model: "gpt-5.4",
			InputTokens: 100, OutputTokens: 50,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
			MessageID: "tk:rollout.jsonl:L7",
			TurnID:    "turn-2",
		},
		{
			SourceFile: "rollout.jsonl", SourceEventID: "tk:rollout.jsonl:L11",
			SessionID: "sCx", ProjectRoot: root, Timestamp: ts.Add(2 * time.Second),
			Tool: models.ToolCodex, Model: "gpt-5.4",
			InputTokens: 200, OutputTokens: 75,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
			MessageID: "tk:rollout.jsonl:L11",
			TurnID:    "turn-2",
		},
	}, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}

	type rowShape struct {
		MessageID     string `json:"message_id"`
		Input         int64  `json:"input"`
		Output        int64  `json:"output"`
		ToolCallCount int    `json:"tool_call_count"`
	}
	type envelope struct {
		Messages []rowShape `json:"messages"`
	}

	// Default mode: msg_key = COALESCE(turn_id, message_id, source_event_id).
	// Both token rows map to msg_key="turn-2" and merge with the
	// assistant action (also message_id="turn-2"). One row, summed
	// tokens, one tool call.
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(
		http.MethodGet, "/api/session/sCx/messages", nil,
	))
	if rr.Code != 200 {
		t.Fatalf("default status: %d body=%s", rr.Code, rr.Body.String())
	}
	var defaultMode envelope
	if err := json.NewDecoder(rr.Body).Decode(&defaultMode); err != nil {
		t.Fatal(err)
	}
	if len(defaultMode.Messages) != 1 {
		t.Fatalf("default rows: got %d want 1; rows=%+v", len(defaultMode.Messages), defaultMode.Messages)
	}
	r0 := defaultMode.Messages[0]
	if r0.MessageID != "turn-2" {
		t.Errorf("default row msg_key: got %q want turn-2", r0.MessageID)
	}
	if r0.Input != 300 || r0.Output != 125 {
		t.Errorf("default summed tokens: in=%d out=%d want 300/125", r0.Input, r0.Output)
	}
	if r0.ToolCallCount != 1 {
		t.Errorf("default tool_call_count: got %d want 1", r0.ToolCallCount)
	}

	// detail=inference mode: msg_key = COALESCE(message_id, source_event_id).
	// Each token row is its own msg_key. The assistant action's own key
	// ("turn-2") has no matching token row at this grain, so
	// inferenceBucketIndex (see its doc comment) assigns it to whichever
	// per-inference bucket actually emitted it by timestamp — here the
	// action is stamped at the SAME instant as the L7 bucket, so it
	// attaches to L7 rather than stranding as its own action-only row or
	// as a synthetic "API call (no recovered text)" placeholder on L7.
	// Two rows total: L7 carries the real "ls" tool call; L11 has no
	// tool call and, since the orphan ratio (1 of 2 assistant rows) sits
	// at exactly 0.5 — not > 0.5 — stays orphaned rather than picking up
	// an orphan-stub-injection placeholder.
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(
		http.MethodGet, "/api/session/sCx/messages?detail=inference", nil,
	))
	if rr.Code != 200 {
		t.Fatalf("inference status: %d body=%s", rr.Code, rr.Body.String())
	}
	var inferMode envelope
	if err := json.NewDecoder(rr.Body).Decode(&inferMode); err != nil {
		t.Fatal(err)
	}
	if len(inferMode.Messages) != 2 {
		t.Fatalf("inference rows: got %d want 2; rows=%+v", len(inferMode.Messages), inferMode.Messages)
	}
	byKey := map[string]rowShape{}
	for _, m := range inferMode.Messages {
		byKey[m.MessageID] = m
	}
	if _, ok := byKey["turn-2"]; ok {
		t.Errorf("inference mode: unexpected standalone turn-2 action row; rows=%+v", inferMode.Messages)
	}
	if r := byKey["tk:rollout.jsonl:L7"]; r.Input != 100 || r.Output != 50 || r.ToolCallCount != 1 {
		t.Errorf("inference L7 row: %+v want in=100 out=50 tc=1 (the real ls tool call, routed here by inferenceBucketIndex)", r)
	}
	if r := byKey["tk:rollout.jsonl:L11"]; r.Input != 200 || r.Output != 75 || r.ToolCallCount != 0 {
		t.Errorf("inference L11 row: %+v want in=200 out=75 tc=0 (orphan ratio 0.5 does not cross the >0.5 stub-injection threshold)", r)
	}
}

// TestAPISessionMessages_LongContextPerTurn pins the message-timeline
// pricing bug the user hit locally: message rows may aggregate multiple
// turns, but long-context repricing is per-turn. Summing the tokens
// first and then pricing once would falsely double the displayed cost
// for models like GPT-5.5 whenever the aggregate crosses the LC
// threshold even though each underlying turn stayed below it.
func TestAPISessionMessages_LongContextPerTurn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	ts := time.Date(2026, 5, 5, 6, 18, 43, 0, time.UTC)

	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "toolu_1", SessionID: "sLC",
		ProjectRoot: root, Timestamp: ts, Tool: models.ToolCodex,
		ActionType: models.ActionReadFile, Target: "main.go", Success: true,
		MessageID: "msg_lc",
	}}, []models.TokenEvent{
		// Two distinct per-turn delta emissions under the same
		// message_id. Use slightly different token tuples so the v1.6.5
		// tuple-dedup leaves both alive (production-realistic shape:
		// codex delta token_count events never share byte-identical
		// last_token_usage). Sum still = 300_000 input.
		{
			SourceFile: "f", SourceEventID: "tk_1", SessionID: "sLC",
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolCodex,
			Model: "gpt-5.5", InputTokens: 149_999, MessageID: "msg_lc",
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
		},
		{
			SourceFile: "f", SourceEventID: "tk_2", SessionID: "sLC",
			ProjectRoot: root, Timestamp: ts.Add(20 * time.Second), Tool: models.ToolCodex,
			Model: "gpt-5.5", InputTokens: 150_001, MessageID: "msg_lc",
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
		},
	}, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sLC/messages", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Messages []struct {
			MessageID string  `json:"message_id"`
			Input     int64   `json:"input"`
			CostUSD   float64 `json:"cost_usd"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 1 {
		t.Fatalf("messages: got %d want 1", len(got.Messages))
	}
	msg := got.Messages[0]
	if msg.MessageID != "msg_lc" {
		t.Fatalf("message_id: got %q want msg_lc", msg.MessageID)
	}
	if msg.Input != 300_000 {
		t.Fatalf("input: got %d want 300000", msg.Input)
	}
	const wantCost = 1.50 // 2 x (150K * $5 / 1M), both turns stay below 272K.
	if diff := msg.CostUSD - wantCost; diff > 1e-6 || diff < -1e-6 {
		t.Errorf("cost_usd: got %v want %v (message rollup must sum per-turn pricing, not LC-price the aggregate)", msg.CostUSD, wantCost)
	}
}

// TestAPISessionMessages_TieBreakUserBeforeAssistant pins the v1.4.28
// ordering rule: when a user_prompt and its assistant turn share an
// identical timestamp (common when the proxy stamps the synthesized
// user row with the same wall-clock as the assistant turn), the user
// row must render first in the timeline.
func TestAPISessionMessages_TieBreakUserBeforeAssistant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	ts := time.Date(2026, 5, 3, 6, 50, 0, 0, time.UTC)

	// User prompt and assistant tool call at the EXACT same timestamp.
	// Note: the user row is inserted SECOND so the natural insertion
	// order in the merged slice puts the assistant first — which is
	// what the bug looks like before the tie-break fix.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "toolu_1", SessionID: "sB",
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "main.go", Success: true,
			MessageID: "msg_B",
		},
		{
			SourceFile: "f", SourceEventID: "u1", SessionID: "sB",
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionUserPrompt, Target: "do X", Success: true,
			MessageID: "user_evt_1",
		},
	}, []models.TokenEvent{
		{
			SourceFile: "f", SourceEventID: "msg_B", SessionID: "sB",
			Timestamp: ts, Tool: models.ToolClaudeCode,
			Model: "claude-opus-4-7", InputTokens: 100, OutputTokens: 500,
			MessageID: "msg_B",
			Source:    models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
		},
	}, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sB/messages", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Messages []struct {
			Role string `json:"role"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 2 {
		t.Fatalf("messages: got %d want 2", len(got.Messages))
	}
	if got.Messages[0].Role != "user" || got.Messages[1].Role != "assistant" {
		t.Errorf("tie-break ordering: got %q,%q want user,assistant",
			got.Messages[0].Role, got.Messages[1].Role)
	}
}

// TestAPISessionMessages_ElapsedMs pins v1.4.28's per-message
// wall-clock duration: each message exposes the gap (ms) to the
// next message in the timeline. The final message has no successor
// and reports null.
func TestAPISessionMessages_ElapsedMs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	t0 := time.Date(2026, 5, 3, 6, 50, 0, 0, time.UTC)

	// User prompt → assistant turn 12s later → user follow-up 47s
	// after that. Three messages, two gaps.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "u1", SessionID: "sE",
			ProjectRoot: root, Timestamp: t0, Tool: models.ToolClaudeCode,
			ActionType: models.ActionUserPrompt, Target: "do X", Success: true,
			MessageID: "user_evt_1",
		},
		{
			SourceFile: "f", SourceEventID: "toolu_1", SessionID: "sE",
			ProjectRoot: root, Timestamp: t0.Add(12 * time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "main.go", Success: true,
			MessageID: "msg_E",
		},
		{
			SourceFile: "f", SourceEventID: "u2", SessionID: "sE",
			ProjectRoot: root, Timestamp: t0.Add(59 * time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionUserPrompt, Target: "now Y", Success: true,
			MessageID: "user_evt_2",
		},
	}, []models.TokenEvent{
		{
			SourceFile: "f", SourceEventID: "msg_E", SessionID: "sE",
			Timestamp: t0.Add(12 * time.Second), Tool: models.ToolClaudeCode,
			Model: "claude-opus-4-7", InputTokens: 100, OutputTokens: 500,
			MessageID: "msg_E",
			Source:    models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
		},
	}, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sE/messages", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Messages []struct {
			Role      string `json:"role"`
			ElapsedMs *int64 `json:"elapsed_ms"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 3 {
		t.Fatalf("messages: got %d want 3", len(got.Messages))
	}
	// First message → 12000ms gap to assistant turn.
	if got.Messages[0].ElapsedMs == nil || *got.Messages[0].ElapsedMs != 12000 {
		t.Errorf("messages[0].elapsed_ms: got %v want 12000", got.Messages[0].ElapsedMs)
	}
	// Assistant turn → 47000ms gap to next user prompt.
	if got.Messages[1].ElapsedMs == nil || *got.Messages[1].ElapsedMs != 47000 {
		t.Errorf("messages[1].elapsed_ms: got %v want 47000", got.Messages[1].ElapsedMs)
	}
	// Last message has no successor → null.
	if got.Messages[2].ElapsedMs != nil {
		t.Errorf("messages[2].elapsed_ms: got %v want null", *got.Messages[2].ElapsedMs)
	}
}

// TestAPISessionMessages_ToolDurationMs pins v1.4.28's per-message
// tool-execution time: each assistant turn's message row carries the
// sum of its contained tool_calls' duration_ms (separately from the
// wall-clock ElapsedMs). Exposes per-tool-call duration_ms too.
func TestAPISessionMessages_ToolDurationMs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	ts := time.Date(2026, 5, 3, 7, 0, 0, 0, time.UTC)

	// Two tool calls under the same assistant message — durations 250ms
	// and 750ms — should sum to 1000ms on the message row.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "tu_1", SessionID: "sT",
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			DurationMs: 250, MessageID: "msg_T",
		},
		{
			SourceFile: "f", SourceEventID: "tu_2", SessionID: "sT",
			ProjectRoot: root, Timestamp: ts.Add(time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "ls -la", Success: true,
			DurationMs: 750, MessageID: "msg_T",
		},
	}, []models.TokenEvent{
		{
			SourceFile: "f", SourceEventID: "msg_T", SessionID: "sT",
			Timestamp: ts, Tool: models.ToolClaudeCode,
			Model: "claude-opus-4-7", InputTokens: 100, OutputTokens: 500,
			MessageID: "msg_T",
			Source:    models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
		},
	}, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sT/messages", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Messages []struct {
			Role           string `json:"role"`
			ToolDurationMs int64  `json:"tool_duration_ms"`
			ToolCalls      []struct {
				DurationMs int64 `json:"duration_ms"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 1 {
		t.Fatalf("messages: got %d want 1", len(got.Messages))
	}
	m := got.Messages[0]
	if m.ToolDurationMs != 1000 {
		t.Errorf("tool_duration_ms: got %d want 1000 (250+750)", m.ToolDurationMs)
	}
	if len(m.ToolCalls) != 2 {
		t.Fatalf("tool_calls: got %d want 2", len(m.ToolCalls))
	}
	if m.ToolCalls[0].DurationMs != 250 || m.ToolCalls[1].DurationMs != 750 {
		t.Errorf("per-tool durations: got %d/%d want 250/750",
			m.ToolCalls[0].DurationMs, m.ToolCalls[1].DurationMs)
	}
}

// TestAPISessionDetail_PerTurnDedup_GapFillAndPerModel is the regression
// test for the b9bd459d-shape complaint: a session whose proxy intercepted
// SOME turns must have token_usage rows for the OTHER turns folded back
// into the totals (gap-fill), and the per-model breakdown must show every
// model that contributed (haiku + opus), not just the session's
// most-recent model. Pre-2026-04-29 the session detail endpoint had its
// own per-session dedup ("if api_turns has any rows, drop all
// token_usage") that mirrored the cost-engine bug fixed in v1.4.12 — that
// silently dropped 80%+ of tokens when the proxy was off for most of a
// session.
func TestAPISessionDetail_PerTurnDedup_GapFillAndPerModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	ts := time.Date(2026, 4, 28, 6, 50, 0, 0, time.UTC)

	// Create session sA with one action so the row exists.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sA",
		ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// Two proxy turns the proxy DID intercept — one haiku, one opus —
	// each with a request_id (msg_xxx) that matches a JSONL row. Plus
	// two JSONL-only turns (representing turns the proxy missed and
	// only the JSONL adapter recorded), one per model.
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sA", Provider: models.ProviderAnthropic,
		Model: "claude-haiku-4-5", InputTokens: 100, OutputTokens: 500,
		CacheReadTokens: 50_000, CacheCreationTokens: 10_000,
		Timestamp: ts, RequestID: "msg_haiku_1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sA", Provider: models.ProviderAnthropic,
		Model: "claude-opus-4-7", InputTokens: 50, OutputTokens: 5_000,
		CacheReadTokens: 800_000, CacheCreationTokens: 200_000,
		Timestamp: ts.Add(time.Minute), RequestID: "msg_opus_1",
	}); err != nil {
		t.Fatal(err)
	}

	// Insert four token_usage rows directly (not via the adapter).
	// Two have source_event_id matching the proxy request_ids — those
	// must be deduped out. Two have novel ids — those must survive.
	for _, tu := range []struct {
		eid, model      string
		in, out, cr, cw int64
	}{
		{"msg_haiku_1", "claude-haiku-4-5", 100, 500, 50_000, 10_000},            // dup of proxy
		{"msg_opus_1", "claude-opus-4-7", 50, 5_000, 800_000, 200_000},           // dup of proxy
		{"msg_haiku_gap", "claude-haiku-4-5", 7_200, 28_700, 1_950_000, 313_000}, // gap-fill
		{"msg_opus_gap", "claude-opus-4-7", 97, 78_100, 3_200_000, 800_000},      // gap-fill
	} {
		_, err := database.ExecContext(context.Background(),
			`INSERT INTO token_usage (session_id, source_file, source_event_id, timestamp, tool, model,
				input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
				source, reliability)
			 VALUES ('sA', 'f-tu', ?, ?, 'claude-code', ?, ?, ?, ?, ?, 'jsonl', 'unreliable')`,
			tu.eid, ts.Format(time.RFC3339Nano), tu.model, tu.in, tu.out, tu.cr, tu.cw)
		if err != nil {
			t.Fatal(err)
		}
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Tokens   map[string]int64 `json:"tokens"`
		PerModel []struct {
			Model         string  `json:"model"`
			Input         int64   `json:"input"`
			Output        int64   `json:"output"`
			CacheRead     int64   `json:"cache_read"`
			CacheCreation int64   `json:"cache_creation"`
			TurnCount     int64   `json:"turn_count"`
			CostUSD       float64 `json:"cost_usd"`
		} `json:"per_model"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}

	// Expected totals: proxy turns + JSONL gap-fill turns; matching
	// JSONL rows for the proxy turns are deduped out.
	wantTotal := map[string]int64{
		"input":          100 + 50 + 7_200 + 97,
		"output":         500 + 5_000 + 28_700 + 78_100,
		"cache_read":     50_000 + 800_000 + 1_950_000 + 3_200_000,
		"cache_creation": 10_000 + 200_000 + 313_000 + 800_000,
	}
	for k, v := range wantTotal {
		if got.Tokens[k] != v {
			t.Errorf("tokens[%s]: got %d want %d", k, got.Tokens[k], v)
		}
	}

	// Per-model breakdown: must surface BOTH haiku and opus, with
	// per-turn-deduped totals. Pre-fix it would have surfaced only
	// the proxy values (or only the JSONL values, depending on which
	// path triggered) — and never the gap-filled mix.
	if len(got.PerModel) != 2 {
		t.Fatalf("per_model: got %d rows want 2 (haiku + opus)", len(got.PerModel))
	}
	byModel := map[string]int64{} // model → input
	turnsByModel := map[string]int64{}
	for _, m := range got.PerModel {
		byModel[m.Model] = m.Input
		turnsByModel[m.Model] = m.TurnCount
	}
	if byModel["claude-haiku-4-5"] != 100+7_200 {
		t.Errorf("haiku input: got %d want %d", byModel["claude-haiku-4-5"], 100+7_200)
	}
	if byModel["claude-opus-4-7"] != 50+97 {
		t.Errorf("opus input: got %d want %d", byModel["claude-opus-4-7"], 50+97)
	}
	// Each model has 2 surviving turns (one proxy + one JSONL gap-fill).
	if turnsByModel["claude-haiku-4-5"] != 2 {
		t.Errorf("haiku turn count: got %d want 2", turnsByModel["claude-haiku-4-5"])
	}
	if turnsByModel["claude-opus-4-7"] != 2 {
		t.Errorf("opus turn count: got %d want 2", turnsByModel["claude-opus-4-7"])
	}
}

// TestAPISessionDetail_CodexShapeDedup is the dashboard end-to-end for
// audit F1 (2026-06-08): a codex turn captured by BOTH the proxy
// (api_turns, request_id=resp_…, fast=0, recorded STANDARD cost) and the
// watcher (token_usage, source_event_id=tk:…, fast=1) must collapse to ONE
// turn — the ids share no scheme, so the id NOT-IN dedup can't fire and the
// shape NOT-EXISTS must. The surviving proxy row inherits the JSONL twin's
// fast flag and re-prices WITH the gpt-5.4 FastMultiplier premium. The
// detail and messages endpoints must AGREE on the result (pre-fix the detail
// CTE dropped the fast column and the two surfaces showed different inflated,
// double-counted numbers).
func TestAPISessionDetail_CodexShapeDedup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	ts := time.Date(2026, 6, 7, 21, 26, 5, 0, time.UTC)

	// Codex session sC with one action so the row exists.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sC",
		ProjectRoot: root, Timestamp: ts, Tool: models.ToolCodex,
		ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// Proxy turn: wire tier standard (fast=0), recorded cost is the STANDARD
	// gpt-5.4 price ($0.40 = 100k*2.5/1e6 + 10k*15/1e6). request_id=resp_…
	if _, err := database.ExecContext(context.Background(),
		`INSERT INTO api_turns (session_id, timestamp, provider, model,
			input_tokens, output_tokens, cache_read_tokens, request_id, cost_usd, fast)
		 VALUES ('sC', ?, 'openai', 'gpt-5.4', 100000, 10000, 0, 'resp_abc', 0.40, 0)`,
		ts.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	// Watcher twin: SAME tokens, disjoint id scheme (tk:…), config priority
	// (fast=1). 11s later — inside the same minute here, but sessionShapeKey
	// / the SQL shape match don't depend on the minute anyway.
	if _, err := database.ExecContext(context.Background(),
		`INSERT INTO token_usage (session_id, source_file, source_event_id, timestamp, tool, model,
			input_tokens, output_tokens, cache_read_tokens, source, reliability, fast)
		 VALUES ('sC', 'f-tu', 'tk:rollout-x:L15', ?, 'codex', 'gpt-5.4', 100000, 10000, 0, 'jsonl', 'approximate', 1)`,
		ts.Add(11*time.Second).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}

	// --- Detail endpoint ---
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/sC", nil))
	if rr.Code != 200 {
		t.Fatalf("detail status: %d body=%s", rr.Code, rr.Body.String())
	}
	var detail struct {
		CostUSD  float64          `json:"cost_usd"`
		Tokens   map[string]int64 `json:"tokens"`
		PerModel []struct {
			Model     string  `json:"model"`
			Input     int64   `json:"input"`
			TurnCount int64   `json:"turn_count"`
			CostUSD   float64 `json:"cost_usd"`
		} `json:"per_model"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.PerModel) != 1 || detail.PerModel[0].TurnCount != 1 {
		t.Fatalf("per_model: got %+v, want exactly 1 gpt-5.4 row with turn_count 1 (codex shape-dedup)", detail.PerModel)
	}
	if detail.Tokens["input"] != 100000 {
		t.Errorf("tokens.input: got %d, want 100000 (not doubled)", detail.Tokens["input"])
	}
	// Proxy inherits fast → re-priced at 2×: $0.40 standard → $0.80 premium.
	if d := detail.CostUSD - 0.80; d < -1e-9 || d > 1e-9 {
		t.Errorf("detail cost_usd: got %.6f, want 0.80 (proxy inherits fast premium, not double-counted $0.40+$0.40)", detail.CostUSD)
	}

	// --- Messages endpoint must AGREE with detail ---
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/api/session/sC/messages", nil))
	if rr2.Code != 200 {
		t.Fatalf("messages status: %d body=%s", rr2.Code, rr2.Body.String())
	}
	var msgs struct {
		Messages []struct {
			CostUSD float64 `json:"cost_usd"`
			Fast    bool    `json:"fast"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(rr2.Body).Decode(&msgs); err != nil {
		t.Fatal(err)
	}
	var msgTotal float64
	var anyFast bool
	for _, m := range msgs.Messages {
		msgTotal += m.CostUSD
		if m.Fast {
			anyFast = true
		}
	}
	if d := msgTotal - detail.CostUSD; d < -1e-9 || d > 1e-9 {
		t.Errorf("messages total %.6f != detail total %.6f (surfaces must agree after F1)", msgTotal, detail.CostUSD)
	}
	if !anyFast {
		t.Errorf("messages: expected the ⚡ fast badge on the inherited-fast gpt-5.4 turn")
	}
}

// TestAPISessionDetail_CacheCreation1hTier is the end-to-end check for
// audit item C5: a session whose proxy turns split cache_creation into
// 5m vs 1h tiers must see the 1h portion billed at the 1h rate (2× the
// 5m rate). Pre-tier-aware code summed all cache_creation at the 5m rate
// and silently under-counted whenever 1h-tier traffic appeared.
func TestAPISessionDetail_CacheCreation1hTier(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	ts := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)

	// Create session sA via Ingest.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sA",
		ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// Proxy turn for sA: 1M cache_creation tokens, 400k of them in the
	// 1h tier. Pricing for claude-sonnet-4-6 per
	// docs/pricing-reference.md:
	//   {Input: 3, Output: 15, CacheRead: 0.30, CacheCreation: 3.75,
	//    CacheCreation1h: 6.00 (= 2 × Input — Anthropic's published ratio)}.
	// Expected cost split:
	//   5m portion: 600_000 × 3.75 / 1e6 = 2.25
	//   1h portion: 400_000 × 6.00 / 1e6 = 2.40
	//   Total cache_creation cost: 4.65
	// (Input/output set to zero so the cache_creation contribution is
	// the entire cost — easier to assert without arithmetic noise.)
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID:             "sA",
		Timestamp:             ts,
		Provider:              models.ProviderAnthropic,
		Model:                 "claude-sonnet-4-6",
		CacheCreationTokens:   1_000_000,
		CacheCreation1hTokens: 400_000,
	}); err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	costUSD, _ := got["cost_usd"].(float64)
	want := 4.65
	if costUSD < want*0.999 || costUSD > want*1.001 {
		t.Errorf("cost_usd: got %v, want ≈ %v (1h tier billed at 2× input)", costUSD, want)
	}

	// Sanity: a session with the *same* total cache_creation but ZERO
	// 1h tier should bill at the 5m rate only — proves we're not just
	// applying the 1h rate uniformly.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e2", SessionID: "sB",
		ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "b.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sB", Timestamp: ts,
		Provider:            models.ProviderAnthropic,
		Model:               "claude-sonnet-4-6",
		CacheCreationTokens: 1_000_000, // entire bundle 5m-tier
	}); err != nil {
		t.Fatalf("InsertAPITurn sB: %v", err)
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/session/sB", nil)
	srv.Handler().ServeHTTP(rr, req)
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	costUSDB, _ := got["cost_usd"].(float64)
	want = 3.75 // 1M × 3.75 / 1e6
	if costUSDB < want*0.999 || costUSDB > want*1.001 {
		t.Errorf("5m-only cost_usd: got %v, want ≈ %v", costUSDB, want)
	}
}

// TestAPISessionDetail_LongContextPerTurn pins the per-turn pricing
// guarantee in the session-detail endpoint. The cost engine reprices an
// entire turn at the long-context tier when the prompt exceeds a
// threshold (Sonnet 4 / 4.5 at 200K). Pre-LC the endpoint aggregated
// tokens at SQL level and called Compute on the sum — a session with N
// sub-threshold turns whose summed prompt cleared the threshold would
// false-positive LC pricing. The fix pulls individual rows and prices
// per-turn before bucketing.
//
// Setup: three Sonnet 4 turns, each 100K input. Aggregate = 300K (over
// the 200K threshold) but no individual turn is. Expected cost is the
// standard rate: 3 × 100K × $3 / 1M = $0.90. If aggregation-then-pricing
// regressed in, the cost would be 300K × $6 / 1M = $1.80.
func TestAPISessionDetail_LongContextPerTurn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	ts := time.Date(2026, 4, 28, 9, 0, 0, 0, time.UTC)

	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sLC",
		ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID:   "sLC",
			Provider:    models.ProviderAnthropic,
			Model:       "claude-sonnet-4-20250514",
			InputTokens: 100_000,
			Timestamp:   ts.Add(time.Duration(i) * time.Minute),
			RequestID:   fmt.Sprintf("msg_lc_%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sLC", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		CostUSD  float64 `json:"cost_usd"`
		PerModel []struct {
			Model     string  `json:"model"`
			Input     int64   `json:"input"`
			TurnCount int64   `json:"turn_count"`
			CostUSD   float64 `json:"cost_usd"`
		} `json:"per_model"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	const wantCost = 0.90 // 3 × 100K × $3 / 1M, all turns under threshold
	if diff := got.CostUSD - wantCost; diff > 1e-6 || diff < -1e-6 {
		t.Errorf("cost_usd: got %v want %v (per-turn pricing must NOT trip LC tier)", got.CostUSD, wantCost)
	}
	if len(got.PerModel) != 1 {
		t.Fatalf("per_model: got %d rows want 1", len(got.PerModel))
	}
	if got.PerModel[0].TurnCount != 3 {
		t.Errorf("turn_count: got %d want 3", got.PerModel[0].TurnCount)
	}
	if got.PerModel[0].Input != 300_000 {
		t.Errorf("aggregated input: got %d want 300_000", got.PerModel[0].Input)
	}
	if diff := got.PerModel[0].CostUSD - wantCost; diff > 1e-6 || diff < -1e-6 {
		t.Errorf("per_model cost: got %v want %v", got.PerModel[0].CostUSD, wantCost)
	}

	// Counter-test: a single Sonnet 4 turn that DOES clear the threshold
	// must price at LC rates. Confirms LC dispatch still runs per-turn.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e2", SessionID: "sLC2",
		ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "b.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID:   "sLC2",
		Provider:    models.ProviderAnthropic,
		Model:       "claude-sonnet-4-20250514",
		InputTokens: 250_000, // single turn clears 200K threshold
		Timestamp:   ts,
		RequestID:   "msg_lc_single",
	}); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/session/sLC2", nil)
	srv.Handler().ServeHTTP(rr, req)
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	const wantLC = 1.50 // 250K × $6 / 1M (LC input rate)
	if diff := got.CostUSD - wantLC; diff > 1e-6 || diff < -1e-6 {
		t.Errorf("LC turn cost_usd: got %v want %v", got.CostUSD, wantLC)
	}
}

// TestAPITimeseriesCost_Chronological pins the chart-axis fix: the
// day-bucket cost timeseries used to inherit cost.Engine.Summary's
// cost_usd-DESC sort, which left chart x-axes reading newest-on-left
// (high-cost days first). Series must come back oldest-first so the
// chart reads chronologically left-to-right.
func TestAPITimeseriesCost_Chronological(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	// Three turns on three different days; insert deliberately in
	// non-chronological order with a *higher* cost on the middle day so
	// a cost-DESC sort would put it first. Chronological sort must put
	// the earliest day first regardless.
	turns := []models.APITurn{
		{
			SessionID: "s", Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 1_000_000,
			Timestamp: time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
		},
		{
			SessionID: "s", Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 5_000_000, // most expensive day
			Timestamp: time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC),
		},
		{
			SessionID: "s", Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 2_000_000,
			Timestamp: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		},
	}
	for _, turn := range turns {
		if _, err := st.InsertAPITurn(context.Background(), turn); err != nil {
			t.Fatalf("InsertAPITurn: %v", err)
		}
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/timeseries/cost?days=365&bucket=day", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Series []struct {
			Bucket  string  `json:"bucket"`
			CostUSD float64 `json:"cost_usd"`
		} `json:"series"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Series) != 3 {
		t.Fatalf("series: got %d points want 3", len(got.Series))
	}
	want := []string{"2026-04-10", "2026-04-15", "2026-04-20"}
	for i, w := range want {
		if got.Series[i].Bucket != w {
			t.Errorf("series[%d].bucket: got %q want %q (chronological order)",
				i, got.Series[i].Bucket, w)
		}
	}
}

// TestAPITimeseriesTokensByModel pins the per-model day-split chart
// endpoint: each (day, model) pair becomes one point, points sort
// chronologically then alphabetically by model, and the cost engine's
// dedup applies (proxy preferred over JSONL for the same session).
func TestAPITimeseriesTokensByModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	// Two days × two models = four expected points. Inserted in a
	// scrambled order to flush out a missing chronological sort.
	turns := []models.APITurn{
		{
			SessionID: "s1", Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 1_000_000,
			Timestamp: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		},
		{
			SessionID: "s2", Provider: models.ProviderAnthropic,
			Model: "claude-haiku-4-5", InputTokens: 500_000,
			Timestamp: time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
		},
		{
			SessionID: "s3", Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 2_000_000,
			Timestamp: time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
		},
		{
			SessionID: "s4", Provider: models.ProviderAnthropic,
			Model: "claude-haiku-4-5", InputTokens: 800_000,
			Timestamp: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		},
	}
	for _, turn := range turns {
		if _, err := st.InsertAPITurn(context.Background(), turn); err != nil {
			t.Fatalf("InsertAPITurn: %v", err)
		}
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/timeseries/tokens-by-model?days=365", nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Metric string `json:"metric"`
		Series []struct {
			Bucket      string `json:"bucket"`
			Model       string `json:"model"`
			TotalTokens int64  `json:"total_tokens"`
			Input       int64  `json:"input"`
		} `json:"series"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Metric != "tokens_by_model" {
		t.Errorf("metric = %q want tokens_by_model", got.Metric)
	}
	if len(got.Series) != 4 {
		t.Fatalf("series: got %d points want 4", len(got.Series))
	}
	want := []struct{ bucket, model string }{
		{"2026-04-10", "claude-haiku-4-5"},
		{"2026-04-10", "claude-sonnet-4-6"},
		{"2026-04-20", "claude-haiku-4-5"},
		{"2026-04-20", "claude-sonnet-4-6"},
	}
	for i, w := range want {
		if got.Series[i].Bucket != w.bucket || got.Series[i].Model != w.model {
			t.Errorf("series[%d]: got (%q, %q) want (%q, %q)",
				i, got.Series[i].Bucket, got.Series[i].Model, w.bucket, w.model)
		}
	}
	// Sanity-check token totals on one specific cell so we know the
	// pivot didn't smear values across rows.
	for _, p := range got.Series {
		if p.Bucket == "2026-04-10" && p.Model == "claude-sonnet-4-6" && p.Input != 2_000_000 {
			t.Errorf("(2026-04-10, sonnet) input = %d want 2_000_000", p.Input)
		}
	}
}

// TestAPITimeseriesActions covers the time-series action endpoint.
func TestAPITimeseriesActions(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/timeseries/actions?days=30&bucket=day", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["metric"] != "actions" || got["bucket"] != "day" {
		t.Errorf("metric/bucket: %v / %v", got["metric"], got["bucket"])
	}
	series, ok := got["series"].([]any)
	if !ok {
		t.Fatalf("series missing or wrong shape: %T", got["series"])
	}
	if len(series) < 1 {
		t.Errorf("expected >= 1 bucket from the seeded action, got %d", len(series))
	}
}

// TestAPITools covers the per-tool breakdown endpoint.
func TestAPITools(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/tools?days=30", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	tools, ok := got["tools"].([]any)
	if !ok {
		t.Fatalf("tools missing or wrong shape: %v", got)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool entry (claude-code), got %d", len(tools))
	}
	first, _ := tools[0].(map[string]any)
	if first["tool"] != "claude-code" {
		t.Errorf("tool name: %v", first["tool"])
	}
	if first["action_count"].(float64) != 1 {
		t.Errorf("action_count: %v", first["action_count"])
	}
}

func TestAPIDiscover(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/discover?limit=5", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("discover: %d", rr.Code)
	}
	var got map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["summary"] == nil {
		t.Errorf("missing summary: %+v", got)
	}
}

// TestAPIActions_MetadataFilters pins the v1.4.48 dashboard filter
// surface: /api/actions accepts effort_level / permission_mode /
// is_interrupt query params that filter on the migration-017
// actions.metadata JSON column via json_extract. Empty / absent
// params skip the corresponding filter so legacy callers' results
// are unchanged.
func TestAPIActions_MetadataFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	base := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)

	// Seed 5 rows covering the filter matrix:
	// - row1: plan + high + interrupt
	// - row2: plan + medium + no interrupt
	// - row3: default + high + no interrupt
	// - row4: acceptEdits + xhigh + interrupt
	// - row5: no metadata at all (Claude Code Tier 0 / pre-017)
	events := []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "e1", SessionID: "s1",
			ProjectRoot: root, Timestamp: base, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Metadata: &models.ActionMetadata{PermissionMode: "plan", EffortLevel: "high", IsInterrupt: true},
		},
		{
			SourceFile: "f", SourceEventID: "e2", SessionID: "s1",
			ProjectRoot: root, Timestamp: base.Add(time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
			Metadata: &models.ActionMetadata{PermissionMode: "plan", EffortLevel: "medium"},
		},
		{
			SourceFile: "f", SourceEventID: "e3", SessionID: "s1",
			ProjectRoot: root, Timestamp: base.Add(2 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "c.go", Success: true,
			Metadata: &models.ActionMetadata{PermissionMode: "default", EffortLevel: "high"},
		},
		{
			SourceFile: "f", SourceEventID: "e4", SessionID: "s1",
			ProjectRoot: root, Timestamp: base.Add(3 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "d.go", Success: true,
			Metadata: &models.ActionMetadata{PermissionMode: "acceptEdits", EffortLevel: "xhigh", IsInterrupt: true},
		},
		{
			SourceFile: "f", SourceEventID: "e5", SessionID: "s1",
			ProjectRoot: root, Timestamp: base.Add(4 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "e.go", Success: true,
		},
	}
	if _, err := st.Ingest(context.Background(), events, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}

	check := func(query string, wantTotal int) {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/actions?"+query, nil)
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", query, rr.Code, rr.Body.String())
		}
		var got struct {
			Total int `json:"total"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatalf("%s: decode: %v", query, err)
		}
		if got.Total != wantTotal {
			t.Errorf("%s: total=%d want %d", query, got.Total, wantTotal)
		}
	}

	// Baseline: no filter = all 5 rows.
	check("limit=50", 5)

	// effort_level=high → rows 1 + 3.
	check("effort_level=high", 2)
	// effort_level=xhigh → row 4 only.
	check("effort_level=xhigh", 1)
	// effort_level=low → none.
	check("effort_level=low", 0)

	// permission_mode=plan → rows 1 + 2.
	check("permission_mode=plan", 2)
	// permission_mode=default → row 3 only.
	check("permission_mode=default", 1)
	// permission_mode=acceptEdits → row 4 only.
	check("permission_mode=acceptEdits", 1)

	// is_interrupt=1 → rows 1 + 4. Row 5 with nil metadata must NOT
	// match (json_extract on NULL returns NULL, which fails the = 1
	// comparison).
	check("is_interrupt=1", 2)
	// is_interrupt=0 is NOT a documented filter value — it's
	// intentionally ignored (only "1" triggers the WHERE clause).
	check("is_interrupt=0", 5)

	// Combined: effort_level=high AND permission_mode=plan → row 1
	// only.
	check("effort_level=high&permission_mode=plan", 1)
	// Combined + interrupt → still row 1.
	check("effort_level=high&permission_mode=plan&is_interrupt=1", 1)

	// Empty filters fall through to baseline.
	check("limit=50&effort_level=&permission_mode=&is_interrupt=", 5)
}

// TestAPIActions_AssistantTextFilter pins the v1.4.49 "AI messages only"
// surface: the multi-pattern OR-chain matches all five assistant-text
// RawToolName conventions across the codebase (new <source>.assistant_text
// wirings + the 4 legacy precedents: Antigravity's structured.assistant_text,
// Pi's message.assistant.<stopReason>, OpenClaw's message.assistant.stop,
// Copilot's agent_response).
func TestAPIActions_AssistantTextFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	base := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)

	events := []models.ToolEvent{
		// New convention rows — should match.
		{
			SourceFile: "f", SourceEventID: "n1", SessionID: "s", ProjectRoot: root, Timestamp: base, Tool: models.ToolCodex,
			ActionType: models.ActionTaskComplete, Target: "codex msg", Success: true,
			RawToolName: "codex.assistant_text",
		},
		{
			SourceFile: "f", SourceEventID: "n2", SessionID: "s", ProjectRoot: root, Timestamp: base.Add(time.Second), Tool: models.ToolCline,
			ActionType: models.ActionTaskComplete, Target: "cline msg", Success: true,
			RawToolName: "cline.assistant_text",
		},
		{
			SourceFile: "f", SourceEventID: "n3", SessionID: "s", ProjectRoot: root, Timestamp: base.Add(2 * time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionTaskComplete, Target: "cc msg", Success: true,
			RawToolName: "claudecode.assistant_text",
		},
		// Legacy convention rows — should also match.
		{
			SourceFile: "f", SourceEventID: "l1", SessionID: "s", ProjectRoot: root, Timestamp: base.Add(3 * time.Second), Tool: models.ToolAntigravity,
			ActionType: models.ActionTaskComplete, Target: "antigravity msg", Success: true,
			RawToolName: "structured.assistant_text",
		},
		{
			SourceFile: "f", SourceEventID: "l2", SessionID: "s", ProjectRoot: root, Timestamp: base.Add(4 * time.Second), Tool: models.ToolPi,
			ActionType: models.ActionTaskComplete, Target: "pi msg", Success: true,
			RawToolName: "message.assistant.stop",
		},
		{
			SourceFile: "f", SourceEventID: "l3", SessionID: "s", ProjectRoot: root, Timestamp: base.Add(5 * time.Second), Tool: models.ToolCopilot,
			ActionType: models.ActionTaskComplete, Target: "copilot msg", Success: true,
			RawToolName: "agent_response",
		},
		// Non-matching rows — tool calls + other action types.
		{
			SourceFile: "f", SourceEventID: "x1", SessionID: "s", ProjectRoot: root, Timestamp: base.Add(6 * time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			RawToolName: "Read",
		},
		{
			SourceFile: "f", SourceEventID: "x2", SessionID: "s", ProjectRoot: root, Timestamp: base.Add(7 * time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionTaskComplete, Target: "stop", Success: true,
			RawToolName: "task_complete",
		},
	}
	if _, err := st.Ingest(context.Background(), events, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}

	check := func(query string, wantTotal int) {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/actions?"+query, nil)
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", query, rr.Code, rr.Body.String())
		}
		var got struct {
			Total int `json:"total"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatalf("%s: decode: %v", query, err)
		}
		if got.Total != wantTotal {
			t.Errorf("%s: total=%d want %d", query, got.Total, wantTotal)
		}
	}

	// Baseline: 8 rows total.
	check("limit=50", 8)
	// assistant_text=1: 6 matching rows (3 new conventions + 3 legacy patterns).
	check("assistant_text=1", 6)
	// Combine with tool filter: assistant_text=1 + tool=codex → 1 row.
	check("assistant_text=1&tool=codex", 1)
	// assistant_text=0 is NOT a documented value — falls through (no filter).
	check("assistant_text=0", 8)
}

// TestAPIPatterns_ToolFilter pins the v1.6.3 tool-scoping behavior on
// /api/patterns. Patterns are project-scoped; the tool filter restricts
// to projects whose actions table has at least one row for the
// requested tool. Seeds two projects with actions for different tools
// and one pattern per project, then asserts every combination of the
// (no filter, project-only, tool-only, both) matrix.
func TestAPIPatterns_ToolFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	rootA := t.TempDir()
	rootB := t.TempDir()
	now := time.Now().UTC()
	events := []models.ToolEvent{
		{
			SourceFile: "fA", SourceEventID: "1", SessionID: "sA", ProjectRoot: rootA,
			Timestamp: now.Add(-time.Hour), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		},
		{
			SourceFile: "fB", SourceEventID: "2", SessionID: "sB", ProjectRoot: rootB,
			Timestamp: now.Add(-time.Hour), Tool: models.ToolCopilot,
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
		},
	}
	if _, err := st.Ingest(context.Background(), events, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// Insert one pattern per project. Resolve project_ids via root_path
	// lookup (Ingest auto-creates projects rows).
	var pidA, pidB int64
	if err := database.QueryRowContext(context.Background(),
		`SELECT id FROM projects WHERE root_path = ?`, rootA).Scan(&pidA); err != nil {
		t.Fatalf("lookup pidA: %v", err)
	}
	if err := database.QueryRowContext(context.Background(),
		`SELECT id FROM projects WHERE root_path = ?`, rootB).Scan(&pidB); err != nil {
		t.Fatalf("lookup pidB: %v", err)
	}
	for _, p := range []struct {
		pid  int64
		kind string
	}{{pidA, "hot_file"}, {pidB, "co_change"}} {
		if _, err := database.ExecContext(context.Background(),
			`INSERT INTO project_patterns
			  (project_id, pattern_type, pattern_data, confidence,
			   last_reinforced_at, decay_half_life_days,
			   observation_count, source_tools, source_session_count)
			 VALUES (?, ?, '{}', 0.9, ?, 30, 5, '[]', 1)`,
			p.pid, p.kind, now.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert pattern: %v", err)
		}
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	check := func(query string, wantTotal int) {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/patterns?"+query, nil)
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", query, rr.Code, rr.Body.String())
		}
		var got struct {
			Total int `json:"total"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatalf("%s: decode: %v", query, err)
		}
		if got.Total != wantTotal {
			t.Errorf("%s: total=%d want %d", query, got.Total, wantTotal)
		}
	}

	check("limit=20", 2)
	check("limit=20&tool=claude-code", 1)
	check("limit=20&tool=copilot", 1)
	check("limit=20&tool=cursor", 0)
	check("limit=20&project="+rootA, 1)
	check("limit=20&project="+rootA+"&tool=claude-code", 1)
	check("limit=20&project="+rootA+"&tool=copilot", 0)
}

// TestAPISessions_CostReconcilesWithModels pins the v1.6.4 fix that
// aligns /api/sessions' per-session cost rollup window to the `days`
// query param (was hardcoded Days=365). After the fix, summing
// cost_usd across all sessions returned by /api/sessions?days=N
// equals /api/models?days=N total_cost_usd to within rounding —
// closing the cross-page discrepancy operators noticed when
// reconciling the Cost-page headline against the Sessions-page sum.
//
// Setup: one session with two api_turns — one inside the 7-day
// window, one 60 days old (outside). With the old Days=365 default,
// the per-session cost rollup included the old turn; with the fix,
// it doesn't.
func TestAPISessions_CostReconcilesWithModels(t *testing.T) {
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	now := time.Now().UTC()
	recent := now.Add(-2 * 24 * time.Hour) // inside 7-day window
	stale := now.Add(-60 * 24 * time.Hour) // outside 7-day window

	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sA", Provider: models.ProviderAnthropic,
		Model:       "claude-sonnet-4-6",
		InputTokens: 1_000_000, OutputTokens: 50_000,
		Timestamp: recent,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sA", Provider: models.ProviderAnthropic,
		Model:       "claude-sonnet-4-6",
		InputTokens: 5_000_000, OutputTokens: 250_000,
		Timestamp: stale,
	}); err != nil {
		t.Fatal(err)
	}

	// Hit both endpoints with days=7.
	getJSON := func(url string) map[string]any {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, url, nil)
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", url, rr.Code, rr.Body.String())
		}
		var got map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatalf("%s: decode: %v", url, err)
		}
		return got
	}

	sessionsRsp := getJSON("/api/sessions?days=7&limit=10")
	modelsRsp := getJSON("/api/models?days=7")

	rows, _ := sessionsRsp["rows"].([]any)
	var sessionsCostSum float64
	for _, r := range rows {
		row, _ := r.(map[string]any)
		if c, ok := row["cost_usd"].(float64); ok {
			sessionsCostSum += c
		}
	}
	modelsTotal, _ := modelsRsp["total_cost_usd"].(float64)

	if sessionsCostSum == 0 {
		t.Fatalf("sessions cost sum is zero; the seeded recent turn should produce a cost")
	}
	// Allow 0.01% tolerance for any rounding in distributed compute.
	delta := sessionsCostSum - modelsTotal
	if delta < 0 {
		delta = -delta
	}
	if delta > sessionsCostSum*0.0001 {
		t.Errorf("sessions cost sum (%.6f) != /api/models total (%.6f): delta=%.6f",
			sessionsCostSum, modelsTotal, delta)
	}

	// Belt-and-suspenders: the recent-only window cost should be much
	// less than the seeded stale turn (5x bigger). If the fix
	// regressed and Days=365 returned, sessionsCostSum would include
	// the stale turn and balloon.
	staleApprox := 5 * sessionsCostSum
	if sessionsCostSum >= staleApprox/2 {
		t.Errorf("sessions cost sum %.6f is suspiciously high — Days param may not be honored",
			sessionsCostSum)
	}
}

// TestAPICost_HonorsToolFilter pins the v1.6.4 fix wiring the `tool`
// query param through handleCost. Pre-fix the handler only read
// `project` and `source` and ignored `tool`, so callers using the
// CLI's `observer cost --tool=X` (which forwards to this endpoint)
// got unfiltered output.
func TestAPICost_HonorsToolFilter(t *testing.T) {
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	now := time.Now().UTC()

	// Two sessions on different tools, each with a priced api_turn.
	if err := st.UpsertSession(context.Background(), models.Session{
		ID: "sCo", ProjectID: 1, Tool: models.ToolCodex, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sA", Provider: models.ProviderAnthropic, Model: "claude-sonnet-4-6",
		InputTokens: 1_000_000, OutputTokens: 50_000, Timestamp: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sCo", Provider: models.ProviderOpenAI, Model: "gpt-5.5",
		InputTokens: 500_000, OutputTokens: 25_000, Timestamp: now,
	}); err != nil {
		t.Fatal(err)
	}

	getJSON := func(url string) map[string]any {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, url, nil)
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", url, rr.Code, rr.Body.String())
		}
		var got map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatalf("%s: decode: %v", url, err)
		}
		return got
	}

	unfiltered := getJSON("/api/cost?days=30")
	claude := getJSON("/api/cost?days=30&tool=claude-code")
	codex := getJSON("/api/cost?days=30&tool=codex")
	missing := getJSON("/api/cost?days=30&tool=nonexistent")

	unfilteredTotal := unfiltered["total_cost_usd"].(float64)
	claudeTotal := claude["total_cost_usd"].(float64)
	codexTotal := codex["total_cost_usd"].(float64)
	missingTotal := missing["total_cost_usd"].(float64)

	if unfilteredTotal <= claudeTotal {
		t.Errorf("unfiltered (%.4f) should exceed claude-only (%.4f)", unfilteredTotal, claudeTotal)
	}
	if claudeTotal == 0 || codexTotal == 0 {
		t.Errorf("tool filter returned zero for a seeded tool: claude=%.4f codex=%.4f",
			claudeTotal, codexTotal)
	}
	// Tool=claude-code + tool=codex should sum to unfiltered (modulo
	// rounding) when no other tools have data.
	delta := claudeTotal + codexTotal - unfilteredTotal
	if delta < 0 {
		delta = -delta
	}
	if delta > unfilteredTotal*0.0001 {
		t.Errorf("claude (%.4f) + codex (%.4f) != unfiltered (%.4f): delta=%.4f",
			claudeTotal, codexTotal, unfilteredTotal, delta)
	}
	if missingTotal != 0 {
		t.Errorf("nonexistent tool should return 0, got %.4f", missingTotal)
	}
}

// TestAPIActionFullText pins the v1.6.29 on-demand full-text endpoint:
// /api/action/<id>/full_text returns the untruncated raw_tool_input +
// raw_tool_output for the requested action, 404s on unknown ids, and
// 400s on a malformed path. Companion of the /messages elision: the
// timeline payload carries a 4 KiB preview; this endpoint serves the
// full body when the operator clicks copy or view-full-text.
func TestAPIActionFullText(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)

	// Seed one action with raw_tool_input AND raw_tool_output set
	// so the endpoint has both fields to return.
	bigInput := strings.Repeat("INPUT-", 800) // ~4.8 KiB, exceeds inline preview cap
	bigOutput := strings.Repeat("OUT-", 1500) // ~6 KiB
	_, err := store.New(s.opts.DB).Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "ft", SourceEventID: "ft-1", SessionID: "sFT",
		ProjectRoot: t.TempDir(), Timestamp: time.Now().UTC(),
		Tool: models.ToolClaudeCode, ActionType: models.ActionUserPrompt,
		Target: "preview-target", RawToolInput: bigInput, ToolOutput: bigOutput,
		Success: true,
	}}, nil, store.IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var actionID int64
	if err := s.opts.DB.QueryRow(
		`SELECT id FROM actions WHERE source_event_id = ?`, "ft-1",
	).Scan(&actionID); err != nil {
		t.Fatal(err)
	}

	// Happy path.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/action/%d/full_text", actionID), nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET /api/action/%d/full_text: %d body=%s", actionID, rr.Code, rr.Body.String())
	}
	var got struct {
		ActionID      int64  `json:"action_id"`
		ActionType    string `json:"action_type"`
		Target        string `json:"target"`
		RawToolInput  string `json:"raw_tool_input"`
		RawToolOutput string `json:"raw_tool_output"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if got.ActionID != actionID {
		t.Errorf("action_id: got %d, want %d", got.ActionID, actionID)
	}
	if got.RawToolInput != bigInput {
		t.Errorf("raw_tool_input length: got %d, want %d", len(got.RawToolInput), len(bigInput))
	}
	if got.RawToolOutput != bigOutput {
		t.Errorf("raw_tool_output length: got %d, want %d", len(got.RawToolOutput), len(bigOutput))
	}
	if got.ActionType != models.ActionUserPrompt {
		t.Errorf("action_type: got %q, want %q", got.ActionType, models.ActionUserPrompt)
	}

	// 404: unknown id.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/action/999999/full_text", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Errorf("missing id: got %d, want 404", rr.Code)
	}

	// 400: malformed id.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/action/not-a-number/full_text", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Errorf("malformed id: got %d, want 400", rr.Code)
	}

	// 404: missing sub-resource (path without /full_text suffix).
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/action/%d", actionID), nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Errorf("unsupported sub-resource: got %d, want 404", rr.Code)
	}
}

// TestAPITimeseriesCost_HourBucketCost pins the fix for the hour-bucket
// cost path: the sub-day (bucket=hour) query must select + scan
// api_turns.cost_usd. Pre-fix the hour branch omitted cost entirely, so
// every sub-day cost bucket rendered $0 even when turns had a stored cost.
func TestAPITimeseriesCost_HourBucketCost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "s", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 1000, OutputTokens: 200,
		CostUSD:   1.23, // load-bearing: the hour path reads this column directly
		Timestamp: time.Now().UTC().Add(-30 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/timeseries/cost?bucket=hour&hours=6", nil))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Bucket string `json:"bucket"`
		Series []struct {
			Bucket  string  `json:"bucket"`
			CostUSD float64 `json:"cost_usd"`
		} `json:"series"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Bucket != "hour" {
		t.Fatalf("bucket echo: got %q want hour", got.Bucket)
	}
	if len(got.Series) != 1 {
		t.Fatalf("series: got %d points want 1", len(got.Series))
	}
	if !approxEqual(got.Series[0].CostUSD, 1.23, 1e-9) {
		t.Errorf("hour-bucket cost_usd: got %v want 1.23 (pre-fix this was 0)", got.Series[0].CostUSD)
	}
	// Bucket string must be hour-grained, not day-truncated.
	if !strings.Contains(got.Series[0].Bucket, "T") {
		t.Errorf("hour bucket string %q is day-grained; expected hour resolution", got.Series[0].Bucket)
	}
}

// TestAPIStatusScoped_HonorsUntil pins the fix for /api/status/scoped
// discarding `until`: with a bounded [since, until) window the four
// unioned count subqueries must each apply the exclusive upper bound.
func TestAPIStatusScoped_HonorsUntil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()
	twoHours := now.Add(-2 * time.Hour)
	fiveDays := now.Add(-5 * 24 * time.Hour)
	sixtyDays := now.Add(-60 * 24 * time.Hour)

	// Actions at 2h / 5d / 60d ago (distinct sessions).
	for i, ts := range []time.Time{twoHours, fiveDays, sixtyDays} {
		if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
			SourceFile: fmt.Sprintf("f%d", i), SourceEventID: fmt.Sprintf("e%d", i),
			SessionID:   fmt.Sprintf("s%d", i),
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// api_turns at the same three timestamps.
	for i, ts := range []time.Time{twoHours, fiveDays, sixtyDays} {
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: fmt.Sprintf("s%d", i), Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 100, Timestamp: ts,
		}); err != nil {
			t.Fatal(err)
		}
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}

	scoped := func(query string) (actions, apiTurns int64) {
		t.Helper()
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/status/scoped?"+query, nil))
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", query, rr.Code, rr.Body.String())
		}
		var got struct {
			Actions  int64 `json:"actions"`
			APITurns int64 `json:"api_turns"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got.Actions, got.APITurns
	}

	since := now.Add(-10 * 24 * time.Hour).Format(time.RFC3339)
	until := now.Add(-1 * 24 * time.Hour).Format(time.RFC3339)
	// [10d, 1d) brackets ONLY the 5-day-ago rows; the 2h row is after
	// `until`, the 60d row is before `since`.
	a, at := scoped("since=" + since + "&until=" + until)
	if a != 1 {
		t.Errorf("actions with until: got %d want 1 (pre-fix until ignored → 2)", a)
	}
	if at != 1 {
		t.Errorf("api_turns with until: got %d want 1 (pre-fix until ignored → 2)", at)
	}
	// Sanity: without `until`, the lower bound alone catches 2h + 5d rows.
	a2, at2 := scoped("since=" + since)
	if a2 != 2 || at2 != 2 {
		t.Errorf("actions/api_turns without until: got %d/%d want 2/2", a2, at2)
	}
}

// TestAPISessionsCalendar_CostHonorsWindow pins the fix where the
// calendar's session counts respected since/until but the cost rollup
// only received Days — so hours=1 returned 1h counts alongside 30d costs.
func TestAPISessionsCalendar_CostHonorsWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()
	old := now.Add(-10 * 24 * time.Hour)

	// Recent session with a small costed turn.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "fr", SourceEventID: "er", SessionID: "sRecent",
		ProjectRoot: root, Timestamp: now.Add(-20 * time.Minute), Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "r.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sRecent", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 100_000, Timestamp: now.Add(-20 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	// Old session (10d ago) with a much larger costed turn.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "fo", SourceEventID: "eo", SessionID: "sOld",
		ProjectRoot: root, Timestamp: old, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "o.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sOld", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 10_000_000, Timestamp: old,
	}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	sums := func(query string) (cost float64, sessions int) {
		t.Helper()
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions/calendar?"+query, nil))
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", query, rr.Code, rr.Body.String())
		}
		var got struct {
			Cells []struct {
				CostUSD      float64 `json:"cost_usd"`
				SessionCount int     `json:"session_count"`
			} `json:"cells"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		for _, c := range got.Cells {
			cost += c.CostUSD
			sessions += c.SessionCount
		}
		return
	}

	hourCost, hourSessions := sums("hours=1")
	dayCost, daySessions := sums("days=30")
	if hourSessions != 1 {
		t.Errorf("hours=1 session count: got %d want 1", hourSessions)
	}
	if daySessions != 2 {
		t.Errorf("days=30 session count: got %d want 2", daySessions)
	}
	if hourCost <= 0 {
		t.Errorf("hours=1 cost: got %v want > 0 (recent turn is priced)", hourCost)
	}
	// The regression guard: pre-fix the cost rollup ignored the 1h window
	// (Days defaulted to 30), so hourCost == dayCost. Post-fix the 10d-old
	// turn's (large) cost is excluded from the 1h window.
	if hourCost >= dayCost {
		t.Errorf("hours=1 cost %v must be < days=30 cost %v (cost window ignored?)", hourCost, dayCost)
	}
}

// TestAPISessions_UntilBoundsActivityExists pins the fix where the OR
// activity EXISTS branches applied only the lower bound: a session that
// STARTED before `since` and whose only in-lower-bound activity is
// actually AFTER `until` must NOT leak into a bounded window.
func TestAPISessions_UntilBoundsActivityExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()
	fortyDays := now.Add(-40 * 24 * time.Hour)
	fiveDays := now.Add(-5 * 24 * time.Hour)
	twoHours := now.Add(-2 * time.Hour)

	// sLeak: started 40d ago (before `since`), only in-window-lower-bound
	// activity is an api_turn at 2h ago (AFTER `until`).
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "fl", SourceEventID: "el", SessionID: "sLeak",
		ProjectRoot: root, Timestamp: fortyDays, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "l.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sLeak", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 100, Timestamp: twoHours,
	}); err != nil {
		t.Fatal(err)
	}
	// sIn: started 5d ago, activity 5d ago — squarely inside [30d, 1d).
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "fi", SourceEventID: "ei", SessionID: "sIn",
		ProjectRoot: root, Timestamp: fiveDays, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "i.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	sinceStr := now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	untilStr := now.Add(-1 * 24 * time.Hour).Format(time.RFC3339)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/sessions?since="+sinceStr+"&until="+untilStr, nil))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Total != 1 {
		t.Errorf("sessions total: got %d want 1 (sLeak's activity is after until; pre-fix it leaked → 2)", got.Total)
	}
}

// TestAPIActions_MalformedUntilKeepsToDate pins the fix where the legacy
// to_date param was suppressed by the mere PRESENCE of `until`, even when
// `until` was malformed and failed open. Suppression must key off actual
// resolution.
func TestAPIActions_MalformedUntilKeepsToDate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	// Fixed historical anchor (not wall-clock): the now-2h row must land on
	// the SAME date as `now` so `to_date=yesterday` excludes it. A real
	// time.Now() anchor fails in the first ~2h after UTC midnight, when
	// now-2h falls on yesterday's date (observed on CI at 00:48 UTC).
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	for i, ts := range []time.Time{now.Add(-2 * time.Hour), now.Add(-2 * 24 * time.Hour), now.Add(-60 * 24 * time.Hour)} {
		if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
			SourceFile: fmt.Sprintf("f%d", i), SourceEventID: fmt.Sprintf("e%d", i),
			SessionID:   "s1",
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	total := func(query string) int {
		t.Helper()
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/actions?"+query, nil))
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", query, rr.Code, rr.Body.String())
		}
		var got struct {
			Total int `json:"total"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got.Total
	}

	yesterday := now.Add(-1 * 24 * time.Hour).Format("2006-01-02")
	// Malformed until fails open → to_date (yesterday) must still apply,
	// excluding the 2h-ago (today) row → 2 rows.
	if n := total("until=not-a-time&to_date=" + yesterday); n != 2 {
		t.Errorf("malformed until + to_date: got %d want 2 (to_date must survive a failed-open until)", n)
	}
	// A VALID until resolves → to_date is correctly suppressed → the
	// upper bound alone (now) admits all 3 rows.
	nowStr := now.Format(time.RFC3339)
	if n := total("until=" + nowStr + "&to_date=" + yesterday); n != 3 {
		t.Errorf("valid until + to_date: got %d want 3 (resolved until suppresses to_date)", n)
	}
}

// TestAPICompressionTimeseries_BucketHour pins the fix where
// /api/compression/timeseries ignored the `bucket` param and always
// bucketed daily. bucket=hour must produce hour-grained buckets and echo
// the resolved bucket.
func TestAPICompressionTimeseries_BucketHour(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	now := time.Now().UTC()
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "s1", Timestamp: now.Add(-90 * time.Minute),
		Provider: models.ProviderAnthropic, Model: "claude-sonnet-4",
		CompressionEvents: []models.CompressionEvent{
			{Mechanism: "json", Timestamp: now.Add(-90 * time.Minute), OriginalBytes: 10000, CompressedBytes: 3000},
		},
	}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/compression/timeseries?bucket=hour&hours=6", nil))
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Bucket string `json:"bucket"`
		Series []struct {
			Bucket string `json:"bucket"`
		} `json:"series"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Bucket != "hour" {
		t.Fatalf("bucket echo: got %q want hour", got.Bucket)
	}
	if len(got.Series) != 1 {
		t.Fatalf("series: got %d want 1", len(got.Series))
	}
	// Hour-grained bucket strings carry a 'T' separator; the pre-fix
	// daily strftime ('%Y-%m-%d') never did.
	if !strings.Contains(got.Series[0].Bucket, "T") {
		t.Errorf("bucket string %q is day-grained; bucket=hour must be hour-grained", got.Series[0].Bucket)
	}
}
