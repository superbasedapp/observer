package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/browserchat"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	browseringest "github.com/marmutapp/superbased-observer/internal/ingest/browser"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// openTestStore opens a fresh migrated store for the ingest-path tests and
// returns both the store and the raw handle (for assertion queries).
func openTestStore(t *testing.T) (*store.Store, *sql.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database), database
}

func chatGPTBody(t *testing.T, gran string) []byte {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"schema_version":  1,
		"site":            "chatgpt-web",
		"conversation_id": "conv-x",
		"message_id":      "msg-x",
		"model":           "gpt-4o",
		"prompt_text":     "a prompt with content",
		"response_text":   "a response with content",
		"captured_at":     "2026-07-10T09:30:00Z",
		"granularity":     gran,
	})
	return b
}

// TestIngestBrowserTurnGranularityCeiling proves the daemon ceiling (§5.1):
// a "full" turn stores no content when [browser].granularity_ceiling caps at
// usage_only — the daemon is the final authority on what is STORED.
func TestIngestBrowserTurnGranularityCeiling(t *testing.T) {
	st, database := openTestStore(t)
	bc := config.BrowserConfig{Enabled: true, GranularityCeiling: "usage_only"}
	if err := ingestBrowserTurn(context.Background(), st, chatGPTBody(t, "full"), bc, ""); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var out string
	if err := database.QueryRowContext(context.Background(),
		`SELECT COALESCE(raw_tool_output, '') FROM actions WHERE tool = 'chatgpt-web'`).Scan(&out); err != nil {
		t.Fatalf("query: %v", err)
	}
	if out != "" {
		t.Errorf("tool_output = %q, want empty (ceiling clamped full → usage_only)", out)
	}
}

// TestIngestBrowserTurnSiteToggle proves the per-site daemon toggle drops a
// disabled site's turns before anything is stored.
func TestIngestBrowserTurnSiteToggle(t *testing.T) {
	st, database := openTestStore(t)
	bc := config.BrowserConfig{Enabled: true, Sites: map[string]bool{"chatgpt-web": false}}
	if err := ingestBrowserTurn(context.Background(), st, chatGPTBody(t, "usage_only"), bc, ""); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var n int
	if err := database.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM actions WHERE tool = 'chatgpt-web'`).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 0 {
		t.Errorf("actions = %d, want 0 (site toggled off)", n)
	}
}

// TestBrowserLoopbackListenerLandsRow wires the loopback receiver to the SAME
// ingestBrowserTurn one-owner path the hook uses, POSTs a captured turn, and
// asserts the row lands. This is the loopback-graft verification: transport
// (HTTP) is a deployment detail; the normalize→ingest owner is shared.
func TestBrowserLoopbackListenerLandsRow(t *testing.T) {
	st, database := openTestStore(t)
	bc := config.BrowserConfig{Enabled: true, GranularityCeiling: "full"}
	recv, err := browseringest.New(browseringest.Options{
		Addr: "127.0.0.1:0",
		Handler: func(ctx context.Context, body []byte) error {
			return ingestBrowserTurn(ctx, st, body, bc, "")
		},
	})
	if err != nil {
		t.Fatalf("receiver New: %v", err)
	}
	recv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = recv.Shutdown(ctx)
	})

	url := "http://" + recv.Addr() + "/v1/browser/capture"
	resp, err := http.Post(url, "application/json", bytes.NewReader(chatGPTBody(t, "full"))) //nolint:noctx // test
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	var n int
	if err := database.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM actions WHERE tool = 'chatgpt-web'`).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	// A content-bearing (full) turn lands TWO action rows since the chat
	// reshape: the user_prompt row + the assistant_message row.
	if n != 2 {
		t.Errorf("actions(chatgpt-web) via loopback = %d, want 2 (user_prompt + assistant_message)", n)
	}
}

// TestBrowserHookEndToEnd proves the full server-side path MINUS the live
// browser: a realistic captured-turn JSON payload fed to `observer browser
// hook` (via handleBrowserHook) normalizes through internal/adapter/
// browserchat and lands an action row plus an ESTIMATED token row under
// tool=chatgpt-web via the unchanged store.Ingest seam.
//
// The live authenticated-browser capture (extension → native host → this
// command) is an operator-attended step and is NOT exercised here; this test
// drives everything downstream of the native host.
func TestBrowserHookEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "observer.db")
	configPath := filepath.Join(tmp, "config.toml")
	if err := os.WriteFile(configPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	payload := map[string]any{
		"schema_version":      1,
		"site":                "chatgpt-web",
		"conversation_id":     "conv-e2e-1",
		"message_id":          "msg-e2e-1",
		"model":               "gpt-4o",
		"request_url":         "https://chatgpt.com/backend-api/conversation",
		"prompt_text":         "summarize the plot of Hamlet in one sentence",
		"response_text":       "A Danish prince avenges his father's murder and dies in the attempt.",
		"prompt_tokens_est":   11,
		"response_tokens_est": 14,
		"latency_ms":          950,
		"captured_at":         "2026-07-10T09:30:00Z",
		"granularity":         "full",
		"title":               "lit",
	}
	body, _ := json.Marshal(payload)

	// Redirect stdin (payload) and stdout (ack) around the call.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	go func() {
		_, _ = stdinW.Write(body)
		_ = stdinW.Close()
	}()
	oldStdin, oldStdout := os.Stdin, os.Stdout
	os.Stdin = stdinR
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = devNull
	t.Cleanup(func() {
		os.Stdin, os.Stdout = oldStdin, oldStdout
		_ = devNull.Close()
	})

	handleBrowserHook(context.Background(), "capture", configPath)
	os.Stdin, os.Stdout = oldStdin, oldStdout

	// Assert the rows landed.
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	var actionCount int
	if err := database.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM actions WHERE tool = 'chatgpt-web' AND action_type = 'assistant_message'`).
		Scan(&actionCount); err != nil {
		t.Fatalf("query actions: %v", err)
	}
	if actionCount != 1 {
		t.Fatalf("actions(chatgpt-web) = %d, want 1", actionCount)
	}

	var (
		input, output int64
		source        string
	)
	if err := database.QueryRowContext(context.Background(),
		`SELECT input_tokens, output_tokens, source FROM token_usage WHERE tool = 'chatgpt-web'`).
		Scan(&input, &output, &source); err != nil {
		t.Fatalf("query token_usage: %v", err)
	}
	if input != 11 || output != 14 {
		t.Errorf("tokens = (%d, %d), want (11, 14) from the client estimate", input, output)
	}
	if source != "estimated" {
		t.Errorf("token source = %q, want estimated", source)
	}

	// The session must be attributed to the synthetic browser project root.
	var projectRoot string
	if err := database.QueryRowContext(context.Background(),
		`SELECT p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = 'conv-e2e-1'`).
		Scan(&projectRoot); err != nil {
		t.Fatalf("query session project: %v", err)
	}
	if projectRoot != "browser://chatgpt.com" {
		t.Errorf("project root = %q, want browser://chatgpt.com", projectRoot)
	}
}

// TestHandleBrowserHookOverLimitRecordsKeyedDrop pins the FIX-2 over-limit
// path: a captured-turn payload larger than the 8MiB ingest cap is truncated
// at the wire (invalid JSON), so instead of a silent parse-drop that still
// ack's "ok" and leaves the health file unable to key the loss, the daemon
// records an EXPLICIT keyed drop with the cap reason. No DB rows land, and the
// ack is still written (semantics unchanged).
func TestHandleBrowserHookOverLimitRecordsKeyedDrop(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "observer.db")
	configPath := filepath.Join(tmp, "config.toml")
	if err := os.WriteFile(configPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// A syntactically-valid payload whose response_text pushes the whole
	// document well past the 8MiB cap. Truncation at the cap severs the JSON.
	payload := map[string]any{
		"schema_version":  1,
		"site":            "chatgpt-web",
		"conversation_id": "conv-big",
		"message_id":      "msg-big",
		"model":           "gpt-4o",
		"prompt_text":     "hi",
		"response_text":   strings.Repeat("A", browserIngestCapBytes+1024),
		"captured_at":     "2026-07-10T09:30:00Z",
		"granularity":     "full",
	}
	body, _ := json.Marshal(payload)
	if len(body) <= browserIngestCapBytes {
		t.Fatalf("test payload not over the cap: %d <= %d", len(body), browserIngestCapBytes)
	}

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	go func() {
		_, _ = stdinW.Write(body)
		_ = stdinW.Close()
	}()
	oldStdin, oldStdout := os.Stdin, os.Stdout
	os.Stdin = stdinR
	// Capture stdout so we can assert the ack semantics are unchanged.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = stdoutW
	t.Cleanup(func() { os.Stdin, os.Stdout = oldStdin, oldStdout })

	handleBrowserHook(context.Background(), "capture", configPath)
	_ = stdoutW.Close()
	os.Stdin, os.Stdout = oldStdin, oldStdout

	var ack bytes.Buffer
	_, _ = ack.ReadFrom(stdoutR)
	if !strings.Contains(ack.String(), `"status":"ok"`) {
		t.Errorf("ack not written (semantics changed): %q", ack.String())
	}

	// No rows landed — the truncated turn was NOT normalized/inserted.
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()
	var actionCount int
	if err := database.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM actions WHERE tool = 'chatgpt-web'`).Scan(&actionCount); err != nil {
		t.Fatalf("query actions: %v", err)
	}
	if actionCount != 0 {
		t.Errorf("actions(chatgpt-web) = %d, want 0 (over-limit turn dropped)", actionCount)
	}

	// The drop is recorded, keyed, with the distinct cap reason. The truncated
	// JSON can't be peeked, so the site keys under "unknown".
	hf := loadBrowserHealthFile(filepath.Join(tmp, browserHealthFileName))
	e, ok := hf.Sites["unknown"]
	if !ok {
		t.Fatalf("no keyed drop recorded; sites=%v", hf.Sites)
	}
	if e.Dropped < 1 {
		t.Errorf("Dropped = %d, want >= 1", e.Dropped)
	}
	if e.LastDropReason != browserIngestCapDropReason {
		t.Errorf("LastDropReason = %q, want %q", e.LastDropReason, browserIngestCapDropReason)
	}
}

// TestHandleBrowserHookOverLimitBoundedByContendedHealthLock is the Go
// re-review MED-fix proof for the over-limit drop-record path specifically:
// its keyed drop record is the ONLY record of that turn's loss, so it must
// not be lost to an indefinite flock wait either. Even with another (here
// simulated: a held, never-released) holder of browser-health.json.lock,
// handleBrowserHook must still return promptly — the telemetry write is
// skipped, not blocked on — rather than hanging until the native host's
// teardown kills the child (the exact loss the 35s work deadline exists to
// prevent).
func TestHandleBrowserHookOverLimitBoundedByContendedHealthLock(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "observer.db")
	configPath := filepath.Join(tmp, "config.toml")
	if err := os.WriteFile(configPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	lockPath := filepath.Join(tmp, browserHealthFileName+".lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	holder, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	defer holder.Close()
	if err := lockFileExclusive(holder); err != nil {
		t.Fatalf("acquire holder lock: %v", err)
	}
	defer unlockFile(holder)

	payload := map[string]any{
		"schema_version":  1,
		"site":            "chatgpt-web",
		"conversation_id": "conv-big",
		"message_id":      "msg-big",
		"model":           "gpt-4o",
		"prompt_text":     "hi",
		"response_text":   strings.Repeat("A", browserIngestCapBytes+1024),
		"captured_at":     "2026-07-10T09:30:00Z",
		"granularity":     "full",
	}
	body, _ := json.Marshal(payload)

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	go func() {
		_, _ = stdinW.Write(body)
		_ = stdinW.Close()
	}()
	oldStdin, oldStdout := os.Stdin, os.Stdout
	os.Stdin = stdinR
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = stdoutW
	t.Cleanup(func() { os.Stdin, os.Stdout = oldStdin, oldStdout })

	done := make(chan struct{})
	start := time.Now()
	go func() {
		handleBrowserHook(context.Background(), "capture", configPath)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleBrowserHook's over-limit branch blocked indefinitely on a contended health lock (MED re-review finding)")
	}
	elapsed := time.Since(start)
	_ = stdoutW.Close()
	os.Stdin, os.Stdout = oldStdin, oldStdout
	var ack bytes.Buffer
	_, _ = ack.ReadFrom(stdoutR)

	if elapsed > 8*time.Second {
		t.Errorf("handleBrowserHook took %s to return with a contended health lock — the flock wait should be bounded well under browserHealthLockTimeout (%s)", elapsed, browserHealthLockTimeout)
	}
	// No drop was recorded — the lock was never acquired — but the process
	// must still have completed its own work (the ack) rather than hanging.
	if !strings.Contains(ack.String(), `"status":"ok"`) {
		t.Errorf("ack not written (semantics changed): %q", ack.String())
	}
}

// --- A6: health beacon (recorded + surfaced) --------------------------------

func cfgWithDBIn(dir string) config.Config {
	var c config.Config
	c.Observer.DBPath = filepath.Join(dir, "observer.db")
	c.Browser.Enabled = true
	return c
}

// TestRecordBrowserHealthWritesAndSurfaces is the A6 core: a beacon is
// recorded to the node-local file and read back with the right fields.
func TestRecordBrowserHealthWritesAndSurfaces(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)

	body := []byte(`{"type":"health","site":"chatgpt-web","status":"degraded","reason":"parser stale","ts":1737000000000}`)
	if err := recordBrowserHealth(context.Background(), cfg, body); err != nil {
		t.Fatalf("recordBrowserHealth: %v", err)
	}
	path := filepath.Join(dir, browserHealthFileName)
	hf := loadBrowserHealthFile(path)
	e, ok := hf.Sites["chatgpt-web"]
	if !ok {
		t.Fatalf("site not recorded; file=%v", hf.Sites)
	}
	if e.Status != "degraded" || e.Reason != "parser stale" || e.TS != 1737000000000 {
		t.Errorf("entry = %+v, want degraded/parser stale/ts", e)
	}
	if e.RecordedAt == 0 {
		t.Errorf("recorded_at should be stamped daemon-side")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("health file mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestRecordBrowserHealthDefaultsAndDropsEmptySite(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	if err := recordBrowserHealth(context.Background(), cfg, []byte(`{"type":"health","site":"claude-web"}`)); err != nil {
		t.Fatalf("record: %v", err)
	}
	hf := loadBrowserHealthFile(filepath.Join(dir, browserHealthFileName))
	if hf.Sites["claude-web"].Status != "ok" {
		t.Errorf("missing status should default ok, got %q", hf.Sites["claude-web"].Status)
	}
	if err := recordBrowserHealth(context.Background(), cfg, []byte(`{"type":"health"}`)); err != nil {
		t.Fatalf("empty-site beacon should be a soft no-op: %v", err)
	}
	if hf2 := loadBrowserHealthFile(filepath.Join(dir, browserHealthFileName)); len(hf2.Sites) != 1 {
		t.Errorf("empty-site beacon should not add an entry, sites=%v", hf2.Sites)
	}
}

func TestEvictOldestHealthBounds(t *testing.T) {
	sites := map[string]browserHealthEntry{}
	for i := 0; i < maxHealthSites+5; i++ {
		sites[string(rune('a'+i))] = browserHealthEntry{RecordedAt: int64(i)}
	}
	evictOldestHealth(sites, maxHealthSites)
	if len(sites) != maxHealthSites {
		t.Fatalf("len = %d, want %d", len(sites), maxHealthSites)
	}
	if _, ok := sites["a"]; ok {
		t.Errorf("oldest entry 'a' should have been evicted")
	}
}

func TestRunBrowserHealthEmptyThenSurfaces(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var out strings.Builder
	if err := runBrowserHealth(&out, cfgPath); err != nil {
		t.Fatalf("runBrowserHealth: %v", err)
	}
	if !strings.Contains(out.String(), "no browser health beacons recorded yet") {
		t.Errorf("empty-state message missing:\n%s", out.String())
	}

	cfg := cfgWithDBIn(dir)
	if err := recordBrowserHealth(context.Background(), cfg, []byte(`{"type":"health","site":"gemini-web","status":"degraded","reason":"shape canary"}`)); err != nil {
		t.Fatalf("record: %v", err)
	}
	var out2 strings.Builder
	if err := runBrowserHealth(&out2, cfgPath); err != nil {
		t.Fatalf("runBrowserHealth: %v", err)
	}
	s := out2.String()
	if !strings.Contains(s, "gemini-web") || !strings.Contains(s, "degraded") || !strings.Contains(s, "shape canary") {
		t.Errorf("rendered health missing fields:\n%s", s)
	}
}

// --- C1: capture drop/ingest telemetry -------------------------------------

// idlessBody is a captured turn with NO conversation_id and NO message_id —
// the real logged-in chatgpt.com new-chat thinking-turn shape that the old
// code silently dropped.
func idlessBody(t *testing.T) []byte {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"schema_version":      1,
		"site":                "chatgpt-web",
		"model":               "gpt-4o",
		"prompt_text":         "a prompt with content",
		"response_text":       "a response with content",
		"prompt_tokens_est":   5,
		"response_tokens_est": 6,
		"captured_at":         "2026-07-10T09:30:00Z",
		"granularity":         "full",
	})
	return b
}

// TestIngestBrowserTurnRecordsIngestTelemetry proves a landed turn bumps the
// per-site ingested counter in the health file (C1) — the durable signal that
// capture is working, independent of the extension's self-reported beacon.
func TestIngestBrowserTurnRecordsIngestTelemetry(t *testing.T) {
	st, _ := openTestStore(t)
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	bc := config.BrowserConfig{Enabled: true, GranularityCeiling: "full"}

	if err := ingestBrowserTurn(context.Background(), st, chatGPTBody(t, "full"), bc, healthPath); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	e := loadBrowserHealthFile(healthPath).Sites["chatgpt-web"]
	if e.Ingested != 1 {
		t.Errorf("Ingested = %d, want 1", e.Ingested)
	}
	if e.Dropped != 0 {
		t.Errorf("Dropped = %d, want 0", e.Dropped)
	}
	if e.Synthetic != 0 {
		t.Errorf("Synthetic = %d, want 0 (turn carried a conversation id)", e.Synthetic)
	}
	if e.RecordedAt == 0 {
		t.Errorf("RecordedAt should be stamped on capture")
	}
}

// TestIngestBrowserTurnRecordsSyntheticTelemetry proves a B1-synthesized
// (id-less) ingest is counted AND flagged synthetic so the operator can see
// id-less turns are landing.
func TestIngestBrowserTurnRecordsSyntheticTelemetry(t *testing.T) {
	st, database := openTestStore(t)
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	bc := config.BrowserConfig{Enabled: true, GranularityCeiling: "full"}

	if err := ingestBrowserTurn(context.Background(), st, idlessBody(t), bc, healthPath); err != nil {
		t.Fatalf("ingest: %v (id-less turn must land, not drop)", err)
	}
	// The row actually landed in the DB.
	var n int
	if err := database.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM actions WHERE tool = 'chatgpt-web'`).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 2 {
		t.Fatalf("actions(chatgpt-web) = %d, want 2 (id-less full-granularity turn = user_prompt + assistant_message)", n)
	}
	e := loadBrowserHealthFile(healthPath).Sites["chatgpt-web"]
	if e.Ingested != 1 {
		t.Errorf("Ingested = %d, want 1", e.Ingested)
	}
	if e.Synthetic != 1 {
		t.Errorf("Synthetic = %d, want 1 (id-less turn)", e.Synthetic)
	}
	if e.LastSyntheticAt == 0 {
		t.Errorf("LastSyntheticAt should be stamped for an id-less ingest")
	}
}

// TestIngestBrowserTurnRecordsDropTelemetry proves a normalize failure
// (unknown site) is recorded as a durable drop with its reason — the C1 fix
// for the invisible-drop bug.
func TestIngestBrowserTurnRecordsDropTelemetry(t *testing.T) {
	st, _ := openTestStore(t)
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	bc := config.BrowserConfig{Enabled: true}

	body, _ := json.Marshal(map[string]any{
		"schema_version":  1,
		"site":            "definitely-not-a-site",
		"conversation_id": "conv-x",
		"prompt_text":     "hi",
		"granularity":     "full",
	})
	if err := ingestBrowserTurn(context.Background(), st, body, bc, healthPath); err == nil {
		t.Fatalf("expected a normalize error for an unknown site")
	}
	e := loadBrowserHealthFile(healthPath).Sites["definitely-not-a-site"]
	if e.Dropped != 1 {
		t.Errorf("Dropped = %d, want 1", e.Dropped)
	}
	if e.LastDropReason == "" {
		t.Errorf("LastDropReason should record the normalize error")
	}
	if e.LastDropAt == 0 {
		t.Errorf("LastDropAt should be stamped for a drop")
	}
	if e.Ingested != 0 {
		t.Errorf("Ingested = %d, want 0 (turn was dropped)", e.Ingested)
	}
}

// TestBeaconAfterCapturePreservesCounters is the HIGH-1 core: a health beacon
// arriving AFTER capture telemetry must MERGE — updating Status/Reason/TS only
// — and leave the ingested/dropped/synthetic counters intact. The old beacon
// writer replaced the whole entry, zeroing them.
func TestBeaconAfterCapturePreservesCounters(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	healthPath := filepath.Join(dir, browserHealthFileName)

	// Capture path writes counters first.
	recordBrowserCapture(context.Background(), healthPath, captureOutcome{site: "chatgpt-web", ingested: true})
	recordBrowserCapture(context.Background(), healthPath, captureOutcome{site: "chatgpt-web", ingested: true, synthetic: true})
	recordBrowserCapture(context.Background(), healthPath, captureOutcome{site: "chatgpt-web", dropReason: "boom"})

	// Beacon arrives afterwards.
	if err := recordBrowserHealth(context.Background(), cfg, []byte(`{"type":"health","site":"chatgpt-web","status":"degraded","reason":"parser stale","ts":42}`)); err != nil {
		t.Fatalf("recordBrowserHealth: %v", err)
	}

	e := loadBrowserHealthFile(healthPath).Sites["chatgpt-web"]
	if e.Ingested != 2 || e.Synthetic != 1 || e.Dropped != 1 {
		t.Errorf("counters clobbered by beacon: Ingested=%d Synthetic=%d Dropped=%d, want 2/1/1", e.Ingested, e.Synthetic, e.Dropped)
	}
	if e.LastDropReason != "boom" {
		t.Errorf("LastDropReason clobbered: %q", e.LastDropReason)
	}
	if e.Status != "degraded" || e.Reason != "parser stale" || e.TS != 42 {
		t.Errorf("beacon fields not applied: %+v", e)
	}
}

// TestCaptureAfterBeaconPreservesStatus is the symmetric HIGH-1 case: capture
// telemetry arriving AFTER a beacon must not overwrite the beacon's
// Status/Reason (it only infers a status when none exists yet).
func TestCaptureAfterBeaconPreservesStatus(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	healthPath := filepath.Join(dir, browserHealthFileName)

	if err := recordBrowserHealth(context.Background(), cfg, []byte(`{"type":"health","site":"claude-web","status":"degraded","reason":"canary"}`)); err != nil {
		t.Fatalf("recordBrowserHealth: %v", err)
	}
	recordBrowserCapture(context.Background(), healthPath, captureOutcome{site: "claude-web", ingested: true})

	e := loadBrowserHealthFile(healthPath).Sites["claude-web"]
	if e.Status != "degraded" || e.Reason != "canary" {
		t.Errorf("capture clobbered beacon status: %+v", e)
	}
	if e.Ingested != 1 {
		t.Errorf("Ingested = %d, want 1", e.Ingested)
	}
}

// TestMalformedHealthFileDoesNotWipeOtherSites is the HIGH-2c core: a
// corrupt-on-disk health file must NOT let the next write silently zero the
// data. The corrupt bytes are quarantined to a .bad sidecar and the writer
// starts fresh (never overwrites in place).
func TestMalformedHealthFileDoesNotWipeOtherSites(t *testing.T) {
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)

	// Simulate a corrupt file on disk.
	if err := os.WriteFile(healthPath, []byte("{not valid json at all"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	// A write must succeed and land the new site (not crash, not no-op).
	recordBrowserCapture(context.Background(), healthPath, captureOutcome{site: "gemini-web", ingested: true})

	hf := loadBrowserHealthFile(healthPath)
	if hf.Sites["gemini-web"].Ingested != 1 {
		t.Errorf("new write lost after corrupt-file recovery: %+v", hf.Sites)
	}
	// The corrupt bytes were preserved in a UNIQUE .bad-<pid-rand> sidecar
	// (MED-2c), not overwritten in place.
	matches, _ := filepath.Glob(healthPath + ".bad-*")
	if len(matches) != 1 {
		t.Fatalf("corrupt file not quarantined to a unique .bad-* sidecar: %v", matches)
	}
	bad, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read quarantined sidecar: %v", err)
	}
	if !strings.Contains(string(bad), "not valid json") {
		t.Errorf(".bad sidecar missing the original corrupt bytes: %q", bad)
	}
}

// TestConcurrentCaptureWritersConverge is the HIGH-2 race proof: N concurrent
// writers (each opening its own lock fd, as separate processes would) doing a
// load→merge→write must sum to exactly N ingested — the flock serializes the
// transaction so no update is lost.
func TestConcurrentCaptureWritersConverge(t *testing.T) {
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			recordBrowserCapture(context.Background(), healthPath, captureOutcome{site: "chatgpt-web", ingested: true})
		}()
	}
	wg.Wait()

	e := loadBrowserHealthFile(healthPath).Sites["chatgpt-web"]
	if e.Ingested != n {
		t.Errorf("Ingested = %d, want %d (a lost update means the cross-process lock failed)", e.Ingested, n)
	}
}

// TestSyntheticCountsOnlyTrueSynthetic is the LOW-1 proof at the ingest seam:
// a turn grouped by a real message id (conversation id absent) is NOT counted
// synthetic — only a turn carrying neither id is.
func TestSyntheticCountsOnlyTrueSynthetic(t *testing.T) {
	st, _ := openTestStore(t)
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	bc := config.BrowserConfig{Enabled: true, GranularityCeiling: "full"}

	// conversation_id absent, message_id PRESENT → message-id tier, NOT synthetic.
	msgIDBody, _ := json.Marshal(map[string]any{
		"schema_version": 1,
		"site":           "chatgpt-web",
		"message_id":     "msg-only-1",
		"model":          "gpt-4o",
		"prompt_text":    "hi",
		"response_text":  "hello",
		"captured_at":    "2026-07-10T09:30:00Z",
		"granularity":    "full",
	})
	if err := ingestBrowserTurn(context.Background(), st, msgIDBody, bc, healthPath); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	e := loadBrowserHealthFile(healthPath).Sites["chatgpt-web"]
	if e.Ingested != 1 {
		t.Fatalf("Ingested = %d, want 1", e.Ingested)
	}
	if e.Synthetic != 0 {
		t.Errorf("Synthetic = %d, want 0 (message-id tier is not synthetic)", e.Synthetic)
	}
}

// TestIdlessSameMsDistinctCaptureIDTwoSessions is the MED-1 end-to-end proof
// at the ingest seam in its real wire shape: two id-less turns with the SAME
// captured_at and IDENTICAL content but DIFFERENT capture_id land as TWO
// distinct sessions — the second is not deduped away. This is the exact case
// the old content fingerprint got wrong: at the default usage_only granularity
// prompt/response are stripped, so a content hash was constant and the second
// turn silently merged into the first. capture_id is opaque and per-turn, so
// it survives the strip.
func TestIdlessSameMsDistinctCaptureIDTwoSessions(t *testing.T) {
	st, database := openTestStore(t)
	bc := config.BrowserConfig{Enabled: true, GranularityCeiling: "full"}

	mk := func(captureID string) []byte {
		b, _ := json.Marshal(map[string]any{
			"schema_version": 1,
			"site":           "chatgpt-web",
			"model":          "gpt-4o",
			"prompt_text":    "identical prompt",
			"response_text":  "identical response",
			"captured_at":    "2026-07-10T09:30:00.000Z",
			"granularity":    "full",
			"capture_id":     captureID,
		})
		return b
	}
	if err := ingestBrowserTurn(context.Background(), st, mk("cap-A"), bc, ""); err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	if err := ingestBrowserTurn(context.Background(), st, mk("cap-B"), bc, ""); err != nil {
		t.Fatalf("ingest B: %v", err)
	}

	var sessions, actions int
	if err := database.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE project_id IN (SELECT id FROM projects WHERE root_path = 'browser://chatgpt.com')`).Scan(&sessions); err != nil {
		t.Fatalf("query sessions: %v", err)
	}
	if err := database.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM actions WHERE tool = 'chatgpt-web'`).Scan(&actions); err != nil {
		t.Fatalf("query actions: %v", err)
	}
	if sessions != 2 {
		t.Errorf("sessions = %d, want 2 (distinct-capture_id same-ms turns must not merge)", sessions)
	}
	if actions != 4 {
		t.Errorf("actions = %d, want 4 (2 full-granularity turns x user_prompt+assistant; fewer = a turn deduped away = silent loss)", actions)
	}
}

// TestIngestBrowserTurnCaptureIDFallbackKey proves an id-less turn (no
// conversation_id, no message_id) that carries a capture_id ingests under the
// "<site>:cap:<capture_id>" fallback session key (MED-1 / MED-3 — content-free).
func TestIngestBrowserTurnCaptureIDFallbackKey(t *testing.T) {
	st, database := openTestStore(t)
	bc := config.BrowserConfig{Enabled: true, GranularityCeiling: "full"}
	body, _ := json.Marshal(map[string]any{
		"schema_version": 1,
		"site":           "chatgpt-web",
		"model":          "gpt-4o",
		"prompt_text":    "hi",
		"response_text":  "hello",
		"captured_at":    "2026-07-10T09:30:00Z",
		"granularity":    "full",
		"capture_id":     "cap-fallback-1",
	})
	if err := ingestBrowserTurn(context.Background(), st, body, bc, ""); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var sid string
	if err := database.QueryRowContext(context.Background(),
		`SELECT s.id FROM sessions s JOIN projects p ON p.id = s.project_id WHERE p.root_path = 'browser://chatgpt.com'`).Scan(&sid); err != nil {
		t.Fatalf("query: %v", err)
	}
	if sid != "chatgpt-web:cap:cap-fallback-1" {
		t.Errorf("session id = %q, want chatgpt-web:cap:cap-fallback-1", sid)
	}
}

// TestIngestBrowserTurnOldExtensionLastResortIngests proves an old pre-fix
// bridge (no conversation_id, no message_id, NO capture_id) still ingests
// under the content-free captured_at last-resort key — never dropped.
func TestIngestBrowserTurnOldExtensionLastResortIngests(t *testing.T) {
	st, database := openTestStore(t)
	bc := config.BrowserConfig{Enabled: true, GranularityCeiling: "full"}
	body, _ := json.Marshal(map[string]any{
		"schema_version": 1,
		"site":           "chatgpt-web",
		"model":          "gpt-4o",
		"prompt_text":    "hi",
		"response_text":  "hello",
		"captured_at":    "2026-07-10T09:30:00Z",
		"granularity":    "full",
	})
	if err := ingestBrowserTurn(context.Background(), st, body, bc, ""); err != nil {
		t.Fatalf("ingest: %v (old-extension turn must still land, not drop)", err)
	}
	var n int
	if err := database.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM actions WHERE tool = 'chatgpt-web'`).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 2 {
		t.Errorf("actions = %d, want 2 (last-resort key must ingest the full-granularity turn's user_prompt + assistant_message)", n)
	}
}

// TestRunBrowserHealthRendersCaptureTelemetry proves `observer browser health`
// surfaces the C1 counters — the ingested/dropped/id-less summary and the
// warn line for a site with drops.
func TestRunBrowserHealthRendersCaptureTelemetry(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	healthPath := filepath.Join(dir, browserHealthFileName)

	// A healthy site with an id-less landing.
	recordBrowserCapture(context.Background(), healthPath, captureOutcome{site: "chatgpt-web", ingested: true})
	recordBrowserCapture(context.Background(), healthPath, captureOutcome{site: "chatgpt-web", ingested: true, synthetic: true})
	// A site suffering drops.
	recordBrowserCapture(context.Background(), healthPath, captureOutcome{site: "gemini-web", dropReason: "browserchat.BuildToolEvent: unknown site"})

	var out strings.Builder
	if err := runBrowserHealth(&out, cfgPath); err != nil {
		t.Fatalf("runBrowserHealth: %v", err)
	}
	s := out.String()
	for _, want := range []string{"2 ingested", "1 id-less", "gemini-web", "warn:", "unknown site"} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered health missing %q:\n%s", want, s)
		}
	}
}

// TestHandleBrowserHookRoutesHealthEvent proves the event branch: an event of
// "health" records to the health file and never touches the actions table.
func TestHandleBrowserHookRoutesHealthEvent(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "observer.db")
	configPath := filepath.Join(tmp, "config.toml")
	if err := os.WriteFile(configPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	body := []byte(`{"type":"health","site":"perplexity-web","status":"ok"}`)

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	go func() { _, _ = stdinW.Write(body); _ = stdinW.Close() }()
	oldStdin, oldStdout := os.Stdin, os.Stdout
	os.Stdin = stdinR
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = devNull
	t.Cleanup(func() { os.Stdin, os.Stdout = oldStdin, oldStdout; _ = devNull.Close() })

	handleBrowserHook(context.Background(), "health", configPath)
	os.Stdin, os.Stdout = oldStdin, oldStdout

	hf := loadBrowserHealthFile(filepath.Join(tmp, browserHealthFileName))
	if hf.Sites["perplexity-web"].Status != "ok" {
		t.Errorf("health event not recorded via handleBrowserHook: %v", hf.Sites)
	}
}

// TestHandleBrowserHookConfigEvent proves the config event: it emits the
// daemon's effective browser policy as the ONLY stdout line (the ack is
// suppressed) so host.js can relay it to the extension, and it never opens the
// DB. The granularity is normalized from [browser].granularity_ceiling and the
// per-site toggles ride verbatim.
func TestHandleBrowserHookConfigEvent(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "observer.db")
	configPath := filepath.Join(tmp, "config.toml")
	toml := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n" +
		"[browser]\nenabled = true\ngranularity_ceiling = \"redacted\"\n" +
		"[browser.sites]\n\"chatgpt-web\" = false\n"
	if err := os.WriteFile(configPath, []byte(toml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Feed a config-request payload on stdin; capture stdout via a pipe so we
	// can assert the config JSON is the sole output.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	go func() { _, _ = stdinW.Write([]byte(`{"type":"config"}`)); _ = stdinW.Close() }()
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	oldStdin, oldStdout := os.Stdin, os.Stdout
	os.Stdin = stdinR
	os.Stdout = stdoutW
	t.Cleanup(func() { os.Stdin, os.Stdout = oldStdin, oldStdout })

	handleBrowserHook(context.Background(), "config", configPath)
	_ = stdoutW.Close()
	os.Stdin, os.Stdout = oldStdin, oldStdout

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(stdoutR); err != nil {
		t.Fatalf("read stdout: %v", err)
	}

	var resp struct {
		Type        string          `json:"type"`
		Granularity string          `json:"granularity"`
		Enabled     bool            `json:"enabled"`
		Sites       map[string]bool `json:"sites"`
		Degraded    bool            `json:"degraded"`
	}
	trimmed := bytes.TrimSpace(buf.Bytes())
	if err := json.Unmarshal(trimmed, &resp); err != nil {
		t.Fatalf("config output not a single JSON object (%q): %v", buf.String(), err)
	}
	if resp.Type != "config" {
		t.Errorf("type = %q, want config", resp.Type)
	}
	if resp.Granularity != "redacted" {
		t.Errorf("granularity = %q, want redacted", resp.Granularity)
	}
	if !resp.Enabled {
		t.Errorf("enabled = false, want true")
	}
	if v, ok := resp.Sites["chatgpt-web"]; !ok || v {
		t.Errorf("sites[chatgpt-web] = %v (ok=%v), want false", v, ok)
	}
	if resp.Degraded {
		t.Errorf("degraded = true, want false for a valid config")
	}
	// The config event must NOT open/create the DB.
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Errorf("config event created the DB at %s (err=%v) — it must not open the DB", dbPath, err)
	}
}

// TestNormalizeBrowserGranularity pins the §5.1 normalization: the closed
// vocabulary passes through; empty / unknown collapses to the usage_only floor.
func TestNormalizeBrowserGranularity(t *testing.T) {
	cases := map[string]string{
		"usage_only": "usage_only",
		"redacted":   "redacted",
		"full":       "full",
		"":           "usage_only",
		"bogus":      "usage_only",
		" full ":     "full", //nolint:gocritic // the leading/trailing whitespace is the intentional test input (normalizer must TrimSpace).
	}
	for in, want := range cases {
		if got := normalizeBrowserGranularity(in); got != want {
			t.Errorf("normalizeBrowserGranularity(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- A4: shared loopback-ingress token -------------------------------------

func TestResolveBrowserIngestTokenGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	tok, err := resolveBrowserIngestToken(cfg)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(tok) < 32 {
		t.Errorf("generated token too short: %q", tok)
	}
	path := filepath.Join(dir, "browser-ingest-token")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("token not persisted: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %v, want 0600", fi.Mode().Perm())
	}
	tok2, err := resolveBrowserIngestToken(cfg)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if tok2 != tok {
		t.Errorf("token not stable across calls: %q != %q", tok, tok2)
	}
}

// --- JS MED-4: idle-beacon priority ranking --------------------------------

// beaconBody builds a health beacon payload with an optional priority.
func beaconBody(site, status, reason, priority string) []byte {
	m := map[string]any{"type": "health", "site": site, "status": status}
	if reason != "" {
		m["reason"] = reason
	}
	if priority != "" {
		m["priority"] = priority
	}
	b, _ := json.Marshal(m)
	return b
}

// TestIdleBeaconDoesNotStompRecentNormalStatus is the JS MED-4 core: a
// low-priority (idle) beacon must NOT overwrite a Status/Reason that a recent
// normal-priority beacon set.
func TestIdleBeaconDoesNotStompRecentNormalStatus(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	if err := recordBrowserHealth(context.Background(), cfg, beaconBody("chatgpt-web", "ok", "healthy", "normal")); err != nil {
		t.Fatalf("normal beacon: %v", err)
	}
	// Idle heartbeat arrives claiming degraded — must be refused.
	if err := recordBrowserHealth(context.Background(), cfg, beaconBody("chatgpt-web", "degraded", "idle canary", "low")); err != nil {
		t.Fatalf("idle beacon: %v", err)
	}
	e := loadBrowserHealthFile(path).Sites["chatgpt-web"]
	if e.Status != "ok" || e.Reason != "healthy" {
		t.Errorf("idle beacon stomped a recent normal status: %+v", e)
	}
}

// TestIdleBeaconDoesNotStompRecentCapture is the symmetric case: a real
// capture stamps a NORMAL-priority status, which an idle beacon must not stomp
// — and the capture counters survive.
func TestIdleBeaconDoesNotStompRecentCapture(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	recordBrowserCapture(context.Background(), path, captureOutcome{site: "claude-web", ingested: true})
	if err := recordBrowserHealth(context.Background(), cfg, beaconBody("claude-web", "degraded", "idle", "low")); err != nil {
		t.Fatalf("idle beacon: %v", err)
	}
	e := loadBrowserHealthFile(path).Sites["claude-web"]
	if e.Status != "ok" {
		t.Errorf("idle beacon stomped a capture-set status: %+v", e)
	}
	if e.Ingested != 1 {
		t.Errorf("Ingested = %d, want 1 (idle beacon must preserve counters)", e.Ingested)
	}
}

// TestIdleBeaconSetsStatusOnEmptySite proves the useful-signal path: on a
// never-captured site an idle beacon DOES set the status.
func TestIdleBeaconSetsStatusOnEmptySite(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	if err := recordBrowserHealth(context.Background(), cfg, beaconBody("perplexity-web", "degraded", "idle canary", "low")); err != nil {
		t.Fatalf("idle beacon: %v", err)
	}
	e := loadBrowserHealthFile(path).Sites["perplexity-web"]
	if e.Status != "degraded" || e.Reason != "idle canary" {
		t.Errorf("idle beacon should set the first status on an empty site: %+v", e)
	}
}

// TestIdleBeaconSetsStatusOnStaleSite proves an idle beacon overwrites a
// normal-priority status that is OLDER than the freshness window.
func TestIdleBeaconSetsStatusOnStaleSite(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	// Seed a stale normal-priority status (set well outside the window).
	stale := time.Now().UnixMilli() - statusFreshnessWindowMs - 1000
	if err := updateBrowserHealth(context.Background(), path, "gemini-web", func(e browserHealthEntry) browserHealthEntry {
		e.Status = "ok"
		e.LastStatusPriority = statusPriorityNormal
		e.LastStatusAt = stale
		e.RecordedAt = stale
		return e
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := recordBrowserHealth(context.Background(), cfg, beaconBody("gemini-web", "degraded", "stale replaced", "low")); err != nil {
		t.Fatalf("idle beacon: %v", err)
	}
	e := loadBrowserHealthFile(path).Sites["gemini-web"]
	if e.Status != "degraded" || e.Reason != "stale replaced" {
		t.Errorf("idle beacon should refresh a stale status: %+v", e)
	}
}

// TestNormalBeaconAlwaysApplies proves a normal-priority beacon (and a
// priority-less legacy beacon) always overwrites, even over a fresh status.
func TestNormalBeaconAlwaysApplies(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	recordBrowserCapture(context.Background(), path, captureOutcome{site: "chatgpt-web", ingested: true}) // fresh ok
	// Explicit normal.
	if err := recordBrowserHealth(context.Background(), cfg, beaconBody("chatgpt-web", "degraded", "real degrade", "normal")); err != nil {
		t.Fatalf("normal beacon: %v", err)
	}
	if e := loadBrowserHealthFile(path).Sites["chatgpt-web"]; e.Status != "degraded" || e.Reason != "real degrade" {
		t.Errorf("normal beacon should apply: %+v", e)
	}
	// Legacy beacon with NO priority field is treated as normal.
	if err := recordBrowserHealth(context.Background(), cfg, beaconBody("chatgpt-web", "ok", "recovered", "")); err != nil {
		t.Fatalf("legacy beacon: %v", err)
	}
	if e := loadBrowserHealthFile(path).Sites["chatgpt-web"]; e.Status != "ok" || e.Reason != "recovered" {
		t.Errorf("priority-less beacon should apply as normal: %+v", e)
	}
}

// TestIdleBeaconStompsStaleLegacyUnstampedEntry is the MED-4 core: a legacy
// entry with landed captures but NO priority stamp and an OLD RecordedAt must
// NOT be protected from an idle beacon forever — the endpoint-churn case idle
// is meant to surface.
func TestIdleBeaconStompsStaleLegacyUnstampedEntry(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	stale := time.Now().UnixMilli() - statusFreshnessWindowMs - 1000
	if err := updateBrowserHealth(context.Background(), path, "chatgpt-web", func(e browserHealthEntry) browserHealthEntry {
		e.Status = "ok"
		e.Ingested = 3
		e.RecordedAt = stale
		// LastStatusPriority intentionally left "" — the legacy/unstamped shape.
		return e
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := recordBrowserHealth(context.Background(), cfg, beaconBody("chatgpt-web", "degraded", "endpoint churn", "low")); err != nil {
		t.Fatalf("idle beacon: %v", err)
	}
	e := loadBrowserHealthFile(path).Sites["chatgpt-web"]
	if e.Status != "degraded" || e.Reason != "endpoint churn" {
		t.Errorf("stale legacy entry should accept the idle status (MED-4): %+v", e)
	}
}

// TestIdleBeaconDoesNotStompRecentLegacyUnstampedEntry is the MED-4 boundary:
// a legacy/unstamped entry with landed captures AND a RecordedAt within the
// freshness window is still protected (real recent capture activity).
func TestIdleBeaconDoesNotStompRecentLegacyUnstampedEntry(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	recent := time.Now().UnixMilli() - 1000 // well within the window
	if err := updateBrowserHealth(context.Background(), path, "chatgpt-web", func(e browserHealthEntry) browserHealthEntry {
		e.Status = "ok"
		e.Ingested = 3
		e.RecordedAt = recent
		return e // LastStatusPriority left "" — legacy shape.
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := recordBrowserHealth(context.Background(), cfg, beaconBody("chatgpt-web", "degraded", "idle canary", "low")); err != nil {
		t.Fatalf("idle beacon: %v", err)
	}
	e := loadBrowserHealthFile(path).Sites["chatgpt-web"]
	if e.Status != "ok" {
		t.Errorf("recent legacy entry with captures should still be protected within window: %+v", e)
	}
}

// TestIdleBeaconRollingRefreshEventuallyStompsLegacyEntry is the MED-4
// rolling-refresh case the adversarial review flagged. A legacy/unstamped
// entry that starts RECENTLY active then receives idle beacons every ~3 min:
// every SUPPRESSED idle beacon refreshes the liveness RecordedAt, so if
// suppression kept keying on RecordedAt the entry would stay idle-protected
// FOREVER. promoteLegacyStatusStamp freezes the status-freshness instant at
// first contact, so the entry stays protected for ~10 min (the window) and
// then accepts the idle status — not protected forever. Uses the mockable
// clock (nowMillisFn) to advance >10 min across many beacons without sleeping.
func TestIdleBeaconRollingRefreshEventuallyStompsLegacyEntry(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	// Virtual clock: fixed epoch-millis base we hand-advance. Restore the real
	// clock on exit (these tests don't run in parallel, so the package var is
	// safe to swap).
	clock := int64(1_700_000_000_000)
	restore := nowMillisFn
	nowMillisFn = func() int64 { return clock }
	defer func() { nowMillisFn = restore }()

	// Seed a RECENTLY-active legacy/unstamped entry: landed captures, NO
	// priority stamp, RecordedAt == the current virtual now.
	if err := updateBrowserHealth(context.Background(), path, "chatgpt-web", func(e browserHealthEntry) browserHealthEntry {
		e.Status = "ok"
		e.Ingested = 5
		e.RecordedAt = clock
		return e // LastStatusPriority left "" — legacy shape.
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const threeMin = int64(3 * 60 * 1000)
	sawProtected := false
	sawStomped := false
	// 8 * 3 min = 24 min of idle beacons — well past the 10 min window.
	for i := 0; i < 8; i++ {
		clock += threeMin
		if err := recordBrowserHealth(context.Background(), cfg, beaconBody("chatgpt-web", "degraded", "endpoint churn", "low")); err != nil {
			t.Fatalf("idle beacon %d: %v", i, err)
		}
		e := loadBrowserHealthFile(path).Sites["chatgpt-web"]
		switch e.Status {
		case "ok":
			if sawStomped {
				t.Fatalf("beacon %d: status reverted to ok after being stomped: %+v", i, e)
			}
			sawProtected = true
		case "degraded":
			sawStomped = true
		default:
			t.Fatalf("beacon %d: unexpected status %q: %+v", i, e.Status, e)
		}
	}
	if !sawProtected {
		t.Error("legacy entry was never protected within the freshness window (should hold ~10 min after promotion)")
	}
	if !sawStomped {
		t.Error("legacy entry stayed idle-protected FOREVER across 24 min of idle beacons — MED-4 rolling-refresh bug not fixed")
	}
}

// TestActiveLegacyEntryStaysProtectedWhileCapturing proves MED-4 verify case
// (b): a genuinely active site whose captures keep landing stays protected
// from idle suppression indefinitely, because each real capture refreshes the
// immutable LastStatusAt stamp (idle beacons never do). Interleaves a capture
// with an idle beacon every ~3 min across 24 min and asserts the status never
// flips to the idle "degraded".
func TestActiveLegacyEntryStaysProtectedWhileCapturing(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	clock := int64(1_700_000_000_000)
	restore := nowMillisFn
	nowMillisFn = func() int64 { return clock }
	defer func() { nowMillisFn = restore }()

	// Seed a legacy/unstamped entry with landed captures.
	if err := updateBrowserHealth(context.Background(), path, "claude-web", func(e browserHealthEntry) browserHealthEntry {
		e.Status = "ok"
		e.Ingested = 2
		e.RecordedAt = clock
		return e
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const threeMin = int64(3 * 60 * 1000)
	for i := 0; i < 8; i++ {
		clock += threeMin
		// A real capture lands (recent-normal), then an idle beacon fires.
		recordBrowserCapture(context.Background(), path, captureOutcome{site: "claude-web", ingested: true})
		if err := recordBrowserHealth(context.Background(), cfg, beaconBody("claude-web", "degraded", "idle canary", "low")); err != nil {
			t.Fatalf("idle beacon %d: %v", i, err)
		}
		if e := loadBrowserHealthFile(path).Sites["claude-web"]; e.Status != "ok" {
			t.Fatalf("beacon %d: idle beacon stomped a genuinely active (capturing) site: %+v", i, e)
		}
	}
}

// TestFailingCaptureNotIdleProtected is the JS MED-4 residual core (new case
// (c)): a site whose captures ONLY FAIL (normalize/insert drops) must NOT be
// idle-protected — the failed captures must never mark it healthy or stamp a
// normal-priority freshness window, so the very next idle beacon surfaces the
// churn. A failed capture refreshing the freshness stamp was the silent lie
// this fix removes.
func TestFailingCaptureNotIdleProtected(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	// The site only ever FAILS to ingest.
	recordBrowserCapture(context.Background(), path, captureOutcome{site: "chatgpt-web", dropReason: "normalize: boom"})
	recordBrowserCapture(context.Background(), path, captureOutcome{site: "chatgpt-web", dropReason: "insert: boom"})

	// The failing captures must NOT have marked it healthy or stamped a
	// normal-priority freshness window.
	e := loadBrowserHealthFile(path).Sites["chatgpt-web"]
	if e.LastStatusPriority == statusPriorityNormal {
		t.Errorf("failing captures stamped a normal-priority status: %+v", e)
	}
	if e.LastStatusAt != 0 {
		t.Errorf("failing captures refreshed the status-freshness stamp: %+v", e)
	}
	if e.Status == "ok" {
		t.Errorf("failing captures marked the site healthy: %+v", e)
	}
	if e.Dropped != 2 {
		t.Errorf("Dropped = %d, want 2", e.Dropped)
	}

	// An idle beacon must therefore be able to set the status (not suppressed).
	if err := recordBrowserHealth(context.Background(), cfg, beaconBody("chatgpt-web", "degraded", "endpoint churn", "low")); err != nil {
		t.Fatalf("idle beacon: %v", err)
	}
	e = loadBrowserHealthFile(path).Sites["chatgpt-web"]
	if e.Status != "degraded" || e.Reason != "endpoint churn" {
		t.Errorf("a failing-only site must NOT be idle-protected: %+v", e)
	}
}

// TestFailingCapturesAgeOutOfProtection proves the mixed timeline: a site that
// captures SUCCESSFULLY (stamping the freshness window), then stops succeeding
// and only FAILS, must age out of idle protection ~10 min after the LAST
// successful capture — because a failed capture refreshes liveness (RecordedAt)
// but never the status-freshness stamp (JS MED-4 residual). Uses the virtual
// clock so we can advance past the window without sleeping.
func TestFailingCapturesAgeOutOfProtection(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	clock := int64(1_700_000_000_000)
	restore := nowMillisFn
	nowMillisFn = func() int64 { return clock }
	defer func() { nowMillisFn = restore }()

	// A successful capture stamps the normal-priority freshness window.
	recordBrowserCapture(context.Background(), path, captureOutcome{site: "chatgpt-web", ingested: true})
	// Immediately after, an idle beacon is still suppressed (protected).
	if err := recordBrowserHealth(context.Background(), cfg, beaconBody("chatgpt-web", "degraded", "idle", "low")); err != nil {
		t.Fatalf("idle beacon: %v", err)
	}
	if e := loadBrowserHealthFile(path).Sites["chatgpt-web"]; e.Status != "ok" {
		t.Fatalf("a recent successful capture should protect the status: %+v", e)
	}

	// Now captures stop SUCCEEDING and only FAIL. Each failed capture refreshes
	// liveness but must not refresh the freshness stamp, so protection ages out
	// ~10 min after the last successful capture.
	const threeMin = int64(3 * 60 * 1000)
	sawProtected := false
	sawStomped := false
	for i := 0; i < 8; i++ {
		clock += threeMin
		recordBrowserCapture(context.Background(), path, captureOutcome{site: "chatgpt-web", dropReason: "insert: boom"})
		if err := recordBrowserHealth(context.Background(), cfg, beaconBody("chatgpt-web", "degraded", "endpoint churn", "low")); err != nil {
			t.Fatalf("idle beacon %d: %v", i, err)
		}
		switch e := loadBrowserHealthFile(path).Sites["chatgpt-web"]; e.Status {
		case "ok":
			if sawStomped {
				t.Fatalf("beacon %d: status reverted to ok after being stomped: %+v", i, e)
			}
			sawProtected = true
		case "degraded":
			sawStomped = true
		default:
			t.Fatalf("beacon %d: unexpected status %q: %+v", i, e.Status, e)
		}
	}
	if !sawProtected {
		t.Error("site was never protected in the window after its last successful capture")
	}
	if !sawStomped {
		t.Error("failing captures kept the site idle-protected FOREVER — a failed capture must not refresh normal-status freshness (MED-4 residual)")
	}
}

// TestLegacyEntryThenOnlyDropsAgesOut proves the capture-path promotion +
// ingest-gating together (JS MED-4 residual, points 1+2): a legacy/unstamped
// entry with landed captures that then receives ONLY FAILED captures freezes
// its status-freshness at the pre-capture RecordedAt and never refreshes it, so
// it ages out of idle protection instead of sliding RecordedAt forward and
// staying protected forever.
func TestLegacyEntryThenOnlyDropsAgesOut(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	path := filepath.Join(dir, browserHealthFileName)

	clock := int64(1_700_000_000_000)
	restore := nowMillisFn
	nowMillisFn = func() int64 { return clock }
	defer func() { nowMillisFn = restore }()

	// Seed a legacy/unstamped entry with landed captures, RecordedAt == now.
	if err := updateBrowserHealth(context.Background(), path, "chatgpt-web", func(e browserHealthEntry) browserHealthEntry {
		e.Status = "ok"
		e.Ingested = 4
		e.RecordedAt = clock
		return e // LastStatusPriority left "" — legacy shape.
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const threeMin = int64(3 * 60 * 1000)
	sawStomped := false
	for i := 0; i < 8; i++ {
		clock += threeMin
		// A FAILED capture: refreshes liveness but must freeze the promotion
		// stamp at the pre-capture RecordedAt and never refresh it.
		recordBrowserCapture(context.Background(), path, captureOutcome{site: "chatgpt-web", dropReason: "insert: boom"})
		if err := recordBrowserHealth(context.Background(), cfg, beaconBody("chatgpt-web", "degraded", "endpoint churn", "low")); err != nil {
			t.Fatalf("idle beacon %d: %v", i, err)
		}
		if e := loadBrowserHealthFile(path).Sites["chatgpt-web"]; e.Status == "degraded" {
			sawStomped = true
		}
	}
	if !sawStomped {
		t.Error("legacy entry receiving only FAILED captures stayed idle-protected forever — capture-path promotion/gating not applied (MED-4 residual)")
	}
}

// --- MED-2: corruption-recovery abort paths --------------------------------

// TestUpdateBrowserHealthAbortsOnReadError proves a NON-ENOENT read failure
// aborts the update rather than replacing the file with a fresh empty one
// (which would silently zero every site's counters, MED-2a). A directory at
// the health path forces os.ReadFile to fail with a non-IsNotExist error.
func TestUpdateBrowserHealthAbortsOnReadError(t *testing.T) {
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	if err := os.Mkdir(healthPath, 0o755); err != nil {
		t.Fatalf("mkdir health path: %v", err)
	}
	err := updateBrowserHealth(context.Background(), healthPath, "chatgpt-web", func(e browserHealthEntry) browserHealthEntry {
		e.Ingested++
		return e
	})
	if err == nil {
		t.Fatalf("expected an error on a non-ENOENT read failure (must abort, not wipe)")
	}
	fi, statErr := os.Stat(healthPath)
	if statErr != nil || !fi.IsDir() {
		t.Errorf("health path should be left intact on a read error (isDir=%v err=%v)", fi != nil && fi.IsDir(), statErr)
	}
}

// TestLoadBrowserHealthAbortsWhenQuarantineFails proves that when the corrupt
// file can't be renamed to its .bad sidecar, the loader returns the error
// WITHOUT starting fresh — the corrupt primary (the only forensic copy)
// survives (MED-2b). A read+execute-only dir blocks the rename.
func TestLoadBrowserHealthAbortsWhenQuarantineFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based quarantine-failure cannot be simulated as root")
	}
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	if err := os.WriteFile(healthPath, []byte("{corrupt bytes"), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // r-x: no create/rename in dir
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := loadBrowserHealthFileForUpdate(healthPath); err == nil {
		t.Fatalf("expected an error when the quarantine rename fails (must not start fresh)")
	}
	_ = os.Chmod(dir, 0o700)
	raw, rerr := os.ReadFile(healthPath)
	if rerr != nil {
		t.Fatalf("corrupt primary should survive a failed quarantine: %v", rerr)
	}
	if !strings.Contains(string(raw), "corrupt bytes") {
		t.Errorf("corrupt primary was modified after a failed quarantine: %q", raw)
	}
}

// --- JS LOW: id_source provenance telemetry --------------------------------

// idSourceBody is a landable chatgpt-web turn carrying an explicit id_source.
func idSourceBody(idSource string) []byte {
	b, _ := json.Marshal(map[string]any{
		"schema_version":  1,
		"site":            "chatgpt-web",
		"conversation_id": "conv-" + idSource,
		"message_id":      "msg-" + idSource,
		"model":           "gpt-4o",
		"prompt_text":     "hi",
		"response_text":   "hello",
		"captured_at":     "2026-07-10T09:30:00Z",
		"granularity":     "full",
		"id_source":       idSource,
	})
	return b
}

// TestIngestBrowserTurnRecordsIDSourceNone proves a turn reporting
// id_source=="none" bumps the id_source_none counter, while a turn with real
// provenance does not.
func TestIngestBrowserTurnRecordsIDSourceNone(t *testing.T) {
	st, _ := openTestStore(t)
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	bc := config.BrowserConfig{Enabled: true, GranularityCeiling: "full"}

	if err := ingestBrowserTurn(context.Background(), st, idSourceBody("none"), bc, healthPath); err != nil {
		t.Fatalf("ingest none: %v", err)
	}
	if err := ingestBrowserTurn(context.Background(), st, idSourceBody("request"), bc, healthPath); err != nil {
		t.Fatalf("ingest request: %v", err)
	}
	e := loadBrowserHealthFile(healthPath).Sites["chatgpt-web"]
	if e.Ingested != 2 {
		t.Fatalf("Ingested = %d, want 2", e.Ingested)
	}
	if e.IDSourceNone != 1 {
		t.Errorf("IDSourceNone = %d, want 1 (only the id_source==none turn counts)", e.IDSourceNone)
	}
}

// TestPeekBrowserTurnParsesIDSource proves the wire field is parsed (not
// dropped) into the peek used by the telemetry path.
func TestPeekBrowserTurnParsesIDSource(t *testing.T) {
	site, _, none := peekBrowserTurn(idSourceBody("none"))
	if site != "chatgpt-web" || !none {
		t.Errorf("peek(id_source=none) = (%q, none=%v), want (chatgpt-web, true)", site, none)
	}
	_, _, none2 := peekBrowserTurn(idSourceBody("stream"))
	if none2 {
		t.Errorf("peek(id_source=stream) reported no-id-source, want false")
	}
}

// TestPeekBrowserTurnNormalizesUnknownIDSource is the Go re-review LOW-fix
// proof: peekBrowserTurn must recognize the SAME closed enum
// browserchat.buildMetadata normalizes against (browserchat.NormalizeIDSource)
// when computing idSourceNone — not just the literal raw "none" — so a
// garbage/omitted id_source the adapter stores as "none" also counts as
// "none" in health telemetry, rather than silently incrementing nothing.
func TestPeekBrowserTurnNormalizesUnknownIDSource(t *testing.T) {
	cases := []struct {
		name     string
		idSource string
		wantNone bool
	}{
		{"literal none", "none", true},
		{"empty (omitted by an old bridge)", "", true},
		{"garbage/unknown value", "totally-bogus-value", true},
		{"oversized value", strings.Repeat("x", 64), true},
		{"legit request", "request", false},
		{"legit stream", "stream", false},
		{"legit resume", "resume", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, none := peekBrowserTurn(idSourceBody(tc.idSource))
			if none != tc.wantNone {
				t.Errorf("peek(id_source=%q) none=%v, want %v", tc.idSource, none, tc.wantNone)
			}
			// Cross-check against the adapter's own normalizer directly so
			// this test can't drift from what buildMetadata actually stores.
			if got := browserchat.NormalizeIDSource(tc.idSource) == "none"; got != tc.wantNone {
				t.Errorf("browserchat.NormalizeIDSource(%q) == \"none\" = %v, want %v", tc.idSource, got, tc.wantNone)
			}
		})
	}
}

// TestIngestBrowserTurnRecordsIDSourceNoneForGarbageValue proves the fix at
// the ingest seam, not just the peek helper: a turn whose id_source is a
// garbage/unrecognized value (not the literal "none") still bumps the
// id_source_none counter, matching the "none" the adapter actually persists.
func TestIngestBrowserTurnRecordsIDSourceNoneForGarbageValue(t *testing.T) {
	st, _ := openTestStore(t)
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	bc := config.BrowserConfig{Enabled: true, GranularityCeiling: "full"}

	if err := ingestBrowserTurn(context.Background(), st, idSourceBody("not-a-real-source"), bc, healthPath); err != nil {
		t.Fatalf("ingest garbage id_source: %v", err)
	}
	e := loadBrowserHealthFile(healthPath).Sites["chatgpt-web"]
	if e.IDSourceNone != 1 {
		t.Errorf("IDSourceNone = %d, want 1 (a garbage id_source normalizes to \"none\", same as the adapter)", e.IDSourceNone)
	}
}

// TestRunBrowserHealthRendersIDSourceNone proves the CLI surfaces the counter.
func TestRunBrowserHealthRendersIDSourceNone(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	healthPath := filepath.Join(dir, browserHealthFileName)
	recordBrowserCapture(context.Background(), healthPath, captureOutcome{site: "chatgpt-web", ingested: true, idSourceNone: true})

	var out strings.Builder
	if err := runBrowserHealth(&out, cfgPath); err != nil {
		t.Fatalf("runBrowserHealth: %v", err)
	}
	if !strings.Contains(out.String(), "no-id-source") {
		t.Errorf("rendered health missing the id_source counter:\n%s", out.String())
	}
}

func TestResolveBrowserIngestTokenPrefersConfigured(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithDBIn(dir)
	pinned := "pin" + "ned-value"
	cfg.Browser.Listener.Token = pinned
	tok, err := resolveBrowserIngestToken(cfg)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tok != pinned {
		t.Errorf("resolved %q, want the configured value %q", tok, pinned)
	}
	if _, err := os.Stat(filepath.Join(dir, "browser-ingest-token")); !os.IsNotExist(err) {
		t.Errorf("configured token should not persist a file (stat err = %v)", err)
	}
}

// --- Go re-review MED fix: the health flock acquisition is bounded ---------

// TestUpdateBrowserHealthSkipsWhenDeadlineAlreadyExpired proves the flock
// acquisition is skipped OUTRIGHT — never even attempted — once ctx's
// deadline has already passed, rather than being attempted and then
// abandoned. mutate must never run and the file must never be written.
func TestUpdateBrowserHealthSkipsWhenDeadlineAlreadyExpired(t *testing.T) {
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	called := false
	err := updateBrowserHealth(ctx, healthPath, "chatgpt-web", func(e browserHealthEntry) browserHealthEntry {
		called = true
		return e
	})
	if err == nil {
		t.Fatal("want an error when ctx's deadline has already expired, got nil")
	}
	if called {
		t.Error("mutate ran despite the already-expired deadline — best-effort telemetry must be skipped, not attempted")
	}
	if _, statErr := os.Stat(healthPath); !os.IsNotExist(statErr) {
		t.Errorf("health file was written despite the expired deadline (stat err = %v)", statErr)
	}
}

// TestWithBrowserHealthLockBoundedByContendedLock is the core MED-fix proof:
// a lock held by another (here: never-releasing, simulating a wedged
// process) holder must not block the acquisition past ctx's own deadline —
// the call must return an error close to that deadline, never hang
// indefinitely waiting for the holder to release.
func TestWithBrowserHealthLockBoundedByContendedLock(t *testing.T) {
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	lockPath := healthPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	holder, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	defer holder.Close()
	if err := lockFileExclusive(holder); err != nil {
		t.Fatalf("acquire holder lock: %v", err)
	}
	defer unlockFile(holder)

	const budget = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	start := time.Now()
	err = updateBrowserHealth(ctx, healthPath, "chatgpt-web", func(e browserHealthEntry) browserHealthEntry {
		t.Error("mutate ran despite the lock being held by another holder for the whole test")
		return e
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("want a timeout/context error when the lock is contended past ctx's deadline, got nil")
	}
	// Bounded, not indefinite: must return within a small multiple of the
	// budget, never hang until the holder releases (it never does in this
	// test, until the deferred unlock at the very end).
	if elapsed > 2*time.Second {
		t.Errorf("withBrowserHealthLock (via updateBrowserHealth) blocked %s against a %s ctx deadline — the flock wait is not bounded (MED re-review finding)", elapsed, budget)
	}
	if _, statErr := os.Stat(healthPath); !os.IsNotExist(statErr) {
		t.Errorf("health file was written despite never acquiring the contended lock (stat err = %v)", statErr)
	}
}

// TestWithBrowserHealthLockFallsBackToShortTimeoutWithoutCtxDeadline proves
// the browserHealthLockTimeout fallback engages (rather than blocking
// forever) when the caller's ctx carries no deadline of its own — e.g. the
// health-beacon event path, whose ctx is the hook's own (undeadlined)
// cmd.Context().
func TestWithBrowserHealthLockFallsBackToShortTimeoutWithoutCtxDeadline(t *testing.T) {
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	lockPath := healthPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	holder, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	defer holder.Close()
	if err := lockFileExclusive(holder); err != nil {
		t.Fatalf("acquire holder lock: %v", err)
	}
	defer unlockFile(holder)

	start := time.Now()
	err = updateBrowserHealth(context.Background(), healthPath, "chatgpt-web", func(e browserHealthEntry) browserHealthEntry {
		t.Error("mutate ran despite the lock being held by another holder for the whole test")
		return e
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("want a timeout error when the lock is contended and ctx carries no deadline, got nil")
	}
	if elapsed < browserHealthLockTimeout-500*time.Millisecond || elapsed > browserHealthLockTimeout+2*time.Second {
		t.Errorf("elapsed = %s, want close to browserHealthLockTimeout (%s) — a background.Context() caller must fall back to the short bounded timeout, not block forever", elapsed, browserHealthLockTimeout)
	}
}

// TestWithBrowserHealthLockNoGoroutineLeakOnTimeout is the leak-fix proof:
// against a lock held for the whole test, many bounded withBrowserHealthLock
// calls must each return promptly WITHOUT ever running fn, and — the actual
// regression — must leave NO background goroutine blocked in the flock
// acquisition. The old blocking-goroutine + releaseAbandonedHealthLock design
// leaked one goroutine + fd per timeout; the nonblocking-poll design closes
// the fd synchronously and returns, so the goroutine count stabilizes.
// Finally, after the holder releases, no lingering abandoned acquisition may
// still land and mutate the file.
func TestWithBrowserHealthLockNoGoroutineLeakOnTimeout(t *testing.T) {
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	lockPath := healthPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	holder, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	if err := lockFileExclusive(holder); err != nil {
		t.Fatalf("acquire holder lock: %v", err)
	}
	holderReleased := false
	defer func() {
		if !holderReleased {
			_ = unlockFile(holder)
		}
		_ = holder.Close()
	}()

	// Let any goroutines from earlier subtests settle, then snapshot.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	const (
		iterations = 20
		budget     = 60 * time.Millisecond
	)
	var mutateRan int32
	for i := 0; i < iterations; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		start := time.Now()
		lockErr := withBrowserHealthLock(ctx, healthPath, func() error {
			atomic.AddInt32(&mutateRan, 1)
			return nil
		})
		elapsed := time.Since(start)
		cancel()
		if lockErr == nil {
			t.Fatalf("iteration %d: want a timeout error against the held lock, got nil", i)
		}
		// Each call must return promptly (bounded by the budget), never hang.
		if elapsed > budget+2*time.Second {
			t.Fatalf("iteration %d: withBrowserHealthLock blocked %s against a %s budget — acquisition is not bounded", i, elapsed, budget)
		}
	}
	if got := atomic.LoadInt32(&mutateRan); got != 0 {
		t.Fatalf("mutate ran %d times despite the lock being held for the whole loop — only-run-fn-when-acquired violated", got)
	}

	// The leak assertion: after all 20 timeouts, the goroutine count must not
	// have grown by ~one-per-iteration. Allow a small delta for runtime/test
	// scheduler noise; the leak would show up as ~iterations extra goroutines.
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()
	if delta := after - before; delta > 5 {
		t.Errorf("goroutine count grew by %d over %d timed-out acquisitions (before=%d after=%d) — a blocked flock goroutine is leaking per timeout", delta, iterations, before, after)
	}

	// No abandoned acquisition may still be pending: release the holder, wait,
	// and confirm nothing landed the lock behind our back and mutated the file.
	_ = unlockFile(holder)
	holderReleased = true
	time.Sleep(200 * time.Millisecond)
	if got := atomic.LoadInt32(&mutateRan); got != 0 {
		t.Fatalf("a lingering abandoned acquisition ran the mutate %d times after the holder released — the timed-out call did not truly give up", got)
	}
	if _, statErr := os.Stat(healthPath); !os.IsNotExist(statErr) {
		t.Errorf("health file exists after release despite every acquisition timing out (stat err = %v) — a leaked acquisition wrote it", statErr)
	}
}

// TestWithBrowserHealthLockAlreadyCanceledSkipsFnEvenWhenLockIsFree is the
// cancellation-boundary proof (Go re-review LOW fix): withBrowserHealthLock
// must never run fn() against an already-canceled ctx, even when the lock is
// completely FREE and the very first nonblocking attempt would otherwise
// succeed immediately. Before the fix, ctx was only consulted inside the
// contended-retry select — an uncontended lock skipped that check entirely,
// so a canceled ctx slipped straight through to fn().
func TestWithBrowserHealthLockAlreadyCanceledSkipsFnEvenWhenLockIsFree(t *testing.T) {
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled BEFORE withBrowserHealthLock ever attempts the lock

	var ran int32
	start := time.Now()
	err := withBrowserHealthLock(ctx, healthPath, func() error {
		atomic.AddInt32(&ran, 1)
		return nil
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("want an error when ctx is already canceled, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}
	if atomic.LoadInt32(&ran) != 0 {
		t.Error("fn ran despite ctx being canceled before the first lock attempt — cancellation boundary violated with an uncontended lock")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("withBrowserHealthLock took %s to return on an already-canceled ctx with a FREE lock — should return promptly, not poll", elapsed)
	}
	if _, statErr := os.Stat(healthPath); !os.IsNotExist(statErr) {
		t.Errorf("health file was created despite fn never running (stat err = %v)", statErr)
	}
}

// TestWithBrowserHealthLockDoesNotRunFnPastAbsoluteExpiryOnBackgroundCtx is
// the absolute-clock proof (Go re-review LOW fix): a context.Background()
// ctx carries no deadline of its own, so withBrowserHealthLock falls back to
// browserHealthLockTimeout, and ctx.Err() is always nil for the whole run —
// nothing about ctx itself can ever end the poll loop. If the contended
// lock is freed just AFTER that fallback budget elapses, the loop must still
// give up and return WITHOUT running fn, even though the very next
// nonblocking attempt would succeed. Before the fix this relied entirely on
// select choosing the timer.C case over a simultaneously-ready ticker.C —
// pseudo-random per the language spec — so a late-freed lock could still be
// acquired and fn started past the budget purely by chance.
func TestWithBrowserHealthLockDoesNotRunFnPastAbsoluteExpiryOnBackgroundCtx(t *testing.T) {
	dir := t.TempDir()
	healthPath := filepath.Join(dir, browserHealthFileName)
	lockPath := healthPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	holder, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	if err := lockFileExclusive(holder); err != nil {
		t.Fatalf("acquire holder lock: %v", err)
	}

	// Free the lock strictly AFTER the fallback budget elapses — never
	// before — so any successful acquisition would necessarily have
	// happened past expiresAt.
	go func() {
		time.Sleep(browserHealthLockTimeout + 100*time.Millisecond)
		_ = unlockFile(holder)
		_ = holder.Close()
	}()

	var ran int32
	start := time.Now()
	err = withBrowserHealthLock(context.Background(), healthPath, func() error {
		atomic.AddInt32(&ran, 1)
		return nil
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("want a timeout error when the lock is freed only after the fallback budget, got nil")
	}
	if atomic.LoadInt32(&ran) != 0 {
		t.Error("fn ran after the lock was freed past the absolute expiry — the timer-vs-ticker select race let a late acquisition through")
	}
	// Must return close to the fallback budget, not linger until (or past)
	// the moment the holder actually releases.
	if elapsed < browserHealthLockTimeout-500*time.Millisecond || elapsed > browserHealthLockTimeout+2*time.Second {
		t.Errorf("elapsed = %s, want close to browserHealthLockTimeout (%s) — should give up at the absolute expiry, not wait for/past the holder's release", elapsed, browserHealthLockTimeout)
	}
	if _, statErr := os.Stat(healthPath); !os.IsNotExist(statErr) {
		t.Errorf("health file was written despite the acquisition attempt expiring before the lock was freed (stat err = %v)", statErr)
	}
}
