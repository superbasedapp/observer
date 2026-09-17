package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// TestBuildProxy_DefaultConfigWiresCacheEngine is the
// integration test the operator demanded after the
// daemon-wiring-gap bug: TestProxyAnthropic_WritesCacheRows
// passed because it built the proxy DIRECTLY with a
// cachetrack.Engine + CacheSink injected; the actual daemon
// path through `buildProxy` did NOT wire the engine, so live
// captures silently no-op.
//
// This test goes through buildProxy exactly the way `observer
// start` does (config.Load → db.Open → store.New →
// buildProxy → proxy.New). After one proxied Anthropic turn,
// cache_segments / cache_entries / cache_events MUST be > 0.
// A regression here means the daemon assembly drifted from
// the engine wiring again.
func TestBuildProxy_DefaultConfigWiresCacheEngine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Stage a fake upstream that returns a real-shape
	// Anthropic streaming response.
	sse := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_integration_test","model":"claude-opus-4-8","usage":{"input_tokens":200,"cache_read_input_tokens":0,"cache_creation_input_tokens":50000,"output_tokens":1,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":50000}}}}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":100}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")
	anth := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if f, ok := w.(http.Flusher); ok {
			_, _ = w.Write([]byte(sse))
			f.Flush()
		}
	})
	anthUp := httptest.NewServer(anth)
	t.Cleanup(anthUp.Close)

	// Write a config.toml WITH NO [cachetrack] SECTION. This is
	// the operator's exact failing case — the default-on
	// invariant must rescue them.
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "observer.db")
	configPath := filepath.Join(tmp, "config.toml")
	configBody := fmt.Sprintf(`
[observer]
db_path = %q
log_level = "warn"

[proxy]
enabled = true
port = 8820
anthropic_upstream = %q
openai_upstream = "http://127.0.0.1:1"
chatgpt_upstream = "http://127.0.0.1:2"
prewarm_targets = []
`, dbPath, anthUp.URL)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Pre-flight: confirm the loader actually defaults
	// CacheTrack.Enabled to true when the section is absent
	// from the file. Operator-reported regression: this was
	// SILENTLY false on their box.
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if !cfg.CacheTrack.Enabled {
		t.Fatalf("config.Load returned CacheTrack.Enabled=false; default-on invariant broken — every install captures nothing until hand-edited")
	}
	if cfg.CacheTrack.MaxTrackedSessions != 64 {
		t.Errorf("CacheTrack.MaxTrackedSessions = %d, want 64", cfg.CacheTrack.MaxTrackedSessions)
	}

	// Build the proxy the way `observer start` does.
	p, cleanup, _, _, _, _, _, err := buildProxy(ctx, configPath, "", 0, "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}
	t.Cleanup(cleanup)
	if p == nil {
		t.Fatal("buildProxy returned nil proxy")
	}

	// Serve the real proxy handler and fire one R1(a)-shape
	// Anthropic request through it.
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	body := `{
		"model":"claude-opus-4-8",
		"stream":true,
		"tools":[
			{"name":"Read","input_schema":{"type":"object"}}
		],
		"system":[
			{"type":"text","text":"sys head"},
			{"type":"text","text":"sys body","cache_control":{"type":"ephemeral","ttl":"1h"}}
		],
		"messages":[
			{"role":"user","content":[
				{"type":"text","text":"hi","cache_control":{"type":"ephemeral","ttl":"1h"}}
			]}
		]
	}`
	req, _ := http.NewRequest("POST", srv.URL+"/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Id", "sIntegration")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Open the SAME DB and poll for rows.
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("re-open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	var apiTurns, segments, events, entries int
	for i := 0; i < 100; i++ {
		_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_turns`).Scan(&apiTurns)
		_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM cache_segments`).Scan(&segments)
		_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM cache_events`).Scan(&events)
		_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM cache_entries`).Scan(&entries)
		if apiTurns >= 1 && segments > 0 && events > 0 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if apiTurns == 0 {
		t.Fatal("api_turns row never written — proxy assembly broken in a different way")
	}
	if segments == 0 {
		t.Errorf("cache_segments = 0 despite the proxy receiving a turn with markers — daemon wiring gap (the operator-reported bug). buildProxy must construct cachetrack.Engine + pass *Store as CacheSink.")
	}
	if events == 0 {
		t.Errorf("cache_events = 0 — engine ran but didn't emit events (or PersistCacheObservation isn't wired through CacheSink)")
	}
	if entries == 0 {
		t.Errorf("cache_entries = 0 despite CacheCreationTokens=50000 — engine isn't creating write entries")
	}
}

// TestBuildProxy_CacheTrackDisabledByConfig confirms the opt-
// out path: when an operator explicitly sets enabled=false, no
// cache_* rows are written even on a fully-formed request.
func TestBuildProxy_CacheTrackDisabledByConfig(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	anth := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_off","model":"claude-opus-4-8","stop_reason":"end_turn","usage":{"input_tokens":42,"output_tokens":17,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}`))
	})
	anthUp := httptest.NewServer(anth)
	t.Cleanup(anthUp.Close)

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "observer.db")
	configPath := filepath.Join(tmp, "config.toml")
	configBody := fmt.Sprintf(`
[observer]
db_path = %q
log_level = "warn"

[proxy]
enabled = true
port = 8820
anthropic_upstream = %q
openai_upstream = "http://127.0.0.1:1"
chatgpt_upstream = "http://127.0.0.1:2"
prewarm_targets = []

[cachetrack]
enabled = false
`, dbPath, anthUp.URL)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	p, cleanup, _, _, _, _, _, err := buildProxy(ctx, configPath, "", 0, "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}
	t.Cleanup(cleanup)

	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	body := `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}]}`
	req, _ := http.NewRequest("POST", srv.URL+"/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	// Give the api_turn write a moment to flush.
	var apiTurns int
	for i := 0; i < 100; i++ {
		_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_turns`).Scan(&apiTurns)
		if apiTurns > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if apiTurns == 0 {
		t.Fatal("api_turn write failed — test setup broken")
	}

	var segments, events int
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM cache_segments`).Scan(&segments)
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM cache_events`).Scan(&events)
	if segments != 0 || events != 0 {
		t.Errorf("[cachetrack].enabled=false but rows written: segments=%d events=%d", segments, events)
	}
}

// TestConfigLoad_CacheTrackDefaultsOnWhenSectionAbsent is the
// focused unit test for the secondary half of the operator's
// bug: every install with no [cachetrack] section was silently
// off. The Default() invariant must rescue them.
func TestConfigLoad_CacheTrackDefaultsOnWhenSectionAbsent(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.toml")
	// Minimal config WITHOUT [cachetrack] (the original
	// silent-off shape).
	body := `
[observer]
db_path = "/tmp/observer.db"
log_level = "info"
`
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if !cfg.CacheTrack.Enabled {
		t.Fatalf("CacheTrack.Enabled = false; default-on invariant broken — silent-off bug reintroduced")
	}
	if cfg.CacheTrack.MaxTrackedSessions != 64 {
		t.Errorf("MaxTrackedSessions = %d, want 64 (Default)", cfg.CacheTrack.MaxTrackedSessions)
	}
}
