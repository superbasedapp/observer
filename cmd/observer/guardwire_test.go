package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestAcquireProcessGuard_SharedPerDBPath pins the daemon-wide guard
// invariant (G9): the proxy build and the watcher build — separate
// Store handles over the same observer.db — must receive the SAME
// Guard instance, so proxy-marked taint is visible to the watcher
// ingest seam's T-5xx rules. Distinct DB paths (distinct daemons in
// one test process) get distinct instances; disabled/off configs get
// nil.
func TestAcquireProcessGuard_SharedPerDBPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	openStore := func(path string) *store.Store {
		t.Helper()
		database, err := dbtemplate.Open(ctx, db.Options{Path: path})
		if err != nil {
			t.Fatalf("db.Open: %v", err)
		}
		t.Cleanup(func() { _ = database.Close() })
		return store.New(database)
	}
	cfgFor := func(dbPath string) config.Config {
		cfg := config.Default()
		cfg.Observer.DBPath = dbPath
		return cfg
	}

	pathA := filepath.Join(t.TempDir(), "observer.db")
	stProxy := openStore(pathA)
	stWatcher := openStore(pathA)

	g1 := acquireProcessGuard(ctx, cfgFor(pathA), stProxy, logger)
	if g1 == nil {
		t.Fatal("acquireProcessGuard returned nil for an enabled config")
	}
	g2 := acquireProcessGuard(ctx, cfgFor(pathA), stWatcher, logger)
	if g1 != g2 {
		t.Fatal("two acquires over the same observer.db returned distinct Guards — taint state would split between proxy and watcher")
	}

	pathB := filepath.Join(t.TempDir(), "observer.db")
	g3 := acquireProcessGuard(ctx, cfgFor(pathB), openStore(pathB), logger)
	if g3 == nil || g3 == g1 {
		t.Fatal("a different observer.db must get its own Guard instance")
	}

	off := cfgFor(filepath.Join(t.TempDir(), "observer.db"))
	off.Guard.Mode = "off"
	if g := acquireProcessGuard(ctx, off, stProxy, logger); g != nil {
		t.Fatal("mode=off must not construct a Guard")
	}
	disabled := cfgFor(filepath.Join(t.TempDir(), "observer.db"))
	disabled.Guard.Enabled = false
	if g := acquireProcessGuard(ctx, disabled, stProxy, logger); g != nil {
		t.Fatal("enabled=false must not construct a Guard")
	}
}

// promptLaneTestPAN is a Luhn-valid, non-test-suppressed PAN (contract
// §4.3's testValues list — 4242.../4111... are all suppressed by
// design) — the same literal internal/guard's own proxyguard_test.go
// uses as promptTestPAN, duplicated here rather than exported since
// it's a one-line fixture value, not shared behavior.
const promptLaneTestPAN = "4532015112830366"

// anthropicUserOnlyBody mirrors internal/guard/proxyguard_test.go's
// helper of the same name: the simplest possible Anthropic Messages
// body carrying one user turn.
func anthropicUserOnlyBody(t *testing.T, text string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model":    "claude-opus-4-8",
		"messages": []any{map[string]any{"role": "user", "content": text}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

// TestBuildGuardForStore_PromptLaneEndToEnd is the Group 3 (phase-3a
// review) proxy-lane wiring test, run through the SAME two seams the
// real proxy handler uses: buildGuardForStore (item 1 — the daemon-
// shared Guard's reconsider-once persistence, previously never wired
// so every proxy-lane ask-once finding degraded to an unconditional
// "store_unwired" block) and guardScannerAdapter.ScanRequest (item 2 —
// reading PromptDeny/PromptStatus/PromptRuleID/PromptReason so a
// prompt-lane interrupt renders through guardPromptDenyBody's
// developer-facing 400/403 wording instead of the generic egress-deny
// fallback). A fresh ask-once occurrence must deny with Action ==
// "prompt_deny" at 400; an IDENTICAL resend within the TTL must
// confirm and forward (Action == "") — that second assertion is only
// possible if buildGuardForStore's reconsider store genuinely
// persists through the real *store.Store, not a zero-value stub.
func TestBuildGuardForStore_PromptLaneEndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)

	cfg := config.Default()
	cfg.Observer.DBPath = dbPath
	// config.Default()'s [guard.prompt] already ships Enabled/HookLane/
	// ProxyLane/EnforceIndependent all true, Mode "ask-once", and
	// credit_card seeded at "ask-once" (config.go's Guard.Prompt
	// defaults) — exactly the shape internal/guard's own promptCfg/
	// promptProxyCfg test helpers build by hand, so no override needed
	// here beyond disabling the whole-body egress scanner (it would
	// otherwise ALSO fire on the same PAN and muddy which lane denied).
	cfg.Guard.Proxy.EgressScan = false
	// The retry floor ([guard.prompt].reconsider_min_delay, default 3s)
	// would read this test's millisecond-apart resend as a client
	// retry; the floor has its own pins in internal/guard, so disable it
	// here to keep this an end-to-end test of the STORE seam.
	cfg.Guard.Prompt.ReconsiderMinDelay = "0s"

	g := buildGuardForStore(ctx, cfg, st, logger)
	if g == nil {
		t.Fatal("buildGuardForStore returned nil for an enabled config")
	}
	adapter := guardScannerAdapter{g: g, st: st, logger: logger}

	body := anthropicUserOnlyBody(t, "here is my card "+promptLaneTestPAN)

	res1 := adapter.ScanRequest(ctx, models.ProviderAnthropic, body, "s1")
	if res1.Action != "prompt_deny" {
		t.Fatalf("fresh ask-once occurrence: Action = %q, want prompt_deny (%+v)", res1.Action, res1)
	}
	if res1.Status != 400 {
		t.Errorf("Status = %d, want 400 for a fresh ask-once interrupt", res1.Status)
	}
	if res1.RuleID == "" || res1.Reason == "" {
		t.Errorf("RuleID/Reason must be populated on a prompt_deny: %+v", res1)
	}

	// Identical resend within the TTL: this only confirms if item 1's
	// reconsider store actually persisted the warned-fingerprint row
	// through st — a zero-value (unwired) store degrades EVERY
	// ask-once finding to an unconditional block, so a resend here
	// would still come back prompt_deny if item 1 regressed.
	res2 := adapter.ScanRequest(ctx, models.ProviderAnthropic, body, "s1")
	if res2.Action == "prompt_deny" {
		t.Fatalf("identical resend still denied — the reconsider store is not persisting through the real *store.Store: %+v", res2)
	}
}

type guardwireAPITurnSink struct {
	mu    sync.Mutex
	turns []models.APITurn
}

func (s *guardwireAPITurnSink) InsertAPITurn(_ context.Context, turn models.APITurn) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turns = append(s.turns, turn)
	return int64(len(s.turns)), nil
}

func (s *guardwireAPITurnSink) snapshot() []models.APITurn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]models.APITurn(nil), s.turns...)
}

type recordingGuardScanner struct {
	mu     sync.Mutex
	inner  guardScannerAdapter
	prompt []string
	after  []string
}

func (s *recordingGuardScanner) ScanRequest(ctx context.Context, provider string, body []byte, sessionID string) proxy.GuardRequestResult {
	return s.inner.ScanRequest(ctx, provider, body, sessionID)
}

func (s *recordingGuardScanner) ScanPrompt(ctx context.Context, provider string, body []byte, sessionID string) proxy.GuardRequestResult {
	s.mu.Lock()
	s.prompt = append(s.prompt, sessionID)
	s.mu.Unlock()
	return s.inner.ScanPrompt(ctx, provider, body, sessionID)
}

func (s *recordingGuardScanner) ScanRequestAfterPrompt(ctx context.Context, provider string, body []byte, sessionID string) proxy.GuardRequestResult {
	s.mu.Lock()
	s.after = append(s.after, sessionID)
	s.mu.Unlock()
	return s.inner.ScanRequestAfterPrompt(ctx, provider, body, sessionID)
}

func (s *recordingGuardScanner) InspectResponse(ctx context.Context, sessionID string, apiTurnID int64, tools []proxy.GuardToolUse) {
	s.inner.InspectResponse(ctx, sessionID, apiTurnID, tools)
}

func (s *recordingGuardScanner) snapshot() (prompt, after []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.prompt...), append([]string(nil), s.after...)
}

var (
	_ proxy.GuardScanner       = (*recordingGuardScanner)(nil)
	_ proxy.PromptPhaseScanner = (*recordingGuardScanner)(nil)
)

// TestProxyPromptLane_SessionlessRealGuardAskOnce exercises the daemon's
// real guard composition through the proxy two-phase seam. A session-less
// client receives a stable prompt-only fallback scope, but phase 2 and the
// captured API turn remain unattributed. The immediate retry stays blocked by
// reconsider_min_delay; a delayed identical resend confirms and forwards.
func TestProxyPromptLane_SessionlessRealGuardAskOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_guardwire","model":"claude-opus-4-8","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	cfg := config.Default()
	cfg.Observer.DBPath = dbPath
	cfg.Guard.Proxy.EgressScan = false

	g := buildGuardForStore(ctx, cfg, st, logger)
	if g == nil {
		t.Fatal("buildGuardForStore returned nil for an enabled config")
	}
	sink := &guardwireAPITurnSink{}
	scanner := &recordingGuardScanner{inner: guardScannerAdapter{g: g, st: st, logger: logger}}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	t.Cleanup(client.CloseIdleConnections)
	p, err := proxy.New(proxy.Options{
		AnthropicUpstream: upstream.URL,
		OpenAIUpstream:    upstream.URL,
		PrewarmTargets:    []string{},
		Client:            client,
		Sink:              sink,
		Guard:             scanner,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	proxyServer := httptest.NewServer(p.Handler())
	defer proxyServer.Close()

	body := anthropicUserOnlyBody(t, "here is my card "+promptLaneTestPAN)
	post := func() int {
		req, err := http.NewRequest(http.MethodPost, proxyServer.URL+"/v1/messages", strings.NewReader(string(body)))
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "sessionless-guardwire/1")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("proxy request: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if got := post(); got != http.StatusBadRequest {
		t.Fatalf("fresh ask-once status = %d, want 400", got)
	}
	if got := post(); got != http.StatusBadRequest {
		t.Fatalf("immediate retry status = %d, want 400 from reconsider_min_delay", got)
	}
	time.Sleep(3100 * time.Millisecond)
	if got := post(); got != http.StatusOK {
		t.Fatalf("delayed identical resend status = %d, want 200", got)
	}

	promptScopes, afterScopes := scanner.snapshot()
	if len(promptScopes) != 3 || promptScopes[0] == "" || promptScopes[0] != promptScopes[1] || promptScopes[1] != promptScopes[2] {
		t.Fatalf("prompt scopes = %q, want one stable non-empty fallback scope", promptScopes)
	}
	if len(afterScopes) != 1 || afterScopes[0] != "" {
		t.Fatalf("phase-2 session ids = %q, want one empty real API session id", afterScopes)
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want only the delayed confirmed resend", got)
	}
	turns := sink.snapshot()
	if len(turns) != 3 {
		t.Fatalf("api turns = %d, want one row per request", len(turns))
	}
	for i, turn := range turns {
		if turn.SessionID != "" {
			t.Errorf("turn %d SessionID = %q, want empty session-less attribution", i, turn.SessionID)
		}
	}
}
