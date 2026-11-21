//go:build !sbo_omit_capture_proxy

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/ownagent"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestOwnAgentCaptureOn: the header capture follows the custom-agent
// adapter's allow-list entry and component gate.
func TestOwnAgentCaptureOn(t *testing.T) {
	on := func(string) bool { return true }
	off := func(string) bool { return false }
	cases := []struct {
		name   string
		allow  []string
		active func(string) bool
		want   bool
	}{
		{"default list", config.Default().Observer.Watch.EnabledAdapters, on, true},
		{"empty list allows all", nil, on, true},
		{"removed from the list", []string{"claude-code"}, on, false},
		{"component inactive", []string{models.ToolCustomAgent}, off, false},
		{"no gate", []string{models.ToolCustomAgent}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Observer.Watch.EnabledAdapters = tc.allow
			if got := ownAgentCaptureOn(cfg, tc.active); got != tc.want {
				t.Errorf("ownAgentCaptureOn = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestOwnAgentBudgetDenyAppliesThroughRealGuard (fix round 1): the node's
// own [guard.budget] hard cap, evaluated by the REAL guard over the real
// store's spend, stops a claimed request whose own-agent session is over
// its session cap, before the upstream. A claimed request on a fresh
// session of the same agent still goes through, so the deny is keyed by the
// claim's session.
func TestOwnAgentBudgetDenyAppliesThroughRealGuard(t *testing.T) {
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
	cfg.Guard.Enabled = true
	cfg.Guard.Mode = "enforce"
	cfg.Guard.Proxy.EgressScan = false
	cfg.Guard.Budget = config.GuardBudgetConfig{SessionUSD: 1, Hard: true}
	g := buildGuardForStore(ctx, cfg, st, logger)
	if g == nil {
		t.Fatal("buildGuardForStore returned nil")
	}

	// The claimed session already spent past its $1 cap.
	spent := ownagent.SessionID("budget-bot", "run-over")
	now := time.Now().UTC()
	if err := st.EnsureOwnAgentSession(ctx, spent, "budget-bot", "[custom-agent]", "claude-sonnet-4", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(ctx, models.APITurn{
		SessionID: spent, Timestamp: now.Add(-30 * time.Second), Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4", InputTokens: 2_000_000, OutputTokens: 10_000, CostUSD: 6.15,
	}); err != nil {
		t.Fatal(err)
	}

	var upstreamHits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_b","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":1}}`))
	}))
	defer up.Close()
	p, err := proxy.New(proxy.Options{
		AnthropicUpstream: up.URL, Sink: st, OwnAgentSessions: st,
		Guard: guardScannerAdapter{g: g, st: st, logger: logger},
	})
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(p.Handler())
	defer ps.Close()
	send := func(session string) int {
		req, _ := http.NewRequest(http.MethodPost, ps.URL+"/v1/messages",
			strings.NewReader(`{"model":"claude-sonnet-4","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(ownagent.AgentHeader, "budget-bot")
		req.Header.Set(ownagent.SessionHeader, session)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if code := send("run-over"); code != http.StatusForbidden {
		t.Fatalf("over-budget claimed session = %d, want 403 (budget hard deny)", code)
	}
	if upstreamHits.Load() != 0 {
		t.Fatal("the over-budget request reached the upstream")
	}
	if code := send("run-fresh"); code != http.StatusOK {
		t.Fatalf("a fresh claimed session = %d, want 200", code)
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1", upstreamHits.Load())
	}
}

// The daemon's pid bridge must offer the own-process answer, or own-agent
// capture would treat every child of a coding tool as the tool (N2).
var _ proxy.OwnToolResolver = (*pidbridge.ProcResolver)(nil)

// TestRegistryToolBinaries (sdk-1f L4): the bridge's own-process check gets
// each tool's executable names from the integration registry's Binary row.
func TestRegistryToolBinaries(t *testing.T) {
	got := registryToolBinaries(models.ToolClaudeCode)
	if !slices.Contains(got, "claude") {
		t.Fatalf("claude-code executables = %v, want them to include claude", got)
	}
	if got := registryToolBinaries(models.ToolCustomAgent); got != nil {
		t.Fatalf("custom-agent has no binary, got %v", got)
	}
	if got := registryToolBinaries("no-such-tool"); got != nil {
		t.Fatalf("unknown tool = %v, want nil", got)
	}
}
