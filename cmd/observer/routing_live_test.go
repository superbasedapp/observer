package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/selfobs/emit"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// liveRouterFixture seeds a store with a read-only opus session and
// returns a refreshed liveRouter in the requested mode plus the seeded
// turn's id (api_turn_id linkage is FK-enforced).
func liveRouterFixture(t *testing.T, mode string) (*liveRouter, *store.Store, int64) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s := store.New(database)

	now := time.Now().UTC()
	pid, _ := s.UpsertProject(ctx, "/tmp/router-live", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "live-1", ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	if _, err := s.InsertActions(ctx, []models.Action{
		{
			SessionID: "live-1", ProjectID: pid, Timestamp: now.Add(-2 * time.Minute),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "e1",
		},
		{
			SessionID: "live-1", ProjectID: pid, Timestamp: now.Add(-1 * time.Minute),
			ActionType: models.ActionSearchText, Target: "func", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "e2",
		},
	}); err != nil {
		t.Fatalf("InsertActions: %v", err)
	}
	turnID, err := s.InsertAPITurn(ctx, models.APITurn{
		SessionID: "live-1", Timestamp: now.Add(-90 * time.Second), Provider: "anthropic",
		Model: "claude-opus-4-8", InputTokens: 1000, OutputTokens: 100,
	})
	if err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}

	policy, issues := routing.Compile(routing.PolicySpec{Policy: "value", RespectCache: true})
	if routing.LintHasErrors(issues) {
		t.Fatalf("value template lints dirty: %+v", issues)
	}
	refresher := store.NewRoutingRefresher(s, policy, routing.NewTierResolver(), nil)
	if err := refresher.RefreshNow(ctx); err != nil {
		t.Fatalf("RefreshNow: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newLiveRouter(policy, mode, refresher, s, logger), s, turnID
}

func liveShape() proxy.RouterShape {
	return proxy.RouterShape{
		Model: "claude-opus-4-8", MessageCount: 6, ToolUseCount: 3,
		PromptTokensEstimate: 4000,
	}
}

func liveSess() proxy.RouterSession {
	return proxy.RouterSession{Provider: "anthropic", SessionID: "live-1", Entitlement: "api_key"}
}

// TestLiveRouter_AdviseLogsWithoutActing pins §R18.2: advise mode
// produces Apply=false verdicts whose decision rows land linked to the
// turn once RecordServed fires.
func TestLiveRouter_AdviseLogsWithoutActing(t *testing.T) {
	lr, s, turnID := liveRouterFixture(t, "advise")
	v := lr.Decide(liveShape(), liveSess())
	if v.Apply {
		t.Fatal("advise mode produced an Apply verdict")
	}
	if v.SelectedModel != "claude-haiku-4-5" {
		t.Fatalf("verdict = %+v, want the read-only downshift selection", v)
	}
	lr.RecordServed(v.Token, turnID, "claude-opus-4-8")

	stats, err := s.SelectRouterDecisionStats(context.Background())
	if err != nil || stats.Count != 1 {
		t.Fatalf("decision rows = %+v err=%v, want 1", stats, err)
	}
}

// TestLiveRouter_EnforceAppliesAndTracksCoherence pins enforce mode:
// the first decision applies; the immediately following one holds on
// the §R13 stickiness floor (turns-since-switch = 0 < 5).
func TestLiveRouter_EnforceAppliesAndTracksCoherence(t *testing.T) {
	lr, _, _ := liveRouterFixture(t, "enforce")
	v1 := lr.Decide(liveShape(), liveSess())
	if !v1.Apply || v1.SelectedModel != "claude-haiku-4-5" {
		t.Fatalf("first verdict = %+v, want applied downshift", v1)
	}
	v2 := lr.Decide(liveShape(), liveSess())
	if v2.Apply {
		t.Fatalf("second verdict = %+v, want stickiness hold (switch 1 turn ago)", v2)
	}
}

// TestLiveRouter_JanitorFlushesOrphans pins the dropped-turn path: a
// decision whose turn never lands persists with a NULL api_turn_id
// once the janitor age passes.
func TestLiveRouter_JanitorFlushesOrphans(t *testing.T) {
	lr, s, _ := liveRouterFixture(t, "advise")
	base := time.Now()
	lr.now = func() time.Time { return base }
	v := lr.Decide(liveShape(), liveSess())
	if v.Token == 0 {
		t.Fatal("no token issued")
	}
	// The turn never lands; a later RecordServed for a DIFFERENT token
	// sweeps the expired orphan.
	lr.now = func() time.Time { return base.Add(2 * pendingJanitorAge) }
	lr.RecordServed(999_999, 0, "")
	stats, err := s.SelectRouterDecisionStats(context.Background())
	if err != nil || stats.Count != 1 {
		t.Fatalf("decision rows = %+v err=%v, want the orphan flushed", stats, err)
	}
}

// TestLiveRouter_NilSnapshotFailsOpen pins the cold-start contract: a
// router whose refresher has never published decides fail-open.
func TestLiveRouter_NilSnapshotFailsOpen(t *testing.T) {
	lr, _, _ := liveRouterFixture(t, "enforce")
	// Fresh refresher that never refreshed.
	policy, _ := routing.Compile(routing.PolicySpec{Policy: "value", RespectCache: true})
	lr.refresher = store.NewRoutingRefresher(lr.store, policy, routing.NewTierResolver(), nil)
	v := lr.Decide(liveShape(), liveSess())
	if v.Apply || v.SelectedModel != "claude-opus-4-8" {
		t.Fatalf("verdict on nil snapshot = %+v, want fail-open original", v)
	}
}

// TestLiveRouter_EscalationAfterFailedDownshift pins §R7.4 end to end:
// an applied downshift followed by a failure spike escalates the kind
// — subsequent decisions of that kind hold with reason=escalation
// until the cooldown lapses, then downshifting resumes.
func TestLiveRouter_EscalationAfterFailedDownshift(t *testing.T) {
	lr, s, _ := liveRouterFixture(t, "enforce")
	base := time.Now()
	lr.now = func() time.Time { return base }

	v1 := lr.Decide(liveShape(), liveSess())
	if !v1.Apply {
		t.Fatalf("first verdict = %+v, want applied downshift", v1)
	}

	// The downshifted turns start failing: seed two failed actions and
	// refresh so the snapshot window carries the spike.
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := s.InsertActions(ctx, []models.Action{
		{
			SessionID: "live-1", ProjectID: 1, Timestamp: now.Add(-30 * time.Second),
			ActionType: models.ActionReadFile, Target: "x.go", Success: false,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "fail1",
		},
		{
			SessionID: "live-1", ProjectID: 1, Timestamp: now.Add(-20 * time.Second),
			ActionType: models.ActionSearchText, Target: "y", Success: false,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "fail2",
		},
	}); err != nil {
		t.Fatalf("InsertActions: %v", err)
	}
	if err := lr.refresher.RefreshNow(ctx); err != nil {
		t.Fatalf("RefreshNow: %v", err)
	}

	v2 := lr.Decide(liveShape(), liveSess())
	if v2.Apply {
		t.Fatalf("second verdict = %+v, want escalation hold", v2)
	}
	// The decision row carries reason=escalation — flush and check.
	lr.RecordServed(v2.Token, 0, "")
	stats, err := s.SelectRouterDecisionStats(ctx)
	if err != nil || stats.Count < 1 {
		t.Fatalf("decision rows = %+v err=%v", stats, err)
	}

	// Past the cooldown the kind routes again — but the stickiness
	// floor (switch at v1) must ALSO have lapsed; advance past both.
	lr.now = func() time.Time { return base.Add(escalationCooldown + time.Minute) }
	st := lr.sessions["live-1"]
	st.turnsSinceSwitch = -1 // coherence floor lapsed (many turns later)
	v3 := lr.Decide(liveShape(), liveSess())
	if !v3.Apply {
		t.Fatalf("post-cooldown verdict = %+v, want downshift resumed", v3)
	}
}

// TestLiveRouter_CalibrationDemotion pins §R18.3: a demoted rule's
// decision logs but never applies, with the calibration_demoted code
// on the row; clearing the demotion restores enforcement.
func TestLiveRouter_CalibrationDemotion(t *testing.T) {
	lr, _, _ := liveRouterFixture(t, "enforce")
	lr.SetDemotedRules(map[string]string{"read_only_overpowered": "test regression"})
	v := lr.Decide(liveShape(), liveSess())
	if v.Apply {
		t.Fatalf("demoted rule still applied: %+v", v)
	}
	lr.mu.Lock()
	var hasCode bool
	for _, p := range lr.pending {
		for _, rc := range p.row.ReasonCodes {
			if rc == string(routing.ReasonCalibrationDemoted) {
				hasCode = true
			}
		}
	}
	lr.mu.Unlock()
	if !hasCode {
		t.Error("calibration_demoted reason missing from the pending row")
	}

	lr.SetDemotedRules(map[string]string{})
	lr.sessions["live-1"].turnsSinceSwitch = -1
	if v := lr.Decide(liveShape(), liveSess()); !v.Apply {
		t.Fatalf("cleared demotion did not restore enforcement: %+v", v)
	}
}

// TestLiveRouter_DemotedRulesAccessor pins the R2.4 read-side surface:
// the dashboard's accessor returns a COPY (mutating it never touches
// the hot path's set) and an empty-non-nil map before any calibration
// pass has run.
func TestLiveRouter_DemotedRulesAccessor(t *testing.T) {
	lr, _, _ := liveRouterFixture(t, "enforce")
	if got := lr.DemotedRules(); got == nil || len(got) != 0 {
		t.Fatalf("pre-calibration DemotedRules = %#v, want empty non-nil", got)
	}
	lr.SetDemotedRules(map[string]string{"read_only_overpowered": "test regression"})
	got := lr.DemotedRules()
	if got["read_only_overpowered"] != "test regression" {
		t.Fatalf("DemotedRules = %v", got)
	}
	got["injected"] = "mutation"
	if again := lr.DemotedRules(); len(again) != 1 {
		t.Errorf("accessor must return a copy; live set grew to %v", again)
	}
}

// TestRunRoutingCalibration_EndToEnd pins the job's persistence path:
// one pass writes calibration cells through the one-owner seam.
func TestRunRoutingCalibration_EndToEnd(t *testing.T) {
	lr, s, _ := liveRouterFixture(t, "enforce")
	cfg := config.Default()
	cfg.Routing.Calibration.AutoDemote = true
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := runRoutingCalibration(context.Background(), s, cfg, lr, logger); err != nil {
		t.Fatalf("runRoutingCalibration: %v", err)
	}
	n, err := s.CountModelCalibrations(context.Background())
	if err != nil || n == 0 {
		t.Fatalf("calibration cells = %d err=%v, want > 0", n, err)
	}
}

// TestWireRouting_RoutingEnabledGate is the W5 proof (plan
// docs/plans/org-observer-fundamentals-fix-plan-2026-09-13.md R4) that
// cmd/observer/proxy.go's wireRouting gate ("if !cfg.Routing.Enabled ...
// return nil, nil") reads whatever value ends up on cfg.Routing.Enabled —
// so a governance-pinned routing.enabled=true (proven to reach cfg in
// internal/config's TestGovernancePinnedRoutingEnabledYieldsARouter) is
// enough to get a router with NO change to this function.
func TestWireRouting_RoutingEnabledGate(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s := store.New(database)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	disabled := config.Default()
	disabled.Routing.Enabled = false
	if demotions, handle := wireRouting(ctx, disabled, s, &proxy.Options{}, logger, emit.Nop()); demotions != nil || handle != nil {
		t.Fatalf("Routing.Enabled=false yielded a router: demotions != nil = %v, handle = %+v", demotions != nil, handle)
	}

	enabled := config.Default()
	enabled.Routing.Enabled = true
	enabled.Routing.Mode = "advise"
	enabled.Routing.Policy = "value"
	if demotions, handle := wireRouting(ctx, enabled, s, &proxy.Options{}, logger, emit.Nop()); demotions == nil || handle == nil {
		t.Fatalf("Routing.Enabled=true (the shape a governance pin produces) did not yield a router: demotions != nil = %v, handle = %+v", demotions != nil, handle)
	}
}

// TestRoutingEffectiveModeManagedEnforce pins the Arc 4 P3b §R23 lift on the
// live router: the effective mode honors the org body's mode ONLY when the
// managed-enforce predicate is true (managed tenancy + enforce.routing), with
// no coercion — observe/off leaves routing advisory — and is exactly the
// node-local mode on every non-managed node.
func TestRoutingEffectiveModeManagedEnforce(t *testing.T) {
	cases := []struct {
		name      string
		localMode string
		orgMode   string
		managed   bool
		want      string
	}{
		{"no managed, no org", "advise", "", false, "advise"},
		{"managed enforce over local advise", "advise", "enforce", true, "enforce"},
		{"managed but predicate false", "advise", "enforce", false, "advise"},
		{"managed observe stays advisory", "advise", "observe", true, "advise"},
		{"managed empty org falls back local", "advise", "", true, "advise"},
		{"local enforce preserved when unmanaged", "enforce", "", false, "enforce"},
		{"managed org observe lowers local enforce", "enforce", "observe", true, "advise"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lr := &liveRouter{mode: tc.localMode, orgMode: tc.orgMode}
			lr.SetManagedEnforce(func() bool { return tc.managed })
			if got := lr.effectiveMode(); got != tc.want {
				t.Errorf("effectiveMode() = %q, want %q", got, tc.want)
			}
		})
	}

	// A router with no effMode ever stored falls back to the local mode.
	bare := &liveRouter{mode: "enforce"}
	if got := bare.effectiveMode(); got != "enforce" {
		t.Errorf("bare effectiveMode() = %q, want the local enforce", got)
	}
}
