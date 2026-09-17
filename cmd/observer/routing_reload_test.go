package main

// Tests for the P0-7 router hot-reload convergence path
// (docs/plans/plane-a-p0-7-guard-router-hotreload-plan.md §7.2 + §7.4).
// These exercise the REAL liveRouter.ReloadOrgPolicy production code
// path — no stubbing — through the same construction sequence
// cmd/observer/proxy.go::wireRouting uses: read cached org policy ->
// routingconfig.ComposeOrgPolicy -> routing.Compile -> refresher ->
// newLiveRouter -> lr.localSpec/lr.handle/handle.reload wiring.

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/routingconfig"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// reloadNoRuleBody is a valid, rule-free org routing body. Composed
// against a Policy:"custom" local spec (which itself carries zero
// local rules) it produces a policy with an EMPTY rule table, so
// routing.Decide always falls through to applyPipelineDefaults (a
// no-op here — no privacy/budget config is in play) and SelectedModel
// always equals the original model.
const reloadNoRuleBody = "[routing]\n"

// reloadRuleBody adds exactly ONE org-composed rule: downshift any
// read-only turn at sonnet-class or above to haiku-class. Because the
// local spec carries no rules of its own, this rule is the ONLY entry
// in the composed policy's rule table — any observed downshift after
// a reload is attributable solely to this org-pushed rule, never to
// local/template noise.
const reloadRuleBody = `[routing]
[[routing.rules]]
name = "org_v2_read_downshift"

  [routing.rules.when]
  turn_kind = "read_only"
  tier_at_least = "sonnet-class"

  [routing.rules.action]
  route_to_tier = "haiku-class"
  reason = "overpowered_read"
`

// reloadBadReasonBody is syntactically valid TOML that compiles
// without error but LINTS dirty: the action reason is not one of
// routing.KnownReasonCodes(), so lintKnownReason flags it LintError.
// This is the deterministic mechanism for proving ReloadOrgPolicy's
// fail-safe gate (routing.LintHasErrors) refuses to promote a bad
// composed policy.
const reloadBadReasonBody = `[routing]
[[routing.rules]]
name = "org_v2_bad_reason"

  [routing.rules.when]
  turn_kind = "read_only"
  tier_at_least = "sonnet-class"

  [routing.rules.action]
  route_to_tier = "haiku-class"
  reason = "not_a_real_reason_xyz"
`

// reloadFixture seeds a fresh store with a read-only claude-opus-4-8
// session (session id "live-1" — the same shape liveShape()/liveSess()
// in routing_live_test.go already classify as TurnReadOnly), then
// constructs a liveRouter through wireRouting's own sequence. The
// local spec is Policy:"custom" with zero rules, so the router starts
// with an inert rule table and any org-pushed rule is the sole actor.
func reloadFixture(t *testing.T, mode string, seedOrgVersion int64, seedOrgBody string) (*liveRouter, *store.Store) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s := store.New(database)

	now := time.Now().UTC()
	pid, _ := s.UpsertProject(ctx, "/tmp/router-reload", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "live-1", ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	if _, err := s.InsertActions(ctx, []models.Action{
		{
			SessionID: "live-1", ProjectID: pid, Timestamp: now.Add(-2 * time.Minute),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "re1",
		},
		{
			SessionID: "live-1", ProjectID: pid, Timestamp: now.Add(-1 * time.Minute),
			ActionType: models.ActionSearchText, Target: "func", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "re2",
		},
	}); err != nil {
		t.Fatalf("InsertActions: %v", err)
	}

	if seedOrgVersion > 0 {
		if err := s.UpsertOrgRoutingPolicy(ctx, store.OrgRoutingPolicyRow{
			Version: seedOrgVersion, Body: seedOrgBody, BodyHash: "test-hash",
			Signature: "test-sig", ServerPubkey: "test-pub", ReceivedAt: now,
		}); err != nil {
			t.Fatalf("UpsertOrgRoutingPolicy(seed): %v", err)
		}
	}

	localSpec := routing.PolicySpec{Policy: "custom", RespectCache: true}
	lr := constructReloadRouter(t, s, localSpec, mode)
	return lr, s
}

// constructReloadRouter mirrors cmd/observer/proxy.go::wireRouting's
// construction sequence exactly, so ReloadOrgPolicy is exercised
// through its real callers' setup, not a synthetic shortcut.
func constructReloadRouter(t *testing.T, s *store.Store, localSpec routing.PolicySpec, mode string) *liveRouter {
	t.Helper()
	ctx := context.Background()

	spec := localSpec
	var composedVersion int64
	if orgPol, ok, err := s.GetOrgRoutingPolicy(ctx); err != nil {
		t.Fatalf("GetOrgRoutingPolicy: %v", err)
	} else if ok {
		composed, cerr := routingconfig.ComposeOrgPolicy(spec, orgPol.Body)
		if cerr != nil {
			t.Fatalf("ComposeOrgPolicy(initial): %v", cerr)
		}
		spec = composed
		composedVersion = orgPol.Version
	}

	policy, issues := routing.Compile(spec)
	if routing.LintHasErrors(issues) {
		t.Fatalf("initial composed policy lints dirty: %+v", issues)
	}

	refresher := store.NewRoutingRefresher(s, policy, routing.NewTierResolver(), nil)
	if err := refresher.RefreshNow(ctx); err != nil {
		t.Fatalf("RefreshNow: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	lr := newLiveRouter(policy, mode, refresher, s, logger)
	lr.localSpec = localSpec

	handle := &RoutingStateHandle{}
	init := routingState{mode: mode}
	if composedVersion > 0 {
		init.version = composedVersion
		init.hash = policy.Hash()
	}
	handle.store(init)
	lr.handle = handle
	handle.reload = lr.ReloadOrgPolicy
	return lr
}

// TestRouterReloadOrgPolicy_SwapsPolicyAndHandle pins the swap half of
// §7.2: a v2 org policy body containing a rule the v1 body lacks
// becomes visible in BOTH the RoutingStateHandle (version/hash) and
// live Decide() output, with no daemon restart.
//
// Mutation-ready: commenting out lr.policy.Store(&policy) inside
// ReloadOrgPolicy leaves Decide operating on the v1 (empty-rule)
// policy forever — the post-reload SelectedModel assertion below
// would then observe "claude-opus-4-8" (no downshift) instead of
// "claude-haiku-4-5", failing the test.
func TestRouterReloadOrgPolicy_SwapsPolicyAndHandle(t *testing.T) {
	lr, s := reloadFixture(t, "advise", 1, reloadNoRuleBody)
	ctx := context.Background()

	v1Version := lr.handle.RunningVersion()
	v1Hash := lr.handle.EffectiveHash()
	if v1Version != 1 {
		t.Fatalf("initial RunningVersion = %d, want 1", v1Version)
	}
	if v1Hash == "" {
		t.Fatal("initial EffectiveHash is empty")
	}

	// v1: no rule exists anywhere in the composed policy, so the
	// read-only turn passes through unchanged.
	pre := lr.Decide(liveShape(), liveSess())
	if pre.SelectedModel != "claude-opus-4-8" {
		t.Fatalf("pre-reload verdict = %+v, want the original model unchanged", pre)
	}

	if err := s.UpsertOrgRoutingPolicy(ctx, store.OrgRoutingPolicyRow{
		Version: 2, Body: reloadRuleBody, BodyHash: "test-hash-2",
		Signature: "test-sig-2", ServerPubkey: "test-pub", ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertOrgRoutingPolicy(v2): %v", err)
	}

	if err := lr.ReloadOrgPolicy(ctx); err != nil {
		t.Fatalf("ReloadOrgPolicy(v2): %v", err)
	}

	if got := lr.handle.RunningVersion(); got != 2 {
		t.Fatalf("post-reload RunningVersion = %d, want 2", got)
	}
	if got := lr.handle.EffectiveHash(); got == v1Hash || got == "" {
		t.Fatalf("post-reload EffectiveHash = %q, want a new non-empty hash (was %q)", got, v1Hash)
	}
	if got := lr.handle.Mode(); got != "advise" {
		t.Fatalf("post-reload Mode = %q, want advise", got)
	}

	// v2: the org-pushed rule is now the sole entry in the composed
	// policy's rule table and must fire.
	post := lr.Decide(liveShape(), liveSess())
	if post.SelectedModel != "claude-haiku-4-5" {
		t.Fatalf("post-reload verdict = %+v, want the v2-only downshift", post)
	}
}

// TestRouterReloadOrgPolicy_CompileFailureIsNoOp pins the fail-safe
// half of §7.2: a v2 body that COMPILES but LINTS dirty (an unknown
// reason code) must be refused — ReloadOrgPolicy returns an error and
// the running policy/handle/Decide output stay pinned to v1.
//
// Mutation-ready: removing the `if routing.LintHasErrors(issues) { ...
// return err }` gate inside ReloadOrgPolicy lets the bad v2 policy
// promote anyway (Compile never itself errors) — RunningVersion would
// then read 2 instead of the asserted 1, failing the test.
func TestRouterReloadOrgPolicy_CompileFailureIsNoOp(t *testing.T) {
	lr, s := reloadFixture(t, "advise", 1, reloadNoRuleBody)
	ctx := context.Background()

	v1Version := lr.handle.RunningVersion()
	v1Hash := lr.handle.EffectiveHash()
	v1PolicyHash := lr.policy.Load().Hash()

	if err := s.UpsertOrgRoutingPolicy(ctx, store.OrgRoutingPolicyRow{
		Version: 2, Body: reloadBadReasonBody, BodyHash: "test-hash-bad",
		Signature: "test-sig-bad", ServerPubkey: "test-pub", ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertOrgRoutingPolicy(v2 bad): %v", err)
	}

	if err := lr.ReloadOrgPolicy(ctx); err == nil {
		t.Fatal("ReloadOrgPolicy(v2 with an unknown reason code) = nil error, want a lint refusal")
	}

	if got := lr.handle.RunningVersion(); got != v1Version {
		t.Fatalf("RunningVersion after refused reload = %d, want unchanged %d", got, v1Version)
	}
	if got := lr.handle.EffectiveHash(); got != v1Hash {
		t.Fatalf("EffectiveHash after refused reload = %q, want unchanged %q", got, v1Hash)
	}
	if got := lr.policy.Load().Hash(); got != v1PolicyHash {
		t.Fatalf("running policy hash after refused reload = %q, want unchanged %q", got, v1PolicyHash)
	}

	// Decide output must also still reflect v1 (no rule anywhere).
	post := lr.Decide(liveShape(), liveSess())
	if post.SelectedModel != "claude-opus-4-8" {
		t.Fatalf("post-refused-reload verdict = %+v, want v1's unchanged model", post)
	}
}

// TestRouterReloadOrgPolicy_ConcurrentWithDecide pins the race-safety
// half of §7.2: readers hammering Decide (plus the RoutingStateHandle
// accessors and the refresher snapshot) concurrently with writers
// hammering ReloadOrgPolicy (alternating between the rule-free and
// rule-bearing bodies on strictly increasing versions) must produce
// no data race, and RunningVersion observed during the storm must be
// monotonically non-decreasing (P0-7 BLOCKER 3 — reloadMu +
// non-regression). Once every writer has stopped a final,
// deterministic reload converges Decide to that exact final state.
//
// Stale-reload refusals (composed version < running) are EXPECTED under
// a writer storm and are not failures — the non-regression gate is
// doing its job.
//
// Run with -race (go test -race), as required by §7.2.
func TestRouterReloadOrgPolicy_ConcurrentWithDecide(t *testing.T) {
	lr, s := reloadFixture(t, "advise", 1, reloadNoRuleBody)
	ctx := context.Background()

	var stop atomic.Bool
	var readerWG sync.WaitGroup
	for i := 0; i < 8; i++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			// Per-reader last-seen: a GLOBAL maxSeen is a false positive
			// under concurrency (reader B can load v12, then compare
			// after reader A already advanced maxSeen to 13). A true
			// publish regression shows up as one reader's successive
			// Snapshot loads going backwards.
			var last int64
			for !stop.Load() {
				_ = lr.Decide(liveShape(), liveSess())
				v, _, _, _ := lr.handle.Snapshot()
				if v < last {
					t.Errorf("RunningVersion regresssed for a single reader: observed %d < prior %d", v, last)
					return
				}
				last = v
				_ = lr.refresher.Current()
			}
		}()
	}

	var version atomic.Int64
	version.Store(1)
	var writerWG sync.WaitGroup
	for w := 0; w < 4; w++ {
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			for j := 0; j < 25; j++ {
				v := version.Add(1)
				body := reloadNoRuleBody
				if v%2 == 0 {
					body = reloadRuleBody
				}
				if err := s.UpsertOrgRoutingPolicy(ctx, store.OrgRoutingPolicyRow{
					Version: v, Body: body, BodyHash: "test-hash",
					Signature: "test-sig", ServerPubkey: "test-pub", ReceivedAt: time.Now().UTC(),
				}); err != nil {
					t.Errorf("UpsertOrgRoutingPolicy(v%d): %v", v, err)
					return
				}
				// A non-regressing refusal is expected when another
				// writer already published a newer version between our
				// Upsert and Reload; treat only unexpected errors as
				// failures.
				if err := lr.ReloadOrgPolicy(ctx); err != nil && !strings.Contains(err.Error(), "non-regressing") {
					t.Errorf("ReloadOrgPolicy(v%d): %v", v, err)
					return
				}
			}
		}()
	}

	writerWG.Wait()
	stop.Store(true)
	readerWG.Wait()

	// Deterministic final reload: push one more, strictly-increasing,
	// KNOWN-content version and confirm convergence — the hammering
	// phase above only proves the absence of a data race + monotonic
	// publish; this final step pins the answer.
	finalVersion := version.Add(1)
	if err := s.UpsertOrgRoutingPolicy(ctx, store.OrgRoutingPolicyRow{
		Version: finalVersion, Body: reloadRuleBody, BodyHash: "test-hash-final",
		Signature: "test-sig-final", ServerPubkey: "test-pub", ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertOrgRoutingPolicy(final): %v", err)
	}
	if err := lr.ReloadOrgPolicy(ctx); err != nil {
		t.Fatalf("ReloadOrgPolicy(final): %v", err)
	}

	if got := lr.handle.RunningVersion(); got != finalVersion {
		t.Fatalf("final RunningVersion = %d, want %d", got, finalVersion)
	}
	final := lr.Decide(liveShape(), liveSess())
	if final.SelectedModel != "claude-haiku-4-5" {
		t.Fatalf("final verdict = %+v, want the rule-bearing final body's downshift", final)
	}
}

// TestRouterReloadOrgPolicy_AbsentCacheDoesNotRegressToV0 pins the
// codex re-gate B3 fold: with an org version already running, a reload
// whose cache is ABSENT (composedOrgVersion=0, local-only) must REFUSE
// rather than publish version 0 over the running org version. Mutation-
// ready: restoring the `composedOrgVersion > 0 &&` guard on the
// non-regression check lets this reload succeed and leave
// RunningVersion=0.
func TestRouterReloadOrgPolicy_AbsentCacheDoesNotRegressToV0(t *testing.T) {
	lr, s := reloadFixture(t, "advise", 1, reloadRuleBody)
	ctx := context.Background()

	if got := lr.handle.RunningVersion(); got != 1 {
		t.Fatalf("precondition RunningVersion = %d, want 1", got)
	}
	v1Hash := lr.handle.EffectiveHash()
	if v1Hash == "" {
		t.Fatal("precondition EffectiveHash empty")
	}

	// Clear the org routing-policy cache the same way unenrolment does
	// (DELETE FROM org_routing_policies) — GetOrgRoutingPolicy then
	// returns ok=false → composedOrgVersion=0.
	if err := s.DeleteEnrolment(ctx); err != nil {
		t.Fatalf("DeleteEnrolment (clear routing cache): %v", err)
	}
	if _, ok, err := s.GetOrgRoutingPolicy(ctx); err != nil || ok {
		t.Fatalf("cache still present after clear: ok=%v err=%v", ok, err)
	}

	err := lr.ReloadOrgPolicy(ctx)
	if err == nil {
		t.Fatal("ReloadOrgPolicy(absent cache over running v1) = nil, want non-regressing refusal")
	}
	if !strings.Contains(err.Error(), "non-regressing") {
		t.Fatalf("ReloadOrgPolicy error = %v, want non-regressing refusal", err)
	}
	if got := lr.handle.RunningVersion(); got != 1 {
		t.Fatalf("post-refusal RunningVersion = %d, want 1 (v0 must not publish)", got)
	}
	if got := lr.handle.EffectiveHash(); got != v1Hash {
		t.Fatalf("post-refusal EffectiveHash = %q, want unchanged %q", got, v1Hash)
	}
	// The v1 rule must still be live.
	post := lr.Decide(liveShape(), liveSess())
	if post.SelectedModel != "claude-haiku-4-5" {
		t.Fatalf("post-refusal verdict = %+v, want v1 rule still live", post)
	}
}
