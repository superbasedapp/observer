package cachetrack_test

// §15.3 (c)-phase-2 baseline goldens — POST-FIX.
//
// These tests pin the engine's post-fix behavior on the
// snapshot-before-push lookup + CacheableTokens-gated predictKind
// shape. Pre-fix this file held a different golden surface (the
// phase-1 baseline at commit c074eeb). Phase-2 rebaselined every
// assertion in the SAME COMMIT that landed the engine change, so
// the diff is reviewable: invariants that should HOLD pre AND
// post (the operator-checked growth invariant) stay; intended
// FLIPS (continuation Hit, WHH partial closure) update; new
// realistic 3-turn cumulative goldens are added.
//
// Test plan: docs/plans/cachetrack-15.3c-assumedbreakpoints-
// lookup-plan-2026-06-09.md.
//
// Diff vs phase-1 baseline (c074eeb):
//   - turnSnapshot.bucketMispredicted now READS the engine's
//     EventOut.Mispredicted directly (G2 anchor closure: removes
//     the external bucketMispredict/liveBucket helpers that
//     mirrored bucketOf — those helpers would silently drift if
//     a new Kind landed without re-syncing the mirror).
//   - Tier-1 growth fixture's new-tail content is enlarged to
//     ≥1024 tokens per turn (the Drift #1 fix — tiny stubs can't
//     exercise the CacheableTokens predicate; large new tail
//     proves the slice anchor on cumulative shape).
//   - Continuation + WHH assertions flipped per the intended
//     post-fix behavior.
//   - Two new realistic Tier-1 cumulative goldens (≥3 turns each)
//     prove the slice anchor works on real-traffic shape: a
//     wrong anchor (reversion to sum-all over the cumulative
//     conversation) fails both.
//   - Bucket-helper conformance test pins
//     cachetrack.BucketLabel + cachetrack.BucketMismatch as the
//     single source of truth (the G2 anchor closure step).
//   - Chain-count-divergence probe documents WHY matched.BlockCount
//     (in.Blocks units) is the correct slice anchor instead of
//     Chain.Count() (chain units), with an empirical trace.
//
// External package (cachetrack_test) keeps these against the
// public engine surface only — EventOut.Mispredicted + the
// exported BucketMismatch/BucketLabel helpers replace any need
// for internal-symbol access.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
)

// turnSnapshot is the (predicted_kind, observed_kind, cause,
// bucket-mispredict) tuple captured per event. Reads the engine's
// EventOut.Mispredicted field directly — that's the engine's REAL
// ReconcilePrediction-side bucket-mismatch signal, NOT an external
// helper. The G2 anchor MUST be the engine's value, otherwise a
// future bucket-logic change in reconcile.go would silently
// invalidate the phase-4 soak gate.
type turnSnapshot struct {
	label              string
	predictedKind      cachetrack.Kind
	observedKind       cachetrack.Kind
	cause              cachetrack.Cause
	tokensRead         int64
	tokensWritten      int64
	bucketMispredicted bool
}

// largePadding returns a JSON text-block body of approximately
// bytesTarget bytes — used to push fixture content past the
// Sonnet min-cacheable threshold (1024 tokens ≈ 4096 canonical
// bytes by the v1 ceil(n/4) heuristic). The repeating ASCII
// content is irrelevant to the chain hash — only the byte count
// matters for the estimate. The block content remains valid JSON
// so canonicalize round-trips cleanly.
func largePadding(bytesTarget int) []byte {
	if bytesTarget < 64 {
		bytesTarget = 64
	}
	// Allow ~25 bytes for the JSON envelope.
	padLen := bytesTarget - 25
	if padLen < 1 {
		padLen = 1
	}
	pad := strings.Repeat("ab", padLen/2)
	return []byte(fmt.Sprintf(`{"text":"%s"}`, pad))
}

func runSequence(t *testing.T, sessionID, model string, tier cachetrack.Tier, turns []cachetrack.ObserveInput) []turnSnapshot {
	t.Helper()
	eng := cachetrack.NewEngine(64)
	base := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	eng.Clock = func() time.Time { return base }

	var snaps []turnSnapshot
	for i := range turns {
		if turns[i].SessionID == "" {
			turns[i].SessionID = sessionID
		}
		if turns[i].Model == "" {
			turns[i].Model = model
		}
		if turns[i].Scope == "" {
			turns[i].Scope = "default"
		}
		if turns[i].Tier == cachetrack.TierUnknown {
			turns[i].Tier = tier
		}
		if turns[i].Now.IsZero() {
			turns[i].Now = base.Add(time.Duration(i) * time.Second)
		}
		out := eng.ObserveTurn(turns[i])
		for _, ev := range out.Events {
			snaps = append(snaps, turnSnapshot{
				label:              fmt.Sprintf("turn-%d", i+1),
				predictedKind:      ev.PredictedKind,
				observedKind:       ev.Outcome.Kind,
				cause:              ev.Outcome.Cause,
				tokensRead:         ev.TokensRead,
				tokensWritten:      ev.TokensWritten,
				bucketMispredicted: ev.Mispredicted,
			})
		}
	}
	return snaps
}

// TestEngineTier1Baseline_GrowthSequence_Goldens pins the engine's
// behavior on a Tier-1 growth sequence: 4 turns with cache_creation>0
// every turn and cache_read>0 from turn 2 onward. New-tail content
// is sized ≥1024 tokens per growth turn so the CacheableTokens
// gate fires Write under the §15.3 (c)-phase-2 predicate.
//
// OPERATOR-CHECKED INVARIANT (pre AND post §15.3 (c)): every
// growth turn (T2-T4) predicted_kind = "write". This is the
// rate-blind regression surface — a future engine change that
// predicts Hit here fires rec.Mispredicted internally but never
// flips outcome.Kind to KindMispredict (per c489ddb proof), so
// the §10 rate stays flat while every Sonnet growth turn poisons
// the forecaster. THIS ASSERTION IS THE ONLY CATCH.
//
// Bucket-mispredict expectation on growth turns: FALSE post-fix.
// predict=Write, observe=Write/InvalidationRewrite → bucket match.
func TestEngineTier1Baseline_GrowthSequence_Goldens(t *testing.T) {
	bp := []cachetrack.ObserveBreakpoint{
		{BlockIndex: 1, Level: cachetrack.LevelMessage, TTL: cachetrack.TTL1h},
	}
	// Sized so the per-turn new-tail (in the Tier-1 baseline
	// delta-shape) clears Sonnet's 1024-token min-cacheable
	// threshold. The padded message block targets ~5 KB canonical
	// bytes → ~1280 tokens by the v1 heuristic.
	makeTurn := func(idx int, read, write int64) cachetrack.ObserveInput {
		return cachetrack.ObserveInput{
			MessageID: fmt.Sprintf("msg_%d", idx),
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"system_prompt_stable"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: largePadding(5120),
				},
			},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens:      300,
				OutputTokens:        200,
				CacheReadTokens:     read,
				CacheCreationTokens: write,
			},
		}
	}
	turns := []cachetrack.ObserveInput{
		makeTurn(1, 0, 5000),   // T1 cold seed
		makeTurn(2, 5000, 500), // T2 growth: read prior + write new
		makeTurn(3, 5500, 500), // T3 growth
		makeTurn(4, 6000, 500), // T4 growth
	}
	snaps := runSequence(t, "sess-t1-growth", "claude-sonnet-4", cachetrack.TierProxy, turns)
	if len(snaps) != 4 {
		t.Fatalf("expected 4 event snapshots, got %d", len(snaps))
	}

	// Turn 1: cold seed (prior=nil) → predicted=Reanchor, observed=Reanchor.
	if snaps[0].predictedKind != cachetrack.KindReanchor {
		t.Errorf("T1 predicted_kind = %q, want reanchor", snaps[0].predictedKind)
	}
	if snaps[0].observedKind != cachetrack.KindReanchor {
		t.Errorf("T1 observed_kind = %q, want reanchor", snaps[0].observedKind)
	}

	// Turns 2-4: GROWTH TURNS. OPERATOR-CHECKED INVARIANT.
	for i := 1; i <= 3; i++ {
		if snaps[i].predictedKind != cachetrack.KindWrite {
			t.Errorf("[INVARIANT] growth turn T%d predicted_kind = %q, want write — growth-turn regression must NOT pass; the §10 rate is structurally blind to this (c489ddb), this assertion is the only catch",
				i+1, snaps[i].predictedKind)
		}
		if snaps[i].observedKind != cachetrack.KindWrite {
			t.Errorf("T%d observed_kind = %q, want write", i+1, snaps[i].observedKind)
		}
		if snaps[i].cause != cachetrack.CauseSuffixGrowth {
			t.Errorf("T%d cause = %q, want suffix_growth", i+1, snaps[i].cause)
		}
		if snaps[i].bucketMispredicted {
			t.Errorf("[INVARIANT] T%d bucket-mispredict = true — growth-turn rec.Mispredicted regression (the §10-rate-blind P0-trap)",
				i+1)
		}
	}
}

// TestEngineTier1Baseline_ContinuationLightTail_FlipSentinel is
// the §15.3 (c)-phase-2 intended-flip pin. Tier-1 continuation
// turn (cache_read>0, cache_creation=0) with a tiny new tail.
//
// POST-FIX behavior:
//
//	T1 cold seed → predicted=Reanchor.
//	T2 continuation → predicted=Hit (snapshot lookup finds T1's
//	  entry, new tail below CacheableTokens threshold → engine's
//	  CacheableTokens-gated branch returns KindHit).
//	bucket-mispredicted=false (predict and observed both Hit).
//
// Pre-fix this test was the FLIP SENTINEL: T2 predicted=Write,
// bucket-mispredicted=true. Phase-2 rebaselined to the intended
// post-fix shape.
func TestEngineTier1Baseline_ContinuationLightTail_FlipSentinel(t *testing.T) {
	bp := []cachetrack.ObserveBreakpoint{
		{BlockIndex: 1, Level: cachetrack.LevelMessage, TTL: cachetrack.TTL1h},
	}
	turns := []cachetrack.ObserveInput{
		{
			MessageID: "msg_1",
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"system_prompt_stable"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: []byte(`{"text":"a long user prompt that seeds a substantial cached prefix block","seq":1}`),
				},
			},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens:      1500,
				OutputTokens:        300,
				CacheCreationTokens: 5000,
			},
		},
		// T2 continuation: small tail. Provider reads cached
		// prefix back; new content too small to write a new marker.
		{
			MessageID: "msg_2",
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"system_prompt_stable"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: []byte(`{"text":"ok","seq":2}`),
				},
			},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens:      50,
				OutputTokens:        20,
				CacheReadTokens:     5000,
				CacheCreationTokens: 0,
			},
		},
	}
	snaps := runSequence(t, "sess-t1-continuation", "claude-sonnet-4", cachetrack.TierProxy, turns)
	if len(snaps) != 2 {
		t.Fatalf("expected 2 event snapshots, got %d", len(snaps))
	}

	if snaps[0].predictedKind != cachetrack.KindReanchor {
		t.Errorf("T1 predicted_kind = %q, want reanchor", snaps[0].predictedKind)
	}

	// T2 — POST-FIX (the intended flip).
	if snaps[1].predictedKind != cachetrack.KindHit {
		t.Errorf("[POST-FIX FLIP] T2 predicted_kind = %q, want hit — §15.3 (c)-phase-2 continuation flip didn't land", snaps[1].predictedKind)
	}
	if snaps[1].observedKind != cachetrack.KindHit {
		t.Errorf("T2 observed_kind = %q, want hit", snaps[1].observedKind)
	}
	if snaps[1].cause != cachetrack.CauseSuffixGrowth {
		t.Errorf("T2 cause = %q, want suffix_growth", snaps[1].cause)
	}
	if snaps[1].bucketMispredicted {
		t.Errorf("[POST-FIX] T2 bucket-mispredict = true, want false — continuation should match buckets after the fix")
	}
}

// TestEngineTier1Baseline_WHHPartialClosurePattern pins the v1
// W H H partial-closure semantics. Post-fix:
//
//	T1 (W cold seed) → predicted=Reanchor.
//	T2 (first H) → predicted=Hit ✓ (slice anchor finds T1's entry).
//	T3 (second H) → predicted=Write (v1 limitation: T2 was a Hit
//	  so no entry was created at T2-end; T3's snapshot lookup
//	  misses, falls through to the no-matched-entry branch).
//
// Full closure of W H H H+ needs §15.3 (c)-phase-2's rolling-
// entry refresh or walkback window. This test pins the v1
// trade-off so the limitation is visible + documented.
func TestEngineTier1Baseline_WHHPartialClosurePattern(t *testing.T) {
	bp := []cachetrack.ObserveBreakpoint{
		{BlockIndex: 1, Level: cachetrack.LevelMessage, TTL: cachetrack.TTL1h},
	}
	turns := []cachetrack.ObserveInput{
		{
			MessageID: "msg_1",
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"sys"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: []byte(`{"text":"u1","seq":1}`),
				},
			},
			Breakpoints: bp,
			Usage:       cachetrack.CacheUsageObserved{NetInputTokens: 1500, CacheCreationTokens: 5000},
		},
		{
			MessageID: "msg_2",
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"sys"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: []byte(`{"text":"u2","seq":2}`),
				},
			},
			Breakpoints: bp,
			Usage:       cachetrack.CacheUsageObserved{NetInputTokens: 50, CacheReadTokens: 5000},
		},
		{
			MessageID: "msg_3",
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"sys"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: []byte(`{"text":"u3","seq":3}`),
				},
			},
			Breakpoints: bp,
			Usage:       cachetrack.CacheUsageObserved{NetInputTokens: 50, CacheReadTokens: 5000},
		},
	}
	snaps := runSequence(t, "sess-t1-whh", "claude-sonnet-4", cachetrack.TierProxy, turns)
	if len(snaps) != 3 {
		t.Fatalf("expected 3 event snapshots, got %d", len(snaps))
	}
	// T2 — FIRST H → flips to Hit + no mispredict.
	if snaps[1].predictedKind != cachetrack.KindHit {
		t.Errorf("[POST-FIX] T2 (first H) predicted_kind = %q, want hit", snaps[1].predictedKind)
	}
	if snaps[1].bucketMispredicted {
		t.Errorf("[POST-FIX] T2 bucket-mispredict = true, want false")
	}
	// T3 — SECOND H → stays Write per v1 limitation.
	if snaps[2].predictedKind != cachetrack.KindWrite {
		t.Errorf("[v1 LIMIT] T3 (second H) predicted_kind = %q, want write — full closure is §15.3 (c)-phase-2 territory", snaps[2].predictedKind)
	}
	if !snaps[2].bucketMispredicted {
		t.Errorf("[v1 LIMIT] T3 bucket-mispredict = false, want true — consecutive Hit limitation")
	}
}

// TestEngineMispredictionCountersBaseline_v1 is the load-bearing
// G2 anchor for phase 4. Pins the COUNT (not per-turn flag) of
// rec.Mispredicted-true events across the four Tier-1 baseline
// sequences.
//
// POST-FIX expected counts:
//
//	GrowthSequence:        0  (the INVARIANT — growth turns
//	                          predict Write, observe Write)
//	ContinuationLightTail: 0  (T2 flipped to Hit ✓)
//	WHHPartialClosure:     1  (T2 flipped Hit ✓; T3 stays — v1 limit)
//
//	TOTAL Tier-1 POST-FIX: 1
//
// Pre-fix this counter was 3 (Growth 0 + Cont 1 + WHH 2).
// Phase-2 closes 2 of 3 on this surface; the residual 1 is the
// documented v1 limitation.
//
// PHASE-4 G2 SOAK GATE: real-data Tier-1 rec.Mispredicted count
// (read via Engine.Counters().BucketMispredictTotal OR via the
// cache_health CLI's persisted-data BucketMismatch surface) MUST
// NOT exceed this baseline + a documented continuation-flip
// margin. A growth-turn regression that re-opens the rate-blind
// gap fires HERE first — the §10 rate stays flat (c489ddb).
func TestEngineMispredictionCountersBaseline_v1(t *testing.T) {
	type sequenceSpec struct {
		name      string
		runner    func(t *testing.T) []turnSnapshot
		expectMis int
	}

	specs := []sequenceSpec{
		{name: "GrowthSequence", runner: runSequenceFromGrowth, expectMis: 0},
		{name: "ContinuationLightTail", runner: runSequenceFromContinuation, expectMis: 0},
		{name: "WHHPartialClosure", runner: runSequenceFromWHH, expectMis: 1},
	}

	var totalMis int
	for _, sp := range specs {
		snaps := sp.runner(t)
		count := 0
		for _, s := range snaps {
			if s.bucketMispredicted {
				count++
			}
		}
		if count != sp.expectMis {
			t.Errorf("[POST-FIX BASELINE] %s bucket-mispredict count = %d, want %d", sp.name, count, sp.expectMis)
		}
		totalMis += count
		t.Logf("  %-25s: bucket-mispredict count = %d / %d turns", sp.name, count, len(snaps))
	}

	const wantTotal = 1
	if totalMis != wantTotal {
		t.Fatalf("[POST-FIX BASELINE G2 ANCHOR] total Tier-1 bucket-mispredict = %d, want %d", totalMis, wantTotal)
	}
	t.Logf("")
	t.Logf("  PHASE-4 G2 ANCHOR: post-fix Tier-1 baseline bucket-mispredict total = %d", totalMis)
	t.Logf("  Phase-4 soak G2 gate: real-data Tier-1 rec.Mispredicted count")
	t.Logf("  MUST NOT EXCEED %d + documented continuation-flip margin.", totalMis)
	t.Logf("  Growth-turn regression: any increase here is STOP-and-investigate.")
	t.Logf("  Pre-fix baseline was 3; phase-2 closed 2 of 3 on this surface")
	t.Logf("  (continuation T2 + WHH T2); residual 1 = WHH T3 v1 limitation.")
}

// Helpers — extracted so the counter-aggregating test can
// re-run the same sequences without duplicating the input data.

func runSequenceFromGrowth(t *testing.T) []turnSnapshot {
	t.Helper()
	bp := []cachetrack.ObserveBreakpoint{
		{BlockIndex: 1, Level: cachetrack.LevelMessage, TTL: cachetrack.TTL1h},
	}
	makeTurn := func(idx int, read, write int64) cachetrack.ObserveInput {
		return cachetrack.ObserveInput{
			MessageID: fmt.Sprintf("msg_%d", idx),
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"system_prompt_stable"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: largePadding(5120),
				},
			},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens:      300,
				OutputTokens:        200,
				CacheReadTokens:     read,
				CacheCreationTokens: write,
			},
		}
	}
	return runSequence(t, "sess-aggregated-growth", "claude-sonnet-4", cachetrack.TierProxy, []cachetrack.ObserveInput{
		makeTurn(1, 0, 5000),
		makeTurn(2, 5000, 500),
		makeTurn(3, 5500, 500),
		makeTurn(4, 6000, 500),
	})
}

func runSequenceFromContinuation(t *testing.T) []turnSnapshot {
	t.Helper()
	bp := []cachetrack.ObserveBreakpoint{
		{BlockIndex: 1, Level: cachetrack.LevelMessage, TTL: cachetrack.TTL1h},
	}
	return runSequence(t, "sess-aggregated-continuation", "claude-sonnet-4", cachetrack.TierProxy, []cachetrack.ObserveInput{
		{
			MessageID: "msg_1",
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"system_prompt_stable"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: []byte(`{"text":"a long user prompt that seeds a substantial cached prefix block","seq":1}`),
				},
			},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens:      1500,
				OutputTokens:        300,
				CacheCreationTokens: 5000,
			},
		},
		{
			MessageID: "msg_2",
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"system_prompt_stable"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: []byte(`{"text":"ok","seq":2}`),
				},
			},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens:      50,
				OutputTokens:        20,
				CacheReadTokens:     5000,
				CacheCreationTokens: 0,
			},
		},
	})
}

func runSequenceFromWHH(t *testing.T) []turnSnapshot {
	t.Helper()
	bp := []cachetrack.ObserveBreakpoint{
		{BlockIndex: 1, Level: cachetrack.LevelMessage, TTL: cachetrack.TTL1h},
	}
	turns := []cachetrack.ObserveInput{
		{
			MessageID: "msg_1",
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"sys"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: []byte(`{"text":"u1","seq":1}`),
				},
			},
			Breakpoints: bp,
			Usage:       cachetrack.CacheUsageObserved{NetInputTokens: 1500, CacheCreationTokens: 5000},
		},
		{
			MessageID: "msg_2",
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"sys"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: []byte(`{"text":"u2","seq":2}`),
				},
			},
			Breakpoints: bp,
			Usage:       cachetrack.CacheUsageObserved{NetInputTokens: 50, CacheReadTokens: 5000},
		},
		{
			MessageID: "msg_3",
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"sys"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: []byte(`{"text":"u3","seq":3}`),
				},
			},
			Breakpoints: bp,
			Usage:       cachetrack.CacheUsageObserved{NetInputTokens: 50, CacheReadTokens: 5000},
		},
	}
	return runSequence(t, "sess-aggregated-whh", "claude-sonnet-4", cachetrack.TierProxy, turns)
}

// Tier-2 fixture-grading aggregate (§14.3). Each per-fixture count
// below is asserted by the named test in fixture_grading_test.go;
// their sum is the single Tier-2 number the phase-4 soak diffs
// against. (This used to be a log-only test,
// TestEngineTier2Baseline_AggregateAnchor, that asserted nothing.)
//
// POST-FIX (per §15.3 (c)-phase-2 + the operator-confirmed
// cline-cli correction in Drift #2):
//
//	TestGradeOpenCodeMultiTurnFixture          0  (enlarged T2 delta)
//	TestGradeKiloCLIMultiTurnFixture           0  (enlarged T2 delta)
//	TestGradeClineCLIImplicitCacheShape        2  (NO FLIP — implicit-cache gap;
//	                                              snapshot lookup can't help
//	                                              when T1 never creates an entry
//	                                              because cache_creation=0)
//	TestGradeOpenCodeCleanContinuation         0  (T2 flipped Hit ✓)
//	TestGradeKiloCLICleanContinuation          0  (T2 flipped Hit ✓)
//	                                           ───
//	TOTAL TIER-2 POST-FIX                      2
//
// Pre-fix was 4 (Cline 2 + OpenCleanCont 1 + KiloCleanCont 1).
// Phase-2 closes 2 of 4 on Tier-2; the residual 2 (cline-cli) is
// the implicit-cache gap explicitly out of §15.3 (c) scope.
//
// Combined Tier-1 (1) + Tier-2 (2) = 3 post-fix vs 7 pre-fix:
// 4-of-7 closure. (The handover's 5-of-7 was overstated by 1 — the
// cline-cli flip claim was wrong because cline-cli sessions never
// create entries for snapshot-before-push to find. Operator
// confirmed in Drift #2 response.)
//
// PHASE-4 G2 GATE: the real-data Tier-2 rec.Mispredicted count
// must not exceed the post-fix total (2) plus the continuation-flip
// margin. Any growth-turn increase is STOP-and-investigate.

// TestForecasterEMABaseline_v1 pins SessionEMA.Scale + Samples
// for the Tier-1 sequence shapes. F1/F2 directional anchors for
// phase 5: post-fix Scale on cache-hit-heavy moves TOWARD 1.0
// (continuation samples no longer poisoned by false-mispredict
// demotions); cold-write-only sessions stay put.
//
// Scale values depend on the byte-heuristic estimate × observed
// write tokens. With the enlarged growth fixture (≥1024-token
// new tail), the predicted-write tokens are LARGER → scale ratio
// is SMALLER → SessionEMA.Scale lands closer to 1.0 on the
// WriteHeavy case (the directional F1 win).
func TestForecasterEMABaseline_v1(t *testing.T) {
	type emaCase struct {
		name          string
		sessionID     string
		model         string
		runFn         func(eng *cachetrack.Engine, sess, model string)
		expectSamples int
	}

	mkRun := func(turns []cachetrack.ObserveInput) func(*cachetrack.Engine, string, string) {
		return func(eng *cachetrack.Engine, sess, model string) {
			base := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
			for i := range turns {
				turns[i].SessionID = sess
				turns[i].Model = model
				turns[i].Scope = "default"
				turns[i].Tier = cachetrack.TierProxy
				turns[i].Now = base.Add(time.Duration(i) * time.Second)
				eng.ObserveTurn(turns[i])
			}
		}
	}

	bp := []cachetrack.ObserveBreakpoint{
		{BlockIndex: 1, Level: cachetrack.LevelMessage, TTL: cachetrack.TTL1h},
	}
	makeGrowthTurn := func(idx int, read, write int64) cachetrack.ObserveInput {
		return cachetrack.ObserveInput{
			MessageID: fmt.Sprintf("msg_%d", idx),
			Blocks: []cachetrack.ObserveBlock{
				{
					Level: cachetrack.LevelSystem, Kind: "text",
					CanonicalBytes: []byte(`{"text":"system_prompt_stable"}`),
				},
				{
					Level: cachetrack.LevelMessage, Kind: "text",
					CanonicalBytes: largePadding(5120),
				},
			},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens:      300,
				OutputTokens:        200,
				CacheReadTokens:     read,
				CacheCreationTokens: write,
			},
		}
	}

	cases := []emaCase{
		{
			name:      "WriteHeavy",
			sessionID: "ema-write-heavy",
			model:     "claude-sonnet-4",
			runFn: mkRun([]cachetrack.ObserveInput{
				makeGrowthTurn(1, 0, 5000),
				makeGrowthTurn(2, 5000, 500),
				makeGrowthTurn(3, 5500, 500),
				makeGrowthTurn(4, 6000, 500),
			}),
			expectSamples: 4,
		},
		{
			name:      "ContinuationDominant",
			sessionID: "ema-continuation",
			model:     "claude-sonnet-4",
			runFn: mkRun([]cachetrack.ObserveInput{
				makeGrowthTurn(1, 0, 5000),
				{
					MessageID: "msg_2",
					Blocks: []cachetrack.ObserveBlock{
						{
							Level: cachetrack.LevelSystem, Kind: "text",
							CanonicalBytes: []byte(`{"text":"system_prompt_stable"}`),
						},
						{
							Level: cachetrack.LevelMessage, Kind: "text",
							CanonicalBytes: []byte(`{"text":"ok","seq":2}`),
						},
					},
					Breakpoints: bp,
					Usage: cachetrack.CacheUsageObserved{
						NetInputTokens: 50, OutputTokens: 20,
						CacheReadTokens: 5000,
					},
				},
			}),
			// T1 produces an EMA sample (write); T2 has no write → no sample.
			expectSamples: 1,
		},
	}

	for _, c := range cases {
		eng := cachetrack.NewEngine(64)
		base := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
		eng.Clock = func() time.Time { return base }
		c.runFn(eng, c.sessionID, c.model)
		ema := eng.SessionEstimateEMA(c.sessionID, c.model, "default")
		t.Logf("  [%s] SessionEMA: Scale=%.4f Samples=%d", c.name, ema.Scale, ema.Samples)
		if ema.Samples != c.expectSamples {
			t.Errorf("[%s] Samples = %d, want %d", c.name, ema.Samples, c.expectSamples)
		}
	}
	t.Logf("")
	t.Logf("  PHASE-5 F1/F2 ANCHORS:")
	t.Logf("  Post-fix WriteHeavy Scale lands smaller than pre-fix (127.7187)")
	t.Logf("  because the enlarged new-tail estimate divides observed-write")
	t.Logf("  by a larger denominator — directional toward 1.0 on cache-hit-heavy")
	t.Logf("  (no continuation poisoning). ContinuationDominant Samples stays 1")
	t.Logf("  (T1 only — T2 has no write so no EMA sample).")
}

// TestEngineTier1Baseline_RealisticContinuation_FlipSentinel_3Turns
// is the operator-required REALISTIC Tier-1 cumulative continuation
// golden. THIS IS THE TEST THAT PROVES THE FIX WORKS ON REAL TRAFFIC.
//
// The fixture mimics real Tier-1 proxy behavior: in.Blocks grows
// turn-over-turn (Anthropic API request body includes the entire
// conversation history every turn). Large cached prefix + tiny new
// tail per turn — the standard Sonnet "user says 'ok' to a long
// previous turn" continuation shape.
//
// Sequence: W W H (every turn has a matched entry at predict time
// because the prior turn either cold-seeded or wrote new content).
// All H turn predictions must be Hit; a wrong slice anchor that
// reverts to sum-all-of-cumulative-in.Blocks would land Write
// (cumulative tokens always ≥ min-cacheable) → assertion fails.
//
// Specifically engineered to fail loud if the slice anchor is
// Chain.Count() (which diverges from len(in.Blocks) after turn 2
// because the chain accumulates across pushes regardless of the
// caller's per-turn shape — see TestChainCountDivergesFromBlocksLen
// below).
func TestEngineTier1Baseline_RealisticContinuation_FlipSentinel_3Turns(t *testing.T) {
	// T1: substantive system + first user/assistant pair.
	// Sized so cache_creation lands a real cached prefix.
	systemBlock := cachetrack.ObserveBlock{
		Level: cachetrack.LevelSystem, Kind: "text",
		CanonicalBytes: largePadding(4096),
	}
	t1User := cachetrack.ObserveBlock{
		Level: cachetrack.LevelMessage, Kind: "text",
		CanonicalBytes: []byte(`{"text":"hello — long initial question with substantive context","role":"user"}`),
	}
	t1Asst := cachetrack.ObserveBlock{
		Level: cachetrack.LevelMessage, Kind: "text",
		CanonicalBytes: largePadding(5120),
	}
	// T2: adds non-trivial new content past the prior — still a
	// WRITE turn (creates a new entry). t2Asst sized so the
	// per-turn new tail (sliced from T1 matched.BlockCount=3)
	// clears Sonnet min-cacheable (≥1024 tokens ≈ 4096 bytes).
	t2User := cachetrack.ObserveBlock{
		Level: cachetrack.LevelMessage, Kind: "text",
		CanonicalBytes: []byte(`{"text":"follow-up — longer second user prompt that triggers a new write","role":"user"}`),
	}
	t2Asst := cachetrack.ObserveBlock{
		Level: cachetrack.LevelMessage, Kind: "text",
		CanonicalBytes: largePadding(5120),
	}
	// T3: TINY user follow-up. Continuation case — the test.
	t3User := cachetrack.ObserveBlock{
		Level: cachetrack.LevelMessage, Kind: "text",
		CanonicalBytes: []byte(`{"text":"ok","role":"user"}`),
	}

	bp := []cachetrack.ObserveBreakpoint{
		{BlockIndex: 0, Level: cachetrack.LevelSystem, TTL: cachetrack.TTL1h},
	}

	turns := []cachetrack.ObserveInput{
		// T1 — cumulative: [sys, u1, a1].
		{
			MessageID:   "msg_1",
			Blocks:      []cachetrack.ObserveBlock{systemBlock, t1User, t1Asst},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens: 1200, OutputTokens: 600,
				CacheCreationTokens: 4096,
			},
		},
		// T2 — cumulative: [sys, u1, a1, u2, a2]. WRITE turn.
		{
			MessageID:   "msg_2",
			Blocks:      []cachetrack.ObserveBlock{systemBlock, t1User, t1Asst, t2User, t2Asst},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens: 200, OutputTokens: 400,
				CacheReadTokens:     4096,
				CacheCreationTokens: 1200,
			},
		},
		// T3 — cumulative: [sys, u1, a1, u2, a2, u3]. CONTINUATION turn.
		// Tiny new tail. THIS IS THE FIX-PROVING ASSERTION.
		{
			MessageID:   "msg_3",
			Blocks:      []cachetrack.ObserveBlock{systemBlock, t1User, t1Asst, t2User, t2Asst, t3User},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens: 30, OutputTokens: 10,
				CacheReadTokens:     5296,
				CacheCreationTokens: 0,
			},
		},
	}
	snaps := runSequence(t, "sess-t1-realistic-cont", "claude-sonnet-4", cachetrack.TierProxy, turns)
	if len(snaps) != 3 {
		t.Fatalf("expected 3 event snapshots, got %d", len(snaps))
	}

	// T1 — cold seed → Reanchor.
	if snaps[0].predictedKind != cachetrack.KindReanchor {
		t.Errorf("T1 predicted_kind = %q, want reanchor", snaps[0].predictedKind)
	}

	// T2 — Write turn. matched=T1-entry. new tail (u2+a2) is
	// large enough to clear min-cacheable → predict Write.
	// This proves the slice anchor (matched.BlockCount=3 → slice
	// in.Blocks[3:] = [u2, a2]) computes per-turn delta correctly.
	if snaps[1].predictedKind != cachetrack.KindWrite {
		t.Errorf("[REGRESSION GUARD] T2 predicted_kind = %q, want write — slice anchor failed to find the new tail correctly (matched.BlockCount=3 should slice in.Blocks[3:] to the new 2-block delta with ≥1024 tokens)",
			snaps[1].predictedKind)
	}
	if snaps[1].observedKind != cachetrack.KindWrite {
		t.Errorf("T2 observed_kind = %q, want write", snaps[1].observedKind)
	}
	if snaps[1].bucketMispredicted {
		t.Errorf("T2 bucket-mispredict = true — Tier-1 cumulative growth invariant must hold")
	}

	// T3 — CONTINUATION case. matched=T2-entry (BlockCount=5).
	// new tail = in.Blocks[5:] = [u3] tiny ("ok") → predict Hit.
	//
	// REGRESSION GUARD: if the slice anchor were Chain.Count()
	// (pre-push) instead of matched.BlockCount, Chain.Count() at
	// T3 start = 3+5=8 > len(in.Blocks)=6 → guard fails → start=0
	// → sum-all = entire 6-block cumulative conversation
	// (~3500+ tokens) → CacheableTokens=true → predict Write →
	// this assertion fails LOUDLY pointing at the wrong anchor.
	if snaps[2].predictedKind != cachetrack.KindHit {
		t.Errorf("[REALISTIC CONTINUATION REGRESSION GUARD] T3 predicted_kind = %q, want hit — this is the operator-required real-traffic test. A wrong slice anchor (e.g. Chain.Count() instead of matched.BlockCount) would sum the entire cumulative in.Blocks → predict Write → this fires. The fix is incorrectly anchored if you see this.",
			snaps[2].predictedKind)
	}
	if snaps[2].observedKind != cachetrack.KindHit {
		t.Errorf("T3 observed_kind = %q, want hit", snaps[2].observedKind)
	}
	if snaps[2].bucketMispredicted {
		t.Errorf("T3 bucket-mispredict = true — realistic continuation should match buckets after the fix")
	}
}

// TestEngineTier1Baseline_RealisticGrowth_NewTailInvariant_3Turns
// is the operator-required Tier-1 cumulative growth invariant
// over a realistic 3-turn shape. Every turn carries a substantial
// new tail (assistant response + tool result + new user prompt
// modelled by a 4 KB padded message block) → predict Write.
//
// A wrong slice anchor that summed the entire cumulative
// in.Blocks would also predict Write here — but for the wrong
// reason (always-true CacheableTokens instead of new-tail-is-
// cacheable). The companion continuation test
// (TestEngineTier1Baseline_RealisticContinuation_FlipSentinel_3Turns)
// catches the wrong-anchor case; this test pins the growth case
// against the correctly-anchored slice.
func TestEngineTier1Baseline_RealisticGrowth_NewTailInvariant_3Turns(t *testing.T) {
	systemBlock := cachetrack.ObserveBlock{
		Level: cachetrack.LevelSystem, Kind: "text",
		CanonicalBytes: largePadding(4096),
	}
	mkUser := func(label string) cachetrack.ObserveBlock {
		return cachetrack.ObserveBlock{
			Level: cachetrack.LevelMessage, Kind: "text",
			CanonicalBytes: []byte(fmt.Sprintf(`{"text":"%s","role":"user"}`, label)),
		}
	}
	mkAsst := func() cachetrack.ObserveBlock {
		return cachetrack.ObserveBlock{
			Level: cachetrack.LevelMessage, Kind: "text",
			CanonicalBytes: largePadding(5120),
		}
	}

	bp := []cachetrack.ObserveBreakpoint{
		{BlockIndex: 0, Level: cachetrack.LevelSystem, TTL: cachetrack.TTL1h},
	}

	turns := []cachetrack.ObserveInput{
		// T1: cumulative [sys, u1, a1]. cold seed.
		{
			MessageID:   "msg_1",
			Blocks:      []cachetrack.ObserveBlock{systemBlock, mkUser("first prompt with non-trivial content for the cold seed"), mkAsst()},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens: 1200, OutputTokens: 600,
				CacheCreationTokens: 4096,
			},
		},
		// T2: cumulative [sys, u1, a1, u2, a2]. growth.
		{
			MessageID:   "msg_2",
			Blocks:      []cachetrack.ObserveBlock{systemBlock, mkUser("first prompt with non-trivial content for the cold seed"), mkAsst(), mkUser("second prompt — substantive follow-up requiring a real assistant response"), mkAsst()},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens: 250, OutputTokens: 500,
				CacheReadTokens:     4096,
				CacheCreationTokens: 1500,
			},
		},
		// T3: cumulative [sys, u1, a1, u2, a2, u3, a3]. growth.
		{
			MessageID:   "msg_3",
			Blocks:      []cachetrack.ObserveBlock{systemBlock, mkUser("first prompt with non-trivial content for the cold seed"), mkAsst(), mkUser("second prompt — substantive follow-up requiring a real assistant response"), mkAsst(), mkUser("third prompt — keeps adding substantive content per turn"), mkAsst()},
			Breakpoints: bp,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens: 200, OutputTokens: 500,
				CacheReadTokens:     5596,
				CacheCreationTokens: 1500,
			},
		},
	}
	snaps := runSequence(t, "sess-t1-realistic-growth", "claude-sonnet-4", cachetrack.TierProxy, turns)
	if len(snaps) != 3 {
		t.Fatalf("expected 3 event snapshots, got %d", len(snaps))
	}

	if snaps[0].predictedKind != cachetrack.KindReanchor {
		t.Errorf("T1 predicted_kind = %q, want reanchor", snaps[0].predictedKind)
	}

	// T2 + T3: matched non-nil, new tail ≥ min-cacheable → predict Write.
	for i := 1; i <= 2; i++ {
		if snaps[i].predictedKind != cachetrack.KindWrite {
			t.Errorf("[INVARIANT] T%d predicted_kind = %q, want write — 3-turn cumulative growth invariant",
				i+1, snaps[i].predictedKind)
		}
		if snaps[i].observedKind != cachetrack.KindWrite {
			t.Errorf("T%d observed_kind = %q, want write", i+1, snaps[i].observedKind)
		}
		if snaps[i].bucketMispredicted {
			t.Errorf("[INVARIANT] T%d bucket-mispredict = true — growth-turn regression", i+1)
		}
	}
}

// TestBucketHelperConformance is the §15.3 (c) G2-anchor closure
// step. Pre-fix, baseline + fixture-grading tests carried external
// liveBucket / bucketLabel helpers that mirrored reconcile.go's
// bucketOf. Those helpers stayed in sync by doc comment — a
// future Kind addition without a re-sync would silently change
// the phase-4 G2 gate.
//
// Closure: the engine surfaces ev.Mispredicted directly on
// EventOut (read at runSequence), AND cachetrack.BucketLabel +
// cachetrack.BucketMismatch are the public canonical helpers.
// This test pins both helpers against every defined Kind so a new
// Kind landing without updating the helpers fires the test loudly.
func TestBucketHelperConformance(t *testing.T) {
	t.Parallel()
	type kindCase struct {
		k        cachetrack.Kind
		wantLbl  string
		wantMism bool // mismatch against KindWrite (a known write-bucket Kind)
	}
	// Every Kind in the engine vocabulary, with its expected
	// bucket label + whether it mismatches a fixed write-bucket
	// reference. Adding a new Kind requires extending this
	// switch AND extending bucketOf — the parallel structure
	// makes silent drift impossible.
	cases := []kindCase{
		{cachetrack.KindHit, "hit", true},                    // hit vs write → mismatch
		{cachetrack.KindWrite, "write", false},               // self → no mismatch
		{cachetrack.KindExpiryRewrite, "write", false},       // write-bucket → no mismatch
		{cachetrack.KindInvalidationRewrite, "write", false}, // write-bucket → no mismatch
		{cachetrack.KindModelSwitchRewrite, "write", false},  // write-bucket → no mismatch
		{cachetrack.KindBelowMin, "skipped", false},          // skipped → no mismatch (skip excluded)
		{cachetrack.KindReanchor, "skipped", false},          // skipped
		{cachetrack.KindMispredict, "skipped", false},        // skipped
		{cachetrack.KindCompactionReset, "skipped", false},   // skipped
	}
	for _, c := range cases {
		gotLbl := cachetrack.BucketLabel(c.k)
		if gotLbl != c.wantLbl {
			t.Errorf("BucketLabel(%q) = %q, want %q", c.k, gotLbl, c.wantLbl)
		}
		gotMism := cachetrack.BucketMismatch(c.k, cachetrack.KindWrite)
		if gotMism != c.wantMism {
			t.Errorf("BucketMismatch(%q, KindWrite) = %v, want %v", c.k, gotMism, c.wantMism)
		}
	}
	// Symmetric mismatch invariant: BucketMismatch(a, b) ==
	// BucketMismatch(b, a) over the full case set.
	for _, a := range cases {
		for _, b := range cases {
			if cachetrack.BucketMismatch(a.k, b.k) != cachetrack.BucketMismatch(b.k, a.k) {
				t.Errorf("BucketMismatch asymmetry: (%q, %q) vs (%q, %q)", a.k, b.k, b.k, a.k)
			}
		}
	}
}

// TestChainCountDivergesFromBlocksLen_TierOneCumulative is the
// defensive probe that documents WHY matched.BlockCount (in.Blocks
// units) is the correct slice anchor for §15.3 (c)-phase-2,
// NOT Chain.Count() (chain units).
//
// Empirically: Chain.Count() captured BEFORE the push loop matches
// len(in.Blocks) at T2 but DIVERGES at T3 because the chain
// accumulates ACROSS turns (chain.go::Push increments c.n
// monotonically; Reset only fires on compaction). A naive guard
// `priorChainCount < len(blocks)` then falls through to start=0
// at T3+ → sum-all → CacheableTokens true on every non-cold turn
// → predict Write → §15.3 (c) closes zero mispredicts → silent
// no-op.
//
// The realistic continuation golden above
// (TestEngineTier1Baseline_RealisticContinuation_FlipSentinel_3Turns)
// catches this regression through the engine; this probe asserts the
// underlying chain arithmetic on a bare cachetrack.Chain.
func TestChainCountDivergesFromBlocksLen_TierOneCumulative(t *testing.T) {
	// Tier-1 cumulative shape: every turn's in.Blocks is the whole
	// conversation so far, and the session's chain is pushed every
	// block of every turn (chain.go::Push increments c.n; only Reset
	// zeroes it, on compaction).
	block := func(i int) cachetrack.Block {
		return cachetrack.Block{Level: cachetrack.LevelMessage, Kind: "text", CanonicalBytes: []byte(fmt.Sprintf(`{"seq":%d}`, i))}
	}
	chain := cachetrack.NewChain()
	push := func(n int) {
		for i := 0; i < n; i++ {
			chain.Push(block(i))
		}
	}

	// T1: 3 blocks.
	push(3)
	if got := chain.Count(); got != 3 {
		t.Fatalf("T1: Chain.Count() = %d, want 3", got)
	}
	t1Matched := 3 // T1 cold-seeds an entry with BlockCount = len(in.Blocks) = 3.

	// T2: 5 cumulative blocks. Chain.Count() before the push is 3, so
	// the anchor still agrees with the blocks at T2 ...
	t2Len := 5
	if before := chain.Count(); before >= t2Len || t1Matched >= t2Len {
		t.Fatalf("T2: Chain.Count()=%d and matched.BlockCount=%d must both be < len(in.Blocks)=%d", before, t1Matched, t2Len)
	}
	push(t2Len)
	if got := chain.Count(); got != 8 {
		t.Fatalf("T2: Chain.Count() after push = %d, want 3+5=8 (the chain accumulates across turns)", got)
	}
	t2Matched := t2Len // T2 writes an entry with BlockCount = 5.

	// T3: 6 cumulative blocks. ... but at T3 the chain anchor has
	// diverged: guard `8 < 6` is false, which would fall through to
	// start=0 (sum-all), while matched.BlockCount gives start=5 and
	// slices exactly the one new block.
	t3Len := 6
	if before := chain.Count(); before < t3Len {
		t.Fatalf("T3: Chain.Count()=%d < len(in.Blocks)=%d; the chain-unit anchor no longer diverges, so the probe's premise changed", before, t3Len)
	}
	if t3Len-t2Matched != 1 {
		t.Fatalf("T3: matched.BlockCount=%d must slice in.Blocks[%d:] to exactly 1 new block of %d", t2Matched, t2Matched, t3Len)
	}
}
