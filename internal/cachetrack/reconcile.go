package cachetrack

// Reconciliation per spec §10. The engine's attribution (§7) is a
// PREDICTION about what the provider should report; reconciliation
// scores it against the actual usage envelope and surfaces drift.
//
// Two layers ride on top of [Attribute]:
//
//  1. Prediction scoring — was our predicted Kind the same shape
//     as the observed Kind? Mispredicts mark the matched entry
//     [StateUnverified] so the next turn either confirms or
//     re-classifies it (state machine §6).
//
//  2. Per-session token-estimate calibration (R6) — every write
//     turn produces an (estimated, observed) tuple. The EMA
//     captures the per-session byte-per-token scaling factor
//     that the forecaster (§14.2) consumes.
//
// All operations are pure functions of inputs + a small state
// struct. No I/O, no time.Now (caller injects). The engine's
// [Engine.ObserveTurn] calls Reconcile after Attribute; the
// doctor / health-metric script reads the persisted events and
// computes the §10 ≥95% gate.

// PredictedShape is the shape the engine expected to observe for
// a turn, derived from its model state before usage arrives.
// Compared against [ObservedShape] by [ReconcilePrediction].
type PredictedShape struct {
	// Kind is the engine's prediction. Reconciliation compares
	// shape only — a predicted KindHit vs an observed KindWrite
	// is a mispredict regardless of which write subtype.
	Kind Kind
	// EstimatedWrittenTokens is what the engine expected the
	// provider to charge for cache_creation, based on
	// [EstimateTokens] over the per-turn new-suffix bytes.
	// Zero when prediction was hit (no new write expected).
	EstimatedWrittenTokens int64
}

// ObservedShape is the actual outcome reported by the provider
// (proxy) or extracted from a transcript usage envelope (watcher).
// Reconciliation compares against [PredictedShape].
type ObservedShape struct {
	Kind                Kind
	ObservedReadTokens  int64
	ObservedWriteTokens int64
}

// ReconcileResult is what [ReconcilePrediction] returns to the
// engine. The engine writes Mispredicted into the [EventOut]
// (cache_events.predicted_kind already carries the predicted
// label) and applies EntryStateUpdate per the §6 state machine.
type ReconcileResult struct {
	// Mispredicted is true when Predicted.Kind classifies in a
	// different bucket than Observed.Kind. The classify-bucket
	// shape collapses every "rewrite" Kind into one bucket and
	// every "hit" Kind into another so cause-specific subtypes
	// (model_switch_rewrite vs invalidation_rewrite) don't
	// register as mispredicts against each other.
	Mispredicted bool
	// EstimateScale is the per-turn observed/estimated ratio for
	// write turns where both numbers are positive. Zero when
	// not applicable. Drives the [SessionEMA] update.
	EstimateScale float64
	// EntryTrigger is the §6 trigger the engine should apply to
	// the matched entry. TriggerMispredict on mispredict,
	// TriggerRead on a confirmed hit, TriggerWrite on a confirmed
	// write. TriggerUnknown when no entry update is warranted.
	EntryTrigger Trigger
}

// ReconcilePrediction is the predict-vs-observe core. Pure
// function: same inputs ⇒ same output. Engine call sites pass
// the result to the state machine + EMA update.
func ReconcilePrediction(p PredictedShape, o ObservedShape) ReconcileResult {
	pBucket := bucketOf(p.Kind)
	oBucket := bucketOf(o.Kind)
	mispredicted := pBucket != oBucket

	var scale float64
	if o.ObservedWriteTokens > 0 && p.EstimatedWrittenTokens > 0 {
		scale = float64(o.ObservedWriteTokens) / float64(p.EstimatedWrittenTokens)
	}

	trigger := TriggerUnknown
	switch {
	case mispredicted:
		trigger = TriggerMispredict
	case oBucket == bucketHit:
		trigger = TriggerRead
	case oBucket == bucketWrite:
		trigger = TriggerWrite
	}

	return ReconcileResult{
		Mispredicted:  mispredicted,
		EstimateScale: scale,
		EntryTrigger:  trigger,
	}
}

// kindBucket collapses the §6/§7 Kind enum into the four buckets
// reconciliation actually compares against. The exact write
// subtype (model_switch_rewrite, expiry_rewrite, etc.) is
// diagnostic; the question "did we predict hit-vs-write
// correctly?" is bucket-level.
type kindBucket uint8

const (
	bucketUnknown kindBucket = iota
	bucketHit
	bucketWrite
	bucketSkipped // below_min + reanchor — these are excluded from §10 denominator
)

// bucketOf folds a Kind into its reconciliation bucket. KindHit
// is the only hit bucket; KindWrite + all rewrite subtypes are
// the write bucket. KindBelowMin + KindReanchor + KindMispredict
// + KindCompactionReset are "skipped" (§10 denominator excludes
// them — they are not predictions in the hit-vs-write sense).
//
// §15.3 implicit-cache kinds (KindImplicitHit / KindImplicitMiss /
// KindImplicitWrite) ALL fold into bucketSkipped. They are NOT
// predictions in the Anthropic hit-vs-write sense — the implicit
// cache has no marker-level attribution to grade against. The
// reduced [attributeImplicit] path emits them; the §10 gate
// excludes them via [isRateSkipped]; the separate
// [ImplicitCacheConsistency] metric grades them directly. This
// is THE load-bearing §5 guardrail that protects the soak-
// validated Anthropic §10 path.
func bucketOf(k Kind) kindBucket {
	switch k {
	case KindHit:
		return bucketHit
	case KindWrite,
		KindExpiryRewrite,
		KindInvalidationRewrite,
		KindModelSwitchRewrite:
		return bucketWrite
	case KindBelowMin, KindReanchor, KindMispredict, KindCompactionReset:
		return bucketSkipped
	case KindImplicitHit, KindImplicitMiss, KindImplicitWrite:
		return bucketSkipped
	default:
		return bucketUnknown
	}
}

// BucketLabel returns a stable string label for the bucket a Kind
// folds into ("hit" / "write" / "skipped" / "unknown"). Used by
// diagnostics + the cache-health CLI's G2 surface so callers don't
// re-derive bucketOf in their own helpers (the previous external
// liveBucket/bucketLabel mirrors silently drifted from bucketOf
// if a new Kind landed without re-syncing — closing that drift was
// the §15.3 (c) G2-anchor groundwork).
//
// §15.3 implicit-cache kinds return "skipped" — they're skipped
// from the Anthropic §10 gate by design. Use [IsImplicitCacheKind]
// to test for the implicit-cache subset directly.
func BucketLabel(k Kind) string {
	switch bucketOf(k) {
	case bucketHit:
		return "hit"
	case bucketWrite:
		return "write"
	case bucketSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

// BucketMismatch reports whether predicted and observed fold into
// different non-skipped buckets — the engine's REAL §10
// bucket-mispredict signal (mirrors ReconcilePrediction's internal
// pBucket != oBucket check, with the skipped-side exclusion the
// baseline tests + cache-health CLI both need). This is the exact
// gate the §15.3 (c) phase-4 G2 anchor reads from persisted
// (predicted_kind, kind) pairs.
func BucketMismatch(predicted, observed Kind) bool {
	pb := bucketOf(predicted)
	ob := bucketOf(observed)
	if pb == bucketSkipped || ob == bucketSkipped {
		return false
	}
	return pb != ob
}

// SessionEMA holds the per-session EMA-smoothed token-estimate
// scaling factor (R6). The forecaster (§14.2) multiplies its
// per-byte estimates by this scale to get a session-calibrated
// prediction. Zero/uninitialized falls through to the v1
// constant from [EstimateTokens] (1 token ≈ 4 bytes).
//
// The smoothing constant follows spec §10: α=0.3, applied as
//
//	new = α × observed_ratio + (1−α) × prior_ema
//
// The first observation seeds the EMA directly (avoids a
// cold-start bias against the v1 constant).
type SessionEMA struct {
	// Scale is the current smoothed observed/estimated ratio.
	// Zero means uninitialized; the next call to UpdateEMA
	// seeds rather than smooths.
	Scale float64
	// Samples counts the number of (estimated, observed)
	// tuples folded into Scale. Diagnostic only — operators
	// look at this to gauge how settled the EMA is.
	Samples int
}

// EMAAlpha is the smoothing weight applied to each new sample
// per spec §10. 0.3 weights recent samples enough to track real
// per-session drift without being whipsawed by single noisy
// turns.
const EMAAlpha = 0.3

// UpdateEMA folds one observed/estimated ratio into the session
// EMA. The first sample SEEDS the EMA directly (no prior to
// smooth against). Sample is ignored when ratio is ≤ 0 (we
// learn nothing from a zero or negative observation).
//
// Returns the updated EMA. The session state owns the storage —
// the caller assigns the returned value back to its
// [SessionEMA] field.
func UpdateEMA(prior SessionEMA, ratio float64) SessionEMA {
	if ratio <= 0 {
		return prior
	}
	out := SessionEMA{Samples: prior.Samples + 1}
	if prior.Samples == 0 || prior.Scale == 0 {
		out.Scale = ratio
		return out
	}
	out.Scale = EMAAlpha*ratio + (1-EMAAlpha)*prior.Scale
	return out
}

// MispredictRate computes the §10 health metric over a slice of
// observed events: the fraction of non-skipped events whose Kind
// is KindMispredict.
//
// Denominator EXCLUDES KindBelowMin (the engine knew up-front
// the cache would not engage — uninformative for hit-vs-write
// scoring; see C4 commit d250b68 + KindBelowMin doc comment),
// KindReanchor (first turn for a session has no prior state to
// predict against), and KindCompactionReset (the reset itself
// is the expected outcome, not a prediction). KindMispredict
// IS in the denominator AND the numerator — it's the very thing
// we're scoring.
//
// Important: this function does NOT delegate to [bucketOf] for the
// skip-check. bucketOf folds KindMispredict into bucketSkipped to
// drive ReconcilePrediction's predicted-vs-observed bucket-diff
// (a Tier-1 outcome of "unknown row-12 fallthrough" must still
// demote the matched entry). The rate, by contrast, MUST count
// mispredicts — using bucketOf here silently dropped every
// mispredict event from both numerator and denominator, leaving
// the rate stuck at 0.0000 regardless of how many mispredicts
// the corpus contained. (Pre-fix soaks landed denom=11 misp=0 on
// a 15-event corpus that contained 4 real mispredicts, and
// denom=200 misp=0 on a 201-event corpus that contained 1 — the
// 5% gate had never actually checked the rate.)
//
// Returns the rate in [0.0, 1.0] and the denominator count. A
// denominator of 0 returns (0, 0) — the script reports
// "insufficient data" rather than 0% mispredict.
//
// The P0 exit gate per §20: at least 200 turns and ≥3 sessions
// with rate ≤ 0.05 (= ≥95% correct).
func MispredictRate(eventKinds []Kind) (rate float64, denom int) {
	var mispredicts int
	for _, k := range eventKinds {
		if isRateSkipped(k) {
			continue
		}
		denom++
		if k == KindMispredict {
			mispredicts++
		}
	}
	if denom == 0 {
		return 0, 0
	}
	return float64(mispredicts) / float64(denom), denom
}

// MispredictRateGraded is MispredictRate with zero-usage
// mispredict events excluded from the denominator. Callers that
// have per-event token counts (the dashboard / cache-health CLI)
// should prefer this — it produces an honest rate even when the
// upstream returned zero-usage envelopes.
//
// Zero-usage exclusion rationale: KindMispredict is the §7 row-
// 12 fallthrough — emitted when no rule matched AND no usage
// signal was observed. When BOTH tokens_read and tokens_written
// are zero, the turn is observationally vacant: the engine
// predicted SOMETHING but the provider returned no token data
// to grade against. Counting it as a mispredict is metric
// distortion (same class as the C9 rate bug that silently graded
// every soak as 0.0000). The 2026-06-09 soak surfaced 4 such
// events on opus-4-8 (input/output_tokens 0, http_status NULL,
// 372-453ms total response — short cancelled or partial
// streams); the corresponding api_turns rows show no error
// either, just empty envelopes.
//
// Parallel slices: eventKinds[i] aligns with tokensRead[i] and
// tokensWritten[i]. When the token slices are shorter than the
// kind slice, the missing positions are treated as "tokens
// unknown" and the event is NOT zero-usage-excluded (defensive
// — better to grade an unverified event than silently drop it).
//
// When tokensRead and tokensWritten are nil, behavior matches
// MispredictRate exactly.
func MispredictRateGraded(eventKinds []Kind, tokensRead, tokensWritten []int64) (rate float64, denom int) {
	var mispredicts int
	for i, k := range eventKinds {
		if isRateSkipped(k) {
			continue
		}
		if k == KindMispredict && isZeroUsage(i, tokensRead, tokensWritten) {
			continue
		}
		denom++
		if k == KindMispredict {
			mispredicts++
		}
	}
	if denom == 0 {
		return 0, 0
	}
	return float64(mispredicts) / float64(denom), denom
}

// isZeroUsage reports whether event index i has both token
// columns explicitly at zero. Out-of-range indices return false
// (treat unknown-tokens as "may have been a real mispredict";
// the defensive bias is toward grading, not toward exclusion).
//
// This is the index-based, kind-agnostic form used inside the rate
// denominator, where the caller has already established k ==
// KindMispredict before calling it. The exported, kind-aware spelling
// every event surface uses is [IsZeroUsage]; the two agree on a
// mispredict row (kind check already satisfied here by the caller's
// guard).
func isZeroUsage(i int, tokensRead, tokensWritten []int64) bool {
	if i >= len(tokensRead) || i >= len(tokensWritten) {
		return false
	}
	return tokensRead[i] == 0 && tokensWritten[i] == 0
}

// isRateSkipped names the kinds that the §10 health-metric
// denominator excludes: BelowMin / Reanchor / CompactionReset.
// KindMispredict is INCLUDED here (not skipped) — the rate is
// exactly the fraction of graded events that mispredicted, so
// the mispredicts are the numerator AND part of the denominator.
//
// §15.3 implicit-cache kinds (KindImplicitHit / KindImplicitMiss /
// KindImplicitWrite) are ALL skipped from the §10 rate. This is
// THE load-bearing §5 guardrail: the Anthropic-shaped §10 gate
// must be PROVABLY UNMOVED by implicit-cache events. Pair with
// [bucketOf]'s bucketSkipped routing for the same kinds (predict-
// vs-observe demotion semantics — also skipped for the same
// reason: an implicit-cache event has no Anthropic-grade
// prediction to demote a matched entry against).
//
// Distinct from [bucketOf]'s bucketSkipped vocabulary in scope
// (the rate-side includes KindMispredict in the numerator; bucketOf
// does not); the two concerns answer different questions but agree
// on the implicit-cache exclusion. The
// [TestMispredictRateGraded_AnthropicRateUnmovedByImplicit]
// interleave fixture proves this through the real assembly path.
func isRateSkipped(k Kind) bool {
	switch k {
	case KindBelowMin, KindReanchor, KindCompactionReset:
		return true
	case KindImplicitHit, KindImplicitMiss, KindImplicitWrite:
		return true
	}
	return false
}

// IsImplicitCacheKind reports whether k is one of the §15.3
// implicit-cache kinds (emitted only when caps.ImplicitCache is
// true at the engine boundary). Used by the implicit-cache
// consistency metric + dashboard surfaces that need to separate
// implicit-cache events from Anthropic events.
func IsImplicitCacheKind(k Kind) bool {
	switch k {
	case KindImplicitHit, KindImplicitMiss, KindImplicitWrite:
		return true
	}
	return false
}

// ImplicitCacheConsistencyReport is the §15.3 separate health
// surface: the implicit-cache analog of MispredictRateGraded.
// Implicit cache has no marker-level attribution to grade against,
// so "consistency" is defined as "observed cached_tokens behaved
// the way the per-session tracked prefix expected" — i.e. an
// implicit_hit fired when prefix was stable + above min-cacheable,
// an implicit_miss fired when the prefix changed, etc.
//
// In practice this collapses to: of the graded implicit-cache
// events (anything but KindImplicitWrite, which is the bootstrap
// turn that has nothing to compare against), what fraction landed
// the "expected" kind. Today the engine's reduced attribution
// IS the ground truth (we don't have a separate oracle), so the
// metric grades the AGREEMENT of the per-event PredictedKind vs
// observed Kind on the implicit-cache subset. This is materially
// different from §10:
//
//   - §10 grades Anthropic predict-vs-observe via marker
//     attribution + provider write/read counts.
//   - Implicit-cache consistency grades whether the per-session
//     tracked prefix stayed in sync with the provider's observed
//     `cached_tokens` shape across turns.
//
// A dropping consistency rate means the proxy's LCP prefix tracker
// is drifting from the provider's behavior — i.e. operator
// intervention needed (clear prompt_cache_key, restart agent).
// A high (≥95%) rate means the implicit-cache tracking is healthy.
//
// The metric is surfaced separately in `observer cache-health` so
// the operator can't conflate "is my Anthropic gate green?" with
// "is my implicit-cache tracking healthy?" — they answer different
// questions.
type ImplicitCacheConsistencyReport struct {
	// Total is the count of implicit-cache events in the input.
	Total int
	// Graded is the count of implicit-cache events where the
	// (predicted, observed) pair is informative (predicted is
	// not KindImplicitWrite — the bootstrap turn has no prior
	// state to predict against, same exclusion shape as §10's
	// reanchor skip).
	Graded int
	// Consistent is the count of graded events where predicted
	// kind matched observed kind. Numerator.
	Consistent int
	// Rate is Consistent / Graded in [0, 1]; 0 when Graded == 0.
	Rate float64
}

// ImplicitCacheConsistency computes the §15.3 separate health
// metric over a parallel slice of (predicted, observed) Kind
// pairs. Only implicit-cache events count; non-implicit events
// (Anthropic Kinds) are filtered out — the metric is the
// per-implicit-cache rate, not a mixed-corpus rate.
//
// Parallel slices: predicted[i] aligns with observed[i]; when
// they're different lengths the shorter wins (defensive — never
// panic). An empty input returns the zero report.
//
// The "expected" notion is the agreement of the engine's per-
// event predicted_kind vs observed kind on the implicit-cache
// subset. KindImplicitWrite events are excluded from the graded
// denominator because the bootstrap turn has no prior prefix to
// predict from (same exclusion shape as §10's reanchor skip).
//
// Returns 0 / 0 / 0 / 0 when no implicit-cache events are present
// — the cache-health CLI reports "no implicit-cache traffic"
// rather than 0% consistent.
func ImplicitCacheConsistency(predicted, observed []Kind) ImplicitCacheConsistencyReport {
	n := len(predicted)
	if len(observed) < n {
		n = len(observed)
	}
	var report ImplicitCacheConsistencyReport
	for i := 0; i < n; i++ {
		p, o := predicted[i], observed[i]
		if !IsImplicitCacheKind(o) {
			continue
		}
		report.Total++
		// Bootstrap turns (predicted=KindImplicitWrite) have no
		// prior state to predict against — exclude from graded
		// denominator (same shape as §10's reanchor skip).
		if p == KindImplicitWrite {
			continue
		}
		report.Graded++
		if p == o {
			report.Consistent++
		}
	}
	if report.Graded > 0 {
		report.Rate = float64(report.Consistent) / float64(report.Graded)
	}
	return report
}
