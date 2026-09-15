package handoff

import "fmt"

// PriceFunc prices inputTokens of prompt input on model, in USD. The
// boundary backs it with cost.ComputeBreakdown-derived rates; the pure
// layer never imports the cost engine (imports_test pin).
type PriceFunc func(model string, inputTokens int64) float64

// CarryEstimate is one row of the priced-transaction table (plan §9).
type CarryEstimate struct {
	Mode    CarryMode
	Tokens  int64
	CostUSD float64
	Note    string
}

// EstimateInput carries the rendered-variant token weights the boundary
// measured plus the session's context weight.
type EstimateInput struct {
	TargetModel string
	// MetadataTokens/DistilledTokens/TailTokens are TokenEstimate weights
	// of the rendered metadata doc, the distilled doc, and the tail delta.
	MetadataTokens  int64
	DistilledTokens int64
	TailTokens      int64
	// ContextTokens is the session's cumulative prefix weight (0 = unknown
	// → the full row is omitted honestly).
	ContextTokens int64
	// ForkShare scales ContextTokens to the fork cut (ForkShare()).
	ForkShare float64
	// SourceHasFullReader is true when the source adapter implements the
	// un-excerpted (FullTranscriptReader) read that the full_cache carry
	// needs. When false, full_cache degrades to full (same excerpted bodies),
	// so the full_cache row is priced identically to full and its note says
	// so — otherwise the two rows read as a distinct option they are not.
	SourceHasFullReader bool
	Price               PriceFunc
}

// StayEstimate is the stay-option half of the plan §9 comparison: what
// NOT moving looks like at the source tool. Composed at the boundary
// (predict band + cachewarm value-at-risk) — this pure layer only
// carries the numbers. Both halves are optional and honestly flagged;
// nothing is fabricated when the source has no token substrate or no
// live cache.
type StayEstimate struct {
	// NextMessage*USD is the source session's next-message cost band
	// (low / typical / high), valid when HasBand.
	NextMessageLowUSD  float64 `json:"next_message_low_usd"`
	NextMessageMidUSD  float64 `json:"next_message_mid_usd"`
	NextMessageHighUSD float64 `json:"next_message_high_usd"`
	HasBand            bool    `json:"has_band"`
	// CacheValueAtRiskUSD sums the source session's live cache windows'
	// value-at-risk — what leaving abandons, valid when HasCacheValue.
	CacheValueAtRiskUSD float64 `json:"cache_value_at_risk_usd"`
	HasCacheValue       bool    `json:"has_cache_value"`
}

// EstimateResult is the full carry-mode table for one target model.
type EstimateResult struct {
	TargetModel string
	ForkShare   float64
	Rows        []CarryEstimate
	// SourceHasFullReader mirrors EstimateInput.SourceHasFullReader — whether
	// the source adapter implements the un-excerpted (FullTranscriptReader)
	// read the full_cache carry needs. Callers (the dashboard handoff API)
	// use this to grey out the full_cache option honestly instead of letting
	// it silently collapse to a full-cache row that is byte-identical to
	// full (see the CarryFullCache note in Estimate below).
	SourceHasFullReader bool
	// Stay is the stay-option comparison; nil when the boundary had no
	// grounded numbers for it.
	Stay *StayEstimate
}

// Estimate builds the carry-mode rows. Ordered cheapest-first, matching
// the plan §9 table; rows the input cannot ground are omitted, never
// fabricated.
func Estimate(in EstimateInput) EstimateResult {
	if in.ForkShare <= 0 || in.ForkShare > 1 {
		in.ForkShare = 1
	}
	price := in.Price
	if price == nil {
		price = func(string, int64) float64 { return 0 }
	}
	res := EstimateResult{TargetModel: in.TargetModel, ForkShare: in.ForkShare, SourceHasFullReader: in.SourceHasFullReader}

	add := func(mode CarryMode, tokens int64, note string) {
		res.Rows = append(res.Rows, CarryEstimate{
			Mode:    mode,
			Tokens:  tokens,
			CostUSD: price(in.TargetModel, tokens),
			Note:    note,
		})
	}
	add(CarryMetadata, in.MetadataTokens, "action-derived facts only")
	add(CarryDistilled, in.DistilledTokens, "facts + mission")
	add(CarryDistilledTail, in.DistilledTokens+in.TailTokens, "facts + mission + verbatim tail")
	if in.ContextTokens > 0 {
		full := int64(float64(in.ContextTokens) * in.ForkShare)
		add(CarryFull, full, "whole context through the fork; the target pulls full bodies on demand via get_session_message")
		cacheNote := "full read bodies inlined from the first prompt — replicates the source prompt cache; resent per turn until the target's cache warms"
		if !in.SourceHasFullReader {
			cacheNote = "= full: this source has no un-excerpted (full-body) reader, so full_cache carries the same excerpted bodies as full — no distinct read cache to inline"
		}
		add(CarryFullCache, full, cacheNote)
	}
	return res
}

// ContextFitWarning returns an advisory when the full carry likely will not
// fit the target tool's default model context window, or "" when there is no
// grounded concern. The target tool's default model is often UNKNOWN — each
// tool picks its own, and a "free"/default model may cap near 128K–200K while
// the source (e.g. Claude Code on a 1M-window model) can hold far more. So the
// check is deliberately conservative and honest about that uncertainty: it
// fires when the full carry exceeds warnTokens and points at the smaller
// carries already offered in the same table, or an earlier fork, as the fix.
// warnTokens <= 0 disables the check; a missing full row (unknown context)
// never warns.
func ContextFitWarning(res EstimateResult, warnTokens int64) string {
	if warnTokens <= 0 {
		return ""
	}
	var full, distilledTail int64
	var haveFull bool
	for _, r := range res.Rows {
		switch r.Mode {
		case CarryFull:
			full, haveFull = r.Tokens, true
		case CarryDistilledTail:
			distilledTail = r.Tokens
		}
	}
	if !haveFull || full <= warnTokens {
		return ""
	}
	return fmt.Sprintf(
		"Full carry ≈ %s tokens exceeds a %s-token context window. The target tool's default model may be smaller than the source's (many default/free models cap near 128K–200K), so the full carry can't be rehydrated there in one shot. Fork earlier, or use a smaller carry (Distilled + tail ≈ %s tokens).",
		humanTokens(full), humanTokens(warnTokens), humanTokens(distilledTail),
	)
}

// humanTokens renders a token count compactly (e.g. 350000 → "350K",
// 1_200_000 → "1.2M") for the ContextFitWarning message.
func humanTokens(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%dK", n/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}
