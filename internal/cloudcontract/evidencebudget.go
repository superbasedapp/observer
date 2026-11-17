package cloudcontract

// Evidence budget (managed-SaaS ruling R-AI1, 2026-11-13). A tier's
// enrichment evidence budget is expressed in EVIDENCE TOKENS: what the
// serialized envelope costs the model as prompt input, excluding the fixed
// system prompt. The node steps its own evidence settings down until the
// envelope fits (cloudevidence.FitToBudget), and the hosted service refuses
// an envelope that does not fit. Both sides call the ONE estimator below, so
// they can never disagree about whether an envelope fits.

// Evidence-token calibration: the S-3 spike (docs/plans/managed-saas/
// 06-spikes-2026-11.md, "Data budget") measured 0.323 prompt tokens per
// envelope byte on the gpt-oss tokenizer over 16 max_tokens=1 calls. The
// estimator works in integers so a boundary is exact on every platform.
const (
	// EvidenceTokensPerKiloByte is the calibrated tokens per 1,000 envelope
	// bytes (0.323 tokens per byte).
	EvidenceTokensPerKiloByte = 323

	// DefaultEvidenceTokenBudget is the evidence budget a node fits to when
	// it has never read its account's budget from GET /v1/usage: the free
	// tier's seeded v5 evidence budget (cloud migration 0078), the smallest
	// any tier carries, so an envelope fitted to it is never refused on a
	// tier with a larger budget.
	DefaultEvidenceTokenBudget = 4000
)

// EstimateEvidenceTokens is the estimated prompt-token cost of an envelope
// of the given serialized size: ceil(bytes x 0.323). A non-positive size is
// zero. It is an ESTIMATE, the one both planes agree on for budget fitting;
// the hosted service's reservation uses its own, more conservative worst
// case, and its settlement books what the provider actually reported.
func EstimateEvidenceTokens(bytes int) int {
	if bytes <= 0 {
		return 0
	}
	return (bytes*EvidenceTokensPerKiloByte + 999) / 1000
}

// EvidenceFitsBudget reports whether an envelope of the given serialized size
// fits an evidence-token budget. A non-positive budget means "no budget" and
// always fits.
func EvidenceFitsBudget(bytes, budgetTokens int) bool {
	if budgetTokens <= 0 {
		return true
	}
	return EstimateEvidenceTokens(bytes) <= budgetTokens
}
