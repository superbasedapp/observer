package aigateway

// Gateway built-in defaults (P4 residual — "built-ins stay the fallback",
// tracker Phase P4 / P6 item 3). These were previously private to
// cmd/observer-org; they are lifted here (exported) so BOTH the in-process
// org listener and the standalone cmd/observer-aigateway binary share ONE
// definition instead of each carrying a drifting copy. A later
// org-config/gwstore-backed, versioned rate card + model policy REPLACES these
// at wiring time; when that source is empty or unavailable these remain the
// honest fallback (never a fabricated zero).

// DefaultHardMaxOutputTokens is the absolute output-token ceiling the gateway
// applies when the model policy leaves a per-model cap unset — the backstop
// that bounds a worst-case reservation and the upstream request. Matches the
// org provider registry's own ceiling (llmprovider.MaxOutputTokens).
const DefaultHardMaxOutputTokens = 32000

// BuiltinRateCardVersion is the version string stamped on audit/cost rows when
// the built-in fallback card priced the turn. A DB-sourced card carries its
// own version; keeping this distinct lets a reconciliation pass tell which
// rows were priced by the fallback.
const BuiltinRateCardVersion = "builtin-2026-08-30"

// BuiltinRateCard is the versioned default price table (Sol S12). Dollars are
// ESTIMATES; tokens are authoritative. A model absent here still records
// authoritative usage — its dollar figure is simply zero until the card learns
// the rate.
func BuiltinRateCard() RateCard {
	return RateCard{
		Version: BuiltinRateCardVersion,
		Rates: map[string]ModelRate{
			"claude-opus-4-8":   {InPerMTok: 5, OutPerMTok: 25, CacheReadPerMTok: 0.5, CacheWritePerMTok: 6.25},
			"claude-sonnet-4-5": {InPerMTok: 3, OutPerMTok: 15, CacheReadPerMTok: 0.3, CacheWritePerMTok: 3.75},
			"gpt-5.6":           {InPerMTok: 0.2, OutPerMTok: 1.2, CacheReadPerMTok: 0.02, CacheWritePerMTok: 0.25},
		},
	}
}

// DefaultModelPolicy is the v1 model policy when none is configured: allow-all,
// bounded only by the per-request max_tokens cap. Authn and budgets are the
// hard gates in v1; a later lane compiles the org routing policy into an
// enforceable allow-list here.
func DefaultModelPolicy() ModelPolicy {
	return ModelPolicy{
		DefaultAllow:           []string{"*"},
		DefaultMaxOutputTokens: 8192,
	}
}
