package aigateway

import (
	"math"
	"strings"
)

// ModelRate is the per-million-token price of one model. Cache rates are
// optional (zero ⇒ priced at the input rate is NOT assumed; zero means the
// card does not distinguish cache tokens for this model and they are billed at
// the input/output rate by the caller's Usage split).
type ModelRate struct {
	InPerMTok         float64 `json:"in_per_mtok"`
	OutPerMTok        float64 `json:"out_per_mtok"`
	CacheReadPerMTok  float64 `json:"cache_read_per_mtok,omitempty"`
	CacheWritePerMTok float64 `json:"cache_write_per_mtok,omitempty"`
	// Free is the org's word that the TOKEN PAIR on this row -- InPerMTok and
	// OutPerMTok -- is genuinely zero: the model's tokens are negotiated free,
	// not merely unpriced. It exists because the two used to be one value here,
	// so a model an org pays nothing for could not be put on this card at all
	// (ValidateRateCard reads an unflagged all-zero row as a misconfiguration)
	// and the gateway went on reserving and settling it at the list rate.
	//
	// IT IS ABOUT THE TOKEN PAIR, NOT THE WHOLE ROW. The cache rates beside it
	// may be quoted above zero, and that is not a contradiction: "input and
	// output are free, we still pay the cache-write surcharge" is a real
	// negotiated shape, and reading the flag as a claim about every column
	// meant the projection could express neither half of such a row (it was
	// dropped from the card and the model stayed on the vendor's list rate).
	// What the flag DOES rule out is a non-zero In or Out beside it, which
	// would make the flag contradict the numbers it labels.
	//
	// A free model is PRICED, at zero for its tokens: Rate resolves it, so the
	// handler's unpriced-model refusal never fires on it, and its token dollars
	// are exactly 0 without any reader special-casing zero. Nothing branches on
	// this flag except the validator -- it is a statement about the row's
	// provenance, not an input to the arithmetic, so a quoted cache rate on a
	// free row is charged exactly as quoted by EstimateUSD.
	//
	// It is omitempty so an ordinary priced row serializes byte-identically to
	// a pre-flag document.
	Free bool `json:"free,omitempty"`
}

// RateCard is a VERSIONED price table (Sol S12). Token usage is authoritative;
// every dollar figure this card produces is an ESTIMATE and every surface that
// shows it says so. The Version string is stamped onto each audit/cost row so
// a later reconciliation feature can re-price historical turns against the
// card that was in force.
type RateCard struct {
	Version string `json:"version"`
	// Rates is keyed by normalized model id. Lookup is exact first, then a
	// longest-prefix fallback so a dated model id (claude-opus-4-8-20260114)
	// resolves to a family rate (claude-opus-4-8) without an entry per date.
	Rates map[string]ModelRate `json:"rates"`
}

// normalizeModelKey lower-cases and trims a model id for card lookup. It
// mirrors the light normalization internal/routing applies to its tier keys,
// so the gateway's price table and the org routing policy agree on model
// identity without the core importing routing.
func normalizeModelKey(model string) string {
	return strings.ToLower(strings.TrimSpace(model))
}

// Rate resolves the rate for model: exact match first, then the longest key
// in the card that is a prefix of the model id (family fallback). ok is false
// when the card has no entry — the caller then treats the turn's dollar cost
// as unknown (0) while STILL recording authoritative token usage.
func (rc RateCard) Rate(model string) (ModelRate, bool) {
	key := normalizeModelKey(model)
	if key == "" || len(rc.Rates) == 0 {
		return ModelRate{}, false
	}
	if r, ok := rc.Rates[key]; ok {
		return r, true
	}
	var bestKey string
	var best ModelRate
	for k, r := range rc.Rates {
		if strings.HasPrefix(key, k) && len(k) > len(bestKey) {
			bestKey, best = k, r
		}
	}
	if bestKey != "" {
		return best, true
	}
	return ModelRate{}, false
}

// EstimateUSD prices one turn's observed usage. Cache-read and cache-write
// tokens are billed at their own rates when the card carries them, otherwise
// they fold into the input rate (cache reads are input, cache writes are a
// surcharge on input). The result is an estimate; ok is false when the model
// is unpriced.
func (rc RateCard) EstimateUSD(model string, u Usage) (float64, bool) {
	rate, ok := rc.Rate(model)
	if !ok {
		return 0, false
	}
	cacheRead := rate.CacheReadPerMTok
	if cacheRead == 0 {
		cacheRead = rate.InPerMTok
	}
	cacheWrite := rate.CacheWritePerMTok
	usd := float64(u.InputTokens)/1e6*rate.InPerMTok +
		float64(u.OutputTokens)/1e6*rate.OutPerMTok +
		float64(u.CacheReadTokens)/1e6*cacheRead +
		float64(u.CacheWriteTokens)/1e6*cacheWrite
	if math.IsNaN(usd) || math.IsInf(usd, 0) {
		return 0, true
	}
	return usd, true
}
