package aigateway

import (
	"encoding/json"
	"strings"
	"testing"
)

// AN EXPLICITLY FREE MODEL ON THE GATEWAY CARD.
//
// Server migration 135 made an org's negotiated rate nullable, so "the org
// quotes nothing here" and "the org negotiated this free" stopped being the
// same value. The gateway card was the last place where they were still one:
// ValidateRateCard read a row whose input AND output were zero as a
// misconfiguration, so a model the org priced at zero could not be projected
// at all and the gateway kept reserving and settling it at the list rate while
// the Pricing page said "free".
//
// ModelRate.Free is the org's word that the TOKEN PAIR on the row is genuinely
// zero. The misconfiguration guard survives untouched for the UNFLAGGED case,
// which is the whole reason the flag exists rather than the guard simply being
// dropped.
//
// The flag covers the token pair rather than the whole row (widened for review
// finding P2-3): "input and output are free, we still pay for cache writes" is
// a real negotiated shape, and under the narrower reading the projection could
// express neither half of it - the row was dropped from the card entirely and
// the gateway went on reserving at the vendor's list rate.

func TestValidateRateCardFreeModel(t *testing.T) {
	cases := []struct {
		name    string
		rate    ModelRate
		wantErr string // substring; empty means the card must validate
	}{
		{
			name:    "an all-zero row WITHOUT the flag is still the misconfiguration it always was",
			rate:    ModelRate{},
			wantErr: "prices both input and output at zero",
		},
		{
			name: "an all-zero row WITH the flag is the org saying the model is free",
			rate: ModelRate{Free: true},
		},
		{
			name:    "free with a non-zero input rate contradicts itself",
			rate:    ModelRate{InPerMTok: 3, Free: true},
			wantErr: "is marked free but carries a non-zero token rate",
		},
		{
			name:    "free with a non-zero output rate contradicts itself",
			rate:    ModelRate{OutPerMTok: 15, Free: true},
			wantErr: "is marked free but carries a non-zero token rate",
		},
		{
			// Free is a statement about the TOKEN PAIR, not about every column
			// on the row. An org that negotiated free input and output while
			// still paying the vendor's cache surcharge is a real shape, and it
			// is the shape the gateway projection used to DROP silently.
			name: "free with a quoted cache-read rate is accepted: Free is about the token pair",
			rate: ModelRate{CacheReadPerMTok: 0.3, Free: true},
		},
		{
			name: "free with a quoted cache-write rate is accepted",
			rate: ModelRate{CacheWritePerMTok: 3.75, Free: true},
		},
		{
			name: "an ordinary priced row is unaffected",
			rate: ModelRate{InPerMTok: 3, OutPerMTok: 15},
		},
		{
			name:    "a negative rate is still refused even under the flag",
			rate:    ModelRate{InPerMTok: -1, Free: true},
			wantErr: "has a negative rate",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			card := RateCard{Version: "v1", Rates: map[string]ModelRate{"m": c.rate}}
			err := ValidateRateCard(card)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateRateCard = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateRateCard = nil, want an error containing %q", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("ValidateRateCard = %q, want it to contain %q", err.Error(), c.wantErr)
			}
			if !IsValidationError(err) {
				t.Errorf("ValidateRateCard error is not a validation error: %v", err)
			}
		})
	}
}

// TestFreeModelIsPricedAtZero pins the half of the fix that needs no new code:
// a free model is PRICED, at zero. Rate() must resolve it (so the handler's
// G4 unpriced-model refusal never fires on it) and every dollar figure derived
// from it must be exactly 0 (so it can never consume USD headroom).
func TestFreeModelIsPricedAtZero(t *testing.T) {
	rc := RateCard{
		Version: "org-pricing-v9",
		Rates: map[string]ModelRate{
			"in-house-7b":     {Free: true},
			"claude-opus-4-8": {InPerMTok: 5, OutPerMTok: 25},
		},
	}

	rate, ok := rc.Rate("in-house-7b")
	if !ok {
		t.Fatal("a free model must RESOLVE on the card: an unresolved model is refused " +
			"under a USD cap (403 model_unpriced), which is the opposite of free")
	}
	if !rate.Free {
		t.Error("Rate() dropped the Free flag")
	}

	usd, ok := rc.EstimateUSD("in-house-7b", Usage{
		InputTokens: 5_000_000, OutputTokens: 5_000_000,
		CacheReadTokens: 5_000_000, CacheWriteTokens: 5_000_000,
	})
	if !ok || usd != 0 {
		t.Errorf("EstimateUSD = (%v, %v), want (0, true)", usd, ok)
	}
	if got := WorstCaseCostUSD(rc, "in-house-7b", 1_000_000, 64_000); got != 0 {
		t.Errorf("WorstCaseCostUSD = %v, want 0", got)
	}
	// The family-prefix fallback carries the flag too, so a dated release of a
	// free model is free.
	if r, ok := rc.Rate("in-house-7b-20260114"); !ok || !r.Free {
		t.Errorf("family fallback = (%+v, %v), want the free rate", r, ok)
	}
}

// TestFreeTokenPairWithAPaidCacheRate pins the arithmetic under the WIDENED
// meaning of Free: the flag says the TOKEN PAIR is zero, so a cache rate the
// org still pays is charged exactly as quoted.
//
// It is the half of the P2-3 fix that needs no code change, asserted so a later
// edit to EstimateUSD cannot quietly make the flag load-bearing: the cache-read
// fallback to InPerMTok is reached only when the row quotes NO cache read, and
// on a fully-free row that fallback is itself zero.
func TestFreeTokenPairWithAPaidCacheRate(t *testing.T) {
	rc := RateCard{
		Version: "org-pricing-v12",
		Rates: map[string]ModelRate{
			// Free tokens, a cache surcharge the org still pays.
			"partner-7b": {CacheReadPerMTok: 0.3, CacheWritePerMTok: 3.75, Free: true},
			// Free with nothing quoted: every dollar must be exactly 0.
			"in-house-7b": {Free: true},
		},
	}
	if err := ValidateRateCard(rc); err != nil {
		t.Fatalf("ValidateRateCard = %v, want nil", err)
	}

	usd, ok := rc.EstimateUSD("partner-7b", Usage{
		InputTokens: 2_000_000, OutputTokens: 2_000_000,
		CacheReadTokens: 1_000_000, CacheWriteTokens: 1_000_000,
	})
	if !ok {
		t.Fatal("EstimateUSD did not resolve a free-token-pair model")
	}
	if want := 0.3 + 3.75; usd != want {
		t.Errorf("EstimateUSD = %v, want %v (the quoted cache rates, and nothing for the free token pair)", usd, want)
	}

	// The cache-read FALLBACK (an unquoted cache read is billed at the input
	// rate) still yields zero on a fully-free row, because the input rate it
	// falls back to is zero.
	usd, ok = rc.EstimateUSD("in-house-7b", Usage{CacheReadTokens: 9_000_000})
	if !ok || usd != 0 {
		t.Errorf("EstimateUSD on a fully-free row = (%v, %v), want (0, true)", usd, ok)
	}

	// The USD worst case reserves nothing for a free token pair, whatever the
	// cache rates say: it prices input and output only.
	if got := WorstCaseCostUSD(rc, "partner-7b", 1_000_000, 64_000); got != 0 {
		t.Errorf("WorstCaseCostUSD = %v, want 0", got)
	}
}

// TestModelRateFreeJSONRoundTrip pins the stored-card compatibility both ways.
// The card lives in gw_rate_card as JSON, so an OLD document (no `free` key)
// must decode to a not-free row, and a free row must not emit the key for
// every ordinary priced model.
func TestModelRateFreeJSONRoundTrip(t *testing.T) {
	var old ModelRate
	if err := json.Unmarshal([]byte(`{"in_per_mtok":3,"out_per_mtok":15}`), &old); err != nil {
		t.Fatalf("decode a pre-free card row: %v", err)
	}
	if old.Free {
		t.Error("a row with no `free` key decoded as free")
	}

	b, err := json.Marshal(ModelRate{InPerMTok: 3, OutPerMTok: 15})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if strings.Contains(string(b), "free") {
		t.Errorf("a priced row serialized %s; `free` must be omitempty so an old "+
			"gateway binary sees a byte-identical document", b)
	}

	b, err = json.Marshal(ModelRate{Free: true})
	if err != nil {
		t.Fatalf("encode free: %v", err)
	}
	var back ModelRate
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("decode free: %v", err)
	}
	if !back.Free {
		t.Errorf("free row round-tripped as %s -> %+v", b, back)
	}

	// FORWARD compat, which is what decides whether the org server and the
	// gateway image must roll together: a gateway binary built BEFORE the flag
	// has no `free` field, and nothing validates the card on load (only
	// SetRateCard runs ValidateRateCard, and that is the org server's write
	// path). So an old binary decodes the free row as an all-zero rate,
	// resolves it, and prices it at $0 -- the same answer, minus the label.
	// This asserts that reading, so a future change that made the flag
	// LOAD-BEARING in the arithmetic would fail here rather than silently
	// making the two components version-coupled.
	type preFlagRate struct {
		InPerMTok         float64 `json:"in_per_mtok"`
		OutPerMTok        float64 `json:"out_per_mtok"`
		CacheReadPerMTok  float64 `json:"cache_read_per_mtok"`
		CacheWritePerMTok float64 `json:"cache_write_per_mtok"`
	}
	var preFlag preFlagRate
	if err := json.Unmarshal(b, &preFlag); err != nil {
		t.Fatalf("a pre-flag decoder rejected the free row: %v", err)
	}
	if preFlag != (preFlagRate{}) {
		t.Errorf("a pre-flag decoder read the free row as %+v, want every rate zero", preFlag)
	}
}
