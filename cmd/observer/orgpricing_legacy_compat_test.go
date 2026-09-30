package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// legacyPricingPolicyRow is orgcontract.PricingPolicyRow as it was BEFORE the
// nullable long-context threshold (b922604c2^), copied field for field so this
// test can speak for an org server that predates it. The only differences
// from today's wire row are the bare `int64,omitempty` threshold (so a 0 is
// never on the wire) and the absence of the two `*_unquoted` markers.
type legacyPricingPolicyRow struct {
	Model string `json:"model"`

	InputPerMTok        *float64 `json:"input_per_mtok,omitempty"`
	OutputPerMTok       *float64 `json:"output_per_mtok,omitempty"`
	CacheReadPerMTok    *float64 `json:"cache_read_per_mtok,omitempty"`
	CacheWritePerMTok   *float64 `json:"cache_write_per_mtok,omitempty"`
	CacheWrite1hPerMTok *float64 `json:"cache_write_1h_per_mtok,omitempty"`

	LongContextThreshold           int64    `json:"long_context_threshold,omitempty"`
	LongContextInputPerMTok        *float64 `json:"long_context_input_per_mtok,omitempty"`
	LongContextOutputPerMTok       *float64 `json:"long_context_output_per_mtok,omitempty"`
	LongContextCacheReadPerMTok    *float64 `json:"long_context_cache_read_per_mtok,omitempty"`
	LongContextCacheWritePerMTok   *float64 `json:"long_context_cache_write_per_mtok,omitempty"`
	LongContextCacheWrite1hPerMTok *float64 `json:"long_context_cache_write_1h_per_mtok,omitempty"`

	WebSearchPerRequest *float64 `json:"web_search_per_request,omitempty"`

	EffectiveFrom string `json:"effective_from,omitempty"`
	Source        string `json:"source,omitempty"`

	Peak *orgcontract.PeakRates `json:"peak,omitempty"`
}

// TestOrgRail_OldServerDocumentBillsLikeTheOldNode pins the OLD-SERVER ->
// NEW-NODE direction of review finding F1 (session 3, 2026-09-26).
//
// A server built before the nullable threshold serialises its NOT NULL
// DEFAULT 0 threshold as an OMITTED field, and never writes a peak for a row
// whose peak_json is NULL. The node that server was built with
// (b922604c2^:internal/intelligence/cost/orgprice.go:127) overlaid BOTH
// unconditionally: an org row's threshold 0 turned the seed's long-context
// tier OFF, and its nil peak cleared the seed's peak. A new node reading the
// same bytes must bill exactly the same, or upgrading only the node silently
// re-tiers every negotiated price the org has.
func TestOrgRail_OldServerDocumentBillsLikeTheOldNode(t *testing.T) {
	legacy := []legacyPricingPolicyRow{
		// A negotiated flat price for a model whose seed has a 272K tier.
		{Model: "gpt-6-astra", InputPerMTok: orgcontract.Rate(1), OutputPerMTok: orgcontract.Rate(2)},
		// A negotiated price for a model whose seed has a peak schedule.
		{Model: "deepseek-v4-pro", InputPerMTok: orgcontract.Rate(0.50), OutputPerMTok: orgcontract.Rate(1.50)},
		// A stated positive tier, which both builds honour identically.
		{Model: "gpt-6-sol", InputPerMTok: orgcontract.Rate(3), OutputPerMTok: orgcontract.Rate(9), LongContextThreshold: 500_000, LongContextInputPerMTok: orgcontract.Rate(6)},
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy rows: %v", err)
	}
	var wire []orgcontract.PricingPolicyRow
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("new node decoding a legacy document: %v", err)
	}

	e := cost.NewEngine(config.IntelligenceConfig{})
	if seed, _ := e.Lookup("gpt-6-astra"); seed.LongContextThreshold != 272_000 {
		t.Fatalf("precondition: gpt-6-astra seed threshold = %d, want 272000", seed.LongContextThreshold)
	}
	if seed, _ := e.Lookup("deepseek-v4-pro"); seed.Peak == nil {
		t.Fatal("precondition: deepseek-v4-pro seed has no peak")
	}
	e.SetOrgRows(orgPriceRowsOf(wire), 7, true)

	astra, _ := e.Lookup("gpt-6-astra")
	if astra.LongContextThreshold != 0 {
		t.Errorf("gpt-6-astra threshold = %d, want 0: the old node read the legacy omitted threshold as the row's 0 and flattened the tier", astra.LongContextThreshold)
	}
	ds, _ := e.Lookup("deepseek-v4-pro")
	if ds.Peak != nil {
		t.Errorf("deepseek-v4-pro kept the seed's peak %+v: the old node REPLACED it with the row's nil (flat)", ds.Peak)
	}
	peakAt := time.Date(2026, 9, 23, 2, 0, 0, 0, time.UTC) // inside the seed's peak window
	if p, _ := e.LookupAt("deepseek-v4-pro", peakAt); p.Input != 0.50 {
		t.Errorf("deepseek-v4-pro input at a seed-peak instant = %v, want the org's flat 0.50", p.Input)
	}
	sol, _ := e.Lookup("gpt-6-sol")
	if sol.LongContextThreshold != 500_000 || sol.LongContextInput != 6 {
		t.Errorf("gpt-6-sol = (%d, %v), want the stated (500000, 6)", sol.LongContextThreshold, sol.LongContextInput)
	}
}
