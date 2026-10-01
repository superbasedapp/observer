package cost

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// THE ONE NODE PRICE OWNER (enterprise-pricing plan §3.3 / ruling R13).
//
// Before this arc, 38 constructors each built their own table from the seed
// plus local TOML. The org's negotiated rates are now an INPUT to that same
// build rather than a patch applied to one lucky instance, which is what makes
// "the proxy, the push-time pricer, the dashboard and `observer cost` agree"
// a property of the constructor instead of a thing every call site must
// remember.

// orgRow is a row QUOTING an input and an output rate and nothing else. Since
// server migration 135 "quoting" is a fact the row carries (OrgPriceSet), so a
// helper that set the numbers and forgot the flags would build a row the
// engine correctly refuses.
func orgRow(model string, in, out float64) OrgPrice {
	return OrgPrice{
		Model:   model,
		Pricing: Pricing{Input: in, Output: out},
		Set:     OrgPriceSet{Input: true, Output: true},
	}
}

// quotedInputOutput is orgRow's flag half, for the literals that need to state
// their own dates or rates.
var quotedInputOutput = OrgPriceSet{Input: true, Output: true}

// seedPricedModel is a model the COMPILED seed table prices with a cache-read
// rate, so the fall-through pin has something real to fall through to. The
// test asserts both facts about it rather than assuming them, so a seed-table
// edit fails loudly instead of making the pin vacuous.
const seedPricedModel = "claude-sonnet-4-5"

func localCfg(model string, in, out float64) config.IntelligenceConfig {
	return config.IntelligenceConfig{
		Pricing: config.PricingConfig{
			Models: map[string]config.ModelPricing{
				model: {Input: in, Output: out},
			},
		},
	}
}

// The precedence table: every combination of (tenancy, local override
// present?, org row present?) with the rate that must win and why.
func TestOrgPricePrecedence(t *testing.T) {
	t.Parallel()
	const model = "claude-opus-4-8"
	seed, seedOK := NewTable().Lookup(model)
	if !seedOK || seed.Input == 0 {
		t.Fatalf("fixture assumption broken: the seed table does not price %s", model)
	}

	cases := []struct {
		name          string
		authoritative bool
		cfg           config.IntelligenceConfig
		org           []OrgPrice
		wantInput     float64
		wantSource    PricingSource
		why           string
	}{
		{
			name:       "no org rows and no override leaves the seed alone",
			wantInput:  seed.Input,
			wantSource: PricingSourceExact,
			why:        "an individual node with no org and no config must be byte-identical to a pre-arc node",
		},
		{
			name:       "an org row replaces the seed",
			org:        []OrgPrice{orgRow(model, 1.5, 7)},
			wantInput:  1.5,
			wantSource: PricingSourceOrg,
			why:        "the whole point of the arc: the org's negotiated rate is what the fleet prices at",
		},
		{
			name:       "an INDIVIDUAL node's explicit local override beats the org",
			cfg:        localCfg(model, 0.25, 1),
			org:        []OrgPrice{orgRow(model, 1.5, 7)},
			wantInput:  0.25,
			wantSource: PricingSourceLocal,
			why:        "ruling R3: a developer who typed a rate on their own machine meant it, and an individual node is not managed",
		},
		{
			name:          "a MANAGED authoritative node's org rate beats the local override",
			authoritative: true,
			cfg:           localCfg(model, 0.25, 1),
			org:           []OrgPrice{orgRow(model, 1.5, 7)},
			wantInput:     1.5,
			wantSource:    PricingSourceOrg,
			why:           "ruling R3 the other way: a developer must not be able to re-price their way under an org cap",
		},
		{
			name:          "a managed node with no org row still honours its local override",
			authoritative: true,
			cfg:           localCfg(model, 0.25, 1),
			wantInput:     0.25,
			wantSource:    PricingSourceLocal,
			why:           "authoritative means the org WINS where it spoke, not that it silences the node where it did not",
		},
		{
			name:       "an org row for a model the seed never priced is still applied",
			org:        []OrgPrice{orgRow("acme-private-llm-1", 9, 30)},
			wantInput:  seed.Input,
			wantSource: PricingSourceExact,
			why:        "the other models are untouched; the added key is checked separately below",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(tc.cfg)
			e.SetOrgRows(tc.org, 3, tc.authoritative)
			p, src, ok := e.LookupWithSource(model)
			if !ok {
				t.Fatalf("lookup missed %s", model)
			}
			if p.Input != tc.wantInput {
				t.Errorf("input = %v, want %v — %s", p.Input, tc.wantInput, tc.why)
			}
			if src != tc.wantSource {
				t.Errorf("source = %q, want %q — a surface must be able to say WHOSE rate this is", src, tc.wantSource)
			}
		})
	}

	// The added-key case from the table above, checked on its own key.
	e := NewEngine(config.IntelligenceConfig{})
	e.SetOrgRows([]OrgPrice{orgRow("acme-private-llm-1", 9, 30)}, 1, false)
	p, src, ok := e.LookupWithSource("acme-private-llm-1")
	if !ok || p.Input != 9 || src != PricingSourceOrg {
		t.Errorf("an org row for a model the seed never heard of did not land: %v %q %v", p, src, ok)
	}
}

// F3, the finding this whole seam exists for: Reload rebuilds the table from
// the seed, so before the arc an org rate applied to a live engine would be
// silently reverted the next time the Settings page saved a config.
func TestReloadKeepsTheOrgRates(t *testing.T) {
	t.Parallel()
	const model = "gpt-5.6"
	e := NewEngine(config.IntelligenceConfig{})
	e.SetOrgRows([]OrgPrice{orgRow(model, 0.9, 3)}, 5, false)

	before, _ := e.Lookup(model)
	// Exactly what PUT /api/config/pricing does.
	e.Reload(localCfg("some-other-model", 1, 2))
	after, src, _ := e.LookupWithSource(model)

	if before.Input != 0.9 || after.Input != 0.9 {
		t.Fatalf("org rate did not survive Reload: before=%v after=%v — a config save would silently revert the fleet to list prices",
			before.Input, after.Input)
	}
	if src != PricingSourceOrg {
		t.Errorf("source after Reload = %q, want org", src)
	}
	if e.OrgPricingVersion() != 5 {
		t.Errorf("org pricing version = %d, want 5", e.OrgPricingVersion())
	}
}

// The constructor seam: a standalone CLI command must price the way the daemon
// does, which it can only do by reading the same persisted document.
func TestWithOrgRowsLoads(t *testing.T) {
	t.Parallel()
	const model = "gpt-5.6"
	e := NewEngine(config.IntelligenceConfig{}, WithOrgRows(func() (OrgRows, bool) {
		return OrgRows{Rows: []OrgPrice{orgRow(model, 0.42, 2)}, Version: 11}, true
	}))
	p, src, ok := e.LookupWithSource(model)
	if !ok || p.Input != 0.42 || src != PricingSourceOrg {
		t.Fatalf("WithOrgRows did not apply: %v %q %v", p, src, ok)
	}
	if e.OrgPricingVersion() != 11 {
		t.Errorf("version = %d, want 11", e.OrgPricingVersion())
	}
}

// A loader that fails leaves the engine on the seed table. It must NOT leave
// it on an empty table: an engine that priced everything at zero would make
// every budget look unspent.
func TestWithOrgRowsLoaderFailureKeepsTheSeed(t *testing.T) {
	t.Parallel()
	const model = "claude-opus-4-8"
	seed, _ := NewTable().Lookup(model)

	e := NewEngine(config.IntelligenceConfig{}, WithOrgRows(func() (OrgRows, bool) {
		return OrgRows{}, false
	}))
	p, src, ok := e.LookupWithSource(model)
	if !ok || p.Input != seed.Input {
		t.Fatalf("a failed org load moved the seed rate: %v (want %v)", p.Input, seed.Input)
	}
	if src == PricingSourceOrg {
		t.Error("a failed org load reported the rate as org-sourced")
	}
	if e.OrgPricingVersion() != 0 {
		t.Errorf("version = %d, want 0 after a failed load", e.OrgPricingVersion())
	}
}

// effective_from is resolved at BUILD time, once, so the flat table stays flat
// (F13): a future-dated org rate is not in force, and the newest already-started
// one is.
func TestOrgRowsFlattenAtBuildTime(t *testing.T) {
	t.Parallel()
	const model = "acme-1"
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	e := NewEngine(config.IntelligenceConfig{}, withClock(func() time.Time { return now }))
	e.SetOrgRows([]OrgPrice{
		{Model: model, EffectiveFrom: "", Pricing: Pricing{Input: 1, Output: 4}, Set: quotedInputOutput},
		{Model: model, EffectiveFrom: "2026-09-01", Pricing: Pricing{Input: 2, Output: 8}, Set: quotedInputOutput},
		{Model: model, EffectiveFrom: "2027-01-01", Pricing: Pricing{Input: 9, Output: 36}, Set: quotedInputOutput},
	}, 1, false)

	p, ok := e.Lookup(model)
	if !ok || p.Input != 2 {
		t.Fatalf("input = %v (ok=%v), want the row in force (2), never the undated 1 nor the future 9", p.Input, ok)
	}
	// The un-dated Lookup and the dated LookupAt agree TODAY: the flat rate is
	// the period in force now.
	if cur, _ := e.LookupAt(model, now); cur.Input != 2 {
		t.Errorf("LookupAt(now) = %v, want the row in force (2), the same answer Lookup gives", cur.Input)
	}
	// And a historical question is answered by the row in force THEN: the
	// document states this model's history (undated 1, then 2 from
	// 2026-09-01), so 400 days back is the undated row's 1, never the dated
	// row reaching back before its own date (PRICE-REPRICE-1 review finding 1).
	at, _ := e.LookupAt(model, now.AddDate(0, 0, -400))
	if at.Input != 1 {
		t.Errorf("LookupAt(-400d) = %v, want the undated row in force then (1)", at.Input)
	}
	if fut, _ := e.LookupAt(model, time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)); fut.Input != 9 {
		t.Errorf("LookupAt(2027-02) = %v, want the stated future row (9) at its instant", fut.Input)
	}
}

// A refused org row is REPORTED, never silently dropped: an admin who typed a
// rate must be able to find out it did not apply.
func TestPricingWarningsReportRefusedOrgRows(t *testing.T) {
	t.Parallel()
	e := NewEngine(config.IntelligenceConfig{})
	e.SetOrgRows([]OrgPrice{
		{Model: "", Pricing: Pricing{Input: 1, Output: 2}, Set: quotedInputOutput},
		// QUOTES nothing: every field would fall through, so the row asserts
		// nothing at all. Distinct from a row quoting two ZEROS, which is a
		// negotiated free model and IS applied - see
		// TestOrgFreeRateIsAppliedAndUnquotedRatesFallThrough.
		{Model: "zero-rate", Pricing: Pricing{}},
		{Model: "negative", Pricing: Pricing{Input: -1, Output: 2}, Set: quotedInputOutput},
		orgRow("fine", 1, 2),
	}, 1, false)

	warns := strings.Join(e.PricingWarnings(), "\n")
	for _, want := range []string{"zero-rate", "negative"} {
		if !strings.Contains(warns, want) {
			t.Errorf("warnings %q do not name the refused row %q", warns, want)
		}
	}
	if _, ok := e.Lookup("zero-rate"); ok {
		t.Error("a row quoting NO rate was applied; it asserts nothing and would shadow the seed with a miss")
	}
	if p, ok := e.Lookup("fine"); !ok || p.Input != 1 {
		t.Error("a good row was dropped alongside the bad ones — a refusal must be per row")
	}
}

// A model the ORG priced by FAMILY still reports org provenance. The
// reliability rung ("did we identify this SKU") is real, but for an org row it
// is subordinate: an org that authored "claude-opus-4" authored it AS a family
// rate deliberately, and rendering the resulting match as an approximation
// would misdescribe a number the org itself chose.
func TestOrgProvenanceSurvivesTheFamilyRung(t *testing.T) {
	t.Parallel()
	e := NewEngine(config.IntelligenceConfig{})
	e.SetOrgRows([]OrgPrice{orgRow("acme-family", 3, 12)}, 1, false)
	p, src, ok := e.LookupWithSource("acme-family-turbo-20260901")
	if !ok || p.Input != 3 {
		t.Fatalf("family fallback onto an org row missed: %v %v", p, ok)
	}
	if src != PricingSourceOrg {
		t.Errorf("source = %q, want org", src)
	}
}

// TestOrgFreeRateIsAppliedAndUnquotedRatesFallThrough is the node half of the
// server migration 135 cut-over, walked as a table over BOTH tenancy ladders
// so neither one can quietly disagree with the other.
//
// The two things it pins are the two halves of the same distinction:
//
//   - a rate the org QUOTED wins even at zero (a negotiated free model), and
//     the lookup reports the ORG as its source, not the seed;
//   - a rate the org did NOT quote falls through to whatever this node would
//     otherwise have priced it at. Before 135 that was inexpressible: a nil
//     and a zero were the same value, so an org quoting only an input rate
//     silently zeroed the model's cache rates.
func TestOrgFreeRateIsAppliedAndUnquotedRatesFallThrough(t *testing.T) {
	t.Parallel()
	const model = "acme-partial-1"

	// The node's own explicit override is the "next precedence level" an
	// unquoted org rate must fall through to on an AUTHORITATIVE node, and
	// the thing an org rate must NOT displace on an individual one.
	local := config.IntelligenceConfig{}
	local.Pricing.Models = map[string]config.ModelPricing{
		model: {Input: 8, Output: 40, CacheRead: 0.8, CacheCreation: 10},
	}

	// The org quotes input FREE and output at 4, and says nothing at all
	// about either cache rate.
	orgFree := OrgPrice{
		Model:   model,
		Pricing: Pricing{Input: 0, Output: 4},
		Set:     OrgPriceSet{Input: true, Output: true},
	}

	cases := []struct {
		name          string
		authoritative bool
		wantInput     float64
		wantOutput    float64
		wantCacheRead float64
		wantSource    PricingSource
	}{
		{
			// MANAGED + enforce.budget: the org lands last and wins, so the
			// free input rate applies and the unquoted cache read falls
			// through to the developer's own number rather than to zero.
			name:          "authoritative: a quoted free rate wins, an unquoted one inherits the local override",
			authoritative: true,
			wantInput:     0,
			wantOutput:    4,
			wantCacheRead: 0.8,
			wantSource:    PricingSourceOrg,
		},
		{
			// INDIVIDUAL: the developer's explicit override wins outright, so
			// the org row is not applied at all and the key is not org-owned.
			name:          "individual: the developer's own override still wins outright",
			authoritative: false,
			wantInput:     8,
			wantOutput:    40,
			wantCacheRead: 0.8,
			wantSource:    PricingSourceLocal,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(local)
			e.SetOrgRows([]OrgPrice{orgFree}, 3, tc.authoritative)
			p, src, ok := e.LookupWithSource(model)
			if !ok {
				t.Fatal("lookup missed a model the org priced")
			}
			if p.Input != tc.wantInput {
				t.Errorf("input = %v, want %v", p.Input, tc.wantInput)
			}
			if p.Output != tc.wantOutput {
				t.Errorf("output = %v, want %v", p.Output, tc.wantOutput)
			}
			if p.CacheRead != tc.wantCacheRead {
				t.Errorf("cache read = %v, want %v (an UNQUOTED org rate must fall through, never zero the model)",
					p.CacheRead, tc.wantCacheRead)
			}
			if src != tc.wantSource {
				t.Errorf("source = %q, want %q", src, tc.wantSource)
			}
		})
	}
}

// TestOrgUnquotedRateFallsThroughToTheSeed is the same fall-through against
// the compiled SEED table rather than a local override, which is the ordinary
// case: almost no developer authors a per-model rate, so "the next precedence
// level" is the vendor's list price.
func TestOrgUnquotedRateFallsThroughToTheSeed(t *testing.T) {
	t.Parallel()
	e := NewEngine(config.IntelligenceConfig{})
	seed, ok := e.Lookup(seedPricedModel)
	if !ok {
		t.Fatalf("the seed table does not price %q; pick another model for this pin", seedPricedModel)
	}
	if seed.CacheRead == 0 {
		t.Fatalf("the seed rate for %q has no cache read; the fall-through would be vacuous", seedPricedModel)
	}

	e.SetOrgRows([]OrgPrice{{
		Model:   seedPricedModel,
		Pricing: Pricing{Input: 0},
		Set:     OrgPriceSet{Input: true},
	}}, 1, false)

	got, src, ok := e.LookupWithSource(seedPricedModel)
	if !ok {
		t.Fatal("lookup missed a model the org priced")
	}
	if got.Input != 0 {
		t.Errorf("input = %v, want 0 - a QUOTED free rate is a rate", got.Input)
	}
	if got.Output != seed.Output {
		t.Errorf("output = %v, want the seed's %v - an unquoted rate falls through", got.Output, seed.Output)
	}
	if got.CacheRead != seed.CacheRead {
		t.Errorf("cache read = %v, want the seed's %v", got.CacheRead, seed.CacheRead)
	}
	if src != PricingSourceOrg {
		t.Errorf("source = %q, want %q - the org owns the key it authored, free or not", src, PricingSourceOrg)
	}
}

// TestOrgPriceOverlayPresenceSemantics pins the ONE overlay rule shared by the
// seed snapshot, the standalone feed and the org document (rework 2026-09-23,
// coordinator ruling): a STATED peak / positive threshold / Set fast
// multiplier replaces the seed's; an unstated one KEEPS it. This supersedes the
// earlier peak-off-peak §R2 R1/N2 "a nil org peak wipes the seed's peak" pin -
// omission must never clear seed values.
func TestOrgPriceOverlayPresenceSemantics(t *testing.T) {
	t.Parallel()
	seedPeak := &PeakRates{
		RateSet: RateSet{Input: 20, Output: 40, LongContextThreshold: 128000, LongContextInput: 30},
		Schedule: PeakSchedule{Windows: []PeakWindow{
			{Days: []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday}, StartUTC: "00:00", EndUTC: "16:00"},
		}},
	}
	base := Pricing{Input: 5, Output: 10, LongContextThreshold: 128000, LongContextInput: 12, Peak: seedPeak, FastMultiplier: 2}
	orgPeak := &PeakRates{
		RateSet:  RateSet{Input: 3, Output: 6},
		Schedule: PeakSchedule{Windows: []PeakWindow{{Days: []time.Weekday{time.Saturday}, StartUTC: "01:00", EndUTC: "02:00"}}},
	}

	for _, tc := range []struct {
		name          string
		org           OrgPrice
		wantPeak      *PeakRates
		wantThreshold int64
		wantFast      float64
	}{
		{
			name:          "a stated org peak and threshold replace the seed's",
			org:           OrgPrice{Pricing: Pricing{Input: 1, Output: 2, LongContextThreshold: 500, Peak: orgPeak}, Set: OrgPriceSet{Input: true, Output: true, LongContextThreshold: true, Peak: true}},
			wantPeak:      orgPeak,
			wantThreshold: 500,
			wantFast:      2,
		},
		{
			name:          "an unstated peak, threshold and fast multiplier keep the seed's",
			org:           OrgPrice{Pricing: Pricing{Input: 1, Output: 2}, Set: OrgPriceSet{Input: true, Output: true}},
			wantPeak:      seedPeak,
			wantThreshold: 128000,
			wantFast:      2,
		},
		{
			// Values present but NOT marked quoted: a projection that could
			// not tell absence from zero leaves them unset, so they never
			// erase the seed's.
			name:          "unflagged threshold/peak values are not quoted",
			org:           OrgPrice{Pricing: Pricing{Input: 1, Output: 2, LongContextThreshold: 500, Peak: orgPeak}, Set: OrgPriceSet{Input: true, Output: true}},
			wantPeak:      seedPeak,
			wantThreshold: 128000,
			wantFast:      2,
		},
		{
			// (d) at the overlay: a QUOTED threshold of 0 = negotiated flat.
			name:          "a quoted threshold of 0 removes the seed's long-context tier",
			org:           OrgPrice{Pricing: Pricing{Input: 1, Output: 2}, Set: OrgPriceSet{Input: true, Output: true, LongContextThreshold: true}},
			wantPeak:      seedPeak,
			wantThreshold: 0,
			wantFast:      2,
		},
		{
			// (e) at the overlay: the §R2 R1/N2 case, kept for the explicit
			// statement - a quoted empty peak clears the seed's peak.
			name:          "a quoted empty peak clears the seed's peak",
			org:           OrgPrice{Pricing: Pricing{Input: 1, Output: 2, Peak: &PeakRates{}}, Set: OrgPriceSet{Input: true, Output: true, Peak: true}},
			wantPeak:      nil,
			wantThreshold: 128000,
			wantFast:      2,
		},
		{
			name:          "a quoted nil peak also clears it",
			org:           OrgPrice{Pricing: Pricing{Input: 1, Output: 2}, Set: OrgPriceSet{Input: true, Output: true, Peak: true}},
			wantPeak:      nil,
			wantThreshold: 128000,
			wantFast:      2,
		},
		{
			name:          "a Set fast multiplier wins, a quoted 0 included",
			org:           OrgPrice{Pricing: Pricing{Input: 1, Output: 2, FastMultiplier: 0}, Set: OrgPriceSet{Input: true, Output: true, FastMultiplier: true}},
			wantPeak:      seedPeak,
			wantThreshold: 128000,
			wantFast:      0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.org.overlay(base)
			if out.Peak != tc.wantPeak {
				t.Errorf("Peak = %+v, want %+v (identity)", out.Peak, tc.wantPeak)
			}
			if out.LongContextThreshold != tc.wantThreshold {
				t.Errorf("LongContextThreshold = %d, want %d", out.LongContextThreshold, tc.wantThreshold)
			}
			if out.FastMultiplier != tc.wantFast {
				t.Errorf("FastMultiplier = %v, want %v", out.FastMultiplier, tc.wantFast)
			}
			// An unquoted long-context rate keeps the seed's - EXCEPT under a
			// quoted FLAT threshold (0), which clears the whole tier, rates
			// included (the 2026-09-30 ruling: no tier = flat).
			wantLC := 12.0
			if tc.org.Set.LongContextThreshold && tc.org.LongContextThreshold == 0 {
				wantLC = 0
			}
			if out.LongContextInput != wantLC {
				t.Errorf("unquoted LongContextInput = %v, want %v", out.LongContextInput, wantLC)
			}
		})
	}
}

// TestOrgRows_NegotiatedInputOutputKeepsSeedTiers is coordinator test (a): an
// org NEGOTIATED row for gpt-6-astra quoting only input/output, composed on an
// authoritative (managed) node AND an individual node, leaves the seed's
// >272K long-context tier and 2x fast multiplier in force - and they still
// reprice a long prompt / fast turn.
func TestOrgRows_NegotiatedInputOutputKeepsSeedTiers(t *testing.T) {
	t.Parallel()
	seed, _ := NewTable().Lookup("gpt-6-astra")
	if seed.LongContextThreshold != 272_000 || seed.FastMultiplier != 2 {
		t.Fatalf("precondition: seed gpt-6-astra = %+v", seed)
	}
	row := OrgPrice{
		Model: "gpt-6-astra", Pricing: Pricing{Input: 8, Output: 40},
		Set: OrgPriceSet{Input: true, Output: true},
	}
	for _, authoritative := range []bool{true, false} {
		e := NewEngine(config.IntelligenceConfig{})
		e.SetOrgRows([]OrgPrice{row}, 3, authoritative)
		p, src, ok := e.LookupWithSource("gpt-6-astra")
		if !ok || src != PricingSourceOrg || p.Input != 8 || p.Output != 40 {
			t.Fatalf("authoritative=%v: %+v %q %v, want the negotiated 8/40 at source org", authoritative, p, src, ok)
		}
		if p.LongContextThreshold != 272_000 || p.LongContextInput != seed.LongContextInput || p.LongContextOutput != seed.LongContextOutput {
			t.Errorf("authoritative=%v: LC tier cleared: %+v", authoritative, p)
		}
		if p.FastMultiplier != 2 {
			t.Errorf("authoritative=%v: FastMultiplier = %v, want the seed's 2", authoritative, p.FastMultiplier)
		}
		if bd, _ := e.ComputeBreakdown("gpt-6-astra", TokenBundle{Input: 300_000}); bd.InputCost < 300_000*seed.LongContextInput/1e6-1e-9 {
			t.Errorf("authoritative=%v: a 300K prompt billed %v, want the long-context input rate", authoritative, bd.InputCost)
		}
	}
}

// TestOrgRows_StatedThresholdStillOverrides is coordinator test (c): a row
// that EXPLICITLY states a long-context threshold (and LC rates) still wins.
func TestOrgRows_StatedThresholdStillOverrides(t *testing.T) {
	t.Parallel()
	e := NewEngine(config.IntelligenceConfig{})
	e.SetOrgRows([]OrgPrice{{
		Model: "gpt-6-astra",
		Pricing: Pricing{
			Input: 8, Output: 40, LongContextThreshold: 500_000, LongContextInput: 16,
		},
		Set: OrgPriceSet{Input: true, Output: true, LongContextInput: true, LongContextThreshold: true},
	}}, 4, true)
	p, _ := e.Lookup("gpt-6-astra")
	if p.LongContextThreshold != 500_000 || p.LongContextInput != 16 {
		t.Errorf("stated threshold/LC input = %d/%v, want 500000/16", p.LongContextThreshold, p.LongContextInput)
	}
	seed, _ := NewTable().Lookup("gpt-6-astra")
	if p.LongContextOutput != seed.LongContextOutput {
		t.Errorf("unquoted LC output = %v, want the seed's %v", p.LongContextOutput, seed.LongContextOutput)
	}
}

// TestOrgRows_QuotedZeroThresholdFlattensTier is test (d): an org row that
// QUOTES a long-context threshold of 0 (negotiated flat) removes the seed's
// >272K tier for gpt-6-astra, so a 300K prompt bills at the base rate.
func TestOrgRows_QuotedZeroThresholdFlattensTier(t *testing.T) {
	t.Parallel()
	e := NewEngine(config.IntelligenceConfig{})
	e.SetOrgRows([]OrgPrice{{
		Model:   "gpt-6-astra",
		Pricing: Pricing{Input: 8, Output: 40, LongContextThreshold: 0},
		Set:     OrgPriceSet{Input: true, Output: true, LongContextThreshold: true},
	}}, 5, true)
	p, _ := e.Lookup("gpt-6-astra")
	if p.LongContextThreshold != 0 {
		t.Fatalf("threshold = %d, want 0 (quoted flat)", p.LongContextThreshold)
	}
	if bd, _ := e.ComputeBreakdown("gpt-6-astra", TokenBundle{Input: 300_000}); math.Abs(bd.InputCost-300_000*8/1e6) > 1e-9 {
		t.Errorf("300K prompt input = %v, want the flat base rate %v", bd.InputCost, 300_000*8/1e6)
	}
}

// TestOrgRows_QuotedEmptyPeakClearsSeedPeak is test (e), the kept §R2 R1/N2
// case: an org row with an EXPLICIT empty peak for deepseek-v4-pro (negotiated
// flat) clears the seed's peak, so a peak-window instant bills the org's base.
func TestOrgRows_QuotedEmptyPeakClearsSeedPeak(t *testing.T) {
	t.Parallel()
	peakAt := time.Date(2026, 9, 23, 2, 0, 0, 0, time.UTC) // Wednesday 02:00 UTC, inside the seed's window
	seed, _ := NewTable().LookupAt("deepseek-v4-pro", peakAt)
	if seed.Input != 1.32 {
		t.Fatalf("precondition: seed peak input = %v, want 1.32", seed.Input)
	}
	for _, tc := range []struct {
		name     string
		set      OrgPriceSet
		peak     *PeakRates
		wantPeak bool
		wantIn   float64
	}{
		{"explicit empty peak = flat", OrgPriceSet{Input: true, Output: true, Peak: true}, &PeakRates{}, false, 0.50},
		{"omitted peak keeps the seed's", OrgPriceSet{Input: true, Output: true}, nil, true, 1.32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(config.IntelligenceConfig{})
			e.SetOrgRows([]OrgPrice{{
				Model: "deepseek-v4-pro", Pricing: Pricing{Input: 0.50, Output: 1.50, Peak: tc.peak}, Set: tc.set,
			}}, 6, true)
			flat, _ := e.Lookup("deepseek-v4-pro")
			if (flat.Peak != nil) != tc.wantPeak {
				t.Errorf("Peak present = %v, want %v", flat.Peak != nil, tc.wantPeak)
			}
			if p, _ := e.LookupAt("deepseek-v4-pro", peakAt); p.Input != tc.wantIn {
				t.Errorf("input at a peak instant = %v, want %v", p.Input, tc.wantIn)
			}
		})
	}
}
