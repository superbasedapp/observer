package advisor

import (
	"context"
	"database/sql"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// Options parameterize one engine run.
type Options struct {
	// WindowDays is the evidence window. Zero means the default 14.
	WindowDays int
	// ProjectRoot filters to a single project (matches projects.root_path).
	ProjectRoot string
	// Tool filters to a single AI tool (matches sessions.tool) — mirrors
	// the dashboard's global Tool dropdown.
	Tool string
	// MinConfidence hides suggestions below this floor. Zero means 0.5.
	MinConfidence float64
	// MinSavingsUSD hides cost suggestions claiming less than this. Zero
	// means 1.00 (calibration T7). Time-denominated suggestions pass on
	// SavingsMin instead.
	MinSavingsUSD float64
	// CooldownDays keeps a dismissed/acted dedup_key quiet. Zero means 7
	// (calibration T11).
	CooldownDays int
	// Thresholds override the calibrated defaults; the zero value means
	// DefaultThresholds().
	Thresholds *Thresholds
	// CostEngine prices counterfactuals. Required in production; tests
	// may inject PriceOverride instead.
	CostEngine *cost.Engine
	// PriceOverride, when non-nil, replaces the CostEngine-backed PriceFn
	// (tests).
	PriceOverride PriceFn
	// MCPConfigured tells the E1 detector whether the MCP server is wired
	// into AI clients (callers read it from config — the advisor never
	// reads config files itself).
	MCPConfigured bool
	// GuardMode / RoutingMode carry the effective feature modes from
	// config ("off" when the feature is disabled) — same injection
	// posture as MCPConfigured. Consumed by the X3.1 posture detectors.
	GuardMode   string
	RoutingMode string
	// RoutingShadow is the §R22 advise-shadow gate read for the
	// routing_evidence_ready detector. Callers compute it through
	// store.AdviseShadowSignal (one gate owner; cheap COUNT early-out
	// when no advise history exists). Nil = detector stays silent.
	RoutingShadow *ShadowSignal
	// ContextWindow resolves a model's context window from the Tokenomics
	// data (callers pass store.LoadModelContextWindows(...).Resolve, the
	// same composition routing reads). Nil, or an unknown model, falls
	// back to the observed-window inference in contextWindowOf.
	ContextWindow func(model string) (int64, bool)
	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

func (o Options) withDefaults() Options {
	if o.WindowDays <= 0 {
		o.WindowDays = 14
	}
	if o.MinConfidence <= 0 {
		o.MinConfidence = 0.5
	}
	if o.MinSavingsUSD <= 0 {
		o.MinSavingsUSD = 1.00
	}
	if o.CooldownDays <= 0 {
		o.CooldownDays = 7
	}
	return o
}

// Registry is the ordered detector table. Walked top-down; order is the
// tie-break for equal-savings suggestions.
func Registry() []Detector {
	return []Detector{
		{Key: "session_balloon", Category: CategoryCost, Detect: detectSessionBalloon},
		{Key: "idle_recache", Category: CategoryCost, Detect: detectIdleRecache},
		{Key: "long_context_crossing", Category: CategoryCost, Detect: detectLongContextCrossing},
		{Key: "trivial_model_overprovisioning", Category: CategoryCost, Detect: detectTrivialModelOverprovisioning},
		// Phase 2 — cache strategy, routing depth, hygiene.
		{Key: "cache_hit_rate", Category: CategoryCost, Detect: detectCacheHitRate},
		{Key: "cache_write_waste", Category: CategoryCost, Detect: detectCacheWriteWaste},
		{Key: "prefix_thrash", Category: CategoryCost, Detect: detectPrefixThrash},
		{Key: "read_heavy_expensive_model", Category: CategoryCost, Detect: detectReadHeavyExpensiveModel},
		{Key: "effort_overprovisioning", Category: CategoryCost, Detect: detectEffortOverprovisioning},
		{Key: "fast_tier_premium", Category: CategoryLatency, Detect: detectFastTierPremium},
		{Key: "unrecovered_failure", Category: CategoryQuality, Detect: detectUnrecoveredFailures},
		{Key: "mcp_overhead", Category: CategoryHygiene, Detect: detectMCPOverhead},
		{Key: "compression_off", Category: CategoryHygiene, Detect: detectCompressionOff},
		{Key: "not_proxied", Category: CategoryHygiene, Detect: detectNotProxied},
		// Phase 4 — trends + redundancy long tail.
		{Key: "wasteful_stale_reads", Category: CategoryCost, Detect: detectCrossSessionStaleReads},
		{Key: "quality_regression", Category: CategoryQuality, Detect: detectQualityRegression},
		{Key: "web_search_spend", Category: CategoryCost, Detect: detectWebSearchSpend},
		// P6.12 — the "something changed TODAY" reflex.
		{Key: "spend_spike", Category: CategoryCost, Detect: detectSpendSpike},
		// X3.1 (security/routing usability arc) — posture nudges with
		// navigate-only Actions; the linked surfaces own the evidence
		// and every consent flow.
		{Key: "guard_observe_idle", Category: CategoryHygiene, Detect: detectGuardObserveIdle},
		{Key: "routing_evidence_ready", Category: CategoryCost, Detect: detectRoutingEvidenceReady},
	}
}

// Run loads Facts and walks the registry, returning the filtered, ranked
// report. This is the single seam every surface (dashboard, CLI, MCP)
// calls.
func Run(ctx context.Context, db *sql.DB, opts Options) (Report, error) {
	opts = opts.withDefaults()
	f, err := LoadFacts(ctx, db, opts)
	if err != nil {
		return Report{}, err
	}
	f.Price = opts.priceFn()
	f.LCThreshold = opts.lcThresholdFn()
	f.MCPConfigured = f.MCPConfigured || opts.MCPConfigured
	f.GuardMode = opts.GuardMode
	f.RoutingMode = opts.RoutingMode
	f.RoutingShadow = opts.RoutingShadow
	if opts.ContextWindow != nil {
		for i := range f.Sessions {
			if w, ok := opts.ContextWindow(sessionModelOf(&f.Sessions[i])); ok && w > 0 {
				f.Sessions[i].ContextWindow = w
			}
		}
	}

	th := DefaultThresholds()
	if opts.Thresholds != nil {
		th = *opts.Thresholds
	}

	var all []Suggestion
	for _, d := range Registry() {
		all = append(all, stamp(d.Detect(f, th), f)...)
	}

	// User state: dismissed/acted keys stay quiet for the cooldown;
	// snoozed keys until their snooze elapses. Best-effort (P6): a state
	// read failure must not take down the report.
	muted, err := loadMuted(ctx, db, f.Now, opts.CooldownDays)
	if err != nil {
		muted = nil
	}

	rep := Report{WindowDays: f.WindowDays, GeneratedAt: f.Now.Format(time.RFC3339), SessionsScanned: len(f.Sessions)}
	for _, s := range all {
		if muted[s.DedupKey] {
			continue
		}
		if s.Confidence < opts.MinConfidence {
			continue
		}
		// The savings floor suppresses SMALL dollar claims, not the
		// absence of one: a suggestion claiming nothing (the X3.1
		// navigate-only posture nudges) passes on confidence alone.
		// Every pre-X3.1 detector claims USD or minutes, so this
		// relaxation changes nothing for them.
		if s.SavingsUSD > 0 && s.SavingsMin == 0 && s.SavingsUSD < opts.MinSavingsUSD {
			continue
		}
		rep.Suggestions = append(rep.Suggestions, s)
		rep.TotalSavingsUSD += s.SavingsUSD
		rep.TotalSavingsMin += s.SavingsMin
	}
	sort.SliceStable(rep.Suggestions, func(i, j int) bool {
		return rep.Suggestions[i].SavingsUSD > rep.Suggestions[j].SavingsUSD
	})
	rep.TotalCount = len(rep.Suggestions)
	return rep, nil
}

func (o Options) priceFn() PriceFn {
	if o.PriceOverride != nil {
		return o.PriceOverride
	}
	ce := o.CostEngine
	if ce == nil {
		// Degenerate fallback (P6): no pricing → detectors that need
		// dollars emit nothing rather than wrong numbers.
		return func(string, cost.TokenBundle) (float64, bool) { return 0, false }
	}
	return func(model string, b cost.TokenBundle) (float64, bool) {
		br, ok := ce.ComputeBreakdown(model, b)
		if !ok {
			return 0, false
		}
		return br.Total, true
	}
}

func (o Options) lcThresholdFn() func(string) int64 {
	ce := o.CostEngine
	if ce == nil {
		return func(string) int64 { return 0 }
	}
	return func(model string) int64 {
		p, _, ok := ce.LookupWithSource(model)
		if !ok {
			return 0
		}
		return p.LongContextThreshold
	}
}
