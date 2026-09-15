package cost

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// DefaultBlendedInputRate is the fallback $/1M used when the install
// has no usable api_turns history (no proxy traffic yet, or all the
// observed models lack pricing entries). Set to claude-sonnet-4's
// input rate as a reasonable middle-of-the-road default — Anthropic
// pricing as of 2026-04.
const DefaultBlendedInputRate = 3.0

// ErrPricingTableChanged means an enforcement callback was given a table
// snapshot that is no longer the engine's published table.
var ErrPricingTableChanged = errors.New("cost: pricing table changed")

// ErrPricingTableDeadlineRequired means a pricing-table fence was requested
// without a bounded context. Holding the publication lock across an
// unbounded callback could indefinitely delay a table refresh.
var ErrPricingTableDeadlineRequired = errors.New("cost: pricing table fence requires a deadline")

// Engine computes costs from tokens using a Pricing Table plus the spec §24
// reliability matrix. The table is held behind atomic.Pointer so the
// dashboard's Settings page can hot-reload pricing edits without
// restarting the daemon — in-flight Lookup callers keep their snapshot
// of the old table, fresh callers see the new one.
type Engine struct {
	table    atomic.Pointer[Table]
	warnings atomic.Pointer[[]string]
	// rebuildMu serializes config/org input changes with table publication. A
	// single publisher cannot replace a newer org document with an older table
	// built concurrently by a config reload.
	rebuildMu sync.Mutex
	// cfg is the LAST config the table was built from. It is held so
	// SetOrgRows can re-compose without a caller having to hand back a config
	// it may not have: the org push loop knows about rates, not about
	// [intelligence.pricing]. See orgprice.go for the whole rationale.
	cfg atomic.Pointer[config.IntelligenceConfig]
	// orgRows is the org's applied pricing document, an INPUT to every
	// rebuild rather than a patch on one built table (ruling R13 / F3).
	orgRows atomic.Pointer[OrgRows]
	// orgLoader is WithOrgRows' one-shot loader, consulted at construction.
	// Set before the first build and never afterwards, so it needs no atomic.
	orgLoader func() (OrgRows, bool)
	// now is the clock the effective_from resolution reads. nil means
	// time.Now; only this package's tests replace it.
	now func() time.Time
}

// NewEngine returns an engine seeded with baked-in defaults + user pricing
// overrides from cfg, plus any options. Safe to call with a zero config (no
// overrides) and no options.
//
// The variadic options are what make ONE price table reachable from 38
// constructors: a CLI command passes WithOrgRows(store.LoadOrgPricing) and
// prices exactly the way the daemon does, without either of them having to
// know about the other.
func NewEngine(cfg config.IntelligenceConfig, opts ...Option) *Engine {
	e := &Engine{}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	if e.orgLoader != nil {
		if rows, ok := e.orgLoader(); ok {
			e.orgRows.Store(&rows)
		}
	}
	e.Reload(cfg)
	return e
}

// Reload swaps the engine's pricing table for one built from cfg. Used
// by the Settings page after a PUT /api/config/pricing save and by tests.
// Reads against the engine remain valid throughout — atomic.Pointer
// guarantees readers see either the old or new table, never a torn state.
//
// It re-composes the ORG's rates along with the config's (F3): before this
// arc Reload rebuilt from the seed, so a config save would silently revert a
// fleet to list prices — and there is no retroactive re-pricing to undo the
// turns captured in between.
func (e *Engine) Reload(cfg config.IntelligenceConfig) {
	e.rebuildMu.Lock()
	defer e.rebuildMu.Unlock()
	e.cfg.Store(&cfg)
	e.rebuild()
}

// rebuild composes seed + local + org into a fresh table and publishes it.
//
// ONE builder for both entry points ([Reload] on a config change, [SetOrgRows]
// on a rail delivery) so the two can never compose in a different order — the
// bug class that made F3 worth a ruling.
func (e *Engine) rebuild() {
	var cfg config.IntelligenceConfig
	if c := e.cfg.Load(); c != nil {
		cfg = *c
	}
	doc := e.orgRows.Load()
	authoritative := doc != nil && doc.Authoritative

	t := NewTable()

	// The local explicit overrides, resolved once so the org composition can
	// see which keys the developer authored.
	local := map[string]Pricing{}
	for id, mp := range cfg.Pricing.Models {
		local[id] = pricingFromConfig(mp)
	}
	localKeys := make(map[string]bool, len(local))
	for id := range local {
		localKeys[id] = true
	}

	// THE LADDER (ruling R3). On a managed authoritative node the org lands
	// LAST and wins; on an individual node the developer's own override does.
	// Both orders are expressed here, in one place, rather than as a flag
	// consulted at lookup time — a table that had to remember whose rate it
	// held would be a second owner of the precedence rule.
	var orgOwned map[string]bool
	var orgWarnings []string
	if authoritative {
		t.Merge(local)
		orgOwned, orgWarnings = composeOrgRows(t, doc, localKeys, e.clock())
	} else {
		orgOwned, orgWarnings = composeOrgRows(t, doc, localKeys, e.clock())
		t.Merge(local)
	}

	// Dated overrides land AFTER the flat overrides so MergeDated's
	// "seed the flat entry from the newest dated entry when the key has
	// no flat entry" rule can see an operator's flat override too. Zero
	// [intelligence.pricing.dated] → nothing is touched and the table
	// stays on the pre-dated code path.
	dated, warnings := DatedFromConfig(cfg.Pricing)
	t.MergeDated(dated)

	// An org-owned key keeps NO dated timeline. The org authored ONE rate for
	// that model; a leftover seed or config timeline would answer LookupAt
	// with a different number than Lookup answers for the same id, so the
	// session-detail view and the proxy's capture-time stamp would disagree
	// about the same model on the same day. Dropping the timeline is the only
	// answer that keeps them consistent, and it is honest: the org's document
	// carries its own effective_from, already resolved.
	t.markOrg(orgOwned)
	// LOCAL provenance, resolved the same way: a key the developer authored
	// owns its rate unless the org took it (which only happens on an
	// authoritative node, where orgOwned already contains it and markOrg ran
	// first). Marking both is what lets one surface answer "seed, mine, or
	// the org's" without re-reading the config.
	localOwned := map[string]bool{}
	for id := range local {
		if !orgOwned[id] {
			localOwned[id] = true
		}
	}
	t.markLocal(localOwned)

	warnings = append(warnings, orgWarnings...)
	warnings = append(warnings, t.ValidateDated()...)
	if doc != nil {
		t.enrollmentBinding = doc.Binding
		t.pricingDocumentWitness = doc.Witness
	}
	e.table.Store(t)
	e.warnings.Store(&warnings)
}

// clock returns the engine's notion of now.
func (e *Engine) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now().UTC()
}

// PricingWarnings returns advisory problems found while building the
// active table — malformed [intelligence.pricing.dated] rows that were
// SKIPPED, and dated timelines whose newest entry disagrees with the
// current flat rate. Empty when the table is clean. Pricing never fails
// closed on these; the slice exists so a surface can tell the operator
// their override was ignored instead of silently applied.
func (e *Engine) PricingWarnings() []string {
	if e == nil {
		return nil
	}
	w := e.warnings.Load()
	if w == nil {
		return nil
	}
	return append([]string(nil), *w...)
}

// HasDatedPricing reports whether the active table carries any dated
// rate timeline. Per-row hot paths gate their timestamp parsing on this
// so an install with no dated entries pays nothing for the feature.
func (e *Engine) HasDatedPricing() bool {
	return e != nil && e.Table().HasDated()
}

// Table returns the active pricing table snapshot. Safe to call from
// any goroutine; the returned pointer remains valid for reads even if
// a concurrent Reload swaps the engine onto a new table.
func (e *Engine) Table() *Table {
	if e == nil {
		return nil
	}
	return e.table.Load()
}

// WithPricingTable runs fn while the expected immutable pricing table is
// pinned against concurrent Reload and SetOrgRows publication. The callback
// should contain only the bounded enforcement operation; it must not call
// Reload, SetOrgRows, or WithPricingTable recursively. A canceled context
// stops waiting for a publisher without blocking the caller on a mutex.
//
// The table pointer is the snapshot: its rates and EnrollmentBinding are
// paired, and the identity check is repeated while the publication lock is
// held immediately before fn runs. This lets a caller use one table for a
// managed accounting query and then reject a signal if pricing changed before
// the enforcement action. The lock acquisition is deliberately immediate;
// callers already hold the bounded SQLite/policy fence and must retry or fail
// rather than introduce a lock-order wait.
func (e *Engine) WithPricingTable(ctx context.Context, expected *Table, fn func() error) error {
	if ctx == nil {
		return ErrPricingTableDeadlineRequired
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrPricingTableDeadlineRequired
	}
	if e == nil || expected == nil || fn == nil {
		return ErrPricingTableChanged
	}
	if !e.rebuildMu.TryLock() {
		if err := ctx.Err(); err != nil {
			return err
		}
		return ErrPricingTableChanged
	}
	defer e.rebuildMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.table.Load() != expected {
		return ErrPricingTableChanged
	}
	return fn()
}

// Lookup is a convenience wrapper that snapshots the active table and
// runs a Lookup against it. Equivalent to e.Table().Lookup(model).
func (e *Engine) Lookup(model string) (Pricing, bool) {
	t := e.Table()
	if t == nil {
		return Pricing{}, false
	}
	return t.Lookup(model)
}

// LookupWithSource mirrors Lookup but propagates the PricingSource so
// callers can flag fallback-rate rows.
func (e *Engine) LookupWithSource(model string) (Pricing, PricingSource, bool) {
	t := e.Table()
	if t == nil {
		return Pricing{}, PricingSourceMiss, false
	}
	return t.LookupWithSource(model)
}

// LookupAt is the date-aware Lookup — the rate in force for `model` at
// `at`. Use it wherever HISTORICAL usage is being priced (rollups over a
// past window, session detail, per-turn re-pricing). Live insert-time
// pricing should keep using Lookup: the flat table is by contract the
// CURRENT rate card, so Lookup ≡ LookupAt(now).
//
// A zero `at` (unparseable timestamp) deliberately falls back to current
// rates rather than repricing to the oldest known tier.
func (e *Engine) LookupAt(model string, at time.Time) (Pricing, bool) {
	t := e.Table()
	if t == nil {
		return Pricing{}, false
	}
	return t.LookupAt(model, at)
}

// LookupWithSourceAt is the date-aware LookupWithSource.
func (e *Engine) LookupWithSourceAt(model string, at time.Time) (Pricing, PricingSource, bool) {
	t := e.Table()
	if t == nil {
		return Pricing{}, PricingSourceMiss, false
	}
	return t.LookupWithSourceAt(model, at)
}

// TokenBundle is the per-turn token shape the engine prices. Zero fields
// contribute nothing to the total. Tokens are absolute counts (not per-million).
//
// CacheCreation is the total cache-write tokens for the turn; CacheCreation1h
// is the subset of those tokens that landed in the 1h ephemeral tier (the
// remainder is implicitly 5m-tier). This split lets Compute apply the 2×
// premium Anthropic charges for 1h-tier writes. Pre-tier-aware data has
// CacheCreation1h == 0 → priced entirely at the 5m rate, matching prior
// behavior.
type TokenBundle struct {
	// Input MUST be NET non-cached input tokens — the count of
	// fresh prompt tokens the model paid full input-rate to process,
	// EXCLUDING anything that hit prefix cache (which lives in
	// CacheRead and bills at the discounted cache_read rate).
	//
	// Anthropic-shape providers report this natively (input_tokens
	// is already net). OpenAI-shape providers (Codex JSONL, OpenAI
	// proxy responses, GPT-* via any path) report `prompt_tokens` /
	// `input_tokens` as the TOTAL prompt INCLUDING cached, with
	// `cached_tokens` as a subset — those adapters MUST pre-subtract
	// at emit time (see internal/adapter/codex/adapter.go and
	// internal/proxy/{provider,streaming}.go). Without the
	// subtraction, the cached portion would be billed at BOTH the
	// full input rate AND the cache_read rate — ~3.4× overbilling on
	// short cached sessions (audit 2026-05-24).
	Input           int64 `json:"input"`
	Output          int64 `json:"output"`
	CacheRead       int64 `json:"cache_read"`
	CacheCreation   int64 `json:"cache_creation"`
	CacheCreation1h int64 `json:"cache_creation_1h"`
	// Reasoning is the model's internal "thinking" token count
	// (OpenAI o1/o3/o4/gpt-5 family `reasoning_output_tokens`;
	// Anthropic extended-thinking `output_tokens` portion when
	// thinking is enabled). Billed at the output rate by both
	// providers, but tracked as a separate column so cost
	// breakdowns can attribute the reasoning portion of total
	// model spend. Add via b.Reasoning × p.Output / 1e6 in
	// Compute().
	//
	// HARD PRECONDITION — Output and Reasoning must be DISJOINT.
	// The engine bills Reasoning ADDITIVELY at the output rate ON TOP
	// of Output (see ComputeBreakdown: outputCost += b.Reasoning ×
	// rates.Output). Therefore Output must be the NON-reasoning
	// response-token count. Callers whose wire format reports a GROSS
	// output count that already CONTAINS the reasoning subset (the
	// OpenAI/Codex `output_tokens` shape: input+output==total, reasoning
	// ⊂ output) MUST net the reasoning out before populating this
	// bundle — otherwise every reasoning token is billed twice. Wire
	// formats where the total is prompt+output+reasoning (i.e. reasoning
	// is already disjoint from output — the Gemini `totalTokenCount =
	// prompt + candidates + thoughts` shape) need no netting.
	Reasoning int64 `json:"reasoning"`
	// WebSearchRequests is the count of server-side web_search invocations
	// billed under Anthropic's $10/1000 flat per-request fee. Charged on
	// top of token costs. Zero for non-Anthropic providers.
	WebSearchRequests int64 `json:"web_search_requests"`
	// Fast indicates the turn was served in the provider's low-latency
	// "fast" tier (e.g. Anthropic Opus 4.8 with speed:"fast" on the
	// Messages API). When true AND Pricing.FastMultiplier > 0, Compute
	// scales the AI token cost (input/output/cache/reasoning) by
	// FastMultiplier; the flat WebSearchPerRequest fee is unaffected.
	// Captured by the proxy when the outbound request body carries
	// `"speed":"fast"`; defaults false everywhere else.
	Fast bool `json:"fast,omitempty"`
}

// Add accumulates b's fields into t. Used by summary aggregation.
func (t *TokenBundle) Add(b TokenBundle) {
	t.Input += b.Input
	t.Output += b.Output
	t.CacheRead += b.CacheRead
	t.CacheCreation += b.CacheCreation
	t.CacheCreation1h += b.CacheCreation1h
	t.Reasoning += b.Reasoning
	t.WebSearchRequests += b.WebSearchRequests
}

// Compute returns (cost_usd, ok). ok is false only when the model is
// unrecognized; zero-token bundles against known models return (0, true).
//
// The formula is straight pricing × tokens / 1e6; there's no cache discount
// because cache-read tokens live in their own column with their own rate.
func (e *Engine) Compute(model string, b TokenBundle) (float64, bool) {
	p, ok := e.Lookup(model)
	if !ok {
		return 0, false
	}
	return Compute(p, b), true
}

// ComputeBreakdown is the AI/tool/total split variant of Compute.
// Returns a zero Breakdown when the model is unrecognized
// (matching Compute's "unknown model → $0" semantics).
func (e *Engine) ComputeBreakdown(model string, b TokenBundle) (Breakdown, bool) {
	p, ok := e.Lookup(model)
	if !ok {
		return Breakdown{}, false
	}
	return ComputeBreakdown(p, b), true
}

// ComputeAt is the date-aware Compute — prices b at the rate in force
// for `model` at `at`. See LookupAt for the zero-`at` contract.
func (e *Engine) ComputeAt(model string, b TokenBundle, at time.Time) (float64, bool) {
	p, ok := e.LookupAt(model, at)
	if !ok {
		return 0, false
	}
	return Compute(p, b), true
}

// ComputeBreakdownAt is the date-aware ComputeBreakdown.
//
// IMPORTANT — this prices ONE turn's bundle at ONE instant. Never hand
// it tokens aggregated across a rate boundary: aggregate AFTER pricing,
// not before. Every cost path in this repo is already per-row (the
// long-context dispatch forced that years ago), so dated pricing needs
// no SQL-side bucketing; the split-by-rate-period falls out of the
// existing row loop for free.
func (e *Engine) ComputeBreakdownAt(model string, b TokenBundle, at time.Time) (Breakdown, bool) {
	p, ok := e.LookupAt(model, at)
	if !ok {
		return Breakdown{}, false
	}
	return ComputeBreakdown(p, b), true
}

// BlendedInputRate returns the user's effective $/1M-prompt-tokens
// rate, computed by weighting each observed model's input rate by
// the prompt-token volume it consumed in the last `days` days.
//
// "Prompt tokens" here means input + cache_read (the portion of every
// request that bills at input-class rates; output is excluded because
// the metrics this rate is used for — wasted-token cost on Discovery —
// are about prompt waste). When a model has no pricing entry, its
// volume contributes to the denominator but not the numerator, which
// produces a slight under-estimate that's preferred over silently
// dropping unknown models from the average.
//
// Returns DefaultBlendedInputRate when the install has no usable
// proxy data — e.g. fresh install where the proxy isn't engaged yet.
func (e *Engine) BlendedInputRate(ctx context.Context, db *sql.DB, days int) (float64, error) {
	if e == nil || e.Table() == nil || db == nil {
		return DefaultBlendedInputRate, nil
	}
	if days <= 0 {
		days = 30
	}
	since := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	rows, err := db.QueryContext(ctx,
		`SELECT model,
		        COALESCE(SUM(input_tokens), 0) + COALESCE(SUM(cache_read_tokens), 0) AS prompt_tokens
		 FROM api_turns
		 WHERE timestamp >= ?
		 GROUP BY model`,
		since.Format(time.RFC3339Nano))
	if err != nil {
		return DefaultBlendedInputRate, err
	}
	defer rows.Close()
	var weightedRate float64
	var totalTokens int64
	for rows.Next() {
		var model string
		var promptTok int64
		if err := rows.Scan(&model, &promptTok); err != nil {
			return DefaultBlendedInputRate, err
		}
		if promptTok <= 0 {
			continue
		}
		totalTokens += promptTok
		p, ok := e.Lookup(model)
		if !ok || p.Input <= 0 {
			continue
		}
		weightedRate += float64(promptTok) * p.Input
	}
	if totalTokens == 0 {
		return DefaultBlendedInputRate, nil
	}
	return weightedRate / float64(totalTokens), nil
}

// Compute is the rate × tokens formula, factored out so pricing-table lookup
// and the math are independently testable.
//
// The cache-creation total is split into 5m and 1h tiers: the 1h subset is
// b.CacheCreation1h (clamped to [0, b.CacheCreation]), and the rest is 5m.
// Each tier is billed at its own rate. Pre-tier-aware data has
// CacheCreation1h == 0 → entirely 5m-tier (correct: 1h-tier didn't ship).
//
// Long-context dispatch: when p.LongContextThreshold > 0 and the bundle's
// prompt window (Input + CacheRead + CacheCreation) exceeds that
// threshold, each rate is replaced by its LongContext counterpart before
// the rate × tokens math runs. The threshold check is per-bundle, so
// callers MUST pass a per-turn bundle — passing aggregated tokens across
// many turns would false-positive the LC tier.
func Compute(p Pricing, b TokenBundle) float64 {
	return ComputeBreakdown(p, b).Total
}

// Breakdown splits a TokenBundle's cost into the AI-model portion
// (per-token input/output/cache/reasoning charges) and the tool
// portion (per-call fees for server-side tools like web_search).
// Total is AI + Tool. Used by the dashboard to surface "API cost vs
// tool cost vs total" separately rather than collapsing them into a
// single Cost column — different optimization levers, different
// budget lines.
type Breakdown struct {
	AICost   float64 `json:"ai_cost_usd"`
	ToolCost float64 `json:"tool_cost_usd"`
	Total    float64 `json:"total_cost_usd"`

	// Per-bucket components — the AICost split by the four token-billing
	// buckets we track. Reasoning tokens are billed at the model's output
	// rate, so their cost is folded into OutputCost (matching how
	// AICost itself aggregates). Tool fees are NOT in any bucket — they
	// stay on ToolCost. Invariant: InputCost + OutputCost + CacheReadCost
	// + CacheCreationCost == AICost. Added in v1.6.13 to feed the
	// session-detail Models Used panel's cost-by-bucket stacked bar.
	InputCost         float64 `json:"input_cost_usd,omitempty"`
	OutputCost        float64 `json:"output_cost_usd,omitempty"`
	CacheReadCost     float64 `json:"cache_read_cost_usd,omitempty"`
	CacheCreationCost float64 `json:"cache_creation_cost_usd,omitempty"`
}

// ComputeBreakdown is the canonical pricing-math function. Compute()
// is a thin wrapper that discards the split for callers that only
// need the total.
func ComputeBreakdown(p Pricing, b TokenBundle) Breakdown {
	rates := lcAdjusted(p, b)
	inputCost := float64(b.Input) * rates.Input / 1_000_000
	outputCost := float64(b.Output) * rates.Output / 1_000_000
	cacheReadCost := float64(b.CacheRead) * rates.CacheRead / 1_000_000
	cc1h := b.CacheCreation1h
	if cc1h < 0 {
		cc1h = 0
	}
	if cc1h > b.CacheCreation {
		cc1h = b.CacheCreation
	}
	cc5m := b.CacheCreation - cc1h
	cacheCreationCost := float64(cc5m)*rates.CacheCreation/1_000_000 +
		float64(cc1h)*rates.CacheCreation1h/1_000_000
	// Reasoning tokens (OpenAI o-series/gpt-5 reasoning_output_tokens,
	// Anthropic extended-thinking output portion) are billed at the
	// model's output rate. LC-adjusted along with regular output
	// (reasoning is part of the model's output stream). Folded into
	// OutputCost so the four bucket components still sum to AICost.
	outputCost += float64(b.Reasoning) * rates.Output / 1_000_000

	// Fast-mode premium: scale every per-token bucket by FastMultiplier
	// when the turn was served fast AND the model has a fast tier. A
	// uniform multiplier across input/output/cache (Anthropic Opus 4.8's
	// 2× across every dimension) post-multiplies cleanly here without
	// disturbing the LC dispatch — lcAdjusted already swapped in the
	// LC rates above, and 2× × LC = LC × 2 either way. The four bucket
	// components still sum to AICost (each bucket scaled identically).
	// Web search fees stay flat (set in `tool` below — inference
	// premium, not server-tool premium).
	if b.Fast && p.FastMultiplier > 0 {
		inputCost *= p.FastMultiplier
		outputCost *= p.FastMultiplier
		cacheReadCost *= p.FastMultiplier
		cacheCreationCost *= p.FastMultiplier
	}

	ai := inputCost + outputCost + cacheReadCost + cacheCreationCost

	// Tool fees: flat per-call, not per-token, not subject to LC tier,
	// not subject to FastMultiplier (Anthropic's fast mode is an
	// inference throughput premium, not a server-tool-fee premium).
	// Today only server-side web_search is modeled; future tool fees
	// (MCP-tool charges, code-execution sandboxes, etc.) accumulate
	// here so the AI vs Tool split stays meaningful.
	tool := float64(b.WebSearchRequests) * p.WebSearchPerRequest

	return Breakdown{
		AICost:            ai,
		ToolCost:          tool,
		Total:             ai + tool,
		InputCost:         inputCost,
		OutputCost:        outputCost,
		CacheReadCost:     cacheReadCost,
		CacheCreationCost: cacheCreationCost,
	}
}

// lcAdjusted returns p with each rate swapped for its LongContext
// counterpart when the bundle's prompt window exceeds the threshold. A
// zero LongContext* field means "no override at the LC tier" — the
// standard rate carries through. When the threshold is unset (zero) or
// the prompt is below it, p is returned unchanged.
func lcAdjusted(p Pricing, b TokenBundle) Pricing {
	if p.LongContextThreshold <= 0 {
		return p
	}
	prompt := b.Input + b.CacheRead + b.CacheCreation
	if prompt <= p.LongContextThreshold {
		return p
	}
	if p.LongContextInput > 0 {
		p.Input = p.LongContextInput
	}
	if p.LongContextOutput > 0 {
		p.Output = p.LongContextOutput
	}
	if p.LongContextCacheRead > 0 {
		p.CacheRead = p.LongContextCacheRead
	}
	if p.LongContextCacheCreation > 0 {
		p.CacheCreation = p.LongContextCacheCreation
	}
	if p.LongContextCacheCreation1h > 0 {
		p.CacheCreation1h = p.LongContextCacheCreation1h
	}
	return p
}
