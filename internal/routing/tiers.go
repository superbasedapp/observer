package routing

import (
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
)

// TierSource categorises how a tier lookup resolved, mirroring the cost
// engine's PricingSource so dashboards can flag family-inferred placements
// the same way they flag family-inferred rates.
type TierSource string

// Tier lookup sources.
const (
	// TierSourceExact: the model id matched a table entry verbatim (or
	// the :free suffix guard fired — a known placement, not a guess).
	TierSourceExact TierSource = "exact"
	// TierSourceDateStripped: a -YYYYMMDD suffix was stripped to match.
	TierSourceDateStripped TierSource = "date-stripped"
	// TierSourceFamily: matched via longest-prefix family lookup.
	TierSourceFamily TierSource = "family"
	// TierSourceMiss: nothing matched; the model is TierUnclassified.
	TierSourceMiss TierSource = "miss"
)

// TierTable maps normalized model ids to tiers (§R7.1). Keys reuse the
// cost engine's family vocabulary, and Lookup reuses its normalization
// order — exact → `:free` guard → date-strip → family prefix → last-resort
// router/provider-prefix strip — so any model the cost engine can price,
// this table can place. The zero value is unusable; build via newTierTable.
type TierTable struct {
	exact map[string]Tier
	// representatives is the curated per-(shape, tier) canonical model a
	// downshift selects when a rule routes to a tier (§R11.4 same-shape
	// constraint keeps selection within the original request's shape).
	representatives map[ProviderShape]map[Tier]string
}

// newTierTable builds a table from the seed data plus caller overrides
// (overrides replace seed entries wholesale, like cost.Table.Merge).
// localReps, when non-nil, install per-shape TierLocal representatives
// (§R11.7) on a copy of the seed representative map.
func newTierTable(overrides map[string]Tier, localReps map[ProviderShape]string) *TierTable {
	t := &TierTable{
		exact:           make(map[string]Tier, len(seedTiers)+len(overrides)),
		representatives: seedRepresentatives,
	}
	for k, v := range seedTiers {
		t.exact[k] = v
	}
	for k, v := range overrides {
		t.exact[k] = v
	}
	if len(localReps) > 0 {
		reps := make(map[ProviderShape]map[Tier]string, len(seedRepresentatives))
		for shape, byTier := range seedRepresentatives {
			cells := make(map[Tier]string, len(byTier)+1)
			for tier, model := range byTier {
				cells[tier] = model
			}
			reps[shape] = cells
		}
		for shape, model := range localReps {
			if reps[shape] == nil {
				reps[shape] = map[Tier]string{}
			}
			reps[shape][TierLocal] = model
		}
		t.representatives = reps
	}
	return t
}

// Lookup places a model id in a tier. A miss returns TierUnclassified —
// never auto-routed to, only ever routed from by explicit rule (§R7.1).
// Match precedence mirrors cost.Table.LookupWithSource.
func (t *TierTable) Lookup(model string) (Tier, TierSource) {
	if t == nil || t.exact == nil || model == "" {
		return TierUnclassified, TierSourceMiss
	}
	if tier, ok := t.exact[model]; ok {
		return tier, TierSourceExact
	}
	// `:free` suffix guard — every free tier is TierFree regardless of
	// family, and it runs BEFORE the date-strip and family ladders so a
	// paid `<family>` entry never silently claims `<family>:free`
	// traffic. Known placement → TierSourceExact, mirroring the pricing
	// table's known-$0 semantics.
	if strings.HasSuffix(strings.ToLower(model), ":free") {
		return TierFree, TierSourceExact
	}
	stripped := stripTierDateSuffix(model)
	if stripped != model {
		if tier, ok := t.exact[stripped]; ok {
			return tier, TierSourceDateStripped
		}
	}
	lower := strings.ToLower(model)
	for _, family := range tierFamilyKeys(t.exact) {
		if strings.HasPrefix(lower, family) {
			return t.exact[family], TierSourceFamily
		}
	}
	// Last-resort normalization, mirroring the cost engine: strip router
	// prefixes and leading provider path segments
	// (openrouter/anthropic/foo → foo) and retry exact + family once.
	if norm := normalizeUnplacedModel(model); norm != "" {
		if tier, ok := t.exact[norm]; ok {
			return tier, TierSourceFamily
		}
		lnorm := strings.ToLower(norm)
		for _, family := range tierFamilyKeys(t.exact) {
			if strings.HasPrefix(lnorm, family) {
				return t.exact[family], TierSourceFamily
			}
		}
	}
	return TierUnclassified, TierSourceMiss
}

// Representative returns the curated canonical model for a (shape, tier)
// cell — the model a downshift to that tier selects for requests of that
// provider shape. ok=false when the cell has no curated target (the
// engine then declines the move with ReasonNoCandidate).
func (t *TierTable) Representative(shape ProviderShape, tier Tier) (string, bool) {
	if t == nil {
		return "", false
	}
	byTier, ok := t.representatives[shape]
	if !ok {
		return "", false
	}
	m, ok := byTier[tier]
	return m, ok
}

// RepresentativesForShape returns the shape's curated (tier →
// representative model) cells as ModelCandidates — the engine's
// candidate-assembly source. Empty for shapes with no curated cells.
func (t *TierTable) RepresentativesForShape(shape ProviderShape) []ModelCandidate {
	if t == nil {
		return nil
	}
	byTier, ok := t.representatives[shape]
	if !ok {
		return nil
	}
	out := make([]ModelCandidate, 0, len(byTier))
	for tier, model := range byTier {
		out = append(out, ModelCandidate{Model: model, Tier: tier, Shape: shape})
	}
	return out
}

// Known returns the exact model/family keys in the table, sorted. Intended
// for `observer routing status` and debugging.
func (t *TierTable) Known() []string {
	if t == nil {
		return nil
	}
	out := make([]string, 0, len(t.exact))
	for k := range t.exact {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TierResolver holds the active TierTable behind an atomic.Pointer — the
// pricing-table hot-reload pattern (internal/intelligence/cost.Engine).
// In-flight readers keep their snapshot of the old table; fresh callers
// see the new one. P0 reloads only at construction; the shape is ready
// for `[routing.tiers]` config hot-reload in P1.
type TierResolver struct {
	table atomic.Pointer[TierTable]
}

// NewTierResolver returns a resolver seeded with the shipped tier table.
func NewTierResolver() *TierResolver {
	r := &TierResolver{}
	r.Reload(nil)
	return r
}

// Reload swaps the resolver's table for seed + overrides. Reads against
// the resolver remain valid throughout — atomic.Pointer guarantees readers
// see either the old or the new table, never a torn state.
func (r *TierResolver) Reload(overrides map[string]Tier) {
	r.table.Store(newTierTable(overrides, nil))
}

// ReloadWithLocalUpstreams additionally installs per-shape TierLocal
// representatives (§R11.7) so a privacy-driven local routing decision
// has a concrete candidate to select.
func (r *TierResolver) ReloadWithLocalUpstreams(overrides map[string]Tier, localReps map[ProviderShape]string) {
	r.table.Store(newTierTable(overrides, localReps))
}

// Table returns the active tier-table snapshot. Safe from any goroutine;
// the returned pointer stays valid for reads across a concurrent Reload.
func (r *TierResolver) Table() *TierTable {
	if r == nil {
		return nil
	}
	return r.table.Load()
}

// Lookup is a convenience wrapper over the active table snapshot.
func (r *TierResolver) Lookup(model string) (Tier, TierSource) {
	return r.Table().Lookup(model)
}

// ShapeForModel resolves a model id to its provider wire shape (§24.3).
// Conservative: only families whose shape we are certain of resolve;
// everything else is ShapeUnknown, which the engine treats as
// non-candidate. Router/provider path prefixes are stripped first so
// `anthropic/claude-sonnet-4-6` resolves like `claude-sonnet-4-6` —
// EXCEPT the §R11.7 local-host prefixes (ollama/, lmstudio/, vllm/,
// local/), which carry shape meaning themselves: every local inference
// server we route to speaks the OpenAI wire shape.
func ShapeForModel(model string) ProviderShape {
	m := strings.ToLower(model)
	for _, prefix := range localHostPrefixes {
		if strings.HasPrefix(m, prefix) {
			return ShapeOpenAI
		}
	}
	if norm := normalizeUnplacedModel(m); norm != "" {
		m = norm
	}
	for _, row := range shapePrefixes {
		if strings.HasPrefix(m, row.prefix) {
			return row.shape
		}
	}
	return ShapeUnknown
}

// localHostPrefixes are the §R11.7 local-inference id prefixes — they
// resolve to the OpenAI shape BEFORE the path-segment strip.
var localHostPrefixes = []string{"ollama/", "lmstudio/", "vllm/", "local/"}

// shapePrefixes is the ordered prefix → shape resolution table. Walked
// top-down, first match wins.
var shapePrefixes = []struct {
	prefix string
	shape  ProviderShape
}{
	{"claude", ShapeAnthropic},
	{"gpt-", ShapeOpenAI},
	{"o1", ShapeOpenAI},
	{"o3", ShapeOpenAI},
	{"o4", ShapeOpenAI},
	{"davinci", ShapeOpenAI},
	{"babbage", ShapeOpenAI},
	{"gemini", ShapeGoogle},
}

// tierDateSuffix matches a trailing "-YYYYMMDD" on a model id, identical
// to the cost engine's date-strip step.
var tierDateSuffix = regexp.MustCompile(`-\d{8}$`)

func stripTierDateSuffix(model string) string {
	return tierDateSuffix.ReplaceAllString(model, "")
}

// tierFamilyKeys returns the table keys usable as family prefixes (no
// date suffix), sorted longest-first so the most-specific family wins —
// the cost engine's familyKeys semantics.
func tierFamilyKeys(exact map[string]Tier) []string {
	out := make([]string, 0, len(exact))
	for k := range exact {
		if tierDateSuffix.MatchString(k) {
			continue
		}
		out = append(out, strings.ToLower(k))
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j] // deterministic among equal lengths
	})
	return out
}

// normalizeUnplacedModel is the last-resort reducer, mirroring the cost
// engine's normalizeUnpricedModel: strip router prefixes (capi:,
// sweagent-capi:) and ALL leading provider path segments, returning a
// candidate to retry once. "auto"/"" name no real model and stay a miss.
// Returns "" when nothing was stripped.
func normalizeUnplacedModel(model string) string {
	out := model
	switch {
	case strings.HasPrefix(out, "capi:"):
		out = strings.TrimPrefix(out, "capi:")
	case strings.HasPrefix(out, "sweagent-capi:"):
		out = strings.TrimPrefix(out, "sweagent-capi:")
	}
	if i := strings.LastIndex(out, "/"); i >= 0 {
		out = out[i+1:]
	}
	if out == model || out == "" {
		return ""
	}
	return out
}

// seedTiers ships with the binary (§R7.1) and is fully user-overridable
// (config wiring lands in P1; the override seam exists now via Reload).
// Keys reuse the cost engine's family vocabulary — see
// internal/intelligence/cost/pricing.go defaultPricing. Placements are
// quality-class judgments calibrated against published positioning and
// pricing as of 2026-06; per-project calibration (§R7.2, P2) refines them
// from observed outcomes. Models absent here resolve TierUnclassified.
//
// Auto-router sentinels (Cursor "default", kilo-auto, openrouter/auto)
// are deliberately NOT placed: a router is not a quality class, and our
// position is to audit them (§R17.4), not to pretend to know what they
// will serve.
var seedTiers = map[string]Tier{
	// Anthropic. Family prefixes carry the placement; explicit minors
	// pin the flagship SKUs the engine most often reasons about. The
	// bare "claude-opus" family prefix already places every Opus SKU,
	// so an explicit minor here is a statement of prominence, not a
	// correctness fix — claude-opus-5 (2026-07-25) is the current
	// flagship for complex agentic coding, hence the pin.
	"claude-opus-5":    TierOpusClass,
	"claude-opus-4-8":  TierOpusClass,
	"claude-opus-4":    TierOpusClass,
	"claude-opus-4-1":  TierOpusClass,
	"claude-opus":      TierOpusClass,
	"claude-3-opus":    TierOpusClass,
	"claude-fable-5":   TierOpusClass,
	"claude-fable-5-1": TierOpusClass, // current Fable flagship (2026-09-01); prominence pin — the claude-fable-5 prefix already classifies it
	"claude-fable":     TierOpusClass,
	// claude-mythos-5-1 has no bare "claude-mythos" (or "claude-mythos-5")
	// family row in this seed table today, so without this explicit entry
	// it falls through to TierUnclassified — same tier as its Fable 5.1
	// twin (identical rate card, see pricing.go).
	"claude-mythos-5-1": TierOpusClass,
	"claude-sonnet-4-6": TierSonnetClass,
	"claude-sonnet-4":   TierSonnetClass,
	"claude-sonnet":     TierSonnetClass,
	"claude-3-5-sonnet": TierSonnetClass,
	"claude-3-sonnet":   TierSonnetClass,
	"claude-haiku-4-5":  TierHaikuClass,
	"claude-haiku-4.5":  TierHaikuClass, // dot variant — Copilot CLI emits this
	"claude-haiku":      TierHaikuClass,
	"claude-3-5-haiku":  TierHaikuClass,
	"claude-3-haiku":    TierHaikuClass,

	// OpenAI. gpt-6-astra (released 2026-09-03) is the current flagship,
	// gpt-5.5 the prior frontier line; gpt-5.4 and earlier 5.x are the mid
	// line; minis are the small class; the $0 nano is free. Pro variants
	// are flagship-priced regardless of minor.
	"gpt-6-astra":  TierOpusClass,
	"gpt-6":        TierOpusClass, // family prefix → Astra (flagship)
	"gpt-5.5":      TierOpusClass,
	"gpt-5.5-pro":  TierOpusClass,
	"gpt-5.4-pro":  TierOpusClass,
	"gpt-5.2-pro":  TierOpusClass,
	"gpt-5-pro":    TierOpusClass,
	"gpt-5.4":      TierSonnetClass,
	"gpt-5.4-mini": TierHaikuClass,
	"gpt-5.4-nano": TierHaikuClass,
	"gpt-5.3":      TierSonnetClass,
	"gpt-5.2":      TierSonnetClass,
	"gpt-5.1":      TierSonnetClass,
	"gpt-5-mini":   TierHaikuClass,
	"gpt-5-nano":   TierFree, // $0 per OpenAI 2026-04-29 catalog
	"gpt-5":        TierSonnetClass,
	"gpt-4.1":      TierSonnetClass,
	"gpt-4.1-mini": TierHaikuClass,
	"gpt-4.1-nano": TierHaikuClass,
	"gpt-4o":       TierSonnetClass,
	"gpt-4o-mini":  TierHaikuClass,
	"gpt-4":        TierSonnetClass,
	"gpt-3.5":      TierHaikuClass,
	"o1-pro":       TierOpusClass,
	"o1":           TierOpusClass,
	"o1-mini":      TierHaikuClass,
	"o3-pro":       TierOpusClass,
	"o3":           TierSonnetClass,
	"o3-mini":      TierHaikuClass,
	"o4-mini":      TierHaikuClass,

	// Google. 3.x Pro is the frontier line; 2.5 Pro the mid; flash the
	// small class. Family order matters: longest-prefix wins, so the
	// flash families out-match the bare generation families.
	"gemini-3.1-pro":   TierOpusClass,
	"gemini-3-pro":     TierOpusClass,
	"gemini-pro-agent": TierOpusClass,
	"gemini-3.1":       TierOpusClass, // cost family anchors 3.1 at Pro
	"gemini-3.5-flash": TierHaikuClass,
	// gemini-3.6-flash / gemini-3.7-flash: explicit, NOT relying on the
	// bare "gemini-3" fallback below — that fallback is Pro-class, and
	// "gemini-3.6-flash"/"gemini-3.7-flash" DO prefix-match the bare
	// "gemini-3" key (both start with the literal "gemini-3"), so
	// without these two rows a flash-class request would misclassify
	// as Opus-class. Mirrors the pricing.go family-shadow note for the
	// same two models. Both SKUs also share the same introductory
	// pricing (through 2026-12-31, standard rate from 2027-01-01 per
	// pricing.go / docs/pricing-reference.md, re-verified 2026-08-15)
	// but that's a cost-only distinction — the tier classification
	// below (TierHaikuClass) is unaffected either way.
	"gemini-3.6-flash": TierHaikuClass,
	"gemini-3.7-flash": TierHaikuClass,
	"gemini-3.8-flash": TierHaikuClass, // same family-shadow reasoning as 3.6/3.7 above
	"gemini-3-flash":   TierHaikuClass,
	"gemini-3":         TierOpusClass, // Pro-representative, mirroring cost
	"gemini-2.5-pro":   TierSonnetClass,
	"gemini-2.5-flash": TierHaikuClass,
	"gemini-2.5":       TierSonnetClass,
	"gemini-2":         TierHaikuClass,

	// xAI / Moonshot / DeepSeek / open-weight families. Mid-class
	// placements unless the SKU is explicitly a small/cheap line.
	"grok-code":        TierSonnetClass,
	"grok":             TierSonnetClass,
	"kimi":             TierSonnetClass,
	"deepseek-v4-pro":  TierSonnetClass,
	"deepseek":         TierHaikuClass, // family → v4-flash, the cheap default
	"gpt-oss":          TierHaikuClass,
	"nemotron-3-ultra": TierSonnetClass,
	"nemotron":         TierHaikuClass,
	"hermes":           TierSonnetClass,
	"qwen":             TierSonnetClass,
	"glm":              TierSonnetClass,
	"mistral-large":    TierSonnetClass,
	"mistral-small":    TierHaikuClass,
	"mistral":          TierSonnetClass,
	// Ministral 3 — Mistral's small/edge line (pricing.go: ministral-3b/
	// 8b/14b, $0.10-$0.20 per MTok). "mistral" is NOT a prefix of
	// "ministral-*" (the extra leading "mi" breaks the match), so these
	// cannot inherit the bare "mistral" row above and need their own
	// entries or they'd fall through to TierUnclassified. Cheap tier,
	// same class as mistral-small.
	"ministral-3b":      TierHaikuClass,
	"ministral-8b":      TierHaikuClass,
	"ministral-14b":     TierHaikuClass,
	"minimax":           TierSonnetClass,
	"composer":          TierSonnetClass, // Cursor's own coding line
	"cursor-grok":       TierSonnetClass, // Cursor's Grok routing (cursor-grok-4.x-<effort>) → mirrors the `grok` family placement
	"codex-auto-review": TierSonnetClass, // Codex cloud auto-review alias → Codex-codex line, Sonnet-class
	"kilo-auto/free":    TierFree,
	"kilo-auto/small":   TierHaikuClass, // Kilo's title-generation slot
	"ollama":            TierLocal,

	// 2026-08 sweep additions. deepseek-v4-pro / grok-4.5 / grok-4.6 /
	// qwen3.7-max / qwen3.7-plus / qwen3.8-max / kimi-k3 / minimax-m3 /
	// nemotron-3.5-lightning are all already correctly placed by the
	// bare family rows above (verified by prefix walk against
	// tierFamilyKeys) — no new rows needed for those; see the W5 task
	// report for the per-model reasoning. Baidu ERNIE and StepFun had NO
	// existing family row at all (a miss → TierUnclassified), so those
	// two get entries below.
	"ernie":          TierSonnetClass, // Baidu's flagship line (ernie-5.1), same vendor-family pattern as glm/mistral/minimax
	"step-3.7-flash": TierHaikuClass,  // StepFun's budget/speed SKU; no "step" family exists yet to fall back to
}

// seedRepresentatives names the canonical downshift target per
// (provider shape, tier). Selection stays same-shape (§R11.4); a cell
// absent here means "no curated target — decline the move".
//
// The Anthropic Opus-class cell moved claude-opus-4-8 → claude-opus-5 on
// 2026-07-25, operator-approved. This cell is live behaviour, not
// documentation: it is what `[routing] mode = "enforce"` actually
// rewrites an Opus-class request TO, so changing it changes traffic.
// Both SKUs are Anthropic-shape, so the §R11.4 same-shape constraint is
// unaffected, and they price identically ($5 in / $25 out per MTok,
// cache read $0.50, 5m write $6.25, 1h write $10, fast 2×) — so there is
// no per-token cost delta.
//
// Three things are load-bearing — the first is the one reviewers keep
// getting wrong, so it is stated first and explicitly:
//
//  1. It does NOT churn incumbent Opus sessions. A reviewer reading
//     applyPin naturally lands on `!ok || candidate == in.Shape.Model
//     → ReasonNoCandidate` and concludes that a live claude-opus-4-8
//     session under a `pin_tier = opus-class` rule now takes a
//     same-tier rewrite that forfeits its warm prefix for zero gross
//     saving. That is WRONG: applyPin returns at an EARLIER guard,
//     `if tier == r.Action.PinTier`, which matches on TIER identity —
//     an Opus-4.8 incumbent is already opus-class, so it returns with
//     the rule's own reason before the representative is ever
//     resolved. Verified empirically 2026-07-25 (and by mutation: the
//     forfeit scenario appears only if that early return is deleted).
//     The `candidate == in.Shape.Model` guard is in fact unreachable
//     with a self-consistent tier table, since `tier != PinTier`
//     already excludes the pinned tier's own representative; only an
//     operator tier override can reach it.
//  2. What DOES change is the upshift target: a lower-tier incumbent
//     pinned to opus-class now lands on claude-opus-5 rather than
//     claude-opus-4-8. Rates are identical, so that move costs the
//     same as before — genuinely neutral, not merely claimed to be.
//     Pinned by TestApplyPin_OpusFivePromotionEconomics.
//  3. claude-opus-5 draws on a SEPARATE rate-limit / entitlement bucket
//     from the combined Opus 4.x pool (per Anthropic's docs). An
//     enforce-mode node whose account lacks Opus 5 access is now
//     rewritten into a model that fails, where claude-opus-4-8 worked.
//     This is the real operational risk of the swap.
//
// This cell has a SECOND consumer beyond the routing engine:
// cmd/observer/handoff_target.go::resolveTargetModelViaTier uses it to
// pick the cross-family handoff target, so changing it also changes
// what a gpt-5.x → claude-code handoff seeds (pinned by
// cmd/observer/handoff_target_test.go).
//
// Changing a shipped default this way is invasive rather than additive
// (CLAUDE.md §6): it retargets existing behaviour — upshift pins and
// cross-family handoffs — rather than merely making a new option
// available. Incumbent Opus sessions are NOT retargeted (see 1 above).
// Landed deliberately with operator approval; recorded here so the
// trade-off is not rediscovered as a bug.
var seedRepresentatives = map[ProviderShape]map[Tier]string{
	ShapeAnthropic: {
		TierOpusClass:   "claude-opus-5",
		TierSonnetClass: "claude-sonnet-4-6",
		TierHaikuClass:  "claude-haiku-4-5",
	},
	ShapeOpenAI: {
		TierOpusClass:   "gpt-5.5",
		TierSonnetClass: "gpt-5.4",
		TierHaikuClass:  "gpt-5.4-mini",
	},
	ShapeGoogle: {
		TierOpusClass:   "gemini-3.1-pro-preview",
		TierSonnetClass: "gemini-2.5-pro",
		TierHaikuClass:  "gemini-3.5-flash",
	},
}
