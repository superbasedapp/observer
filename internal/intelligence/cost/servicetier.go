package cost

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// TierResolution says how a served provider service tier affected which
// price-table key a turn is billed under. See ResolveServiceTier.
type TierResolution int

const (
	// TierNone: no rule in serviceTierRules names the tier (standard,
	// default, flex, priority, an empty tier, anything unknown). The turn is
	// priced under its own model id exactly as before; Fast mode keeps
	// riding TokenBundle.Fast + Pricing.FastMultiplier, not this table.
	TierNone TierResolution = iota
	// TierOwnSKU: a rule names the tier and the price table holds the
	// tier's own SKU (`<model><suffix>`, e.g. gpt-6-astra-ultrafast) at an
	// EXACT key. The turn is priced under that key's absolute rates.
	TierOwnSKU
	// TierUnpriced: a rule names the tier but the table has no price for the
	// tier's SKU. The turn falls back to its own model id (the standard rate,
	// which UNDER-bills a premium tier) and the engine records a pricing
	// warning so the gap is visible instead of silent.
	TierUnpriced
)

// serviceTierRule maps a provider-reported service tier that is sold as its
// OWN priced SKU to the model-id suffix Tokenomics captures that SKU under.
//
// Only tiers whose price is NOT one uniform multiple of the base model belong
// here. OpenAI's single Fast tier (served `service_tier:"priority"`) is a
// multiplier and stays on Pricing.FastMultiplier. OpenAI's Ultrafast tier is
// captured by Tokenomics as `<model>-ultrafast` with absolute prices
// (model-pricing/DATA-CAPTURE-PLAYBOOK.md, the `claude-opus-5-5-fast`
// precedent). OpenAI's API reference documents the served value:
// "If set to 'ultrafast', then the request will be processed with the
// access-controlled Ultrafast Processing service tier ... a response served
// through it will show `service_tier=ultrafast`."
// (developers.openai.com/api/reference, responses create, fetched 2026-09-30).
//
// Rows hold vocabulary only, never a price: every rate comes from the price
// table (seed / snapshot / Tokenomics feed / org document).
type serviceTierRule struct {
	tier   string // served service_tier value, compared case-insensitively
	suffix string // appended to the model id to name the tier's own SKU
}

var serviceTierRules = []serviceTierRule{
	{tier: "ultrafast", suffix: "-ultrafast"},
}

// ServiceTierModel is the pure rule walk behind Engine.ResolveServiceTier.
// hasExact reports whether the price table holds an EXACT key (never the
// family ladder: `gpt-6-astra-ultrafast` would family-match `gpt-6-astra` and
// pass the standard rate off as the tier's). Candidates are `<model><suffix>`
// and, for a dated served id, `<undated model><suffix>`. A model that already
// carries the suffix is its own SKU and is returned unchanged with TierNone.
func ServiceTierModel(model, tier string, hasExact func(string) bool) (string, TierResolution) {
	tier = strings.ToLower(strings.TrimSpace(tier))
	if model == "" || tier == "" || hasExact == nil {
		return model, TierNone
	}
	for _, r := range serviceTierRules {
		if tier != r.tier {
			continue
		}
		if strings.HasSuffix(strings.ToLower(model), r.suffix) {
			return model, TierNone
		}
		for _, cand := range tierCandidates(model, r.suffix) {
			if hasExact(cand) {
				return cand, TierOwnSKU
			}
		}
		return model, TierUnpriced
	}
	return model, TierNone
}

// tierCandidates lists the tier-SKU keys to try for model, most specific
// first, without duplicates.
func tierCandidates(model, suffix string) []string {
	out := []string{model + suffix}
	if undated := stripDateSuffix(model); undated != model {
		out = append(out, undated+suffix)
	}
	if lower := strings.ToLower(model) + suffix; lower != out[0] {
		out = append(out, lower)
	}
	return out
}

// ResolveServiceTier returns the model id a turn served at `tier` must be
// priced under, and how it was resolved. It is the ONE seam for tier-as-SKU
// pricing: callers pass the provider's served tier and price the returned id
// (the stored model id is not changed, so twin folding and per-model
// grouping keep the id the provider reported). On TierUnpriced the engine
// records a warning surfaced by PricingWarnings.
func (e *Engine) ResolveServiceTier(model, tier string) (string, TierResolution) {
	t := e.Table()
	has := func(k string) bool {
		if t == nil || t.exact == nil {
			return false
		}
		_, ok := t.exact[k]
		return ok
	}
	id, res := ServiceTierModel(model, tier, has)
	if res == TierUnpriced && e != nil {
		e.tierGaps.note(model, tier)
	}
	return id, res
}

// maxTierGaps bounds the remembered unpriced (model, tier) pairs so a stream
// of odd model ids cannot grow the warning list without limit.
const maxTierGaps = 32

// tierGapSet remembers (model, tier) pairs that were served at a tier-as-SKU
// tier the price table cannot price. Engine-owned; the one writer is
// ResolveServiceTier.
type tierGapSet struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (g *tierGapSet) note(model, tier string) {
	key := strings.ToLower(strings.TrimSpace(tier)) + "\x00" + model
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = map[string]bool{}
	}
	if g.seen[key] || len(g.seen) >= maxTierGaps {
		return
	}
	g.seen[key] = true
}

func (g *tierGapSet) warnings() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, 0, len(g.seen))
	for key := range g.seen {
		tier, model, _ := strings.Cut(key, "\x00")
		out = append(out, fmt.Sprintf(
			"%s was served at service tier %q but the price table has no %s%s entry; those turns were priced at %s's standard rate, which under-bills the tier",
			model, tier, model, suffixFor(tier), model))
	}
	sort.Strings(out)
	return out
}

// suffixFor returns the rule suffix for a (lower-cased) tier, or "".
func suffixFor(tier string) string {
	for _, r := range serviceTierRules {
		if r.tier == tier {
			return r.suffix
		}
	}
	return ""
}
