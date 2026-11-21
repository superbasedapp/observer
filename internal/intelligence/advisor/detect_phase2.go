package advisor

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// detectCacheHitRate (research-doc D1, prescriptive): per session, the
// fraction of the prompt window served from cache vs paid fresh. Below the
// healthy floor on a meaningful spend, the nudge names the dominant
// cachetrack cause when verdicts exist. Savings = the missed-read volume
// re-priced (input − cache_read rates) at 50% realization.
func detectCacheHitRate(f *Facts, t Thresholds) []Suggestion {
	var out []Suggestion
	for i := range f.Sessions {
		s := &f.Sessions[i]
		in, _, cr, cc, _, _, _ := s.totals()
		window := in + cr + cc
		if window < 200_000 { // too small for the ratio to mean anything
			continue
		}
		rate := float64(cr) / float64(window)
		if rate >= t.HealthyCacheHitRate {
			continue
		}
		missed := int64((t.HealthyCacheHitRate - rate) * float64(window))
		model := sessionModelOf(s)
		fresh, ok1 := f.Price(model, cost.TokenBundle{Input: missed})
		warm, ok2 := f.Price(model, cost.TokenBundle{CacheRead: missed})
		if !ok1 || !ok2 || fresh <= warm {
			continue
		}
		saving := (fresh - warm) * 0.5
		cause := dominantCause(f.CacheEvents[s.ID])
		hint := "Stable system prompts and finishing subtasks before breaks raise it."
		if cause != "" {
			hint = fmt.Sprintf("cachetrack attributes most misses to %q.", cause)
		}
		out = append(out, Suggestion{
			// no-bare-usd:allow (advisor prose; masked on every surface under the token display)
			DedupKey: "cache_hit_rate|" + s.ID, Detector: "cache_hit_rate",
			Category: CategoryCost, Scope: ScopeSession, ScopeID: s.ID, Severity: SeverityAdvice,
			Title: fmt.Sprintf("Cache hit rate %.0f%% (healthy ≥ %.0f%%)", rate*100, t.HealthyCacheHitRate*100),
			Nudge: fmt.Sprintf(
				"Only %.0f%% of this session's %dK-token prompt volume was served from cache (healthy sessions reach %.0f%%+; cache reads cost a tenth of fresh input). %s Closing the gap is worth about $%.2f here.",
				rate*100, window/1000, t.HealthyCacheHitRate*100, hint, saving,
			),
			SavingsUSD: round2(saving), Confidence: 0.5,
			Evidence: Evidence{
				Numbers: map[string]float64{"hit_rate": rate, "window_tokens": float64(window), "missed_tokens": float64(missed)},
				Math:    fmt.Sprintf("%dK missed-read tokens × (input − cache_read rate) × 50%% = $%.2f", missed/1000, saving),
			},
		})
	}
	return out
}

// detectCacheWriteWaste (D2): sessions whose cachetrack verdicts show cache
// writes that were never read back — the write premium bought nothing.
// Savings = the premium portion (write price − plain-input price).
func detectCacheWriteWaste(f *Facts, t Thresholds) []Suggestion {
	var out []Suggestion
	for i := range f.Sessions {
		s := &f.Sessions[i]
		evs := f.CacheEvents[s.ID]
		if len(evs) < t.IdleRecacheMinEvents {
			continue
		}
		var written, read int64
		var writes int
		for j, e := range evs {
			// A handoff TARGET session's first cache event is the
			// by-design cold rehydration write — never "waste".
			// Exclude the explicitly-attributed cause (the live
			// proxy/store lane fired handoff_rehydration) AND, for
			// handoff-target sessions, the leading event — the belt for
			// non-proxied targets whose live flag never fired and whose
			// first event is therefore a plain reanchor.
			if e.Cause == "handoff_rehydration" {
				continue
			}
			if s.HandoffTarget && j == 0 {
				continue
			}
			written += e.TokensWritten
			read += e.TokensRead
			if e.Kind == "write" {
				writes++
			}
		}
		if writes < 2 || written == 0 || float64(read) >= 0.5*float64(written) {
			continue
		}
		model := sessionModelOf(s)
		asWrite, ok1 := f.Price(model, cost.TokenBundle{CacheCreation: written})
		asInput, ok2 := f.Price(model, cost.TokenBundle{Input: written})
		if !ok1 || !ok2 || asWrite <= asInput {
			continue
		}
		premium := asWrite - asInput
		out = append(out, Suggestion{
			DedupKey: "cache_write_waste|" + s.ID, Detector: "cache_write_waste",
			Category: CategoryCost, Scope: ScopeSession, ScopeID: s.ID, Severity: SeverityInfo,
			Title: fmt.Sprintf("%dK tokens of cache writes were barely read back", written/1000),
			Nudge: fmt.Sprintf(
				"This session paid the cache-write premium on %dK tokens but read back only %dK - short or one-shot sessions don't amortize cache writes. The unamortized premium is about $%.2f.",
				written/1000, read/1000, premium,
			),
			SavingsUSD: round2(premium), Confidence: 0.6,
			Evidence: Evidence{
				Numbers: map[string]float64{"tokens_written": float64(written), "tokens_read": float64(read), "write_events": float64(writes)},
				Math:    fmt.Sprintf("write price − input price on %dK tokens = $%.2f", written/1000, premium),
			},
		})
	}
	return out
}

// detectPrefixThrash (D4): cachetrack cause concentration — when most
// rewrites in a session trace to prefix instability (tools/system changed,
// block diverged) rather than organic growth, the cache keeps invalidating.
// Savings = Σ cost_delta_usd of those events (cachetrack's own write-minus-
// read delta — the advisor never re-derives it).
func detectPrefixThrash(f *Facts, _ Thresholds) []Suggestion {
	thrashCauses := map[string]bool{"tools_changed": true, "system_changed": true, "tools_or_system_changed": true, "block_diverged": true}
	var out []Suggestion
	for i := range f.Sessions {
		s := &f.Sessions[i]
		var thrash int
		var nonGrowth int
		var delta float64
		for _, e := range f.CacheEvents[s.ID] {
			if e.Cause == "" || e.Cause == "suffix_growth" {
				continue
			}
			nonGrowth++
			if thrashCauses[e.Cause] {
				thrash++
				if e.CostDeltaUSD > 0 {
					delta += e.CostDeltaUSD
				}
			}
		}
		if thrash < 3 || nonGrowth == 0 || float64(thrash) < 0.5*float64(nonGrowth) {
			continue
		}
		out = append(out, Suggestion{
			DedupKey: "prefix_thrash|" + s.ID, Detector: "prefix_thrash",
			Category: CategoryCost, Scope: ScopeSession, ScopeID: s.ID, Severity: SeverityAdvice,
			Title: fmt.Sprintf("Prompt prefix changed %d times, forcing cache rebuilds", thrash),
			Nudge: fmt.Sprintf(
				"cachetrack attributes %d cache rewrites in this session to prefix instability (tool/system-prompt changes mid-session), costing about $%.2f in avoidable re-writes. Mid-conversation context injection and unstable system prompts cause this.",
				thrash, delta,
			),
			SavingsUSD: round2(delta), Confidence: 0.7,
			Evidence: Evidence{
				Numbers: map[string]float64{"thrash_events": float64(thrash), "non_growth_events": float64(nonGrowth)},
				Math:    fmt.Sprintf("Σ cachetrack cost_delta_usd over %d thrash-cause events = $%.2f", thrash, delta),
			},
		})
	}
	return out
}

// detectReadHeavyExpensiveModel (B1 generalized, session-mix approximation
// documented in the plan): Opus sessions whose action mix is dominated by
// read/search. Savings = the read-share of the Opus premium vs the routing
// target.
func detectReadHeavyExpensiveModel(f *Facts, t Thresholds) []Suggestion {
	var out []Suggestion
	for i := range f.Sessions {
		s := &f.Sessions[i]
		if !sessionAllOpus(s) || s.Mix.Total < 20 {
			continue
		}
		share := float64(s.Mix.Reads) / float64(s.Mix.Total)
		if share < 0.6 {
			continue
		}
		in, outT, cr, cc, cc1, _, anyFast := s.totals()
		bundle := cost.TokenBundle{Input: in, Output: outT, CacheRead: cr, CacheCreation: cc, CacheCreation1h: min64(cc1, cc), Fast: anyFast}
		actual, ok1 := f.Price(sessionModelOf(s), bundle)
		cheaper, ok2 := f.Price(t.RoutingTargetModel, bundle)
		if !ok1 || !ok2 || actual <= cheaper {
			continue
		}
		saving := (actual - cheaper) * share * t.CounterfactualHaircut
		out = append(out, Suggestion{
			DedupKey: "read_heavy_expensive_model|" + s.ID, Detector: "read_heavy_expensive_model",
			Category: CategoryCost, Scope: ScopeSession, ScopeID: s.ID, Severity: SeverityInfo,
			Title: fmt.Sprintf("%.0f%% of this Opus session was read/search work", share*100),
			Nudge: fmt.Sprintf(
				"%d of %d actions here were reads/searches - exploration a cheaper model handles fine. Routing exploration-heavy sessions to %s would have saved about $%.2f.",
				s.Mix.Reads, s.Mix.Total, t.RoutingTargetModel, saving,
			),
			SavingsUSD: round2(saving), Confidence: 0.5,
			Evidence: Evidence{
				Numbers: map[string]float64{"read_share": share, "actions": float64(s.Mix.Total)},
				Math:    fmt.Sprintf("(opus $%.2f − %s $%.2f) × %.0f%% read share × %.0f%% haircut = $%.2f", actual, t.RoutingTargetModel, cheaper, share*100, t.CounterfactualHaircut*100, saving),
			},
		})
	}
	return out
}

// detectEffortOverprovisioning (B2): sessions running many xhigh/max-effort
// actions while burning reasoning tokens (output-rate priced) on
// small-output work.
func detectEffortOverprovisioning(f *Facts, t Thresholds) []Suggestion {
	var out []Suggestion
	for i := range f.Sessions {
		s := &f.Sessions[i]
		if s.Mix.EffortHigh < 10 {
			continue
		}
		_, outT, _, _, _, reasoning, _ := s.totals()
		if reasoning == 0 || outT == 0 || float64(reasoning) < 0.4*float64(outT) {
			continue
		}
		rCost, ok := f.Price(sessionModelOf(s), cost.TokenBundle{Output: reasoning})
		if !ok {
			continue
		}
		saving := rCost * 0.5 * t.CounterfactualHaircut
		out = append(out, Suggestion{
			DedupKey: "effort_overprovisioning|" + s.ID, Detector: "effort_overprovisioning",
			Category: CategoryCost, Scope: ScopeSession, ScopeID: s.ID, Severity: SeverityInfo,
			Title: fmt.Sprintf("%d high-effort actions spent %dK reasoning tokens", s.Mix.EffortHigh, reasoning/1000),
			Nudge: fmt.Sprintf(
				"This session ran %d actions at xhigh/max effort; reasoning tokens (billed at the output rate) reached %d%% of output volume (≈$%.2f). Lower effort is typically sufficient for routine edits - roughly $%.2f avoidable.",
				s.Mix.EffortHigh, 100*reasoning/max64(outT, 1), rCost, saving,
			),
			SavingsUSD: round2(saving), Confidence: 0.5,
			Evidence: Evidence{
				Numbers: map[string]float64{"effort_high_actions": float64(s.Mix.EffortHigh), "reasoning_tokens": float64(reasoning)},
				Math:    fmt.Sprintf("$%.2f reasoning spend × 50%% reducible × %.0f%% haircut = $%.2f", rCost, t.CounterfactualHaircut*100, saving),
			},
		})
	}
	return out
}

// detectFastTierPremium (B4): the cross-provider fast/priority premium the
// session paid vs standard tier — surfaced so the user decides whether the
// latency was worth 2–2.5×.
func detectFastTierPremium(f *Facts, _ Thresholds) []Suggestion {
	var out []Suggestion
	for i := range f.Sessions {
		s := &f.Sessions[i]
		var premium float64
		var fastTurns int
		for _, r := range s.Rows {
			if !r.Fast {
				continue
			}
			fast, ok1 := rowCost(f, s, r)
			std := r
			std.Fast = false
			stdC, ok2 := rowCost(f, s, std)
			if ok1 && ok2 && fast > stdC {
				premium += fast - stdC
				fastTurns++
			}
		}
		if fastTurns < 5 || premium <= 0 {
			continue
		}
		out = append(out, Suggestion{
			DedupKey: "fast_tier_premium|" + s.ID, Detector: "fast_tier_premium",
			Category: CategoryLatency, Scope: ScopeSession, ScopeID: s.ID, Severity: SeverityInfo,
			Title: fmt.Sprintf("$%.2f fast-tier premium across %d turns", premium, fastTurns),
			Nudge: fmt.Sprintf(
				"%d turns ran in the provider's fast/priority tier at 2-2.5× rates (≈$%.2f premium over standard). Worth it for interactive work - for batch or background sessions, standard tier produces the same output.",
				fastTurns, premium,
			),
			SavingsUSD: round2(premium), Confidence: 0.5,
			Evidence: Evidence{
				Numbers: map[string]float64{"fast_turns": float64(fastTurns)},
				Math:    fmt.Sprintf("Σ(fast price − standard price) over %d turns = $%.2f", fastTurns, premium),
			},
		})
	}
	return out
}

// trivialCommands gates C4 against environment noise (calibration §5: `ls`
// topped the raw never-succeeded list).
var trivialCommands = map[string]bool{
	"ls": true, "ls -la": true, "cat": true, "pwd": true, "echo": true,
	"dir": true, "cd": true, "which": true, "head": true, "tail": true,
}

// detectUnrecoveredFailures (C4): commands that fail repeatedly and never
// succeed — the user's measurable time sinks. Time-denominated.
func detectUnrecoveredFailures(f *Facts, t Thresholds) []Suggestion {
	var out []Suggestion
	for _, ff := range f.Failures {
		if ff.Recovered || ff.Fails < t.C4MinFails {
			continue
		}
		first := strings.Fields(ff.Command)
		if len(first) == 0 || trivialCommands[first[0]] || trivialCommands[ff.Command] || len(ff.Command) < 4 {
			continue
		}
		minutes := float64(ff.Fails) * 2 // ~2min lost per failed attempt (attempt + read + retry)
		out = append(out, Suggestion{
			DedupKey: "unrecovered_failure|" + ff.Project + "|" + ff.Command,
			Detector: "unrecovered_failure",
			Category: CategoryQuality, Scope: ScopeProject, ScopeID: ff.Project, Severity: SeverityWarning,
			Title: fmt.Sprintf("`%s` failed %d times and never passed", truncateStr(ff.Command, 48), ff.Fails),
			Nudge: fmt.Sprintf(
				"`%s` failed %d times in this window (%d retries) and never succeeded - a recurring time sink (~%.0f minutes). Worth fixing the root cause once.",
				truncateStr(ff.Command, 64), ff.Fails, ff.Retries, minutes,
			),
			SavingsMin: minutes, Confidence: 0.8,
			Evidence: Evidence{
				Numbers: map[string]float64{"fails": float64(ff.Fails), "retries": float64(ff.Retries)},
				Math:    fmt.Sprintf("%d failed attempts × ~2 min each = ~%.0f min", ff.Fails, minutes),
			},
		})
	}
	return out
}

// detectMCPOverhead (E1): MCP tool schemas cost ~1,900 tokens on every
// turn; when the tools go essentially uncalled, that's a fixed tax.
func detectMCPOverhead(f *Facts, t Thresholds) []Suggestion {
	if !f.MCPConfigured {
		return nil
	}
	var turns int
	model := ""
	for i := range f.Sessions {
		turns += len(f.Sessions[i].Rows)
		if model == "" {
			model = sessionModelOf(&f.Sessions[i])
		}
	}
	if turns < 200 {
		return nil
	}
	callsPer100 := float64(f.MCPCalls) * 100 / float64(turns)
	if callsPer100 >= t.MCPMinCallsPer100Turns {
		return nil
	}
	taxCost, ok := f.Price(model, cost.TokenBundle{Input: int64(turns) * 1900})
	if !ok || taxCost <= 0 {
		return nil
	}
	return []Suggestion{{
		DedupKey: "mcp_overhead|window", Detector: "mcp_overhead",
		Category: CategoryHygiene, Scope: ScopeGlobal, Severity: SeverityAdvice,
		Title: fmt.Sprintf("MCP schemas taxed ~%d turns but were called %d times", turns, f.MCPCalls),
		Nudge: fmt.Sprintf(
			"MCP tool schemas add ~1,900 tokens to every turn (≈$%.2f across this window) but the tools were called only %d times in %d turns. If you rarely query the observer mid-session, removing Observer's MCP server entry removes the per-turn tax (Settings > Connected tools > Set up > Remove Observer's wiring > MCP server, or `observer uninstall --<tool> --skip-hooks`).",
			taxCost, f.MCPCalls, turns,
		),
		SavingsUSD: round2(taxCost * 0.9), Confidence: 0.6,
		Evidence: Evidence{
			Numbers: map[string]float64{"turns": float64(turns), "mcp_calls": float64(f.MCPCalls), "calls_per_100_turns": callsPer100},
			Math:    fmt.Sprintf("%d turns × 1,900 schema tokens at input rate = $%.2f", turns, taxCost),
		},
		// Q4: E1 remediation routes through the Connected-tools panel
		// (review MCP state per tool; the wizard's consent flow owns
		// any re-registration) — never a direct write from this card.
		Action: &Action{Kind: "settings_section", Target: "tools", Label: "Review MCP in Connected tools"},
	}}
}

// detectCompressionOff (E3): proxied sessions with zero compression —
// the pipeline is off while its input volume is being paid full price.
func detectCompressionOff(f *Facts, _ Thresholds) []Suggestion {
	var proxied, compressed int
	var inputCost float64
	for i := range f.Sessions {
		s := &f.Sessions[i]
		if !s.HasProxy() {
			continue
		}
		proxied++
		if s.CompressionOrig > 0 {
			compressed++
			continue
		}
		in, outT, cr, cc, cc1, _, anyFast := s.totals()
		if c, ok := f.Price(sessionModelOf(s), cost.TokenBundle{Input: in, Output: outT, CacheRead: cr, CacheCreation: cc, CacheCreation1h: min64(cc1, cc), Fast: anyFast}); ok {
			inputCost += c
		}
	}
	if proxied < 3 || compressed > 0 || inputCost <= 0 {
		return nil
	}
	saving := inputCost * 0.08 // the documented 7–10% recipe midpoint
	return []Suggestion{{
		DedupKey: "compression_off|window", Detector: "compression_off",
		Category: CategoryHygiene, Scope: ScopeGlobal, Severity: SeverityInfo,
		Title: fmt.Sprintf("%d proxied sessions ran with compression off", proxied),
		Nudge: fmt.Sprintf(
			"Your traffic routes through the proxy but conversation compression never engaged ($%.2f of spend at full size). Enabling the compression pipeline historically saves 7-10%% on tool-result-heavy sessions - roughly $%.2f here.",
			inputCost, saving,
		),
		SavingsUSD: round2(saving), Confidence: 0.5,
		Evidence: Evidence{
			Numbers: map[string]float64{"proxied_sessions": float64(proxied)},
			Math:    fmt.Sprintf("$%.2f proxied spend × 8%% recipe midpoint = $%.2f", inputCost, saving),
		},
		Action: &Action{Kind: "settings_section", Target: "compression", Label: "Enable in Settings"},
	}}
}

// detectNotProxied (E4): meaningful spend running outside the proxy —
// missing accurate tokens, conversation compression, and cachetrack Tier-1.
func detectNotProxied(f *Facts, _ Thresholds) []Suggestion {
	var unproxied int
	var spend float64
	for i := range f.Sessions {
		s := &f.Sessions[i]
		if s.HasProxy() {
			continue
		}
		var c float64
		for _, r := range s.Rows {
			if v, ok := rowCost(f, s, r); ok {
				c += v
			}
		}
		if c >= 1.0 {
			unproxied++
			spend += c
		}
	}
	if unproxied < 3 || spend < 20 {
		return nil
	}
	saving := spend * 0.07
	return []Suggestion{{
		DedupKey: "not_proxied|window", Detector: "not_proxied",
		Category: CategoryHygiene, Scope: ScopeGlobal, Severity: SeverityInfo,
		Title: fmt.Sprintf("$%.0f of spend isn't routed through the proxy", spend),
		Nudge: fmt.Sprintf(
			"%d sessions ($%.2f) ran outside the proxy this window - without it you miss exact token accounting, conversation compression (~7%%, ≈$%.2f here), and prompt-cache tracking. Route your tools through the proxy on the Compression page (or with `observer init`).",
			unproxied, spend, saving,
		),
		SavingsUSD: round2(saving), Confidence: 0.5,
		Evidence: Evidence{
			Numbers: map[string]float64{"unproxied_sessions": float64(unproxied), "unproxied_spend": round2(spend)},
			Math:    fmt.Sprintf("$%.2f unproxied spend × 7%% compression midpoint = $%.2f", spend, saving),
		},
		Action: &Action{Kind: "page", Target: "/compression", Label: "Route via proxy"},
	}}
}

func dominantCause(evs []CacheEventFact) string {
	counts := map[string]int{}
	best, bestN, total := "", 0, 0
	for _, e := range evs {
		if e.Cause == "" || e.Cause == "suffix_growth" {
			continue
		}
		counts[e.Cause]++
		total++
		if counts[e.Cause] > bestN {
			best, bestN = e.Cause, counts[e.Cause]
		}
	}
	if total < 3 || float64(bestN) < 0.5*float64(total) {
		return ""
	}
	return best
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
