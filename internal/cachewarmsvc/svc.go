package cachewarmsvc

import (
	"context"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cachewarm"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// PriceLookup resolves a model's per-million-token pricing. Callers pass
// cost.Engine.Lookup (or a table's Lookup). May be nil — value-at-risk
// then resolves to 0 (and MinValueUSD>0 suppresses the windows).
type PriceLookup func(model string) (cost.Pricing, bool)

// WindowStatus pairs a classified warning with its keep-warm
// recommendation. The surfaces serialize this directly.
type WindowStatus struct {
	cachewarm.Warning
	Recommendation cachewarm.Recommendation `json:"recommendation"`
}

// LoadOpts bounds a Load call.
type LoadOpts struct {
	// SessionID restricts to one creating session; "" = all.
	SessionID string
	// IncludeCold includes already-cold caches (status surfaces want
	// them; a pure warning feed may not).
	IncludeCold bool
	// ColdGrace bounds how far back recently-expired (state='expired')
	// entries are loaded. Defaults to 5m when IncludeCold and zero.
	ColdGrace time.Duration
	// Limit caps the row count (soonest-expiry first). 0 = no cap.
	Limit int
	// Proxied reports the active session routes through the proxy (gates
	// the enforce-mode replay recommendation).
	Proxied bool
}

// chainFetchCap bounds the raw cache_entries fetch. It is deliberately NOT
// the display limit (LoadOpts.Limit): collapseChains needs every entry of a
// session's cache chain present to sum the full prefix and pick the
// warm-longest expiry, so the display limit is applied AFTER collapse. The
// recency filter (expires_at >= now-grace) already bounds the working set
// to warm + recently-cold rows; this cap is only a runaway-scan backstop.
const chainFetchCap = 5000

// Load reads the live cache windows and returns them classified +
// recommended. now is taken once and shared by the store grace-filter and
// the classifier so the two agree.
func Load(ctx context.Context, s *store.Store, lookup PriceLookup, cfg config.CacheWarmConfig, opts LoadOpts) ([]WindowStatus, error) {
	now := time.Now().UTC()
	grace := opts.ColdGrace
	if opts.IncludeCold && grace == 0 {
		grace = 5 * time.Minute
	}
	storeOpts := store.CacheWindowOpts{
		SessionID: opts.SessionID,
		Now:       now,
		ColdGrace: grace,
		Limit:     chainFetchCap,
	}
	rows, err := s.LoadLiveCacheWindows(ctx, storeOpts)
	if err != nil {
		return nil, err
	}
	// Implicit (OpenAI/Codex) caches have no cache_entries (anonymous, no
	// TTL), so synthesize ESTIMATED warm windows from their cache_events
	// activity with a graded idle-risk model. These flow through the same
	// classify/recommend path; the boundary resolves the expiry model.
	implicit, err := s.LoadImplicitCacheActivity(ctx, storeOpts)
	if err != nil {
		return nil, err
	}

	statuses := assemble(rows, implicit, lookup, now, cfg, opts, grace)
	// Apply the caller's display limit AFTER collapse + the classifier's
	// urgency sort, so the cap counts logical caches (one per
	// session/model/scope), not raw per-turn chain write-points.
	if opts.Limit > 0 && len(statuses) > opts.Limit {
		statuses = statuses[:opts.Limit]
	}
	return statuses, nil
}

// implicitRows converts implicit-cache activity into cache_entries-shaped
// rows so they flow through the same assemble pipeline as Anthropic explicit
// caches. The expiry is ESTIMATED (LastActivity + idle window) — provider
// implicit caches expose no TTL — so Tier is carried through (non-"proxy"
// ⇒ assemble flags the window estimated). idleSeconds<=0 falls back to the
// 600s default so a zero-valued config never collapses the window to expire
// instantly.
func dur(seconds, fallback int) time.Duration {
	if seconds <= 0 {
		seconds = fallback
	}
	return time.Duration(seconds) * time.Second
}

// buildImplicitWindows synthesizes ESTIMATED warm windows for implicit
// (OpenAI/Codex) caches, which expose no TTL and never land in cache_entries.
// Survival is best-effort, not a lease (docs/general_info/openai_cache_expiry.md),
// so we model a GRADED idle-risk progression keyed on time since last
// activity. We set ExpiresAt to the hard-max retention ceiling (idle == Max)
// and map the risk bands onto per-window classifier thresholds:
//
//	idle < Warn          → ok        (high-confidence reuse)
//	Warn ≤ idle < Crit   → soon      ("at risk of expiry")
//	Crit ≤ idle < Max    → critical  ("significantly increased risk")
//	idle ≥ Max           → expired   (hard 24h ceiling)
//
// Since remaining = (LastActivity+Max) − now = Max − idle, "idle ≥ Warn" is
// "remaining ≤ Max − Warn", which is exactly the WarnAtOverride. Windows are
// flagged estimated (ExpiryAuthoritative=false) and never advertise the
// Anthropic 1h tier. Value-at-risk uses the implicit formula (full input −
// cached read; no write premium).
func buildImplicitWindows(acts []store.ImplicitCacheActivity, lookup PriceLookup, cfg config.CacheWarmConfig) []cachewarm.CacheWindow {
	warn := dur(cfg.ImplicitWarnSeconds, 3600)
	crit := dur(cfg.ImplicitCriticalSeconds, 7200)
	maxIdle := dur(cfg.ImplicitMaxSeconds, 86400)
	if crit < warn {
		crit = warn
	}
	if maxIdle < crit {
		maxIdle = crit
	}
	out := make([]cachewarm.CacheWindow, 0, len(acts))
	for _, a := range acts {
		var value float64
		if lookup != nil {
			if p, ok := lookup(a.Model); ok {
				value = valueAtRisk(p, a.PrefixTokens, "", false)
			}
		}
		out = append(out, cachewarm.CacheWindow{
			Model:               a.Model,
			Scope:               "default",
			SessionID:           a.SessionID,
			PrefixTokens:        a.PrefixTokens,
			TTLTier:             "", // implicit caches have no tier label
			ExpiresAt:           a.LastActivity.Add(maxIdle),
			LastRefresh:         a.LastActivity,
			ExpiryAuthoritative: false, // no provider TTL → estimated
			Supports1hTier:      false,
			RefreshableByPatch:  false,
			ValueAtRiskUSD:      value,
			WarnAtOverride:      maxIdle - warn, // idle ≥ Warn ⟺ remaining ≤ Max−Warn
			CriticalAtOverride:  maxIdle - crit, // idle ≥ Crit ⟺ remaining ≤ Max−Crit
		})
	}
	return out
}

// assemble maps rows → windows → warnings + recommendations. Pure given
// its inputs (now injected); exported indirectly via Load.
//
// Explicit (Anthropic) caches come in as cache_entries rows; implicit
// (OpenAI/Codex) caches come in as activity → estimated graded windows
// (buildImplicitWindows). Both are classified in one pass — per-window
// thresholds (CacheWindow.WarnAtOverride) reconcile the seconds-scale hard
// TTL with the hour-scale idle-risk bands.
//
// coldGrace bounds how long a cold cache stays surfaced. This matters
// because the engine only sweeps entries to state='expired' on an OBSERVED
// turn — an idle session's entry stays state='live' in the DB with an
// expires_at far in the past, and the classifier (correctly) calls it
// cold. Without this bound the card would accrete every long-dead cache
// the daemon ever modelled. We surface a cold cache only if it expired
// within coldGrace (recently cold = "you just missed it"); older cold
// caches are dropped as un-actionable noise.
func assemble(rows []store.CacheEntryRow, implicitActs []store.ImplicitCacheActivity, lookup PriceLookup, now time.Time, cfg config.CacheWarmConfig, opts LoadOpts, coldGrace time.Duration) []WindowStatus {
	// Collapse each session's chain of per-turn write-points into one
	// logical warm cache before classifying — see collapseChains.
	rows = collapseChains(rows)

	windows := make([]cachewarm.CacheWindow, 0, len(rows)+len(implicitActs))
	for _, r := range rows {
		var value float64
		if lookup != nil {
			if p, ok := lookup(r.Model); ok {
				value = valueAtRisk(p, r.TokenCount, r.TTLTier, looksAnthropic(r.Model))
			}
		}
		windows = append(windows, cachewarm.CacheWindow{
			Model:               r.Model,
			Scope:               r.CacheScope,
			SessionID:           r.SessionID,
			PrefixTokens:        r.TokenCount,
			TTLTier:             r.TTLTier,
			ExpiresAt:           r.ExpiresAt,
			LastRefresh:         r.LastRefreshAt,
			ExpiryAuthoritative: r.Tier == "proxy", // byte-exact proxy observation
			Supports1hTier:      looksAnthropic(r.Model),
			RefreshableByPatch:  looksGemini(r.Model),
			ValueAtRiskUSD:      value,
		})
	}
	windows = append(windows, buildImplicitWindows(implicitActs, lookup, cfg)...)

	// MinValueUSD suppresses low-value caches so the GLOBAL card / status
	// bar isn't noisy. It must NOT gate the session-scoped detail view:
	// when the operator opens one session they want its live cache
	// countdown regardless of dollar value (token_count is the per-turn
	// write, often well under the floor, so the floor otherwise hides the
	// timer entirely). Value still renders on the card as information.
	minValue := cfg.MinValueUSD
	if opts.SessionID != "" {
		minValue = 0
	}

	warnings := cachewarm.Classify(cachewarm.ClassifyInput{
		Windows:     windows,
		Now:         now,
		WarnAt:      time.Duration(cfg.WarnAtSeconds) * time.Second,
		CriticalAt:  time.Duration(cfg.CriticalAtSeconds) * time.Second,
		MinValueUSD: minValue,
		IncludeCold: opts.IncludeCold,
	})

	coldGraceSecs := int64(coldGrace / time.Second)
	out := make([]WindowStatus, 0, len(warnings))
	for _, w := range warnings {
		// Drop long-dead cold caches (idle entries the engine never swept);
		// keep only recently-cold ones within the grace.
		if w.Severity == cachewarm.SeverityCold && coldGraceSecs > 0 && -w.SecondsToExpiry > coldGraceSecs {
			continue
		}
		rec := cachewarm.Recommend(cachewarm.RecommendInput{
			Window:              w.Window,
			ResumeConfidence:    resumeConfidence(now, w.Window.LastRefresh),
			MinValueUSD:         cfg.Keepwarm.MinValueUSD,
			MinResumeConfidence: cfg.Keepwarm.MinResumeConfidence,
			Mode:                cfg.Keepwarm.Mode,
			Proxied:             opts.Proxied,
		})
		out = append(out, WindowStatus{Warning: w, Recommendation: rec})
	}
	return out
}

// collapseChains folds a session's many per-turn cache write-points into
// ONE logical warm cache per (session, model, scope). This reflects how
// provider caches actually expire: the TTL is a SLIDING WINDOW refreshed on
// every use, not a fixed timer from creation (Anthropic: "the cache is
// refreshed for no additional cost each time the cached content is used";
// OpenAI's implicit cache likewise survives as long as the prefix keeps
// getting hit). Every turn re-sends the conversation and reads the longest
// matching prefix, refreshing the whole chain — so the early prefixes do
// NOT die at creation-time + TTL; the session's cache is warm until the
// MOST RECENT activity + TTL. See the "Cache expiry" section of
// docs/cache-tracking.md.
//
// Therefore the representative window is:
//   - ExpiresAt / TTLTier / Tier / Model taken from the warm-LONGEST entry
//     (max expires_at) — the tip that keeps the chain alive;
//   - LastRefresh = the latest refresh across the chain (last activity);
//   - TokenCount = the SUM across the chain — a cumulative estimate of the
//     full cached prefix at risk if the session goes idle past the TTL
//     (more faithful than any single per-turn write; the exact prefix size
//     would be the latest turn's cache_read tokens, a documented refinement).
//
// Distinct models or scopes in one session stay separate rows (e.g. an
// opus main + a haiku sub-agent are two real caches). Input order is
// preserved by first-seen group order so the result is deterministic.
func collapseChains(rows []store.CacheEntryRow) []store.CacheEntryRow {
	type key struct{ session, model, scope string }
	type agg struct {
		rep         store.CacheEntryRow // entry with the latest expires_at
		tokenSum    int64
		lastRefresh time.Time
	}
	groups := make(map[key]*agg, len(rows))
	order := make([]key, 0, len(rows))
	for _, r := range rows {
		k := key{r.SessionID, r.Model, r.CacheScope}
		a, ok := groups[k]
		if !ok {
			a = &agg{rep: r, lastRefresh: r.LastRefreshAt}
			groups[k] = a
			order = append(order, k)
		}
		a.tokenSum += r.TokenCount
		if r.ExpiresAt.After(a.rep.ExpiresAt) {
			a.rep = r
		}
		if r.LastRefreshAt.After(a.lastRefresh) {
			a.lastRefresh = r.LastRefreshAt
		}
	}
	out := make([]store.CacheEntryRow, 0, len(order))
	for _, k := range order {
		a := groups[k]
		rep := a.rep
		rep.TokenCount = a.tokenSum
		rep.LastRefreshAt = a.lastRefresh
		out = append(out, rep)
	}
	return out
}

// valueAtRisk is the dollar delta of letting a cache go cold vs keeping it
// warm for one resumed turn: tokens × (rate_if_cold − cache_read_rate) / 1e6.
//
// The "rate if cold" differs by provider capability, not source identity:
//   - Anthropic (explicit): going cold means paying a cache WRITE to
//     re-establish the prefix → use CacheCreation (or the 1h write rate
//     when the cache holds the 1h tier).
//   - Implicit (OpenAI/Codex, !anthropic): there is no write premium —
//     going cold simply means paying FULL input price instead of the
//     discounted cached-read price → use Input.
func valueAtRisk(p cost.Pricing, tokens int64, ttlTier string, anthropic bool) float64 {
	var coldRate float64
	if anthropic {
		coldRate = p.CacheCreation
		if ttlTier == "1h" && p.CacheCreation1h > 0 {
			coldRate = p.CacheCreation1h
		}
	} else {
		coldRate = p.Input
	}
	delta := coldRate - p.CacheRead
	if delta < 0 {
		delta = 0
	}
	return float64(tokens) * delta / 1_000_000
}

// resumeConfidence is the v1 boundary heuristic for "will this session send
// another matching turn?" — keyed on how recently the cache was refreshed.
// A cache touched seconds ago belongs to an active session; a cache idle for
// half an hour probably won't be resumed. Documented as a heuristic; a
// future version can key on the session's full inter-turn cadence.
func resumeConfidence(now, lastRefresh time.Time) float64 {
	if lastRefresh.IsZero() {
		return 0.3
	}
	idle := now.Sub(lastRefresh)
	switch {
	case idle < 2*time.Minute:
		return 0.9
	case idle < 10*time.Minute:
		return 0.6
	case idle < 30*time.Minute:
		return 0.4
	default:
		return 0.2
	}
}

// looksAnthropic reports whether a model id is Anthropic-shaped (supports
// the 1h cache tier + byte-exact proxy expiry). Heuristic on the model
// string — the cache_entries row carries no provider id.
func looksAnthropic(model string) bool {
	m := strings.ToLower(model)
	return strings.Contains(m, "claude") ||
		strings.Contains(m, "opus") ||
		strings.Contains(m, "sonnet") ||
		strings.Contains(m, "haiku")
}

// looksGemini reports whether a model id is Gemini-shaped (explicit
// CachedContent with a patchable TTL).
func looksGemini(model string) bool {
	return strings.Contains(strings.ToLower(model), "gemini")
}
