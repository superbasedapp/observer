package dashboard

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// StatuslineResponse is the wire shape of GET /api/statusline — a small,
// dedicated struct (NOT a subset of handleAnalysisHeadline's response)
// because the CLI's DaemonTile (cmd/observer/statusline.go, a later work
// package) mirrors these field names verbatim. SessionUSD /
// SessionCacheReadShare are pointers so "no session_id supplied" and
// "session_id supplied but unknown" both serialize as JSON null rather
// than a fabricated 0 — an honest omission, matching the render-side
// convention documented in the statusline plan §4.1 ("omitted, not
// $0.00").
type StatuslineResponse struct {
	TodayUSD              float64  `json:"today_usd"`
	SessionUSD            *float64 `json:"session_usd"`
	SessionCacheReadShare *float64 `json:"session_cache_read_share"`
	GeneratedAt           string   `json:"generated_at"`
}

// statuslineCacheEntry is one memoized StatuslineResponse plus the instant
// it stops being servable. GeneratedAt inside resp is left exactly as it
// was when the response was computed, so a cache hit still carries an
// honest (if slightly stale) staleness signal — a consumer diffing
// generated_at against wall-clock time can tell.
type statuslineCacheEntry struct {
	resp      StatuslineResponse
	expiresAt time.Time
}

// statuslineCacheKey scopes a cached entry to one Server instance (via
// pointer identity) AND one (day-window, session_id) pair. Server-instance
// scoping matters because this fix's file set is restricted to
// statusline.go/statusline_test.go — adding a cache field to the Server
// struct itself would require editing dashboard.go's type definition and
// New(), which is out of scope here — so the cache lives at package scope
// instead, and the *Server pointer in the key is what keeps two Server
// instances (e.g. two tests' fixtures, both querying "no session_id,
// today") from ever observing each other's cached rows.
type statuslineCacheKey struct {
	srv *Server
	key string
}

// statuslineTTL is how long a computed /api/statusline response is served
// from statuslineCache before the underlying query re-runs (F6 fix — see
// the handler doc comment below). 2s is chosen to be long enough to
// absorb a render-storm — a statusline that fires on every terminal
// render tick can fire on every keystroke, producing a burst of requests
// within the same second or two — while staying short enough that the
// number a human is watching still reads as live.
//
// It is a package-level var rather than a Server field for the same
// out-of-scope-file reason statuslineCacheKey embeds a pointer instead of
// a struct field: tests in this package override it directly (same
// package, no exported knob needed) and MUST restore the previous value
// via tb.Cleanup so one test's override never leaks into the next. Zero
// disables caching outright (every call is a miss) — BenchmarkHandleStatus
// lineTile uses this to keep measuring the uncached per-call query cost
// it exists to guard.
var statuslineTTL = 2 * time.Second

// statuslineCacheMu guards statuslineCache. It is held across the whole
// check-or-compute-and-store step in statuslineCachedOrCompute, not just
// the map access — a deliberate singleflight-lite choice. At this
// endpoint's expected concurrency (one local daemon, at most a handful of
// concurrent statusline pollers) it's cheaper to serialize a rare
// concurrent cache miss than to pull in a real singleflight dependency,
// and it guarantees two requests racing on the same key never both pay
// for the query.
var (
	statuslineCacheMu sync.Mutex
	statuslineCache   = map[statuslineCacheKey]statuslineCacheEntry{}
)

// statuslineCachedOrCompute serves the memoized response for cacheKey when
// one is still live, or computes + (when caching is enabled) stores a
// fresh one otherwise.
func statuslineCachedOrCompute(ctx context.Context, s *Server, cacheKey statuslineCacheKey, sessionID string, dayStart, now time.Time) (StatuslineResponse, error) {
	statuslineCacheMu.Lock()
	defer statuslineCacheMu.Unlock()

	if statuslineTTL > 0 {
		if entry, ok := statuslineCache[cacheKey]; ok && now.Before(entry.expiresAt) {
			return entry.resp, nil
		}
	}

	today, err := statuslineQueryRows(ctx, s.db(), s.opts.CostEngine, dayStart.Format(time.RFC3339Nano), "")
	if err != nil {
		return StatuslineResponse{}, err
	}

	resp := StatuslineResponse{
		TodayUSD:    today.CostUSD,
		GeneratedAt: now.Format(time.RFC3339),
	}

	if sessionID != "" {
		// Session-scoped total is intentionally ALL-TIME for that
		// session (no day window) — a session is the natural unit,
		// and it may have started before today (plan §2, "session_usd
		// + session_cache_read_share: ... all-time for that session,
		// not day-windowed").
		session, err := statuslineQueryRows(ctx, s.db(), s.opts.CostEngine, "", sessionID)
		if err != nil {
			return StatuslineResponse{}, err
		}
		if session.RowCount > 0 {
			usd := session.CostUSD
			resp.SessionUSD = &usd
			var share float64
			if session.PromptTokens > 0 {
				share = float64(session.CacheReadTokens) / float64(session.PromptTokens)
			}
			resp.SessionCacheReadShare = &share
		}
		// session.RowCount == 0 (unknown/empty session_id) leaves both
		// pointers nil → JSON null, per the honest-omission contract.
	}

	if statuslineTTL > 0 {
		statuslineCache[cacheKey] = statuslineCacheEntry{resp: resp, expiresAt: now.Add(statuslineTTL)}
	}
	return resp, nil
}

// handleStatuslineTile serves GET /api/statusline?session_id=<id> — the
// daemon-path data source for `observer statusline` (§2 of
// docs/plans/observer-statusline-plan-2026-07-30.md). It returns two
// numbers: today's (UTC calendar day) total spend, and — only when the
// caller supplies session_id — that session's all-time total plus its
// cache-read share of the prompt window.
//
// Deliberately narrow. handleAnalysisHeadline (analysis.go) is a 30-day,
// multi-tile scan built for the dashboard's Analysis KPI band — month
// projection, LC-tier surcharge decomposition, cache-savings
// counterfactual, burn rate, top-model concentration. WP0 measured that
// handler at 1.2-2.2s per call against a 15GB corpus. A statusline fired
// on every terminal render tick budgets <100ms end-to-end INCLUDING the
// loopback round trip (plan §2.3), so this handler reuses only the part
// of handleAnalysisHeadline's approach that's load-bearing — the per-turn
// -deduped api_turns∪token_usage scan + the recorded-cost-wins pricing
// rule (see statuslineQueryRows) — windowed to one day (or one session),
// with NONE of the extra tiles.
//
// REGRESSION GUARD: do not grow this handler back toward
// handleAnalysisHeadline's breadth. If a future change needs the month
// projection / LC tiles / burn rate / top-model here, that's a sign the
// change belongs on a *different* endpoint the statusline command
// doesn't call on its render hot path. BenchmarkHandleStatuslineTile
// pins the cost bound this comment describes; a regression that
// reintroduces analysis-headline-style scope will show up there first.
//
// Pricing correction (WP0, 2026-07-30): querying
// SUM(estimated_cost_usd) over today's token_usage rows measured $0.0
// on 1,151 real rows — that column is unpopulated for major sources
// (claude-code prices its turns at query time via the cost engine, not
// at ingest time). This handler MUST price every row without a
// positive recorded cost through the cost engine (cost.Compute against
// the pricing table), exactly like handleAnalysisHeadline does, rather
// than summing the raw column.
//
// Caching (F6 fix, adversarial review): "fires on every render tick"
// means, in practice, on every keystroke of an interactive terminal
// session — a render storm the query cost above was never meant to
// absorb per-tick. statuslineCachedOrCompute memoizes the computed
// response for statuslineTTL (2s) keyed on (this Server, day-window,
// session_id), so a burst of ticks within that window shares one
// computation. See statuslineTTL's doc comment for why the cache lives
// at package scope instead of on the Server struct.
func (s *Server) handleStatuslineTile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sessionID := r.URL.Query().Get("session_id")
	now := s.now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	cacheKey := statuslineCacheKey{srv: s, key: dayStart.Format("2006-01-02") + "|" + sessionID}

	resp, err := statuslineCachedOrCompute(ctx, s, cacheKey, sessionID, dayStart, now)
	if err != nil {
		writeErr(w, err)
		return
	}

	writeJSON(w, resp)
}

// statuslineTotals accumulates the priced total plus the cache-read /
// prompt-token aggregates statuslineQueryRows needs for
// session_cache_read_share, over whichever row set the caller's WHERE
// clause selects. RowCount lets the caller distinguish "matched zero
// rows" (unknown session_id → render null) from "matched rows that
// happen to sum to $0".
type statuslineTotals struct {
	CostUSD         float64
	CacheReadTokens int64
	PromptTokens    int64 // input + cache_read + cache_creation, across matched rows
	RowCount        int
}

// statuslineQueryRows sums the node's deduped spend substrate
// (loadSpendTurns: the one session dedup rule, sessionmsg.DeriveVerdicts,
// applied by the cost engine and priced by it) over whichever rows the
// caller selects, so the statusline agrees with the session detail header
// and the Sessions list. It carries NONE of handleAnalysisHeadline's extra
// tiles — see the handleStatuslineTile doc comment for why that's a hard
// constraint, not an oversight.
//
// sinceRFC3339 (when non-empty) bounds rows to timestamp >= that value
// — used for the "today" query. sessionID (when non-empty) bounds rows
// to that session — used for the "session" query. The two callers of
// this function each supply exactly one of the two (never both, never
// neither), but the function itself tolerates any combination.
//
// Pricing is the engine's per-row rule: a positive recorded cost wins, else
// the pricing table's rate at the row's own timestamp; an unknown model
// contributes $0 (no fabricated cost). With no engine there is nothing to
// dedup or price with, and the totals stay zero.
func statuslineQueryRows(ctx context.Context, db *sql.DB, engine *cost.Engine, sinceRFC3339 string, sessionID string) (statuslineTotals, error) {
	var totals statuslineTotals
	if db == nil || engine == nil {
		return totals, nil
	}
	var since time.Time
	if sinceRFC3339 != "" {
		t, err := time.Parse(time.RFC3339Nano, sinceRFC3339)
		if err != nil {
			return totals, fmt.Errorf("dashboard.statuslineQueryRows: since: %w", err)
		}
		since = t
	}
	var ids []string
	if sessionID != "" {
		ids = []string{sessionID}
	}
	turns, err := loadSpendTurns(ctx, db, engine, since, time.Time{}, "", "", ids)
	if err != nil {
		return totals, fmt.Errorf("dashboard.statuslineQueryRows: %w", err)
	}
	for _, t := range turns {
		totals.CostUSD += t.CostUSD
		totals.CacheReadTokens += t.Bundle.CacheRead
		totals.PromptTokens += t.Bundle.Input + t.Bundle.CacheRead + t.Bundle.CacheCreation
		totals.RowCount++
	}
	return totals, nil
}
