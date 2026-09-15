package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/cachewarmsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// CacheStatusResponse is the payload for GET /api/cache/status. It serves
// both the global view (VS Code status bar, the global card) and the
// per-session view (?session=<id>): the cache-expiry warning system + the
// keep-warm recommendation per live cache.
type CacheStatusResponse struct {
	// Enabled mirrors [cachewarm].enabled. When false the surfaces render
	// the disabled help state and Windows is empty.
	Enabled bool `json:"enabled"`
	// KeepwarmMode is "off" | "advise" | "enforce" — the surface shows
	// recommendation pills only when not "off".
	KeepwarmMode string `json:"keepwarm_mode"`
	// Windows are the classified live caches, most-urgent-first.
	Windows []cachewarmsvc.WindowStatus `json:"windows"`
}

// handleCacheStatus serves GET /api/cache/status[?session=<id>]. The
// cache-expiry warning + keep-warm recommendation surface (Part A/B1 of
// docs/plans/cache-expiry-warning-and-keepwarm-plan-2026-06-25.md). A
// read over node-local cache_entries — never pushed, no migration.
func (s *Server) handleCacheStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.opts.CacheWarm
	if !cfg.Enabled {
		writeJSON(w, CacheStatusResponse{Enabled: false})
		return
	}
	var lookup cachewarmsvc.PriceLookup
	if s.opts.CostEngine != nil {
		lookup = s.opts.CostEngine.Lookup
	}
	statuses, err := cachewarmsvc.Load(r.Context(), store.New(s.db()), lookup, cfg, cachewarmsvc.LoadOpts{
		SessionID:   strings.TrimSpace(r.URL.Query().Get("session")),
		IncludeCold: true,
		Limit:       50,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("load cache status: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, CacheStatusResponse{
		Enabled:      true,
		KeepwarmMode: cfg.Keepwarm.Mode,
		Windows:      statuses,
	})
}

// SessionCacheResponse is the payload for GET
// /api/session/<id>/cache. Drives the SessionDetailPanel Cache tab.
// Spec §13 / C13.
//
// Tier collapses the events.tier values for this session into one
// string: "proxy" / "transcript" / "mixed" / "none". A "none"
// tier means cachetrack saw no events for the session — either
// it's pre-cachetrack history (run `observer backfill
// --cache-rescan` to retrofit), or the session never touched a
// cache-capable provider (non-Anthropic; cache_* is Anthropic-
// only today).
type SessionCacheResponse struct {
	Tier       string                     `json:"tier"`
	Entries    []SessionCacheEntry        `json:"entries"`
	Events     []SessionCacheEvent        `json:"events"`
	Efficiency SessionCacheEfficiency     `json:"efficiency"`
	Timeline   []SessionCacheTimelineItem `json:"timeline"`
}

// SessionCacheEntry mirrors a cache_entries row for the panel's
// entry list. ExpiresAt is RFC3339; the frontend computes the
// live TTL countdown client-side from it. The prefix_hash is the
// composite key alongside (model, cache_scope) — sharing the
// table lookup with the engine; not surfaced for display but
// useful for cross-referencing diagnostic dumps.
type SessionCacheEntry struct {
	PrefixHash    string `json:"prefix_hash"`
	Model         string `json:"model"`
	TokenCount    int64  `json:"token_count"`
	TTLTier       string `json:"ttl_tier"`
	Tier          string `json:"tier"`
	State         string `json:"state"`
	CreatedAt     string `json:"created_at"`
	LastRefreshAt string `json:"last_refresh_at"`
	ExpiresAt     string `json:"expires_at"`
}

// SessionCacheEvent mirrors a cache_events row for the diagnostic
// dump alongside the timeline. ZeroUsage is cachetrack.IsZeroUsage
// over (Kind, TokensRead, TokensWritten) — a mispredict whose
// provider envelope carried no token data at all; the frontend
// renders these neutrally and the graded rate excludes them per the
// C12 follow-up (cachetrack.MispredictRateGraded). CostDeltaUSD is a
// nullable pointer (nil = not computed) feeding the efficiency tile's
// AvoidableUSD.
//
// Alias of cachetrack.TimelineEvent — the pure builder now lives
// in internal/cachetrack/timeline.go so the org server can reuse
// it over the same per-event shape arriving on the wire. See
// buildCacheTimeline below.
type SessionCacheEvent = cachetrack.TimelineEvent

// SessionCacheEfficiency is the rollup tile on the Cache tab.
// Ratio is read/write — the cache-payback signal (higher = more
// cache benefit). AvoidableUSD is the sum of per-event cost_delta_usd
// over the avoidable, non-baseline events (cachetrack.BuildEfficiency);
// it stays 0 while every event's cost_delta_usd is NULL — a NULL
// contributes nothing — so the frontend renders "not yet computed"
// rather than a fabricated $0.00.
//
// Alias of cachetrack.Efficiency.
type SessionCacheEfficiency = cachetrack.Efficiency

// SessionCacheTimelineItem is one row of the panel's event
// timeline. The operator UI steer: a long warm session produces
// 100+ baseline events (suffix_growth / hit) that the user
// doesn't need to scroll through one-by-one. Two kinds:
//
//   - Kind="baseline" — a single roll-up entry per
//     contiguous run of baseline events. Count + first/last
//     timestamps + summed token movement. Anomalies break runs.
//   - Kind="anomaly" — a fully itemized event. One row per
//     non-baseline event (rewrites, mispredicts, model_changed,
//     reanchor, etc.) plus a Flagged bool the frontend uses to
//     render a neutral "flagged" pill (not alarm-red) for
//     known-limitation causes like tools_changed where the
//     reading is correct but the alert level is reduced.
//
// The two are interleaved in the response in chronological
// order; the frontend stamps them onto one timeline.
//
// Alias of cachetrack.TimelineItem.
type SessionCacheTimelineItem = cachetrack.TimelineItem

// handleSessionCache serves /api/session/<id>/cache. Spec §13.
//
// Query plan: three small SQL queries scoped to session_id. The
// session-id index keeps each one O(rows-for-this-session); a
// typical warm session has ≤ a few hundred events, so the
// in-memory aggregation in this handler stays bounded.
func (s *Server) handleSessionCache(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	resp := SessionCacheResponse{
		Tier:     "none",
		Entries:  []SessionCacheEntry{},
		Events:   []SessionCacheEvent{},
		Timeline: []SessionCacheTimelineItem{},
	}

	events, err := loadSessionCacheEvents(ctx, s.db(), sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("load events: %v", err), http.StatusInternalServerError)
		return
	}
	entries, err := loadSessionCacheEntries(ctx, s.db(), sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("load entries: %v", err), http.StatusInternalServerError)
		return
	}

	resp.Events = events
	resp.Entries = entries
	resp.Tier = collapseTier(events)
	resp.Efficiency = buildCacheEfficiency(events)
	resp.Timeline = buildCacheTimeline(events)

	writeJSON(w, resp)
}

// loadSessionCacheEvents pulls cache_events for the session in
// chronological order. Empty result = empty slice (NOT nil — keeps
// the JSON response shape stable: `"events": []`).
func loadSessionCacheEvents(ctx context.Context, db *sql.DB, sessionID string) ([]SessionCacheEvent, error) {
	const q = `
		SELECT timestamp, tier, model, kind,
		       COALESCE(cause, ''), COALESCE(predicted_kind, ''),
		       COALESCE(tokens_read, 0), COALESCE(tokens_written, 0),
		       COALESCE(message_id, ''), cost_delta_usd
		FROM cache_events
		WHERE session_id = ?
		ORDER BY timestamp ASC, id ASC`
	rows, err := db.QueryContext(ctx, q, sessionID)
	if err != nil {
		return nil, fmt.Errorf("loadSessionCacheEvents: query: %w", err)
	}
	defer rows.Close()
	out := []SessionCacheEvent{}
	for rows.Next() {
		var ev SessionCacheEvent
		// cost_delta_usd is nullable and NOT COALESCE'd: nil = the
		// reconciliation engine did not compute a delta, 0 = a genuinely
		// zero delta. BuildEfficiency folds only non-nil positive deltas
		// into AvoidableUSD, so the NULL must survive to the struct.
		var costDelta sql.NullFloat64
		if err := rows.Scan(&ev.Timestamp, &ev.Tier, &ev.Model, &ev.Kind,
			&ev.Cause, &ev.PredictedKind, &ev.TokensRead, &ev.TokensWritten, &ev.MessageID, &costDelta); err != nil {
			return nil, fmt.Errorf("loadSessionCacheEvents: scan: %w", err)
		}
		if costDelta.Valid {
			v := costDelta.Float64
			ev.CostDeltaUSD = &v
		}
		// IsZeroUsage is THE rule (cachetrack): a mispredict whose provider
		// envelope carried no token data. A 0/0 hit or write is NOT vacant.
		ev.ZeroUsage = cachetrack.IsZeroUsage(ev.Kind, ev.TokensRead, ev.TokensWritten)
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadSessionCacheEvents: rows: %w", err)
	}
	return out, nil
}

// loadSessionCacheEntries pulls live cache_entries that this
// session created (the session_id column is the creating session
// per cache_entries.session_id's column comment). Sorted by
// expires_at desc so the frontend's TTL list shows the most-
// soon-expiring entries last. State filter is permissive — we
// surface live + expired + unverified for diagnostic visibility;
// invalidated/dropped entries are pruned by PruneCacheRows.
func loadSessionCacheEntries(ctx context.Context, db *sql.DB, sessionID string) ([]SessionCacheEntry, error) {
	const q = `
		SELECT COALESCE(prefix_hash, ''), COALESCE(model, ''),
		       COALESCE(token_count, 0), COALESCE(ttl_tier, ''),
		       COALESCE(tier, ''), COALESCE(state, ''),
		       COALESCE(created_at, ''), COALESCE(last_refresh_at, ''),
		       COALESCE(expires_at, '')
		FROM cache_entries
		WHERE session_id = ?
		ORDER BY expires_at DESC, id ASC
		LIMIT 200`
	rows, err := db.QueryContext(ctx, q, sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []SessionCacheEntry{}, nil
		}
		return nil, fmt.Errorf("loadSessionCacheEntries: query: %w", err)
	}
	defer rows.Close()
	out := []SessionCacheEntry{}
	for rows.Next() {
		var e SessionCacheEntry
		if err := rows.Scan(&e.PrefixHash, &e.Model,
			&e.TokenCount, &e.TTLTier, &e.Tier, &e.State,
			&e.CreatedAt, &e.LastRefreshAt, &e.ExpiresAt); err != nil {
			return nil, fmt.Errorf("loadSessionCacheEntries: scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadSessionCacheEntries: rows: %w", err)
	}
	return out, nil
}

// collapseTier returns the single-string tier label for the
// session's events. "proxy" or "transcript" when all events
// share one tier; "mixed" when both appear; "none" on empty.
//
// Thin delegation to cachetrack.CollapseTier — the one owner of
// this logic (see internal/cachetrack/timeline.go).
func collapseTier(events []SessionCacheEvent) string {
	return cachetrack.CollapseTier(events)
}

// buildCacheEfficiency rolls per-event tokens into the session's
// efficiency tile. Ratio is read/write; division-by-zero falls
// through to 0 (no writes = no cache yet = no payback signal).
// AvoidableUSD sums each non-baseline event's non-nil positive
// cost_delta_usd; while those columns are NULL it stays 0.
//
// Thin delegation to cachetrack.BuildEfficiency.
func buildCacheEfficiency(events []SessionCacheEvent) SessionCacheEfficiency {
	return cachetrack.BuildEfficiency(events)
}

// buildCacheTimeline produces the interleaved baseline-roll-up +
// anomaly-itemized timeline. Operator UI steer #1: a long warm
// session produces 100+ suffix_growth events that the user does
// NOT want itemized — collapse them into a single roll-up row
// per CONTIGUOUS RUN of baseline events. Anomalies break runs +
// land as their own rows.
//
// "Baseline" = (kind=hit OR kind=write) AND cause=suffix_growth.
// Every other event is an anomaly.
//
// Operator UI steer #2: causes that may legitimately fire on a
// real toggle (`tools_changed` after MCP server connect /
// disconnect — documented as known limitation in
// docs/cache-tracking.md) get Flagged=true. The frontend renders
// these with a neutral "flagged" pill, not alarm-red. The
// existing per-event diagnostic stays the same — only the pill
// styling differs.
//
// Thin delegation to cachetrack.BuildTimeline — the pure builder
// now lives in internal/cachetrack/timeline.go so the org server
// can reuse it over the same per-event shape.
func buildCacheTimeline(events []SessionCacheEvent) []SessionCacheTimelineItem {
	return cachetrack.BuildTimeline(events)
}

// isFlaggedCause reports whether cause is a known-limitation
// cause that should render as a neutral "flagged" pill rather
// than alarm-red (tools_changed: MCP server connect/disconnect
// legitimately changes the tools array; see
// docs/cache-tracking.md#mcp-tools_changed-readwrite-over-flag).
//
// Thin delegation to cachetrack.IsFlaggedCause.
func isFlaggedCause(cause string) bool {
	return cachetrack.IsFlaggedCause(cause)
}

// SessionCacheAnnotation is the C15 compact glance-view of
// cachetrack health for a single session. Embedded in
// /api/session/<id> as `cache_summary` next to PerModel +
// ToolBreakdown, so the session detail modal surfaces cache
// efficiency at the same level as API spend and tool spend.
//
// The full Cache tab data continues to load via /api/session/<id>/cache
// (the SessionCacheResponse payload). This annotation is the
// rollup operators see WITHOUT switching tabs — counts + ratio
// + ZeroUsageCount so the [zero-usage, excluded from rate]
// marker is discoverable at the modal level.
type SessionCacheAnnotation struct {
	Tier               string  `json:"tier"`
	EventCount         int64   `json:"event_count"`
	HitCount           int64   `json:"hit_count"`
	WriteCount         int64   `json:"write_count"`
	RewriteCount       int64   `json:"rewrite_count"`
	ReanchorCount      int64   `json:"reanchor_count"`
	MispredictCount    int64   `json:"mispredict_count"`
	ZeroUsageCount     int64   `json:"zero_usage_count"`
	TokensRead         int64   `json:"tokens_read"`
	TokensWritten      int64   `json:"tokens_written"`
	Ratio              float64 `json:"ratio"`
	HasFlaggedRewrites bool    `json:"has_flagged_rewrites"`
}

// loadCacheAnnotationsByKey is the multi-key variant of
// loadSessionCacheAnnotation. Runs ONE batched query over
// cache_events filtered to the supplied keys and returns a map
// of key → annotation. Used by /api/cost and /api/models to
// attach per-row cache annotations to cost summaries (spec §13
// cost-view-annotation).
//
// keyColumn names the cache_events column to group by — today
// "session_id" or "model". keys is the values to bind in the
// WHERE IN clause; only positional parameters enter the SQL.
// Empty keys returns an empty map (no query). The returned map
// only carries entries for keys that had at least one event;
// missing keys mean "no cache events for this key" and the
// frontend renders no annotation.
func loadCacheAnnotationsByKey(ctx context.Context, db *sql.DB, keyColumn string, keys []string) (map[string]*SessionCacheAnnotation, error) {
	if len(keys) == 0 {
		return map[string]*SessionCacheAnnotation{}, nil
	}
	if keyColumn != "session_id" && keyColumn != "model" {
		return nil, fmt.Errorf("loadCacheAnnotationsByKey: unsupported keyColumn %q", keyColumn)
	}
	// Build the WHERE IN placeholder list. Literal '?' and ',' only
	// — no user input enters the SQL string; ids bind as positional
	// parameters via QueryContext.
	placeholders := make([]byte, 0, len(keys)*2-1)
	args := make([]any, len(keys))
	for i, k := range keys {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args[i] = k
	}
	/* #nosec G202 -- placeholders is literal '?,' built from the keys count above; values bind as positional params */
	q := `
		SELECT ` + keyColumn + `, tier, kind, COALESCE(cause, ''),
		       COALESCE(tokens_read, 0), COALESCE(tokens_written, 0)
		FROM cache_events
		WHERE ` + keyColumn + ` IN (` + string(placeholders) + `)`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("loadCacheAnnotationsByKey: query: %w", err)
	}
	defer rows.Close()

	out := map[string]*SessionCacheAnnotation{}
	tiers := map[string]map[string]bool{} // per-key tier set
	for rows.Next() {
		var key, tier, kind, cause string
		var read, written int64
		if err := rows.Scan(&key, &tier, &kind, &cause, &read, &written); err != nil {
			return nil, fmt.Errorf("loadCacheAnnotationsByKey: scan: %w", err)
		}
		ann := out[key]
		if ann == nil {
			ann = &SessionCacheAnnotation{}
			out[key] = ann
			tiers[key] = map[string]bool{}
		}
		ann.EventCount++
		ann.TokensRead += read
		ann.TokensWritten += written
		tiers[key][tier] = true
		switch kind {
		case "hit":
			ann.HitCount++
		case "write":
			ann.WriteCount++
		case "invalidation_rewrite", "expiry_rewrite", "model_switch_rewrite", "compaction_reset":
			ann.RewriteCount++
			if isFlaggedCause(cause) {
				ann.HasFlaggedRewrites = true
			}
		case "reanchor":
			ann.ReanchorCount++
		case "mispredict":
			ann.MispredictCount++
			if cachetrack.IsZeroUsage(kind, read, written) {
				ann.ZeroUsageCount++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadCacheAnnotationsByKey: rows: %w", err)
	}
	// Finalize ratio + tier collapse per key.
	for k, ann := range out {
		if ann.TokensWritten > 0 {
			ann.Ratio = float64(ann.TokensRead) / float64(ann.TokensWritten)
		}
		tset := tiers[k]
		switch len(tset) {
		case 0:
			ann.Tier = "none"
		case 1:
			for t := range tset {
				ann.Tier = t
			}
		default:
			ann.Tier = "mixed"
		}
	}
	return out, nil
}

// loadSessionCacheAnnotation builds the C15 annotation from a
// single scan over the session's cache_events. Returns nil + nil
// when the session has no events (the JSON encoder then omits
// the cache_summary field).
func loadSessionCacheAnnotation(ctx context.Context, db *sql.DB, sessionID string) (*SessionCacheAnnotation, error) {
	if sessionID == "" {
		return nil, nil
	}
	const q = `
		SELECT tier, kind, COALESCE(cause, ''),
		       COALESCE(tokens_read, 0), COALESCE(tokens_written, 0)
		FROM cache_events
		WHERE session_id = ?`
	rows, err := db.QueryContext(ctx, q, sessionID)
	if err != nil {
		return nil, fmt.Errorf("loadSessionCacheAnnotation: query: %w", err)
	}
	defer rows.Close()
	out := &SessionCacheAnnotation{}
	tiers := map[string]bool{}
	for rows.Next() {
		var tier, kind, cause string
		var read, written int64
		if err := rows.Scan(&tier, &kind, &cause, &read, &written); err != nil {
			return nil, fmt.Errorf("loadSessionCacheAnnotation: scan: %w", err)
		}
		out.EventCount++
		out.TokensRead += read
		out.TokensWritten += written
		tiers[tier] = true
		switch kind {
		case "hit":
			out.HitCount++
		case "write":
			out.WriteCount++
		case "invalidation_rewrite", "expiry_rewrite", "model_switch_rewrite", "compaction_reset":
			out.RewriteCount++
			if isFlaggedCause(cause) {
				out.HasFlaggedRewrites = true
			}
		case "reanchor":
			out.ReanchorCount++
		case "mispredict":
			out.MispredictCount++
			if cachetrack.IsZeroUsage(kind, read, written) {
				out.ZeroUsageCount++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadSessionCacheAnnotation: rows: %w", err)
	}
	if out.EventCount == 0 {
		return nil, nil
	}
	if out.TokensWritten > 0 {
		out.Ratio = float64(out.TokensRead) / float64(out.TokensWritten)
	}
	switch len(tiers) {
	case 0:
		out.Tier = "none"
	case 1:
		for t := range tiers {
			out.Tier = t
		}
	default:
		out.Tier = "mixed"
	}
	return out, nil
}

// CacheOverviewResponse is the payload for GET /api/cache/overview.
// Per spec §13: per-project + per-model rollups + top causes
// histogram + worst sessions. Drives the dashboard Overview tile
// (cache efficiency + avoidable $) and the standalone cache
// overview page that surfaces cross-session patterns.
type CacheOverviewResponse struct {
	// Global rolls every cache_event in the window. The frontend
	// renders this as the headline tile.
	Global CacheOverviewGlobal `json:"global"`

	// PerModel breaks the same window out by model so haiku-only
	// sessions can be distinguished from opus-only or mixed. The
	// frontend renders this as a small "by model" table next to
	// the headline.
	PerModel []CacheOverviewModelRollup `json:"per_model"`

	// PerProject joins sessions.project_id → projects.root_path
	// for a per-project rollup. Frontend renders as the project
	// table on the Cache overview page.
	PerProject []CacheOverviewProjectRollup `json:"per_project"`

	// TopCauses histograms ALL events (not just rewrites). The
	// Flagged bool flags causes that may legitimately fire on a
	// real toggle (currently tools_changed); frontend renders
	// these neutrally per operator UI steer #2.
	TopCauses []CacheOverviewCauseRow `json:"top_causes"`

	// WorstSessions are the top N sessions by rewrite count.
	// "Worst" = most cache-invalidating activity, which is the
	// most actionable signal for operators investigating cache
	// underperformance.
	WorstSessions []CacheOverviewSessionRow `json:"worst_sessions"`
}

// CacheOverviewGlobal is the headline tile.
type CacheOverviewGlobal struct {
	Efficiency   SessionCacheEfficiency `json:"efficiency"`
	EventCount   int64                  `json:"event_count"`
	SessionCount int64                  `json:"session_count"`
}

// CacheOverviewModelRollup carries per-model efficiency + event
// count.
type CacheOverviewModelRollup struct {
	Model      string                 `json:"model"`
	Efficiency SessionCacheEfficiency `json:"efficiency"`
	EventCount int64                  `json:"event_count"`
}

// CacheOverviewProjectRollup carries per-project efficiency +
// event count. ProjectRoot is the projects.root_path (NOT
// hashed; this is a node-local read surface).
type CacheOverviewProjectRollup struct {
	ProjectID   int64                  `json:"project_id"`
	ProjectRoot string                 `json:"project_root"`
	Efficiency  SessionCacheEfficiency `json:"efficiency"`
	EventCount  int64                  `json:"event_count"`
}

// CacheOverviewCauseRow is one row of the cause histogram.
// Flagged reflects the same neutral-pill convention as the per-
// session timeline.
type CacheOverviewCauseRow struct {
	Cause   string `json:"cause"`
	Count   int64  `json:"count"`
	Flagged bool   `json:"flagged,omitempty"`
}

// CacheOverviewSessionRow is one row of the worst-sessions
// list. Includes the cause breakdown so operators can see at a
// glance whether a session's rewrites are real invalidations or
// the flagged-cause kind. Tier rolls per-event cache_events.tier
// values into one label per the session — "proxy" / "transcript"
// when uniform, "mixed" when both appear (a session that was
// proxy-captured live and later re-walked by `observer backfill
// --cache-rescan`). Operators reading the worst-sessions list
// need this distinction: a Tier-1 finding is real-time engine
// observation; a Tier-2 finding is historical reconstruction.
type CacheOverviewSessionRow struct {
	SessionID     string `json:"session_id"`
	Model         string `json:"model"`
	Tier          string `json:"tier,omitempty"`
	RewriteCount  int64  `json:"rewrite_count"`
	TokensRead    int64  `json:"tokens_read"`
	TokensWritten int64  `json:"tokens_written"`
	TopCause      string `json:"top_cause,omitempty"`
}

// handleCacheOverview serves /api/cache/overview. Four small
// scoped queries — the cause histogram and per-model rollup
// share a fold over a single events-and-sessions join; the
// per-project and worst-sessions surfaces use the same scan and
// fold in different dimensions. Honors the standard
// days / tool / project query params so the Cache page agrees
// with every other dashboard surface when the operator scopes
// the TopBar.
func (s *Server) handleCacheOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// days defaults to "all-time" by sentinel — older corpora can run
	// pre-cachetrack and the operator's first look at the page should
	// not be empty just because they happened to be on a 30d default.
	// When unset, days == 0 → no time filter applied below.
	days := intArg(r, "days", 0, 0, 36500)
	// period_offset_days shifts the window backward by N days. Used
	// for prior-period comparison fetches; clamped at the same upper
	// bound as days so neither can be abused into a runaway scan.
	offset := intArg(r, "period_offset_days", 0, 0, 36500)
	q := cacheOverviewQuery{
		Days:             days,
		PeriodOffsetDays: offset,
		Tool:             r.URL.Query().Get("tool"),
		Project:          r.URL.Query().Get("project"),
	}

	events, err := loadOverviewEvents(ctx, s.db(), q)
	if err != nil {
		http.Error(w, fmt.Sprintf("load overview events: %v", err), http.StatusInternalServerError)
		return
	}

	resp := buildCacheOverview(events)
	writeJSON(w, resp)
}

// cacheOverviewQuery scopes the cache_events ⨝ sessions ⨝ projects
// join. All three filters are optional. Days==0 disables the
// time bound (full corpus); Tool/Project empty disable the
// matching predicate. Matches the convention used by
// handleStatusScoped + handleCost so the SQL rhythm is uniform.
//
// PeriodOffsetDays shifts the window backward — used by the
// prior-period comparison fetch on the Cache page. Days=30 +
// PeriodOffsetDays=30 returns [now − 60d, now − 30d). Ignored
// when Days==0 (full corpus has no meaningful "prior" period).
type cacheOverviewQuery struct {
	Days             int
	PeriodOffsetDays int
	Tool             string
	Project          string
}

// overviewEvent is the join-shaped row used by the overview
// rollup. Contains the per-event token movement + the session
// and project anchors. Tier is the raw cache_events.tier value
// (collapsed per session into a single label in the row build).
type overviewEvent struct {
	SessionID   string
	Model       string
	Tier        string
	Kind        string
	Cause       string
	Tokens      tokenPair
	ProjectID   int64
	ProjectRoot string
}

type tokenPair struct {
	Read    int64
	Written int64
}

// loadOverviewEvents runs the single join across cache_events,
// sessions, projects. The schema's idx_cache_events_session
// makes this O(events) on the corpus the operator has. Optional
// days / tool / project filters scope the join exactly the way
// handleStatusScoped + handleCost do, so cross-page filter
// behavior agrees.
func loadOverviewEvents(ctx context.Context, db *sql.DB, q cacheOverviewQuery) ([]overviewEvent, error) {
	where := []string{}
	args := []any{}
	if q.Days > 0 {
		// Window: [now − (Days + Offset)days, now − Offset days).
		// When Offset == 0, the upper bound is "now" — original behavior.
		now := time.Now().UTC()
		since := now.Add(-time.Duration(q.Days+q.PeriodOffsetDays) * 24 * time.Hour).Format(time.RFC3339Nano)
		where = append(where, "ce.timestamp >= ?")
		args = append(args, since)
		if q.PeriodOffsetDays > 0 {
			until := now.Add(-time.Duration(q.PeriodOffsetDays) * 24 * time.Hour).Format(time.RFC3339Nano)
			where = append(where, "ce.timestamp < ?")
			args = append(args, until)
		}
	}
	if q.Tool != "" {
		where = append(where, "s.tool = ?")
		args = append(args, q.Tool)
	}
	if q.Project != "" {
		where = append(where, "p.root_path = ?")
		args = append(args, q.Project)
	}
	whereClause := ""
	if len(where) > 0 {
		whereClause = " WHERE " + strings.Join(where, " AND ")
	}
	//nolint:gosec // G202: WHERE fragment is built from code constants; every value is bound via ? args.
	query := `
		SELECT
			ce.session_id, ce.model, COALESCE(ce.tier, ''), ce.kind,
			COALESCE(ce.cause, ''),
			COALESCE(ce.tokens_read, 0), COALESCE(ce.tokens_written, 0),
			COALESCE(s.project_id, 0),
			COALESCE(p.root_path, '')
		FROM cache_events ce
		LEFT JOIN sessions s ON s.id = ce.session_id
		LEFT JOIN projects p ON p.id = s.project_id` + whereClause
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("loadOverviewEvents: query: %w", err)
	}
	defer rows.Close()
	out := []overviewEvent{}
	for rows.Next() {
		var ev overviewEvent
		if err := rows.Scan(&ev.SessionID, &ev.Model, &ev.Tier, &ev.Kind, &ev.Cause,
			&ev.Tokens.Read, &ev.Tokens.Written, &ev.ProjectID, &ev.ProjectRoot); err != nil {
			return nil, fmt.Errorf("loadOverviewEvents: scan: %w", err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadOverviewEvents: rows: %w", err)
	}
	return out, nil
}

// CacheTimeseriesPoint is one bucket in the cache_events
// timeseries — drives the sparklines on the four headline tiles
// of the Cache page.
type CacheTimeseriesPoint struct {
	Bucket        string `json:"bucket"`
	ReadTokens    int64  `json:"read_tokens"`
	WrittenTokens int64  `json:"written_tokens"`
	EventCount    int64  `json:"event_count"`
	RewriteCount  int64  `json:"rewrite_count"`
}

// CacheTimeseriesResponse is the payload for GET
// /api/cache/timeseries?days=&tool=&project=&bucket=day.
type CacheTimeseriesResponse struct {
	Metric string                 `json:"metric"`
	Bucket string                 `json:"bucket"`
	Days   int                    `json:"days"`
	Series []CacheTimeseriesPoint `json:"series"`
}

// handleCacheTimeseries serves /api/cache/timeseries. Buckets
// cache_events by day and returns four series — read_tokens,
// written_tokens, event_count, rewrite_count — over the same
// days / tool / project filter the overview handler uses.
// Drives sparklines on the headline Cache-page tiles so each
// tile carries a visible trajectory in addition to its absolute
// value (matches the Cost-page tile rhythm).
//
// Bucket granularity is fixed at "day" for now — the cache
// engine emits per-turn events; hourly aggregation rarely adds
// signal to a sparkline-shaped surface and would require a
// dedicated bucket=hour code path the Cost handler still
// maintains for its own legacy reasons.
func (s *Server) handleCacheTimeseries(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	q := cacheOverviewQuery{
		Days:    days,
		Tool:    r.URL.Query().Get("tool"),
		Project: r.URL.Query().Get("project"),
	}

	series, err := loadCacheTimeseries(r.Context(), s.db(), q)
	if err != nil {
		http.Error(w, fmt.Sprintf("load cache timeseries: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, CacheTimeseriesResponse{
		Metric: "cache",
		Bucket: "day",
		Days:   days,
		Series: series,
	})
}

// loadCacheTimeseries buckets cache_events by ISO date,
// applying the same days / tool / project scope as
// loadOverviewEvents. The rewrite_count column sums every
// non-baseline kind (invalidation_rewrite / expiry_rewrite /
// model_switch_rewrite) so the surface aligns with the Worst
// sessions ranking.
func loadCacheTimeseries(ctx context.Context, db *sql.DB, q cacheOverviewQuery) ([]CacheTimeseriesPoint, error) {
	where := []string{}
	args := []any{}
	if q.Days > 0 {
		since := time.Now().UTC().Add(-time.Duration(q.Days) * 24 * time.Hour).Format(time.RFC3339Nano)
		where = append(where, "ce.timestamp >= ?")
		args = append(args, since)
	}
	if q.Tool != "" {
		where = append(where, "s.tool = ?")
		args = append(args, q.Tool)
	}
	if q.Project != "" {
		where = append(where, "p.root_path = ?")
		args = append(args, q.Project)
	}
	whereClause := ""
	if len(where) > 0 {
		whereClause = " WHERE " + strings.Join(where, " AND ")
	}
	//nolint:gosec // G202: WHERE fragment is built from code constants; every value is bound via ? args.
	query := `
		SELECT
			substr(ce.timestamp, 1, 10) AS bucket,
			COALESCE(SUM(ce.tokens_read), 0),
			COALESCE(SUM(ce.tokens_written), 0),
			COUNT(*),
			COALESCE(SUM(CASE WHEN ce.kind IN ('invalidation_rewrite','expiry_rewrite','model_switch_rewrite') THEN 1 ELSE 0 END), 0)
		FROM cache_events ce
		LEFT JOIN sessions s ON s.id = ce.session_id
		LEFT JOIN projects p ON p.id = s.project_id` + whereClause + `
		GROUP BY bucket
		ORDER BY bucket ASC`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("loadCacheTimeseries: query: %w", err)
	}
	defer rows.Close()
	out := []CacheTimeseriesPoint{}
	for rows.Next() {
		var p CacheTimeseriesPoint
		if err := rows.Scan(&p.Bucket, &p.ReadTokens, &p.WrittenTokens, &p.EventCount, &p.RewriteCount); err != nil {
			return nil, fmt.Errorf("loadCacheTimeseries: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loadCacheTimeseries: rows: %w", err)
	}
	return out, nil
}

// CacheHealthSummary is the dashboard-facing slim summary of the
// cachetrack engine's grading rate + the two informational
// secondary checks (read:write consistency + cause concentration).
// Mirrors a subset of the cache-health CLI report — only the fields
// the headline tile + WARN banner need so the API surface stays
// small + drift-resistant. The CLI command remains the source of
// truth for full diagnostic output.
type CacheHealthSummary struct {
	// Headline rate signal — drives the Mispredict-rate tile.
	GradedEvents int     `json:"graded_events"`
	Mispredicts  int     `json:"mispredicts"`
	Rate         float64 `json:"mispredict_rate"`
	MinEvents    int     `json:"min_events_threshold"`
	MaxRate      float64 `json:"max_rate_threshold"`
	GatePassed   bool    `json:"gate_passed"`

	// Bucket-mismatch (predicted != observed kind) instrumentation —
	// the rate-blind regression count. Growth-turn mispredicts can
	// land in the same hit-vs-write bucket as the right answer and
	// slip past the rate gate; this surfaces them directly.
	BucketMispredicts int `json:"bucket_mispredicts"`

	// Informational WARNs surfaced as banner pills.
	InconsistentRewriteCount int `json:"inconsistent_rewrite_count"`
	// DominantCause is non-nil when one non-suffix_growth cause
	// exceeds the share threshold over GradedEvents. Banner copy
	// uses the cause + share to call it out by name.
	DominantCause *CacheHealthDominantCause `json:"dominant_cause,omitempty"`

	// UntrackedProviderTurns counts api_turns rows from non-Anthropic
	// providers over the last 7 days — the proxy captured the turn
	// (tokens, cost, model attribution) but cachetrack didn't observe
	// it because the engine's attribution rules are Anthropic-shaped.
	// Surfaced so the operator who routes a codex/openai session
	// through the proxy gets explicit feedback that we SAW the
	// session, just couldn't grade it. Otherwise the Cache page is
	// silently empty and reads as a bug.
	UntrackedProviderTurns int `json:"untracked_provider_turns,omitempty"`
	// UntrackedProviderSessions is the distinct-session count over
	// the same 7-day window.
	UntrackedProviderSessions int `json:"untracked_provider_sessions,omitempty"`
	// UntrackedProviderTopTool names the tool with the most
	// untracked sessions ("codex" / "copilot-cli" / etc.) so the
	// banner copy can call it out by name. Empty when the count
	// is zero.
	UntrackedProviderTopTool string `json:"untracked_provider_top_tool,omitempty"`

	// --- §15.3 implicit-cache surfaces. Counts events whose Kind is
	// in the implicit-cache closed set (KindImplicitHit /
	// KindImplicitMiss / KindImplicitWrite). These events are
	// EXCLUDED from Rate / GradedEvents / Mispredicts above (the
	// Anthropic §10 gate) by design — the dashboard surfaces them
	// on a separate axis. ---

	// ImplicitCacheEvents is the count of implicit-cache events
	// (OpenAI / codex / cline-cli-via-deepseek / etc.) in the
	// window. Zero on an Anthropic-only install.
	ImplicitCacheEvents int `json:"implicit_cache_events,omitempty"`
	// ImplicitCacheHits is the count of KindImplicitHit events.
	ImplicitCacheHits int `json:"implicit_cache_hits,omitempty"`
	// ImplicitCacheMisses is the count of KindImplicitMiss events
	// (cache_read=0 on a turn that should have been cached → the
	// prefix_churn signal). Operator-actionable: high miss count
	// suggests prompt_cache_key churn or aggressive eviction.
	ImplicitCacheMisses int `json:"implicit_cache_misses,omitempty"`
	// ImplicitCacheWrites is the count of KindImplicitWrite events
	// (bootstrap turns + suffix_growth + future
	// prompt_cache_key_overflow signals).
	ImplicitCacheWrites int `json:"implicit_cache_writes,omitempty"`
	// ImplicitCacheConsistencyRate is the implicit-cache analog of
	// the §10 mispredict rate: predicted Kind == observed Kind on
	// the subset of implicit-cache events with a graded prediction
	// (bootstrap writes excluded — see
	// cachetrack.ImplicitCacheConsistency). 0 when ImplicitCacheEvents
	// is zero; the UI suppresses the tile in that case.
	ImplicitCacheConsistencyRate float64 `json:"implicit_cache_consistency_rate,omitempty"`
	// ImplicitCacheConsistencyDenom is the graded-events count for
	// the consistency rate (excludes bootstrap writes that have
	// nothing to predict against).
	ImplicitCacheConsistencyDenom int `json:"implicit_cache_consistency_denom,omitempty"`
	// ImplicitCachePrefixChurnRate is hits / (hits + misses) — the
	// "how often does the prefix survive turn-over-turn" view.
	// 0 when the denominator is zero.
	ImplicitCachePrefixChurnRate float64 `json:"implicit_cache_prefix_churn_rate,omitempty"`
}

// CacheHealthDominantCause names the over-firing non-baseline cause
// when one crosses the share threshold.
type CacheHealthDominantCause struct {
	Cause string  `json:"cause"`
	Count int     `json:"count"`
	Share float64 `json:"share"`
}

// loadCacheHealthSummary reads cache_events and folds the kind +
// token streams through cachetrack.MispredictRateGraded +
// cachetrack.BucketMismatch to produce the slim summary the
// dashboard tile + WARN banner need. Mirrors the math the
// cache-health CLI uses; both share cachetrack's primitives so a
// change there reaches both surfaces simultaneously.
//
// Engine-health is a global signal — the operator's tool / project
// scope is intentionally ignored here so the WARN banner reads
// "engine is unhealthy" without false negatives from a project
// filter narrowing the corpus.
func loadCacheHealthSummary(ctx context.Context, db *sql.DB) (CacheHealthSummary, error) {
	const (
		defaultMinEvents     = 200
		defaultMaxRate       = 0.05
		defaultMaxRewriteRR  = 3.0
		defaultMaxCauseShare = 0.80
	)
	s := CacheHealthSummary{
		MinEvents: defaultMinEvents,
		MaxRate:   defaultMaxRate,
	}

	const q = `SELECT kind, COALESCE(cause, ''), COALESCE(predicted_kind, ''),
	           COALESCE(tokens_read, 0), COALESCE(tokens_written, 0)
	           FROM cache_events ORDER BY id ASC`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return s, fmt.Errorf("loadCacheHealthSummary: query: %w", err)
	}
	defer rows.Close()

	var allKinds []cachetrack.Kind
	var allRead, allWritten []int64
	// §15.3: parallel slices of (predicted, observed) restricted to
	// implicit-cache events so cachetrack.ImplicitCacheConsistency
	// can grade them without touching the Anthropic gate.
	var implicitPredicted, implicitObserved []cachetrack.Kind
	causeCounts := map[string]int{}
	for rows.Next() {
		var kind, cause, predicted string
		var read, written int64
		if err := rows.Scan(&kind, &cause, &predicted, &read, &written); err != nil {
			return s, fmt.Errorf("loadCacheHealthSummary: scan: %w", err)
		}
		k := cachetrack.Kind(kind)
		allKinds = append(allKinds, k)
		allRead = append(allRead, read)
		allWritten = append(allWritten, written)
		if cause != "" {
			causeCounts[cause]++
		}
		if predicted != "" && cachetrack.BucketMismatch(cachetrack.Kind(predicted), k) {
			s.BucketMispredicts++
		}
		// read:write consistency: non-baseline rewrite kinds with
		// read >> write are mechanically inconsistent with a real
		// cache invalidation (a real one rebuilds a cold prefix → read ≈ 0).
		if isRewriteKindLocal(k) && read > int64(defaultMaxRewriteRR*float64(written)) && read > 0 {
			s.InconsistentRewriteCount++
		}
		// §15.3 implicit-cache accounting. The §10 gate above is
		// blind to these by design (cachetrack.isRateSkipped routes
		// them to bucketSkipped); we tally them here for the
		// separate dashboard surface.
		if cachetrack.IsImplicitCacheKind(k) {
			s.ImplicitCacheEvents++
			switch k {
			case cachetrack.KindImplicitHit:
				s.ImplicitCacheHits++
			case cachetrack.KindImplicitMiss:
				s.ImplicitCacheMisses++
			case cachetrack.KindImplicitWrite:
				s.ImplicitCacheWrites++
			}
			implicitObserved = append(implicitObserved, k)
			if predicted != "" {
				implicitPredicted = append(implicitPredicted, cachetrack.Kind(predicted))
			} else {
				implicitPredicted = append(implicitPredicted, cachetrack.Kind(""))
			}
		}
	}
	if err := rows.Err(); err != nil {
		return s, fmt.Errorf("loadCacheHealthSummary: rows: %w", err)
	}

	rate, denom := cachetrack.MispredictRateGraded(allKinds, allRead, allWritten)
	s.Rate = rate
	s.GradedEvents = denom
	for i, k := range allKinds {
		if k == cachetrack.KindMispredict && !zeroUsageAt(i, allRead, allWritten) {
			s.Mispredicts++
		}
	}
	s.GatePassed = s.GradedEvents >= s.MinEvents && s.Rate <= s.MaxRate

	// §15.3 implicit-cache rates. Computed on the separately
	// tracked slices so the consistency metric is provably blind
	// to the Anthropic gate (no shared counter).
	if s.ImplicitCacheEvents > 0 {
		report := cachetrack.ImplicitCacheConsistency(implicitPredicted, implicitObserved)
		s.ImplicitCacheConsistencyRate = report.Rate
		s.ImplicitCacheConsistencyDenom = report.Graded
		if hm := s.ImplicitCacheHits + s.ImplicitCacheMisses; hm > 0 {
			s.ImplicitCachePrefixChurnRate = float64(s.ImplicitCacheHits) / float64(hm)
		}
	}

	// Cause-concentration check. suffix_growth is the healthy
	// baseline; excluded by design. Share is computed against the
	// rate denominator (graded events) so the gate signal and the
	// WARN signal share a base.
	if s.GradedEvents > 0 {
		for cause, count := range causeCounts {
			if cause == string(cachetrack.CauseSuffixGrowth) {
				continue
			}
			share := float64(count) / float64(s.GradedEvents)
			if share > defaultMaxCauseShare {
				s.DominantCause = &CacheHealthDominantCause{
					Cause: cause,
					Count: count,
					Share: share,
				}
				break
			}
		}
	}

	// Untracked-provider visibility. Count api_turns rows from
	// non-Anthropic providers over the last 7 days so the Cache
	// page can surface a "we saw N sessions, just couldn't grade
	// them" info banner. Tolerates the api_turns.provider column
	// being NULL on legacy installs (no rows match → counts stay
	// zero, no banner shown).
	const untrackedQ = `
		SELECT
		  COUNT(*),
		  COUNT(DISTINCT session_id),
		  COALESCE((
		    SELECT s.tool
		    FROM api_turns at
		    LEFT JOIN sessions s ON s.id = at.session_id
		    WHERE at.provider IS NOT NULL AND at.provider != ''
		      AND LOWER(at.provider) != 'anthropic'
		      AND at.timestamp >= ?
		      AND s.tool IS NOT NULL AND s.tool != ''
		    GROUP BY s.tool
		    ORDER BY COUNT(DISTINCT at.session_id) DESC, s.tool ASC
		    LIMIT 1
		  ), '')
		FROM api_turns
		WHERE provider IS NOT NULL AND provider != ''
		  AND LOWER(provider) != 'anthropic'
		  AND timestamp >= ?`
	since := time.Now().UTC().Add(-7 * 24 * time.Hour).Format(time.RFC3339Nano)
	_ = db.QueryRowContext(ctx, untrackedQ, since, since).Scan(
		&s.UntrackedProviderTurns,
		&s.UntrackedProviderSessions,
		&s.UntrackedProviderTopTool,
	)

	return s, nil
}

// zeroUsageAt mirrors the cache-health CLI's helper of the same
// name — out-of-range index returns false (defensive: "unknown
// tokens = grade the event"; bias toward grading, not exclusion).
func zeroUsageAt(i int, read, written []int64) bool {
	if i >= len(read) || i >= len(written) {
		return false
	}
	return read[i] == 0 && written[i] == 0
}

// isRewriteKindLocal mirrors the cache-health CLI's isRewriteKind —
// duplicated rather than imported because the CLI symbol is unexported
// and a moving-target refactor risks breaking the rate-gate test
// surface. The list is small and the cachetrack.Kind constants are
// stable.
func isRewriteKindLocal(k cachetrack.Kind) bool {
	switch k {
	case cachetrack.KindInvalidationRewrite,
		cachetrack.KindExpiryRewrite,
		cachetrack.KindModelSwitchRewrite,
		cachetrack.KindCompactionReset:
		return true
	}
	return false
}

// handleCacheHealth serves /api/cache/health. Always returns the
// global summary regardless of TopBar filters — engine health is
// not a windowed signal.
func (s *Server) handleCacheHealth(w http.ResponseWriter, r *http.Request) {
	summary, err := loadCacheHealthSummary(r.Context(), s.db())
	if err != nil {
		http.Error(w, fmt.Sprintf("load cache health: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, summary)
}

// CacheEventRow is one row of the paginated recent-events list —
// the surface the operator drills into when investigating "what
// cache events fired today?" without going turn-by-turn through
// session details.
type CacheEventRow struct {
	ID            int64  `json:"id"`
	Timestamp     string `json:"timestamp"`
	SessionID     string `json:"session_id"`
	Model         string `json:"model"`
	Tier          string `json:"tier"`
	Kind          string `json:"kind"`
	Cause         string `json:"cause,omitempty"`
	PredictedKind string `json:"predicted_kind,omitempty"`
	TokensRead    int64  `json:"tokens_read"`
	TokensWritten int64  `json:"tokens_written"`
}

// CacheEventsResponse is the paginated payload for
// GET /api/cache/events?limit=N&offset=N&days=N&tool=&project=.
type CacheEventsResponse struct {
	Rows   []CacheEventRow `json:"rows"`
	Total  int64           `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
}

// handleCacheEvents serves /api/cache/events. Returns the most
// recent cache_events rows (newest first) under the standard
// days/tool/project filters, with limit + offset pagination.
// Default page size 50; max 200 — same Compression "Recent events"
// pagination footprint so the dashboard rhythm reads uniformly.
func (s *Server) handleCacheEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	days := intArg(r, "days", 0, 0, 36500)
	limit := intArg(r, "limit", 50, 1, 200)
	offset := intArg(r, "offset", 0, 0, 1_000_000)
	q := cacheOverviewQuery{
		Days:    days,
		Tool:    r.URL.Query().Get("tool"),
		Project: r.URL.Query().Get("project"),
	}

	rows, total, err := loadCacheEvents(ctx, s.db(), q, limit, offset)
	if err != nil {
		http.Error(w, fmt.Sprintf("load cache events: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, CacheEventsResponse{
		Rows: rows, Total: total, Limit: limit, Offset: offset,
	})
}

// loadCacheEvents shares the WHERE-clause shape with
// loadOverviewEvents so paging + filtering converge on the same
// scope. Returns rows DESC by id (proxy for chronological newest-
// first; id is monotonically increasing per migration 036).
func loadCacheEvents(ctx context.Context, db *sql.DB, q cacheOverviewQuery, limit, offset int) ([]CacheEventRow, int64, error) {
	where := []string{}
	args := []any{}
	if q.Days > 0 {
		since := time.Now().UTC().Add(-time.Duration(q.Days) * 24 * time.Hour).Format(time.RFC3339Nano)
		where = append(where, "ce.timestamp >= ?")
		args = append(args, since)
	}
	if q.Tool != "" {
		where = append(where, "s.tool = ?")
		args = append(args, q.Tool)
	}
	if q.Project != "" {
		where = append(where, "p.root_path = ?")
		args = append(args, q.Project)
	}
	whereClause := ""
	if len(where) > 0 {
		whereClause = " WHERE " + strings.Join(where, " AND ")
	}

	//nolint:gosec // G202: WHERE fragment built from code constants; values bound via ? args.
	countQ := `
		SELECT COUNT(*)
		FROM cache_events ce
		LEFT JOIN sessions s ON s.id = ce.session_id
		LEFT JOIN projects p ON p.id = s.project_id` + whereClause
	var total int64
	if err := db.QueryRowContext(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("loadCacheEvents: count: %w", err)
	}

	//nolint:gosec // G202: WHERE fragment built from code constants; values bound via ? args; LIMIT/OFFSET are validated ints.
	rowsQ := `
		SELECT ce.id, ce.timestamp, ce.session_id, ce.model,
		       COALESCE(ce.tier, ''), ce.kind,
		       COALESCE(ce.cause, ''),
		       COALESCE(ce.predicted_kind, ''),
		       COALESCE(ce.tokens_read, 0), COALESCE(ce.tokens_written, 0)
		FROM cache_events ce
		LEFT JOIN sessions s ON s.id = ce.session_id
		LEFT JOIN projects p ON p.id = s.project_id` + whereClause + `
		ORDER BY ce.id DESC
		LIMIT ? OFFSET ?`
	pagedArgs := append(append([]any{}, args...), limit, offset)
	rows, err := db.QueryContext(ctx, rowsQ, pagedArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("loadCacheEvents: query: %w", err)
	}
	defer rows.Close()
	out := []CacheEventRow{}
	for rows.Next() {
		var ev CacheEventRow
		if err := rows.Scan(&ev.ID, &ev.Timestamp, &ev.SessionID, &ev.Model,
			&ev.Tier, &ev.Kind, &ev.Cause, &ev.PredictedKind,
			&ev.TokensRead, &ev.TokensWritten); err != nil {
			return nil, 0, fmt.Errorf("loadCacheEvents: scan: %w", err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("loadCacheEvents: rows: %w", err)
	}
	return out, total, nil
}

// CacheEntryStateRow is one (state, count) pair from the
// cache_entries table — drives the entry-state distribution panel
// on the Cache page.
type CacheEntryStateRow struct {
	State string `json:"state"`
	Count int64  `json:"count"`
}

// CacheEntryStatesResponse wraps the rows in a small envelope so
// the frontend can read the total alongside the breakdown without
// summing client-side.
type CacheEntryStatesResponse struct {
	Rows  []CacheEntryStateRow `json:"rows"`
	Total int64                `json:"total"`
}

// handleCacheEntryStates serves /api/cache/entry-states. Returns
// the cache_entries.state histogram (live / unverified / expired /
// invalidated) — the F2 surface the cachetrack P3 backlog item 7+8
// were going to expose via the CLI; bringing it onto the dashboard
// makes the engine-state distribution visible without requiring a
// soak measurement first.
func (s *Server) handleCacheEntryStates(w http.ResponseWriter, r *http.Request) {
	rows, total, err := loadCacheEntryStates(r.Context(), s.db())
	if err != nil {
		http.Error(w, fmt.Sprintf("load cache entry states: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, CacheEntryStatesResponse{Rows: rows, Total: total})
}

// loadCacheEntryStates groups cache_entries by state. Returns a
// deterministic state-ordered slice (alphabetical) so the front-
// end can map state→color without surprises across reloads.
func loadCacheEntryStates(ctx context.Context, db *sql.DB) ([]CacheEntryStateRow, int64, error) {
	const q = `SELECT COALESCE(state, ''), COUNT(*)
	           FROM cache_entries GROUP BY 1 ORDER BY 1 ASC`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, 0, fmt.Errorf("loadCacheEntryStates: query: %w", err)
	}
	defer rows.Close()
	out := []CacheEntryStateRow{}
	var total int64
	for rows.Next() {
		var r CacheEntryStateRow
		if err := rows.Scan(&r.State, &r.Count); err != nil {
			return nil, 0, fmt.Errorf("loadCacheEntryStates: scan: %w", err)
		}
		out = append(out, r)
		total += r.Count
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("loadCacheEntryStates: rows: %w", err)
	}
	return out, total, nil
}

// buildCacheOverview folds raw overview events into the four
// rollup dimensions. Pure function — testable without a DB.
func buildCacheOverview(events []overviewEvent) CacheOverviewResponse {
	resp := CacheOverviewResponse{
		PerModel:      []CacheOverviewModelRollup{},
		PerProject:    []CacheOverviewProjectRollup{},
		TopCauses:     []CacheOverviewCauseRow{},
		WorstSessions: []CacheOverviewSessionRow{},
	}

	uniqueSessions := map[string]struct{}{}
	modelAgg := map[string]*CacheOverviewModelRollup{}
	projectAgg := map[int64]*CacheOverviewProjectRollup{}
	causeAgg := map[string]int64{}
	sessionAgg := map[string]*sessionAggRow{}

	for _, ev := range events {
		resp.Global.Efficiency.ReadTokens += ev.Tokens.Read
		resp.Global.Efficiency.WrittenTokens += ev.Tokens.Written
		resp.Global.EventCount++
		uniqueSessions[ev.SessionID] = struct{}{}

		// Per-model.
		m, ok := modelAgg[ev.Model]
		if !ok {
			m = &CacheOverviewModelRollup{Model: ev.Model}
			modelAgg[ev.Model] = m
		}
		m.Efficiency.ReadTokens += ev.Tokens.Read
		m.Efficiency.WrittenTokens += ev.Tokens.Written
		m.EventCount++

		// Per-project — only when the join resolved.
		if ev.ProjectID > 0 {
			p, ok := projectAgg[ev.ProjectID]
			if !ok {
				p = &CacheOverviewProjectRollup{ProjectID: ev.ProjectID, ProjectRoot: ev.ProjectRoot}
				projectAgg[ev.ProjectID] = p
			}
			p.Efficiency.ReadTokens += ev.Tokens.Read
			p.Efficiency.WrittenTokens += ev.Tokens.Written
			p.EventCount++
		}

		// Cause histogram (skip empty).
		if ev.Cause != "" {
			causeAgg[ev.Cause]++
		}

		// Worst sessions (rewrite-kinded events only). Tier rolls
		// across every rewrite event in the session — uniform when
		// they all came from the same capture path, "mixed" when
		// proxy + transcript both contributed.
		if isRewriteKindString(ev.Kind) {
			r, ok := sessionAgg[ev.SessionID]
			if !ok {
				r = &sessionAggRow{SessionID: ev.SessionID, Model: ev.Model, Causes: map[string]int64{}, Tiers: map[string]bool{}}
				sessionAgg[ev.SessionID] = r
			}
			r.RewriteCount++
			r.TokensRead += ev.Tokens.Read
			r.TokensWritten += ev.Tokens.Written
			if ev.Cause != "" {
				r.Causes[ev.Cause]++
			}
			if ev.Tier != "" {
				r.Tiers[ev.Tier] = true
			}
		}
	}
	resp.Global.SessionCount = int64(len(uniqueSessions))
	resp.Global.Efficiency = ratioFinalize(resp.Global.Efficiency)

	// Materialize + finalize ratios.
	for _, m := range modelAgg {
		m.Efficiency = ratioFinalize(m.Efficiency)
		resp.PerModel = append(resp.PerModel, *m)
	}
	for _, p := range projectAgg {
		p.Efficiency = ratioFinalize(p.Efficiency)
		resp.PerProject = append(resp.PerProject, *p)
	}
	for cause, count := range causeAgg {
		resp.TopCauses = append(resp.TopCauses, CacheOverviewCauseRow{
			Cause: cause, Count: count, Flagged: isFlaggedCause(cause),
		})
	}
	for _, r := range sessionAgg {
		resp.WorstSessions = append(resp.WorstSessions, CacheOverviewSessionRow{
			SessionID: r.SessionID, Model: r.Model,
			Tier:         collapseTierSet(r.Tiers),
			RewriteCount: r.RewriteCount,
			TokensRead:   r.TokensRead, TokensWritten: r.TokensWritten,
			TopCause: topCauseOf(r.Causes),
		})
	}

	// Sort: per-model desc by event_count; per-project desc by
	// event_count; top_causes desc by count; worst_sessions desc
	// by rewrite_count. Stable sorts keep ordering deterministic
	// for tests.
	sortPerModelDesc(resp.PerModel)
	sortPerProjectDesc(resp.PerProject)
	sortTopCausesDesc(resp.TopCauses)
	sortWorstSessionsDesc(resp.WorstSessions)

	// Cap worst_sessions at 10 — operator-relevant signal lives in
	// the top of the list.
	if len(resp.WorstSessions) > 10 {
		resp.WorstSessions = resp.WorstSessions[:10]
	}
	return resp
}

// sessionAggRow is the in-memory aggregator for worst-sessions.
type sessionAggRow struct {
	SessionID     string
	Model         string
	RewriteCount  int64
	TokensRead    int64
	TokensWritten int64
	Causes        map[string]int64
	Tiers         map[string]bool
}

// collapseTierSet mirrors collapseTier's contract for the worst-
// sessions rollup — empty set → "", single tier → that tier,
// multiple tiers → "mixed". Stays empty (not "none") when zero
// tiers were captured so the omitempty JSON tag elides the field
// rather than render a misleading "none" pill.
func collapseTierSet(set map[string]bool) string {
	if len(set) == 0 {
		return ""
	}
	if len(set) > 1 {
		return "mixed"
	}
	for t := range set {
		return t
	}
	return ""
}

// isRewriteKindString tests against the schema-stable Kind label
// strings. Mirrors cmd/observer/cache_health.go::isRewriteKind
// but takes a string (no cachetrack import on this side of the
// dashboard package).
func isRewriteKindString(kind string) bool {
	switch kind {
	case "invalidation_rewrite", "expiry_rewrite", "model_switch_rewrite", "compaction_reset":
		return true
	}
	return false
}

// topCauseOf returns the most-frequent cause label in the
// session's rewrite-cause histogram. Ties broken by lexicographic
// order so the result is deterministic.
func topCauseOf(causes map[string]int64) string {
	var top string
	var topN int64
	for c, n := range causes {
		if n > topN || (n == topN && c < top) {
			top, topN = c, n
		}
	}
	return top
}

// ratioFinalize sets Ratio = Read/Write (divide-by-zero guarded).
// Called at the end of aggregation; the running aggregate keeps
// Ratio at 0 during the fold to avoid recomputing it per event.
func ratioFinalize(eff SessionCacheEfficiency) SessionCacheEfficiency {
	if eff.WrittenTokens > 0 {
		eff.Ratio = float64(eff.ReadTokens) / float64(eff.WrittenTokens)
	}
	return eff
}

// sortPerModelDesc orders the per-model rollup by event_count
// desc, ties broken alphabetically by model.
func sortPerModelDesc(rows []CacheOverviewModelRollup) {
	for i := 1; i < len(rows); i++ {
		j := i
		for j > 0 && (rows[j-1].EventCount < rows[j].EventCount ||
			(rows[j-1].EventCount == rows[j].EventCount && rows[j-1].Model > rows[j].Model)) {
			rows[j-1], rows[j] = rows[j], rows[j-1]
			j--
		}
	}
}

// sortPerProjectDesc — same shape, by ProjectRoot tiebreak.
func sortPerProjectDesc(rows []CacheOverviewProjectRollup) {
	for i := 1; i < len(rows); i++ {
		j := i
		for j > 0 && (rows[j-1].EventCount < rows[j].EventCount ||
			(rows[j-1].EventCount == rows[j].EventCount && rows[j-1].ProjectRoot > rows[j].ProjectRoot)) {
			rows[j-1], rows[j] = rows[j], rows[j-1]
			j--
		}
	}
}

// sortTopCausesDesc — by count desc, cause name tiebreak.
func sortTopCausesDesc(rows []CacheOverviewCauseRow) {
	for i := 1; i < len(rows); i++ {
		j := i
		for j > 0 && (rows[j-1].Count < rows[j].Count ||
			(rows[j-1].Count == rows[j].Count && rows[j-1].Cause > rows[j].Cause)) {
			rows[j-1], rows[j] = rows[j], rows[j-1]
			j--
		}
	}
}

// sortWorstSessionsDesc — by rewrite_count desc, session_id
// tiebreak.
func sortWorstSessionsDesc(rows []CacheOverviewSessionRow) {
	for i := 1; i < len(rows); i++ {
		j := i
		for j > 0 && (rows[j-1].RewriteCount < rows[j].RewriteCount ||
			(rows[j-1].RewriteCount == rows[j].RewriteCount && rows[j-1].SessionID > rows[j].SessionID)) {
			rows[j-1], rows[j] = rows[j], rows[j-1]
			j--
		}
	}
}
