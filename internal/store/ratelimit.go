package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RateLimitWindows is the subscription-window utilization for a tool that
// captures its 5h / weekly rate-limit state in its own transcript rather
// than in HTTP response headers. Codex 0.130+ embeds
// `rate_limits.{primary,secondary}` in every token_count event, which the
// codex adapter persists as ActionRateLimit rows; this is the read side
// that turns those rows into the same gauge shape the proxy snapshot
// produces. Optional fields are nil when the source omitted that window.
//
// Window5hUtil/Window7dUtil are classified by each reported window's
// window_minutes (see rateLimitWindowClassifyThresholdMinutes), NOT by
// whether Codex called it "primary" or "secondary" — live-observed
// 2026-09-22, an account/plan shape reports only ONE window and it is not
// always the 5h one (a "prolite"-plan account sends
// primary.window_minutes==10080, i.e. the weekly cap, with
// secondary==null). Positional assignment would render that window under
// the wrong label.
type RateLimitWindows struct {
	Window5hUtil  *float64 // 5h-class window (window_minutes <= threshold), 0..1
	Window5hReset *int64   // 5h-class window resets_at, unix seconds
	Window7dUtil  *float64 // weekly-class window (window_minutes > threshold), 0..1
	Window7dReset *int64   // weekly-class window resets_at, unix seconds
	PlanType      string   // "plus" / "pro" / "team"; "" when the source reported it as JSON null
	Status        string   // rate_limit_reached_type, "" when not throttled
	ObservedAt    time.Time
}

// rateLimitActionRaw mirrors the JSON the codex adapter marshals into
// actions.raw_tool_input for an ActionRateLimit row (the codexRateLimits
// envelope). Declared locally so this read seam stays decoupled from the
// adapter package — capabilities, not source identity.
type rateLimitActionRaw struct {
	LimitID              string           `json:"limit_id"`
	Primary              *rateLimitWindow `json:"primary"`
	Secondary            *rateLimitWindow `json:"secondary"`
	PlanType             string           `json:"plan_type"`
	RateLimitReachedType *string          `json:"rate_limit_reached_type"`
}

type rateLimitWindow struct {
	UsedPercent   float64 `json:"used_percent"`
	WindowMinutes int64   `json:"window_minutes"`
	ResetsAt      int64   `json:"resets_at"`
}

// LatestRateLimitWindows returns the most-recent subscription-window
// snapshot captured from a tool's own transcript (ActionRateLimit rows),
// session-scoped first and falling back to the latest for the tool
// account-wide (the window ticks per-account, so a brand-new session with
// no rate_limit row yet still gets a reading). ok=false when the tool
// emits no such rows (every non-codex tool today). Never errors on a
// malformed body — it just skips to the account-wide fallback / returns
// ok=false, since this only feeds an advisory gauge.
func (s *Store) LatestRateLimitWindows(ctx context.Context, tool, sessionID string) (RateLimitWindows, bool, error) {
	if sessionID != "" {
		if w, ok, err := s.latestRateLimitRow(ctx,
			`SELECT raw_tool_input, timestamp FROM actions
			  WHERE session_id = ? AND action_type = 'rate_limit'
			    AND raw_tool_input IS NOT NULL AND raw_tool_input <> ''
			  ORDER BY timestamp DESC, id DESC LIMIT 1`, sessionID); err != nil {
			return RateLimitWindows{}, false, err
		} else if ok {
			return w, true, nil
		}
	}
	if tool == "" {
		return RateLimitWindows{}, false, nil
	}
	return s.latestRateLimitRow(ctx,
		`SELECT raw_tool_input, timestamp FROM actions
		  WHERE tool = ? AND action_type = 'rate_limit'
		    AND raw_tool_input IS NOT NULL AND raw_tool_input <> ''
		  ORDER BY timestamp DESC, id DESC LIMIT 1`, tool)
}

func (s *Store) latestRateLimitRow(ctx context.Context, query string, args ...any) (RateLimitWindows, bool, error) {
	var raw, ts string
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&raw, &ts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RateLimitWindows{}, false, nil
		}
		return RateLimitWindows{}, false, fmt.Errorf("store.LatestRateLimitWindows: %w", err)
	}
	w, ok := parseRateLimitWindows(raw)
	if !ok {
		// Malformed body: not an error, just no usable window.
		return RateLimitWindows{}, false, nil
	}
	if t, ok := parseDBTime(ts); ok {
		w.ObservedAt = t
	}
	return w, true, nil
}

// rateLimitWindowClassifyThresholdMinutes separates a "short" (5h-class)
// window from a "long" (weekly-class) one by its DECLARED DURATION, never
// by whether Codex reported it as primary or secondary (see
// RateLimitWindows's doc comment for why position is unsafe). Live-
// observed values are exactly 300 (5h) and 10080 (7d/weekly) — two orders
// of magnitude apart, so a coarse 1-day (1440min) threshold has no
// boundary risk against real data.
const rateLimitWindowClassifyThresholdMinutes = 1440

// parseRateLimitWindows decodes the codexRateLimits envelope into the
// gauge shape. used_percent is 0..100 → util 0..1. Each of Primary/
// Secondary is classified independently by window_minutes, not position.
// Returns ok=false when neither window is present.
func parseRateLimitWindows(raw string) (RateLimitWindows, bool) {
	var rl rateLimitActionRaw
	if err := json.Unmarshal([]byte(raw), &rl); err != nil {
		return RateLimitWindows{}, false
	}
	var w RateLimitWindows
	w.PlanType = rl.PlanType
	if rl.RateLimitReachedType != nil {
		w.Status = *rl.RateLimitReachedType
	}
	present := false
	for _, win := range []*rateLimitWindow{rl.Primary, rl.Secondary} {
		if win == nil {
			continue
		}
		present = true
		util := win.UsedPercent / 100.0
		var reset *int64
		if win.ResetsAt > 0 {
			r := win.ResetsAt
			reset = &r
		}
		if win.WindowMinutes > rateLimitWindowClassifyThresholdMinutes {
			// Weekly-class. Not observed live, but defensive: on a
			// same-bucket collision (both primary and secondary land in
			// the same class) keep the larger used_percent — the more
			// urgent reading wins rather than an arbitrary last-write.
			if w.Window7dUtil == nil || util > *w.Window7dUtil {
				w.Window7dUtil = &util
				w.Window7dReset = reset
			}
			continue
		}
		if w.Window5hUtil == nil || util > *w.Window5hUtil {
			w.Window5hUtil = &util
			w.Window5hReset = reset
		}
	}
	return w, present
}
