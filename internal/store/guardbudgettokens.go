package store

import (
	"context"
	"fmt"
	"time"
)

// TOKEN-denominated budget windows for the guard's §12.1 budget seam
// (docs/plans/org-budget-enforcement-and-token-display-plan-2026-09-07.md
// §3.3c, wave W3b). It is the exact structural sibling of GuardBudgetSpend in
// guard.go — same windows, same per-session MAX de-dup across the proxy and
// watcher substrates — in the other unit.
//
// WHAT COUNTS AS A TOKEN, and why it is not negotiable here: input + output,
// excluding cache reads and cache creation. That is byte-for-byte what the ORG
// server counts (internal/orgserver/rollup/cost.go's spendCTE, whose `tokens`
// expression is `input_tokens + output_tokens` on BOTH arms). A node that
// counted cache tokens too would breach an org cap the org itself considers
// unbreached, and the developer would have no way to see why.

// GuardBudgetTokenWindows is the token-usage-so-far bundle the B-621..B-624
// rows compare against: the current session's total plus the node-wide totals
// in the day / rolling-7-day / calendar-month windows.
type GuardBudgetTokenWindows struct {
	// WeeklyExpiresAt is when the earliest counted positive row leaves the
	// rolling seven-day window and a measured denial must be re-evaluated.
	WeeklyExpiresAt time.Time
	// Unavailable identifies windows containing corrupt negative input/output
	// counts. Such rows cannot lower the allowance consumed by valid usage.
	Unavailable   GuardBudgetUnavailableWindows
	SessionTokens int64
	DailyTokens   int64
	WeeklyTokens  int64
	MonthlyTokens int64
}

// GuardBudgetTokens returns the token-usage-so-far windows. Structurally
// identical to GuardBudgetSpend: the session total is the larger of the two
// substrates in advisory mode, and each window total uses that same merge.
//
// A session observed through BOTH the proxy and the native parser is the
// ordinary shape for any tool the daemon launches through :8820 and also
// parses from its own store. It is not ambiguity: per-session MAX(proxy,
// watcher) IS the de-duplication rule, and it is already applied by the folded
// CTE below. Marking that overlap unavailable contradicted the rule and denied
// every proxied-and-parsed tool, so the rule is gone here for the same reason
// and on the same ruling as in the $ sibling (accounting-readiness correction,
// 2026-09-14 / W10-2). What remains unavailable is what is genuinely
// unreadable: negative or NULL counters, an unreliable source, and — under a
// managed read — an invalid captured timestamp.
//
// An empty sessionID skips the session leg (the window legs still run) —
// the same contract GuardBudgetSpend offers, so the guard's single cached
// lookup can fill both units from one call site.
func (s *Store) GuardBudgetTokens(ctx context.Context, sessionID string, dayStart, weekStart, monthStart time.Time, options ...GuardBudgetReadOptions) (tok GuardBudgetTokenWindows, err error) {
	earliest := dayStart
	if weekStart.Before(earliest) {
		earliest = weekStart
	}
	if monthStart.Before(earliest) {
		earliest = monthStart
	}
	// Validate and sum all windows in ONE SQLite snapshot. A separate validity
	// probe followed by SUM could race a newly ingested invalid negative row.
	// Invalid counts contribute no tokens and mark their exact windows unknown;
	// they never reduce good usage. SQL integer overflow is a read error.
	var sessionBad, dayBad, weekBad, monthBad int
	var weeklyFirst string
	where := guardBudgetUsageWhere(managedBudgetRead(options))
	err = s.db.QueryRowContext(
		ctx, `
		WITH params AS (SELECT ? managed), raw AS (
		  SELECT 0 source, COALESCE(session_id,'') sid, timestamp, `+guardBudgetTimestampOrderSQL+` ordered_at,
		         COALESCE(input_tokens,0) i, COALESCE(output_tokens,0) o,
		         input_tokens IS NULL OR output_tokens IS NULL incomplete
		  FROM api_turns `+where+`
		  UNION ALL
		  SELECT 1 source, session_id sid, timestamp, `+guardBudgetTimestampOrderSQL+` ordered_at,
		         COALESCE(input_tokens,0) i, COALESCE(output_tokens,0) o,
		         input_tokens IS NULL OR output_tokens IS NULL OR
		         COALESCE(reliability,'') NOT IN ('accurate','approximate') OR
		         source NOT IN ('jsonl','otel','hook','proxy') incomplete
		  FROM token_usage `+where+`
		), normalized AS (
		  SELECT source,sid,ordered_at,CASE WHEN i < 0 OR o < 0 THEN 0 ELSE i+o END amount,
		         CASE WHEN i < 0 OR o < 0 OR (managed AND (incomplete OR `+guardBudgetInvalidTimestampSQL+`)) THEN 1 ELSE 0 END bad,
		         managed AND (`+guardBudgetInvalidTimestampSQL+`) bad_time
		  FROM raw CROSS JOIN params
		), totals AS (
		  SELECT source,sid,
		    SUM(CASE WHEN sid = ? AND ? <> '' THEN amount ELSE 0 END) s,
		    SUM(CASE WHEN ordered_at >= ? THEN amount ELSE 0 END) d,
		    SUM(CASE WHEN ordered_at >= ? THEN amount ELSE 0 END) w,
		    SUM(CASE WHEN ordered_at >= ? THEN amount ELSE 0 END) m,
		    MAX(CASE WHEN sid = ? AND ? <> '' THEN bad ELSE 0 END) sb,
		    MAX(CASE WHEN ordered_at >= ? OR bad_time THEN bad ELSE 0 END) db,
		    MAX(CASE WHEN ordered_at >= ? OR bad_time THEN bad ELSE 0 END) wb,
		    MAX(CASE WHEN ordered_at >= ? OR bad_time THEN bad ELSE 0 END) mb,
		    MIN(CASE WHEN ordered_at >= ? AND amount > 0 THEN ordered_at END) weekly_first
		  FROM normalized GROUP BY source,sid
		), folded AS (
		  SELECT sid, MAX(s) s,MAX(d) d,MAX(w) w,MAX(m) m,
		         MAX(sb) sb, MAX(db) db, MAX(wb) wb, MAX(mb) mb,
		         MIN(weekly_first) weekly_first
		  FROM totals GROUP BY sid
		)
		SELECT COALESCE(SUM(s),0),COALESCE(SUM(d),0),COALESCE(SUM(w),0),COALESCE(SUM(m),0),
		       COALESCE(MAX(sb),0),COALESCE(MAX(db),0),COALESCE(MAX(wb),0),COALESCE(MAX(mb),0),
		       COALESCE(MIN(weekly_first),'')
		FROM folded`,
		managedBudgetRead(options),
		sessionID, sessionID, earliest.UTC().Format("2006-01-02T15:04:05"), guardBudgetWindowStamp(earliest),
		sessionID, sessionID, earliest.UTC().Format("2006-01-02T15:04:05"), guardBudgetWindowStamp(earliest),
		sessionID, sessionID, guardBudgetWindowStamp(dayStart), guardBudgetWindowStamp(weekStart), guardBudgetWindowStamp(monthStart),
		sessionID, sessionID, guardBudgetWindowStamp(dayStart), guardBudgetWindowStamp(weekStart), guardBudgetWindowStamp(monthStart),
		guardBudgetWindowStamp(weekStart),
	).Scan(&tok.SessionTokens, &tok.DailyTokens, &tok.WeeklyTokens, &tok.MonthlyTokens,
		&sessionBad, &dayBad, &weekBad, &monthBad, &weeklyFirst)
	if err != nil {
		return tok, fmt.Errorf("store.GuardBudgetTokens: snapshot: %w", err)
	}
	tok.Unavailable = GuardBudgetUnavailableWindows{Session: sessionBad != 0, Daily: dayBad != 0, Weekly: weekBad != 0, Monthly: monthBad != 0}
	if at, err := time.Parse(time.RFC3339Nano, weeklyFirst); err == nil {
		tok.WeeklyExpiresAt = at.Add(7 * 24 * time.Hour)
	}
	return tok, nil
}
