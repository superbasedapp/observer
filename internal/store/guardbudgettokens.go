package store

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/spendverdict"
)

// TOKEN-denominated budget windows for the guard's §12.1 budget seam
// (docs/plans/org-budget-enforcement-and-token-display-plan-2026-09-07.md
// §3.3c, wave W3b). It is the exact structural sibling of
// GuardBudgetSpendPriced in guardbudgetpriced.go — same windows, same rows,
// same de-duplication — in the other unit.
//
// WHAT COUNTS AS A TOKEN, and why it is not negotiable here: input + output,
// excluding cache reads and cache creation. That is byte-for-byte what the ORG
// server counts (internal/orgserver/rollup/cost.go's spendCTE, whose `tokens`
// expression is `input_tokens + output` on BOTH arms, the proxy arm's output
// read through its stored dedup verdict). A node that counted cache tokens
// too would breach an org cap the org itself considers unbreached, and the
// developer would have no way to see why.
//
// WHICH ROWS COUNT is the ONE session rule, sessionmsg.Derive, through the
// node's stored verdicts (internal/spendverdict, agent migration 143): a
// transcript row Derive does not count is not read, a proxy row reads its
// verdict's output (a twinned row carries its transcript twin's visible
// output, reasoning excluded like every other token row), and a proxy row
// the session-cumulative reconciliation dropped is not read. So a session's
// guard figure is its session header's input + output, and a window's is
// the sum of its rows' - the same numbers the dashboard and the org show.
// It replaced a per-session MAX(proxy, transcript) fold (lane R2-ONERULE)
// that took the LARGER capture of a session wholesale: it counted nothing a
// proxied session's transcript saw that the proxy missed (or vice versa) and
// could not see an output-only shadow duplicate within one capture.

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

// GuardBudgetTokens returns the token-usage-so-far windows: the session's
// total and the node-wide day / rolling-week / month totals, over the rows
// the stored dedup verdicts count (see the file header). What is marked
// unavailable is what is genuinely unreadable: negative or NULL counters, an
// unreliable source, and — under a managed read — an invalid captured
// timestamp.
//
// WHERE THE PER-SUBJECT TOKEN TOTALS LIVE, and why not here (bundle BUD-N):
// the organization's per-tool / per-model caps need the same windows in both
// units, and both units are accumulated in the ONE row loop of
// GuardBudgetSpendPriced (GuardBudgetSpendResult.ByTool / ByModel), using the
// token rule this file defines. They are not computed a second time here —
// a GROUP BY tool, model here would produce a second set of token totals
// over the same rows, and two totals that could drift apart is exactly the
// defect the single-lookup discipline exists to prevent. This function keeps
// its one job: the node-wide token windows.
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
	s.refreshSpendVerdictsBounded(ctx)
	// Validate and sum all windows in ONE SQLite snapshot. A separate validity
	// probe followed by SUM could race a newly ingested invalid negative row.
	// Invalid counts contribute no tokens and mark their exact windows unknown;
	// they never reduce good usage. SQL integer overflow is a read error.
	var sessionBad, dayBad, weekBad, monthBad int
	var weeklyFirst string
	managed := managedBudgetRead(options)
	//nolint:gosec // G202: the WHERE fragments are compile-time constant SQL; every value binds via args.
	err = s.db.QueryRowContext(
		ctx, `
		WITH params AS (SELECT ? managed), raw AS (
		  SELECT COALESCE(session_id,'') sid, timestamp, `+guardBudgetTimestampOrderSQL+` ordered_at,
		         COALESCE(input_tokens,0) i, `+spendverdict.ProxyOutputOf("api_turns")+` o,
		         input_tokens IS NULL OR output_tokens IS NULL incomplete
		  FROM api_turns `+guardBudgetUsageWhere(managed, spendverdict.CountedProxyRowOf("api_turns"))+`
		  UNION ALL
		  SELECT session_id sid, timestamp, `+guardBudgetTimestampOrderSQL+` ordered_at,
		         COALESCE(input_tokens,0) i, COALESCE(output_tokens,0) o,
		         input_tokens IS NULL OR output_tokens IS NULL OR
		         COALESCE(reliability,'') NOT IN ('accurate','approximate') OR
		         source NOT IN ('jsonl','otel','hook','proxy') incomplete
		  FROM token_usage `+guardBudgetUsageWhere(managed, spendverdict.CountedTokenRow("token_usage"))+`
		), normalized AS (
		  SELECT sid,ordered_at,CASE WHEN i < 0 OR o < 0 THEN 0 ELSE i+o END amount,
		         CASE WHEN i < 0 OR o < 0 OR (managed AND (incomplete OR `+guardBudgetInvalidTimestampSQL+`)) THEN 1 ELSE 0 END bad,
		         managed AND (`+guardBudgetInvalidTimestampSQL+`) bad_time
		  FROM raw CROSS JOIN params
		)
		SELECT COALESCE(SUM(CASE WHEN sid = ? AND ? <> '' THEN amount ELSE 0 END),0),
		       COALESCE(SUM(CASE WHEN ordered_at >= ? THEN amount ELSE 0 END),0),
		       COALESCE(SUM(CASE WHEN ordered_at >= ? THEN amount ELSE 0 END),0),
		       COALESCE(SUM(CASE WHEN ordered_at >= ? THEN amount ELSE 0 END),0),
		       COALESCE(MAX(CASE WHEN sid = ? AND ? <> '' THEN bad ELSE 0 END),0),
		       COALESCE(MAX(CASE WHEN ordered_at >= ? OR bad_time THEN bad ELSE 0 END),0),
		       COALESCE(MAX(CASE WHEN ordered_at >= ? OR bad_time THEN bad ELSE 0 END),0),
		       COALESCE(MAX(CASE WHEN ordered_at >= ? OR bad_time THEN bad ELSE 0 END),0),
		       COALESCE(MIN(CASE WHEN ordered_at >= ? AND amount > 0 THEN ordered_at END),'')
		FROM normalized`,
		managed,
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
