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
// timestamp on a row written since the window opened (T-422: the check is
// bounded by insertion order, see guardBudgetMalformedFloorSQL, so its cost
// follows the window and not the node's whole history).
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
	//nolint:gosec // G202: guardBudgetTokensSQL is compile-time constant SQL; every value binds via args.
	err = s.db.QueryRowContext(
		ctx, guardBudgetTokensSQL(managed),
		guardBudgetTokensArgs(managed, sessionID, dayStart, weekStart, monthStart, earliest, time.Now())...,
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

// The two read shapes of GuardBudgetTokens, built once. They differ ONLY in
// whether the managed-only validity checks are compiled into the statement.
//
// WHY TWO STATEMENTS, not one with a bound `managed` flag (T-418): SQLite
// evaluates both operands of AND in a value context, so `? AND (<invalid
// timestamp checks>)` ran the julianday/strftime validation twice per row on
// EVERY advisory read, where the flag is false and the answer is discarded.
// Over a rolling week of usage on a large node (about 68k rows) that was
// roughly 70% of the statement's cost. guardBudgetUsageWhere already keeps the
// managed OR branch out of the advisory WHERE for the same reason; this keeps
// it out of the projection too. (T-422 later bounded the managed statement's
// malformed-row check by insertion order; see guardBudgetMalformedFloorSQL.)
var (
	guardBudgetTokensAdvisorySQL = buildGuardBudgetTokensSQL(false)
	guardBudgetTokensManagedSQL  = buildGuardBudgetTokensSQL(true)
)

// guardBudgetTokensArgs binds guardBudgetTokensSQL(managed), in order: the
// two usage arms, then the session and window stamps of the projection.
func guardBudgetTokensArgs(managed bool, sessionID string, dayStart, weekStart, monthStart, earliest, now time.Time) []any {
	args := guardBudgetUsageArgs(managed, sessionID, earliest, now)
	args = append(args, guardBudgetUsageArgs(managed, sessionID, earliest, now)...)
	return append(args,
		sessionID, sessionID, guardBudgetWindowStamp(dayStart), guardBudgetWindowStamp(weekStart), guardBudgetWindowStamp(monthStart),
		sessionID, sessionID, guardBudgetWindowStamp(dayStart), guardBudgetWindowStamp(weekStart), guardBudgetWindowStamp(monthStart),
		guardBudgetWindowStamp(weekStart),
	)
}

// guardBudgetTokensSQL returns the token-window statement for one read mode.
func guardBudgetTokensSQL(managed bool) string {
	if managed {
		return guardBudgetTokensManagedSQL
	}
	return guardBudgetTokensAdvisorySQL
}

// buildGuardBudgetTokensSQL assembles the statement. bad marks a row whose
// counts cannot be trusted (negative always; incomplete or a malformed
// timestamp only under a managed read); bad_time marks a malformed timestamp,
// which a managed read assigns to every window because it cannot be placed in
// one. In the advisory shape bad_time is the constant 0.
//
// The validity check is computed ONCE per row, as raw's bt column (T-422).
// raw is a compound query, so SQLite materializes it as a co-routine and bt
// is evaluated once; normalized is flattened into the aggregate, so an
// expression written there is re-evaluated by every SUM / MAX that names its
// column (bad four times, bad_time three), which made the julianday/strftime
// check run about seven times per window row.
func buildGuardBudgetTokensSQL(managed bool) string {
	badTimeExpr := `0`
	if managed {
		badTimeExpr = `(` + guardBudgetInvalidTimestampSQL + `)`
	}
	bad := `CASE WHEN i < 0 OR o < 0 THEN 1 ELSE 0 END`
	badTime := `0`
	if managed {
		bad = `CASE WHEN i < 0 OR o < 0 OR incomplete OR bt THEN 1 ELSE 0 END`
		badTime = `bt`
	}
	return `
		WITH raw AS (
		  SELECT COALESCE(session_id,'') sid, timestamp, ` + guardBudgetTimestampOrderSQL + ` ordered_at,
		         COALESCE(input_tokens,0) i, ` + spendverdict.ProxyOutputOf("api_turns") + ` o,
		         input_tokens IS NULL OR output_tokens IS NULL incomplete,
		         ` + badTimeExpr + ` bt
		  FROM api_turns ` + guardBudgetUsageWhere(managed, "api_turns", spendverdict.GuardCountedProxyRowOf("api_turns")) + `
		  UNION ALL
		  SELECT session_id sid, timestamp, ` + guardBudgetTimestampOrderSQL + ` ordered_at,
		         COALESCE(input_tokens,0) i, COALESCE(output_tokens,0) o,
		         input_tokens IS NULL OR output_tokens IS NULL OR
		         COALESCE(reliability,'') NOT IN ('accurate','approximate') OR
		         source NOT IN ('jsonl','otel','hook','proxy') incomplete,
		         ` + badTimeExpr + ` bt
		  FROM token_usage ` + guardBudgetUsageWhere(managed, "token_usage", spendverdict.CountedTokenRow("token_usage")) + `
		), normalized AS (
		  SELECT sid,ordered_at,CASE WHEN i < 0 OR o < 0 THEN 0 ELSE i+o END amount,
		         ` + bad + ` bad,
		         ` + badTime + ` bad_time
		  FROM raw
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
		FROM normalized`
}
