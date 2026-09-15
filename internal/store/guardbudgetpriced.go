package store

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"
)

// GuardBudgetReadOptions selects the evidence required by managed hard caps.
// Managed rejects unverified stored prices, incomplete counters and ambiguous
// proxy/native overlap. Omission preserves the existing advisory accounting.
type GuardBudgetReadOptions struct{ Managed bool }

func managedBudgetRead(options []GuardBudgetReadOptions) bool {
	for _, option := range options {
		if option.Managed {
			return true
		}
	}
	return false
}

// GuardBudgetPricer prices one stored usage row for the guard's dollar
// budget. The source string is retained in the returned spend metadata so a
// caller can distinguish an exact/org rate from a family fallback. ok=false
// means that the row is unpriced and must contribute no dollars.
//
// The callback is deliberately a pure seam. The command layer supplies the
// process-wide cost engine; store only performs the bounded read and the
// proxy/watcher de-duplication that the guard already uses.
type GuardBudgetPricer func(model string, at time.Time, split PushTokenSplit) (usd float64, source string, ok bool)

// GuardBudgetSpendResult is the guard's dollar spend plus the accounting
// metadata needed to report coverage honestly. Unpriced rows remain visible
// through UnpricedRows and UnpricedTokens and never become invented dollars;
// UnpricedWindows records which windows held a row no ladder tier could price.
//
// REPORTING, NEVER DENIAL (ruling A1/A2, 2026-09-15). UnpricedWindows and
// UnpricedTools describe coverage; they no longer make a budget window
// unavailable at the guard, because a model with no org or exact rate is the
// ORDINARY state of most adapters and stopping a developer's process over it
// denied work the node's own dashboard was pricing perfectly well.
type GuardBudgetSpendResult struct {
	GuardBudgetWindows
	PricedRows      int
	UnpricedRows    int
	UnpricedTokens  int64
	UnpricedWindows GuardBudgetUnavailableWindows
	// UnpricedTools scopes unpriced-but-billable usage to the tool that
	// produced it. token_usage rows name their tool, so a model only one
	// adapter emits - and that no ladder tier can price - is attributed to that
	// tool rather than to the whole node. Rows that name no tool (proxy
	// api_turns) and invalid rows of any origin stay in the node-wide
	// UnpricedWindows above, because nothing narrower is provable.
	// Filled by managed reads only; advisory accounting is unchanged.
	UnpricedTools map[string]GuardBudgetUnavailableWindows
	// FallbackModels names the distinct models that WERE priced, but through a
	// rung the org did not author: a date-stripped, family or local rate, or the
	// adapter's own stored cost. Their dollars DO count against the cap; they
	// are estimates rather than the org's number.
	//
	// It is a separate list from UnpricedModels because the two are opposite
	// facts about a cap (BUDGET-COV-3): one counts at an estimated rate, the
	// other silently under-reads the cap at $0. One combined list let a single
	// true miss choose the wording for every model on it - which is how a
	// correctly family-priced model that had just tripped a live cap was
	// reported as having "no rate at all".
	// Sorted and bounded by guardBudgetMaxUnpricedModels; filled by managed
	// reads only.
	FallbackModels []string
	// UnpricedModels names the distinct models behind the TRUE MISSES in
	// UnpricedRows: rows nothing in the ladder could price, not even the
	// adapter's own stored cost. They contribute $0 to the cap. Sorted and
	// bounded by guardBudgetMaxUnpricedModels, because it exists to be READ - by
	// `observer guard status` and, through the enum-only posture row, by the org
	// Budgets coverage note - not to be joined against.
	//
	// It deliberately does NOT include invalid rows: those are unpriced because
	// their counters or timestamp are broken, and naming their model would
	// accuse a model that may well have a perfectly good rate.
	// Filled by managed reads only.
	UnpricedModels []string
	// WeeklyExpiresAt is the first instant a counted positive row leaves the
	// rolling seven-day window. A measured weekly denial must be re-evaluated
	// at this boundary even when policy and prices have not changed.
	WeeklyExpiresAt time.Time
	// PricingSources counts priced rows by source (for example "exact",
	// "org", "family", or "stored"). It is nil when no priced read was
	// performed. The map is freshly allocated for each result.
	PricingSources map[string]int
}

// GuardBudgetUnavailableWindows identifies dollar windows that contain
// nonzero usage rows which could not be priced. A window with only empty,
// zero-token rows remains available: there is no spend to account for and a
// cap must not deny merely because an adapter emitted an empty event.
// Session is set only for the requested non-empty sessionID; the other fields
// describe the node-wide windows. The type deliberately lives in store so the
// bounded read can report its evidence without importing guard policy types.
type GuardBudgetUnavailableWindows struct {
	Session bool
	Daily   bool
	Weekly  bool
	Monthly bool
}

type guardBudgetSpendRow struct {
	source           int
	sessionID        string
	timestamp        string
	tool             string
	model            string
	inputTokens      int64
	outputTokens     int64
	cacheReadTokens  int64
	cacheCreation    int64
	cacheCreation1h  int64
	reasoningTokens  int64
	webSearchRequest int64
	storedUSD        float64
	fast             bool
	incomplete       bool
}

// guardBudgetSourceSpend holds one session's spend per capture source so the
// two can be de-duplicated by maximum rather than summed.
type guardBudgetSourceSpend struct {
	proxy   float64
	watcher float64
}

// GuardBudgetSpendPriced is the bounded read-time companion to
// GuardBudgetSpend. It reads proxy and watcher rows in one UNION query. Local
// advisory reads retain positive stored prices and the existing per-session
// MAX(proxy, watcher) merge. Managed reads reprice every row using exact/org
// rates; the same MAX merge de-duplicates a session captured by both sources,
// and a row that cannot be priced makes ITS TOOL's windows unavailable
// (UnpricedTools) when it names one, the node's windows otherwise.
//
// Normal rows are bounded by the earliest non-zero window start. Managed
// reads additionally detect malformed timestamps across history, since those
// rows cannot safely be assigned to a window. The caller bounds query time.
// Other rows older than that bound are included only when they belong to
// sessionID, because session budgets span the session lifetime. The production
// caller supplies all three window starts. Missing bounds or a missing pricer
// produce an error for managed reads; advisory reads use the original lookup.
//
// Invalid stored costs make their windows unavailable, even without token
// rows; they cannot reduce
// other spend or turn corrupt data into measured zero. A callback result is
// accepted only when it is finite, non-negative, and marked ok; unknown,
// negative, NaN, and infinite results stay unpriced.
func (s *Store) GuardBudgetSpendPriced(
	ctx context.Context,
	sessionID string,
	dayStart, weekStart, monthStart time.Time,
	pricer GuardBudgetPricer,
	options ...GuardBudgetReadOptions,
) (GuardBudgetSpendResult, error) {
	managed := managedBudgetRead(options)
	if pricer == nil || dayStart.IsZero() || weekStart.IsZero() || monthStart.IsZero() {
		if managed {
			return GuardBudgetSpendResult{}, fmt.Errorf("store.GuardBudgetSpendPriced: managed accounting requires pricing and bounded windows")
		}
		spend, err := s.GuardBudgetSpend(ctx, sessionID, dayStart, weekStart, monthStart)
		return GuardBudgetSpendResult{GuardBudgetWindows: spend}, err
	}

	earliest := dayStart.UTC()
	if candidate := weekStart.UTC(); candidate.Before(earliest) {
		earliest = candidate
	}
	if candidate := monthStart.UTC(); candidate.Before(earliest) {
		earliest = candidate
	}
	earliestStamp := guardBudgetWindowStamp(earliest)
	// Keep the statement static so the SQL remains auditable and gosec cannot
	// mistake a value-dependent predicate for SQL composition. For a requested
	// session, the first arm retains its lifetime rows; the timestamp arm is
	// the node-wide bounded read. With no session, the first arm is disabled.
	args := []any{
		sessionID, sessionID, earliest.UTC().Format("2006-01-02T15:04:05"), earliestStamp,
		sessionID, sessionID, earliest.UTC().Format("2006-01-02T15:04:05"), earliestStamp,
	}
	where := guardBudgetUsageWhere(managed)
	//nolint:gosec // G202: where selects closed constant SQL; all caller values are bound in args.
	q := `
		SELECT 0 AS source, COALESCE(session_id, ''), timestamp, '' AS tool,
		       COALESCE(model, ''), COALESCE(input_tokens, 0),
		       COALESCE(output_tokens, 0), COALESCE(cache_read_tokens, 0),
		       COALESCE(cache_creation_tokens, 0),
		       COALESCE(cache_creation_1h_tokens, 0), 0,
		       COALESCE(web_search_requests, 0), COALESCE(cost_usd, 0),
		       COALESCE(fast, 0),
		       input_tokens IS NULL OR output_tokens IS NULL OR
		       cache_read_tokens IS NULL OR cache_creation_tokens IS NULL
		  FROM api_turns` + where + `
		 UNION ALL
		SELECT 1 AS source, COALESCE(session_id, ''), timestamp,
		       COALESCE(tool, ''),
		       COALESCE(model, ''), COALESCE(input_tokens, 0),
		       COALESCE(output_tokens, 0), COALESCE(cache_read_tokens, 0),
		       COALESCE(cache_creation_tokens, 0),
		       COALESCE(cache_creation_1h_tokens, 0),
		       COALESCE(reasoning_tokens, 0),
		       COALESCE(web_search_requests, 0),
		       COALESCE(estimated_cost_usd, 0), COALESCE(fast, 0),
		       input_tokens IS NULL OR output_tokens IS NULL OR
		       cache_read_tokens IS NULL OR cache_creation_tokens IS NULL OR
		       reasoning_tokens IS NULL OR
		       COALESCE(reliability, '') NOT IN ('accurate', 'approximate') OR
		       source NOT IN ('jsonl', 'otel', 'hook', 'proxy')
		  FROM token_usage` + where

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return GuardBudgetSpendResult{}, fmt.Errorf("store.GuardBudgetSpendPriced: query: %w", err)
	}
	defer rows.Close()

	result := GuardBudgetSpendResult{PricingSources: map[string]int{}}
	var sessionRows, dayRows, weekRows, monthRows map[string]guardBudgetSourceSpend
	sessionRows = make(map[string]guardBudgetSourceSpend)
	dayRows = make(map[string]guardBudgetSourceSpend)
	weekRows = make(map[string]guardBudgetSourceSpend)
	monthRows = make(map[string]guardBudgetSourceSpend)
	dayStamp := guardBudgetWindowStamp(dayStart)
	weekStamp := guardBudgetWindowStamp(weekStart)
	monthStamp := guardBudgetWindowStamp(monthStart)
	fallbackModels := map[string]struct{}{}
	unpricedModels := map[string]struct{}{}

	for rows.Next() {
		var r guardBudgetSpendRow
		var source, fast, incomplete int
		if err := rows.Scan(
			&source, &r.sessionID, &r.timestamp, &r.tool, &r.model,
			&r.inputTokens, &r.outputTokens, &r.cacheReadTokens,
			&r.cacheCreation, &r.cacheCreation1h, &r.reasoningTokens,
			&r.webSearchRequest, &r.storedUSD, &fast, &incomplete,
		); err != nil {
			return GuardBudgetSpendResult{}, fmt.Errorf("store.GuardBudgetSpendPriced: scan: %w", err)
		}
		r.source = source
		r.fast = fast != 0
		r.incomplete = incomplete != 0

		usd, sourceName, priced, invalid := priceGuardBudgetRow(r, pricer, managed)
		// TWO CLASSES, TWO LISTS (BUDGET-COV-3). A row the org's own rates did
		// not price is either priced by a fallback rung - real dollars, counted
		// against the cap, just not the org's number - or a true miss that counts
		// as $0. Invalid rows name no model on either list: they are unpriced
		// because their counters or timestamp are broken, not because of what
		// produced them.
		if managed && !invalid && !guardBudgetOrgPriced(sourceName) && r.model != "" {
			if priced {
				fallbackModels[r.model] = struct{}{}
			} else {
				unpricedModels[r.model] = struct{}{}
			}
		}
		if managed && !validGuardBudgetTimestamp(r.timestamp) {
			// A malformed time cannot be assigned to a known calendar window.
			result.UnpricedWindows.Daily, result.UnpricedWindows.Weekly, result.UnpricedWindows.Monthly = true, true, true
			result.UnpricedWindows.Session = result.UnpricedWindows.Session || (sessionID != "" && r.sessionID == sessionID)
		}

		if at, err := time.Parse(time.RFC3339Nano, r.timestamp); err == nil {
			r.timestamp = guardBudgetWindowStamp(at)
		}

		if priced {
			result.PricedRows++
			result.PricingSources[sourceName]++
		} else {
			recordGuardBudgetUnpriced(&result, r, invalid, managed, guardBudgetReadWindows{sessionID, dayStamp, weekStamp, monthStamp})
		}

		addGuardBudgetRow(sessionRows, r, usd)
		if r.timestamp >= dayStamp {
			addGuardBudgetRow(dayRows, r, usd)
		}
		if r.timestamp >= weekStamp {
			addGuardBudgetRow(weekRows, r, usd)
			result.WeeklyExpiresAt = nextGuardBudgetWeeklyExpiry(result.WeeklyExpiresAt, r.timestamp, usd)
		}
		if r.timestamp >= monthStamp {
			addGuardBudgetRow(monthRows, r, usd)
		}
	}
	if err := rows.Err(); err != nil {
		return GuardBudgetSpendResult{}, fmt.Errorf("store.GuardBudgetSpendPriced: rows: %w", err)
	}

	result.FallbackModels = sortedBoundedModels(fallbackModels, guardBudgetMaxUnpricedModels)
	result.UnpricedModels = sortedBoundedModels(unpricedModels, guardBudgetMaxUnpricedModels)
	if sessionID != "" {
		result.SessionUSD = maxGuardBudgetSpend(sessionRows, sessionID)
	}
	result.DailyUSD = sumGuardBudgetSpend(dayRows)
	result.WeeklyUSD = sumGuardBudgetSpend(weekRows)
	result.MonthlyUSD = sumGuardBudgetSpend(monthRows)
	// A session observed through BOTH the proxy and the native parser is the
	// ordinary shape for any tool the daemon launches through :8820 and also
	// parses from its own store. It is not ambiguity: per-session
	// MAX(proxy, watcher) is the established de-duplication rule and is applied
	// above. Marking the overlap unavailable contradicted that rule and denied
	// every proxied-and-parsed tool (accounting-readiness correction,
	// 2026-09-14).
	return result, nil
}

// sortedBoundedModels renders a model set as the deterministic, bounded slice
// the report carries. Sorted BEFORE the cap so the same corpus always names the
// same models: a set walk is random, and a coverage note that named a different
// pair of models on every push would read as churn rather than as a fact.
func sortedBoundedModels(set map[string]struct{}, limit int) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for model := range set {
		out = append(out, model)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func addGuardBudgetRow(dst map[string]guardBudgetSourceSpend, r guardBudgetSpendRow, usd float64) {
	entry := dst[r.sessionID]
	if r.source == 0 {
		entry.proxy += usd
	} else {
		entry.watcher += usd
	}
	dst[r.sessionID] = entry
}

func maxGuardBudgetSpend(rows map[string]guardBudgetSourceSpend, sessionID string) float64 {
	entry := rows[sessionID]
	if entry.proxy > entry.watcher {
		return entry.proxy
	}
	return entry.watcher
}

func sumGuardBudgetSpend(rows map[string]guardBudgetSourceSpend) float64 {
	var total float64
	for _, entry := range rows {
		if entry.proxy > entry.watcher {
			total += entry.proxy
		} else {
			total += entry.watcher
		}
	}
	return total
}

func nonNegativeTokenCount(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

func hasGuardBudgetBillableUsage(r guardBudgetSpendRow) bool {
	return nonNegativeTokenCount(r.inputTokens) > 0 ||
		nonNegativeTokenCount(r.outputTokens) > 0 ||
		nonNegativeTokenCount(r.cacheReadTokens) > 0 ||
		nonNegativeTokenCount(r.cacheCreation) > 0 ||
		nonNegativeTokenCount(r.cacheCreation1h) > 0 ||
		nonNegativeTokenCount(r.reasoningTokens) > 0 ||
		nonNegativeTokenCount(r.webSearchRequest) > 0
}

// priceGuardBudgetRow resolves ONE row to dollars through the SAME ladder the
// rest of Observer prices with (ruling A1, 2026-09-15):
//
//	org > exact > date-stripped > family > local > the adapter's own stored cost
//
// The pricer seam owns the first five rungs (they are cost.Table's own
// resolution order and its PricingSource is what comes back); this function
// owns the tail: when nothing in the table matched, an adapter-reported cost
// on a row with valid counters is still real money and is counted.
//
// WHY MANAGED NO LONGER DEMANDS AN EXACT-OR-ORG RATE. It used to, and the
// result was the defect this ruling reverses: the node's dashboard priced a
// day at $0.97 through the fallback rungs while the managed read called the
// very same rows unpriced, reported the window unavailable, and the guard
// TERMed the developer's running process at "$0.26 of $2". Three truths on one
// node is worse than one imperfect truth: an org that wants exact rates
// authors them (`observer-org pricing`), and until it does, a family rate is
// the honest estimate every other surface already shows.
//
// A true miss with no stored cost still counts as $0 - and is FLAGGED, through
// the result's UnpricedRows/UnpricedModels - but it never denies. Invalid rows
// (NaN/negative/incomplete counters, a timestamp that belongs to no window) are
// flagged zero for the same reason: corrupt data must not become invented
// dollars, and it must not become a stopped process either.
//
// Advisory (individual) accounting is UNCHANGED: it keeps its adapter-reported
// cost first, exactly as it always has.
func priceGuardBudgetRow(r guardBudgetSpendRow, pricer GuardBudgetPricer, managed bool) (float64, string, bool, bool) {
	if managed && !validGuardBudgetTimestamp(r.timestamp) {
		return 0, "invalid_timestamp", false, true
	}
	invalidStored := math.IsNaN(r.storedUSD) || math.IsInf(r.storedUSD, 0) || r.storedUSD < 0
	invalidUsage := r.inputTokens < 0 || r.outputTokens < 0 || r.cacheReadTokens < 0 ||
		r.cacheCreation < 0 || r.cacheCreation1h < 0 || r.reasoningTokens < 0 || r.webSearchRequest < 0
	invalidUsage = invalidUsage || (managed && (r.incomplete || (r.storedUSD > 0 && !hasGuardBudgetBillableUsage(r))))
	if invalidStored || invalidUsage {
		return 0, "invalid_stored", false, true
	}
	if !managed && r.storedUSD > 0 {
		return r.storedUSD, "stored", true, false
	}
	at, _ := time.Parse(time.RFC3339Nano, r.timestamp)
	usd, sourceName, priced := pricer(r.model, at, PushTokenSplit{
		Input:             r.inputTokens,
		Output:            r.outputTokens,
		CacheRead:         r.cacheReadTokens,
		CacheCreation:     r.cacheCreation,
		CacheCreation1h:   r.cacheCreation1h,
		Reasoning:         r.reasoningTokens,
		WebSearchRequests: r.webSearchRequest,
		Fast:              r.fast,
	})
	if priced && sourceName != "" && !math.IsNaN(usd) && !math.IsInf(usd, 0) && usd >= 0 {
		return usd, sourceName, true, false
	}
	// The pricer declined - a genuine miss, or a managed read refusing an org
	// rate that belongs to a different enrollment. Either way the ladder is not
	// finished: the adapter's own reported cost is the last rung.
	if r.storedUSD > 0 {
		return r.storedUSD, "stored", true, false
	}
	if sourceName == "" {
		sourceName = "miss"
	}
	return 0, sourceName, false, false
}

// guardBudgetMaxUnpricedModels bounds each coverage list (FallbackModels and
// UnpricedModels are bounded separately). Eight is the number the
// posture wire carries and a coverage sentence can name without becoming a
// list; a ninth distinct model tells an admin nothing the first eight did not.
const guardBudgetMaxUnpricedModels = 8

// guardBudgetOrgPriced reports whether a resolved pricing source is one of the
// two rungs the ORG itself authored. Everything else - the fallback rungs and
// the stored-cost tail - is a price the org did not set, which is the
// distinction the coverage report is built on.
func guardBudgetOrgPriced(source string) bool { return source == "exact" || source == "org" }

func validGuardBudgetTimestamp(value string) bool {
	at, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !at.IsZero()
}

// guardBudgetReadWindows are canonical UTC stamps used by the bounded query.
type guardBudgetReadWindows struct{ sessionID, day, week, month string }

// recordGuardBudgetUnpriced marks the windows an unpriced billable row leaves
// unaccounted. A managed read attributes the row to its TOOL when it names one
// and is otherwise well formed; an invalid row, or one with no tool column
// (proxy turns), stays node-wide because nothing narrower is provable. Advisory
// reads keep the original node-wide behaviour unchanged.
func recordGuardBudgetUnpriced(result *GuardBudgetSpendResult, r guardBudgetSpendRow, invalid, managed bool, windows guardBudgetReadWindows) {
	result.UnpricedRows++
	result.UnpricedTokens += nonNegativeTokenCount(r.inputTokens) + nonNegativeTokenCount(r.outputTokens)
	if !invalid && !hasGuardBudgetBillableUsage(r) {
		return
	}
	scoped := managed && !invalid && r.tool != ""
	target := result.UnpricedWindows
	if scoped {
		target = result.UnpricedTools[r.tool]
	}
	if windows.sessionID != "" && r.sessionID == windows.sessionID {
		target.Session = true
	}
	if r.timestamp >= windows.day {
		target.Daily = true
	}
	if r.timestamp >= windows.week {
		target.Weekly = true
	}
	if r.timestamp >= windows.month {
		target.Monthly = true
	}
	if !scoped {
		result.UnpricedWindows = target
		return
	}
	if result.UnpricedTools == nil {
		result.UnpricedTools = make(map[string]GuardBudgetUnavailableWindows)
	}
	result.UnpricedTools[r.tool] = target
}
