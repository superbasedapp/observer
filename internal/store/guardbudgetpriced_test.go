package store

import (
	"context"
	"database/sql"
	"math"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func guardBudgetTestSession(t *testing.T, s *Store, id string) {
	t.Helper()
	ctx := context.Background()
	projectID, err := s.UpsertProject(ctx, "/tmp/guard-budget-priced", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: id, ProjectID: projectID, Tool: models.ToolClaudeCode,
		StartedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("UpsertSession(%q): %v", id, err)
	}
}

func insertGuardBudgetAPI(t *testing.T, db *sql.DB, sessionID, model string, at time.Time, input, output int64, usd float64) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO api_turns(session_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
		VALUES (?, ?, 'anthropic', ?, ?, ?, ?)`,
		sessionID, timestamp(at), model, input, output, usd); err != nil {
		t.Fatalf("insert api_turn %q: %v", model, err)
	}
}

func insertGuardBudgetUsage(t *testing.T, db *sql.DB, sessionID, model, eventID string, at time.Time, input, output int64, usd float64) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO token_usage(
			session_id, timestamp, tool, model, input_tokens, output_tokens,
			estimated_cost_usd, source, reliability, source_event_id)
		VALUES (?, ?, 'claude-code', ?, ?, ?, ?, 'jsonl', 'estimated', ?)`,
		sessionID, timestamp(at), model, input, output, usd, eventID); err != nil {
		t.Fatalf("insert token_usage %q: %v", eventID, err)
	}
}

func guardBudgetTestWindows() (time.Time, time.Time, time.Time) {
	day := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	return day, day.Add(-5 * 24 * time.Hour), time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
}

func assertGuardBudgetNear(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("%s = %.9f, want %.9f", name, got, want)
	}
}

func TestGuardBudgetSpendPriced_PreservesStoredCostAndPricesZeroRows(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "native")
	at := time.Date(2026, 9, 10, 12, 34, 56, 123456789, time.FixedZone("IST", 5*60*60+30*60))
	insertGuardBudgetUsage(t, db, "native", "muse-spark-1.3-contributor", "native-zero", at, 100, 50, 0)
	insertGuardBudgetUsage(t, db, "native", "muse-spark-1.3-contributor", "native-stored", at, 100, 50, 2.50)

	day, week, month := guardBudgetTestWindows()
	var calls int
	var gotAt time.Time
	var gotSplit PushTokenSplit
	spend, err := s.GuardBudgetSpendPriced(context.Background(), "native", day, week, month,
		func(model string, at time.Time, split PushTokenSplit) (float64, string, bool) {
			calls++
			gotAt, gotSplit = at, split
			if model != "muse-spark-1.3-contributor" {
				t.Fatalf("pricer model = %q", model)
			}
			return 4.25, "exact", true
		})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	assertGuardBudgetNear(t, "session spend", spend.SessionUSD, 6.75)
	assertGuardBudgetNear(t, "daily spend", spend.DailyUSD, 6.75)
	assertGuardBudgetNear(t, "weekly spend", spend.WeeklyUSD, 6.75)
	assertGuardBudgetNear(t, "monthly spend", spend.MonthlyUSD, 6.75)
	if calls != 1 {
		t.Fatalf("pricer calls = %d, want 1 for the zero-cost row", calls)
	}
	if !gotAt.Equal(at.UTC()) {
		t.Errorf("pricer timestamp = %s, want %s", gotAt, at.UTC())
	}
	if gotSplit.Input != 100 || gotSplit.Output != 50 {
		t.Errorf("pricer split = %+v, want input/output 100/50", gotSplit)
	}
	if spend.PricedRows != 2 || spend.UnpricedRows != 0 || spend.UnpricedTokens != 0 {
		t.Errorf("pricing metadata = %+v, want two priced rows and no unpriced rows", spend)
	}
	if spend.PricingSources["exact"] != 1 || spend.PricingSources["stored"] != 1 {
		t.Errorf("pricing sources = %#v, want exact=1 and stored=1", spend.PricingSources)
	}
	if spend.UnpricedWindows != (GuardBudgetUnavailableWindows{}) {
		t.Errorf("unpriced windows = %+v, want all windows available", spend.UnpricedWindows)
	}
	var estimated float64
	if err := db.QueryRowContext(
		context.Background(),
		`SELECT estimated_cost_usd FROM token_usage WHERE source_event_id = 'native-zero'`,
	).Scan(&estimated); err != nil {
		t.Fatalf("read back usage costs: %v", err)
	}
	if estimated != 0 {
		t.Errorf("read-time pricing mutated stored token row: %v", estimated)
	}
}

func TestGuardBudgetSpendPriced_DeduplicatesProxyAndWatcherByMaximum(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "both")
	at := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	insertGuardBudgetAPI(t, db, "both", "proxy-model", at, 10, 10, 0)
	insertGuardBudgetUsage(t, db, "both", "watcher-model", "watcher", at, 10, 10, 0)
	day, week, month := guardBudgetTestWindows()

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "both", day, week, month,
		func(model string, _ time.Time, _ PushTokenSplit) (float64, string, bool) {
			if model == "proxy-model" {
				return 3, "exact", true
			}
			return 2, "family", true
		})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	assertGuardBudgetNear(t, "session spend", spend.SessionUSD, 3)
	assertGuardBudgetNear(t, "daily spend", spend.DailyUSD, 3)
	assertGuardBudgetNear(t, "weekly spend", spend.WeeklyUSD, 3)
	assertGuardBudgetNear(t, "monthly spend", spend.MonthlyUSD, 3)
	if spend.PricedRows != 2 {
		t.Errorf("priced rows = %d, want 2 source rows", spend.PricedRows)
	}
	var apiCost, tokenCost float64
	if err := db.QueryRowContext(
		context.Background(),
		`SELECT cost_usd, (SELECT estimated_cost_usd FROM token_usage WHERE source_event_id = 'watcher')
		   FROM api_turns WHERE session_id = 'both'`,
	).Scan(&apiCost, &tokenCost); err != nil {
		t.Fatalf("read back dedup rows: %v", err)
	}
	if apiCost != 0 || tokenCost != 0 {
		t.Errorf("read-time de-dup mutated rows: api=%v token=%v", apiCost, tokenCost)
	}
}

func TestGuardBudgetSpendPriced_PartialUnknownKeepsKnownMaximumAndMarksWindow(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "partial")
	at := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	insertGuardBudgetAPI(t, db, "partial", "known-proxy", at, 10, 10, 0)
	insertGuardBudgetUsage(t, db, "partial", "unknown-watcher", "partial-unknown", at, 10, 10, 0)
	day, week, month := guardBudgetTestWindows()

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "partial", day, week, month,
		func(model string, _ time.Time, _ PushTokenSplit) (float64, string, bool) {
			if model == "known-proxy" {
				return 3, "exact", true
			}
			return 0, "miss", false
		})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	assertGuardBudgetNear(t, "partial session spend", spend.SessionUSD, 3)
	assertGuardBudgetNear(t, "partial daily spend", spend.DailyUSD, 3)
	if spend.UnpricedRows != 1 || spend.UnpricedTokens != 20 {
		t.Errorf("partial unknown metadata = %+v, want one unknown row and 20 tokens", spend)
	}
	wantWindows := GuardBudgetUnavailableWindows{Session: true, Daily: true, Weekly: true, Monthly: true}
	if spend.UnpricedWindows != wantWindows {
		t.Errorf("partial unknown windows = %+v, want %+v", spend.UnpricedWindows, wantWindows)
	}
}

func TestGuardBudgetSpendPriced_UnknownModelIsUnpriced(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "unknown")
	at := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	insertGuardBudgetUsage(t, db, "unknown", "model-without-a-rate", "unknown", at, 11, 7, 0)
	day, week, month := guardBudgetTestWindows()

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "unknown", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) {
			return 0, "miss", false
		})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	if spend.PricedRows != 0 || spend.UnpricedRows != 1 || spend.UnpricedTokens != 18 {
		t.Errorf("pricing metadata = %+v, want one unpriced row and 18 tokens", spend)
	}
	assertGuardBudgetNear(t, "session spend", spend.SessionUSD, 0)
	assertGuardBudgetNear(t, "daily spend", spend.DailyUSD, 0)
	if len(spend.PricingSources) != 0 {
		t.Errorf("pricing sources = %#v, want no priced sources", spend.PricingSources)
	}
	windows := GuardBudgetUnavailableWindows{Session: true, Daily: true, Weekly: true, Monthly: true}
	if spend.UnpricedWindows != windows {
		t.Errorf("unpriced windows = %+v, want %+v", spend.UnpricedWindows, windows)
	}
}

func TestGuardBudgetSpendPriced_RejectsInvalidPricerResults(t *testing.T) {
	cases := []struct {
		name  string
		value float64
	}{
		{name: "nan", value: math.NaN()},
		{name: "positive infinity", value: math.Inf(1)},
		{name: "negative infinity", value: math.Inf(-1)},
		{name: "negative", value: -0.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, db := newTestStore(t)
			guardBudgetTestSession(t, s, "invalid")
			at := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
			insertGuardBudgetUsage(t, db, "invalid", "known-model", "invalid", at, 3, 2, 0)
			day, week, month := guardBudgetTestWindows()

			spend, err := s.GuardBudgetSpendPriced(context.Background(), "invalid", day, week, month,
				func(string, time.Time, PushTokenSplit) (float64, string, bool) {
					return tc.value, "exact", true
				})
			if err != nil {
				t.Fatalf("GuardBudgetSpendPriced: %v", err)
			}
			if spend.PricedRows != 0 || spend.UnpricedRows != 1 || spend.UnpricedTokens != 5 {
				t.Errorf("pricing metadata = %+v, want one unpriced row and 5 tokens", spend)
			}
			wantWindows := GuardBudgetUnavailableWindows{Session: true, Daily: true, Weekly: true, Monthly: true}
			if spend.UnpricedWindows != wantWindows {
				t.Errorf("unpriced windows = %+v, want %+v", spend.UnpricedWindows, wantWindows)
			}
			assertGuardBudgetNear(t, "session spend", spend.SessionUSD, 0)
		})
	}
}

func TestGuardBudgetSpendPriced_EmptyUnpricedRowsDoNotDisableWindows(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "empty")
	day, week, month := guardBudgetTestWindows()
	insertGuardBudgetUsage(t, db, "empty", "unknown-empty", "empty", day, 0, 0, 0)

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "empty", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) {
			return 0, "miss", false
		})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	if spend.UnpricedRows != 1 || spend.UnpricedTokens != 0 {
		t.Errorf("empty-row metadata = %+v, want one row and zero tokens", spend)
	}
	if spend.UnpricedWindows != (GuardBudgetUnavailableWindows{}) {
		t.Errorf("empty-row unpriced windows = %+v, want all windows available", spend.UnpricedWindows)
	}
}

func TestGuardBudgetSpendPriced_UnpricedWindowsFollowTheirOwnBounds(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "windowed")
	day, week, month := guardBudgetTestWindows()
	// Two days before the day boundary is still in the rolling week and
	// calendar month. The session window remains lifetime-scoped.
	insertGuardBudgetUsage(t, db, "windowed", "unknown-windowed", "windowed", day.Add(-48*time.Hour), 4, 1, 0)

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "windowed", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) {
			return 0, "miss", false
		})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	if spend.UnpricedWindows != (GuardBudgetUnavailableWindows{Session: true, Weekly: true, Monthly: true}) {
		t.Errorf("windowed unpriced flags = %+v, want session+weekly+monthly only", spend.UnpricedWindows)
	}
	assertGuardBudgetNear(t, "windowed daily spend", spend.DailyUSD, 0)
}

func TestGuardBudgetSpendPriced_NilPricerPreservesLegacySpend(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "legacy")
	day, week, month := guardBudgetTestWindows()
	at := day.Add(time.Hour)
	insertGuardBudgetAPI(t, db, "legacy", "legacy-model", at, 1, 1, 1.25)

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "legacy", day, week, month, nil)
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced(nil): %v", err)
	}
	assertGuardBudgetNear(t, "legacy session spend", spend.SessionUSD, 1.25)
	assertGuardBudgetNear(t, "legacy daily spend", spend.DailyUSD, 1.25)
	if spend.PricedRows != 0 || spend.UnpricedRows != 0 || spend.PricingSources != nil ||
		spend.UnpricedWindows != (GuardBudgetUnavailableWindows{}) {
		t.Errorf("nil-pricer compatibility metadata = %+v, want legacy zero metadata", spend)
	}
}

func TestGuardBudgetSpendPriced_IncludesBoundariesAndSessionLifetime(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "lifetime")
	guardBudgetTestSession(t, s, "day")
	guardBudgetTestSession(t, s, "week")
	guardBudgetTestSession(t, s, "month")
	day, week, month := guardBudgetTestWindows()
	insertGuardBudgetUsage(t, db, "lifetime", "old", "old", month.Add(-time.Hour), 1, 1, 0)
	insertGuardBudgetUsage(t, db, "day", "day-boundary", "day", day, 1, 1, 0)
	insertGuardBudgetUsage(t, db, "week", "week-boundary", "week", week, 1, 1, 0)
	insertGuardBudgetUsage(t, db, "month", "month-boundary", "month", month, 1, 1, 0)
	prices := map[string]float64{"old": 9, "day-boundary": 1, "week-boundary": 2, "month-boundary": 3}
	pricer := func(model string, _ time.Time, _ PushTokenSplit) (float64, string, bool) {
		return prices[model], "exact", true
	}

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "lifetime", day, week, month, pricer)
	if err != nil {
		t.Fatalf("session GuardBudgetSpendPriced: %v", err)
	}
	assertGuardBudgetNear(t, "lifetime session spend", spend.SessionUSD, 9)
	assertGuardBudgetNear(t, "daily boundary spend", spend.DailyUSD, 1)
	assertGuardBudgetNear(t, "weekly boundary spend", spend.WeeklyUSD, 3)
	assertGuardBudgetNear(t, "monthly boundary spend", spend.MonthlyUSD, 6)
	if spend.UnpricedWindows != (GuardBudgetUnavailableWindows{}) {
		t.Errorf("unpriced windows = %+v, want all windows available", spend.UnpricedWindows)
	}

	spend, err = s.GuardBudgetSpendPriced(context.Background(), "", day, week, month, pricer)
	if err != nil {
		t.Fatalf("node GuardBudgetSpendPriced: %v", err)
	}
	assertGuardBudgetNear(t, "node daily boundary spend", spend.DailyUSD, 1)
	assertGuardBudgetNear(t, "node weekly boundary spend", spend.WeeklyUSD, 3)
	assertGuardBudgetNear(t, "node monthly boundary spend", spend.MonthlyUSD, 6)
}

func TestGuardBudgetSpendPriced_NormalizesTimeZonesAtWindowBoundaries(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "zones")
	loc := time.FixedZone("IST", 5*60*60+30*60)
	day := time.Date(2026, 9, 10, 0, 0, 0, 0, loc)
	week := day.Add(-5 * 24 * time.Hour)
	month := time.Date(2026, 9, 1, 0, 0, 0, 0, loc)
	insertGuardBudgetUsage(t, db, "zones", "at-local-midnight", "at", day, 1, 1, 0)
	insertGuardBudgetUsage(t, db, "zones", "before-local-midnight", "before", day.Add(-time.Nanosecond), 1, 1, 0)
	var callbackAt time.Time
	spend, err := s.GuardBudgetSpendPriced(context.Background(), "zones", day, week, month,
		func(model string, at time.Time, _ PushTokenSplit) (float64, string, bool) {
			if model == "at-local-midnight" {
				callbackAt = at
				return 1, "exact", true
			}
			return 2, "exact", true
		})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	assertGuardBudgetNear(t, "daily spend", spend.DailyUSD, 1)
	assertGuardBudgetNear(t, "weekly spend", spend.WeeklyUSD, 3)
	assertGuardBudgetNear(t, "monthly spend", spend.MonthlyUSD, 3)
	if !callbackAt.Equal(day.UTC()) {
		t.Errorf("callback timestamp = %s, want %s", callbackAt, day.UTC())
	}
}

// insertManagedGuardBudgetUsage writes a token_usage row that a MANAGED read
// accepts: every counter present, a recognized source and a reliability the
// verified read admits. The tool column is explicit because tool attribution
// is what the per-tool coverage under test is built on.
func insertManagedGuardBudgetUsage(t *testing.T, db *sql.DB, sessionID, tool, model, eventID string, at time.Time, input, output int64) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO token_usage(
			session_id, timestamp, tool, model, input_tokens, output_tokens,
			cache_read_tokens, cache_creation_tokens, cache_creation_1h_tokens,
			reasoning_tokens, web_search_requests, estimated_cost_usd,
			source, reliability, source_event_id)
		VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 'jsonl', 'approximate', ?)`,
		sessionID, timestamp(at), tool, model, input, output, eventID); err != nil {
		t.Fatalf("insert managed token_usage %q: %v", eventID, err)
	}
}

func insertManagedGuardBudgetAPI(t *testing.T, db *sql.DB, sessionID, model string, at time.Time, input, output int64) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO api_turns(
			session_id, timestamp, provider, model, input_tokens, output_tokens,
			cache_read_tokens, cache_creation_tokens, cache_creation_1h_tokens,
			web_search_requests, cost_usd)
		VALUES (?, ?, 'anthropic', ?, ?, ?, 0, 0, 0, 0, 0)`,
		sessionID, timestamp(at), model, input, output); err != nil {
		t.Fatalf("insert managed api_turn %q: %v", model, err)
	}
}

// TestManagedBudgetUnpricedUsageIsScopedToItsTool pins the correction of
// 2026-09-14: one adapter emitting a model no exact or org rate can price used
// to make the WHOLE node's dollar windows unavailable, which denied every
// other governed tool for the rest of the window. token_usage names its tool,
// so the unavailability is recorded against that tool instead.
func TestManagedBudgetUnpricedUsageIsScopedToItsTool(t *testing.T) {
	t.Parallel()
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "muse-session")
	guardBudgetTestSession(t, st, "opencode-session")
	day, week, month := guardBudgetTestWindows()
	at := day.Add(2 * time.Hour)
	insertManagedGuardBudgetUsage(t, database, "muse-session", "muse", "muse-spark-1.3-contributor", "muse-usage", at, 100, 20)
	insertManagedGuardBudgetUsage(t, database, "opencode-session", "opencode", "priced-model", "opencode-usage", at, 10, 5)

	price := func(model string, _ time.Time, _ PushTokenSplit) (float64, string, bool) {
		if model == "priced-model" {
			return 0.25, "exact", true
		}
		return 0, "miss", false
	}
	spend, err := st.GuardBudgetSpendPriced(context.Background(), "", day, week, month, price, GuardBudgetReadOptions{Managed: true})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	if spend.UnpricedWindows != (GuardBudgetUnavailableWindows{}) {
		t.Fatalf("node-wide windows = %+v; an attributable unpriced row must not deny the node", spend.UnpricedWindows)
	}
	wantTool := GuardBudgetUnavailableWindows{Daily: true, Weekly: true, Monthly: true}
	if got := spend.UnpricedTools["muse"]; got != wantTool {
		t.Fatalf("muse coverage = %+v, want %+v", got, wantTool)
	}
	if got, ok := spend.UnpricedTools["opencode"]; ok {
		t.Fatalf("priced tool reported unavailable coverage: %+v", got)
	}
	assertGuardBudgetNear(t, "daily spend", spend.DailyUSD, 0.25)
	if spend.PricedRows != 1 || spend.UnpricedRows != 1 || spend.UnpricedTokens != 120 {
		t.Fatalf("honesty counters = %+v, want one priced and one unpriced row", spend)
	}

	// The advisory (individual) read is unchanged: no tool scoping, node-wide
	// windows exactly as before.
	advisory, err := st.GuardBudgetSpendPriced(context.Background(), "", day, week, month, price)
	if err != nil {
		t.Fatalf("advisory GuardBudgetSpendPriced: %v", err)
	}
	if len(advisory.UnpricedTools) != 0 {
		t.Fatalf("advisory read gained tool scoping: %+v", advisory.UnpricedTools)
	}
	if advisory.UnpricedWindows != wantTool {
		t.Fatalf("advisory node-wide windows = %+v, want %+v", advisory.UnpricedWindows, wantTool)
	}
}

// TestManagedBudgetUnpricedProxyRowStaysNodeWide pins the other half: an
// api_turn carries no tool column, so nothing narrower than the node is
// provable and the node-wide windows must still close.
func TestManagedBudgetUnpricedProxyRowStaysNodeWide(t *testing.T) {
	t.Parallel()
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "proxy-session")
	day, week, month := guardBudgetTestWindows()
	insertManagedGuardBudgetAPI(t, database, "proxy-session", "model-without-a-rate", day.Add(time.Hour), 100, 20)

	spend, err := st.GuardBudgetSpendPriced(context.Background(), "proxy-session", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 0, "miss", false },
		GuardBudgetReadOptions{Managed: true})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	want := GuardBudgetUnavailableWindows{Session: true, Daily: true, Weekly: true, Monthly: true}
	if spend.UnpricedWindows != want {
		t.Fatalf("node-wide windows = %+v, want %+v", spend.UnpricedWindows, want)
	}
	if len(spend.UnpricedTools) != 0 {
		t.Fatalf("a row with no tool was attributed to one: %+v", spend.UnpricedTools)
	}
}

// TestManagedBudgetInvalidToolRowStaysNodeWide keeps corrupt data fail-closed:
// an invalid row names a tool but proves nothing about which window it belongs
// to, so it is not narrowed.
func TestManagedBudgetInvalidToolRowStaysNodeWide(t *testing.T) {
	t.Parallel()
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "corrupt-session")
	day, week, month := guardBudgetTestWindows()
	insertManagedGuardBudgetUsage(t, database, "corrupt-session", "muse", "any-model", "corrupt", day.Add(time.Hour), 100, 20)
	if _, err := database.ExecContext(context.Background(),
		`UPDATE token_usage SET timestamp='not-a-timestamp' WHERE source_event_id='corrupt'`); err != nil {
		t.Fatalf("malform row: %v", err)
	}

	spend, err := st.GuardBudgetSpendPriced(context.Background(), "", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 1, "exact", true },
		GuardBudgetReadOptions{Managed: true})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	want := GuardBudgetUnavailableWindows{Daily: true, Weekly: true, Monthly: true}
	if spend.UnpricedWindows != want {
		t.Fatalf("node-wide windows = %+v, want %+v", spend.UnpricedWindows, want)
	}
	if len(spend.UnpricedTools) != 0 {
		t.Fatalf("invalid row was narrowed to a tool: %+v", spend.UnpricedTools)
	}
}

// TestManagedBudgetProxyAndNativeOverlapTotalsByMaximum pins the removal of
// the sources==3 rule. Every tool the daemon launches through the proxy AND
// parses from its own store produces this shape; MAX(proxy, watcher) is the
// established de-duplication and the window stays available.
func TestManagedBudgetProxyAndNativeOverlapTotalsByMaximum(t *testing.T) {
	t.Parallel()
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "overlap")
	day, week, month := guardBudgetTestWindows()
	at := day.Add(3 * time.Hour)
	insertManagedGuardBudgetAPI(t, database, "overlap", "proxy-model", at, 200, 20)
	insertManagedGuardBudgetUsage(t, database, "overlap", "opencode", "native-model", "overlap-native", at, 200, 20)

	spend, err := st.GuardBudgetSpendPriced(context.Background(), "overlap", day, week, month,
		func(model string, _ time.Time, _ PushTokenSplit) (float64, string, bool) {
			if model == "proxy-model" {
				return 0.30, "exact", true
			}
			return 0.20, "org", true
		}, GuardBudgetReadOptions{Managed: true})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	if spend.UnpricedWindows != (GuardBudgetUnavailableWindows{}) {
		t.Fatalf("proxy/native overlap closed the windows: %+v", spend.UnpricedWindows)
	}
	if len(spend.UnpricedTools) != 0 {
		t.Fatalf("overlap produced tool coverage gaps: %+v", spend.UnpricedTools)
	}
	for name, got := range map[string]float64{
		"session": spend.SessionUSD, "daily": spend.DailyUSD,
		"weekly": spend.WeeklyUSD, "monthly": spend.MonthlyUSD,
	} {
		assertGuardBudgetNear(t, name+" spend", got, 0.30)
	}
}
