package store

import (
	"context"
	"testing"
	"time"
)

func TestManagedBudgetRepricesEstimatesAndRejectsMissingEvidence(t *testing.T) {
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "native")
	day, week, month := guardBudgetTestWindows()
	insertGuardBudgetUsage(t, database, "native", "fixture-model", "usage", day, 100, 10, 0.01)
	// THE LADDER (ruling A1, 2026-09-15), one row per rung. Managed accounting
	// prices with the SAME ladder every other Observer surface uses -
	// org > exact > date-stripped > family > local > the adapter's own stored
	// cost - and counts every priced row against the cap.
	//
	// It used to accept ONLY exact and org, and that is the defect this table
	// now pins reversed: a family rate made the row "unpriced", the guard read
	// that as unavailable accounting, and the developer's process was stopped.
	// A family rate is an estimate, not an absence; the org closes the gap by
	// authoring a price, and until then the estimate is what every other
	// surface already shows.
	//
	// What is still REFUSED is broken data, not cheap data: an unverifiable
	// source, estimated counters, a missing counter. Those are unpriced and
	// flagged - and, since this ruling, they do not deny either.
	for _, tc := range []struct {
		name, rate, source, reliability string
		missing                         bool
		wantUSD                         float64
		wantSource                      string
		wantUnpriced                    bool
	}{
		{name: "exact reprice", rate: "exact", source: "jsonl", reliability: "approximate", wantUSD: 0.35, wantSource: "exact"},
		{name: "org authored rate", rate: "org", source: "jsonl", reliability: "approximate", wantUSD: 0.35, wantSource: "org"},
		{name: "family estimate", rate: "family", source: "jsonl", reliability: "approximate", wantUSD: 0.35, wantSource: "family"},
		{name: "developer override", rate: "local", source: "jsonl", reliability: "approximate", wantUSD: 0.35, wantSource: "local"},
		// The pricer misses entirely, so the ladder's last rung - the adapter's
		// own reported cost, $0.01 on this fixture - is what counts.
		{name: "missing rate falls to the stored cost", rate: "miss", source: "jsonl", reliability: "approximate", wantUSD: 0.01, wantSource: "stored"},
		{name: "unreliable source", rate: "exact", source: "jsonl", reliability: "unreliable", wantUnpriced: true},
		{name: "estimated counters", rate: "exact", source: "estimated", reliability: "approximate", wantUnpriced: true},
		{name: "missing counter", rate: "exact", source: "jsonl", reliability: "approximate", missing: true, wantUnpriced: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input any = 100
			if tc.missing {
				input = nil
			}
			_, err := database.ExecContext(context.Background(), `UPDATE token_usage SET input_tokens=?, cache_read_tokens=0, cache_creation_tokens=0, reasoning_tokens=0, source=?, reliability=?`, input, tc.source, tc.reliability)
			if err != nil {
				t.Fatal(err)
			}
			pricer := func(string, time.Time, PushTokenSplit) (float64, string, bool) {
				return 0.35, tc.rate, tc.rate != "miss"
			}
			got, err := st.GuardBudgetSpendPriced(context.Background(), "native", day, week, month, pricer, GuardBudgetReadOptions{Managed: true})
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantUnpriced {
				if got.UnpricedRows != 1 || got.PricedRows != 0 || got.DailyUSD != 0 {
					t.Fatalf("broken row was priced anyway: %+v", got)
				}
				// Flagged, not denied: the windows the read reports are
				// REPORTING data now; the guard no longer consumes them.
				if !got.UnpricedWindows.Daily {
					t.Fatalf("broken row was not flagged: %+v", got)
				}
				return
			}
			if got.DailyUSD != tc.wantUSD || got.PricingSources[tc.wantSource] != 1 || got.UnpricedRows != 0 {
				t.Fatalf("ladder rung %q priced %+v, want $%v from %q", tc.rate, got, tc.wantUSD, tc.wantSource)
			}
			if got.UnpricedWindows != (GuardBudgetUnavailableWindows{}) || len(got.UnpricedTools) != 0 {
				t.Fatalf("a priced row closed a window: %+v", got)
			}
			// COVERAGE is still reported for the rungs the org did not author,
			// because that gap is what the org Budgets note names. A row that
			// WAS priced by a fallback rung lands on FallbackModels, not
			// UnpricedModels (BUDGET-COV-3): its dollars count against the cap,
			// so it is not a $0 hole. Only exact/org rows name no model at all.
			wantFallback := 1
			if tc.wantSource == "exact" || tc.wantSource == "org" {
				wantFallback = 0
			}
			if len(got.FallbackModels) != wantFallback {
				t.Fatalf("fallback models = %v, want %d for a %q rate", got.FallbackModels, wantFallback, tc.wantSource)
			}
			if len(got.UnpricedModels) != 0 {
				t.Fatalf("a priced row named a true miss: %v", got.UnpricedModels)
			}
			advisory, err := st.GuardBudgetSpendPriced(context.Background(), "native", day, week, month, pricer)
			if err != nil || advisory.DailyUSD != 0.01 {
				t.Fatalf("advisory accounting changed: %+v err=%v", advisory, err)
			}
		})
	}
}

func TestManagedBudgetAmbiguousSourcesAreWindowScoped(t *testing.T) {
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "mixed")
	guardBudgetTestSession(t, st, "separate")
	day, week, month := guardBudgetTestWindows()
	insertGuardBudgetUsage(t, database, "mixed", "fixture", "native", day, 100, 10, 0)
	insertGuardBudgetAPI(t, database, "mixed", "fixture", day.Add(-time.Hour), 200, 20, 0)
	insertGuardBudgetAPI(t, database, "separate", "fixture", day, 300, 30, 0)
	_, err := database.ExecContext(context.Background(), `UPDATE token_usage SET cache_read_tokens=0,cache_creation_tokens=0,reasoning_tokens=0,reliability='approximate'`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.ExecContext(context.Background(), `UPDATE api_turns SET cache_read_tokens=0,cache_creation_tokens=0`)
	if err != nil {
		t.Fatal(err)
	}
	// NEITHER unit treats a session seen by both the proxy and the native
	// parser as ambiguous: per-session MAX(proxy, watcher) is the
	// de-duplication rule, and every proxy-launched-and-parsed tool produces
	// this shape. The $ read dropped the rule in the accounting-readiness
	// correction (2026-09-14); the token read follows it on the same ruling,
	// so the two units can never disagree about which turns they counted.
	got, err := st.GuardBudgetSpendPriced(context.Background(), "mixed", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 0.1, "exact", true }, GuardBudgetReadOptions{Managed: true})
	if err != nil || got.UnpricedWindows != (GuardBudgetUnavailableWindows{}) {
		t.Fatalf("USD mixed coverage=%+v err=%v", got, err)
	}
	tokens, err := st.GuardBudgetTokens(context.Background(), "mixed", day, week, month, GuardBudgetReadOptions{Managed: true})
	if err != nil || tokens.Unavailable != (GuardBudgetUnavailableWindows{}) {
		t.Fatalf("token mixed coverage=%+v err=%v", tokens, err)
	}
	// The overlapping session counts ONCE, at the larger substrate: the proxy
	// turn's 200+20 rather than that plus the native row's 100+10.
	if tokens.SessionTokens != 220 {
		t.Fatalf("overlapping session tokens=%d, want the larger substrate (220)", tokens.SessionTokens)
	}
	// The two sources use distinct sessions today; no overlap is guessed.
	if tokens.DailyTokens != 440 {
		t.Fatalf("daily separate-source total=%d", tokens.DailyTokens)
	}
	_, err = database.ExecContext(context.Background(), `UPDATE token_usage SET input_tokens=NULL`)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err = st.GuardBudgetTokens(context.Background(), "mixed", day, week, month, GuardBudgetReadOptions{Managed: true})
	if err != nil || !tokens.Unavailable.Daily {
		t.Fatalf("NULL counter admitted: %+v err=%v", tokens, err)
	}
}

func TestManagedBudgetNeverFallsBackToUnverifiedRead(t *testing.T) {
	st, _ := newTestStore(t)
	day, week, month := guardBudgetTestWindows()
	if _, err := st.GuardBudgetSpendPriced(context.Background(), "", day, week, month, nil, GuardBudgetReadOptions{Managed: true}); err == nil {
		t.Fatal("managed accounting accepted legacy unpriced fallback")
	}
}

func TestManagedBudgetRejectsMalformedCapturedTimestamp(t *testing.T) {
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "malformed")
	day, week, month := guardBudgetTestWindows()
	insertGuardBudgetUsage(t, database, "malformed", "fixture-model", "bad-time", day, 100, 0, 0)
	for _, stamp := range []string{"not-a-timestamp", "", "0001-01-01T00:00:00Z", "100", "2000-01-01", "2000-01-01 00:00:00", "2000-02-30T00:00:00Z", "2000-01-01T24:00:00Z"} {
		t.Run(stamp, func(t *testing.T) {
			_, err := database.ExecContext(context.Background(), `UPDATE token_usage SET timestamp=?,cache_read_tokens=0,cache_creation_tokens=0,reasoning_tokens=0,reliability='approximate'`, stamp)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			price := func(string, time.Time, PushTokenSplit) (float64, string, bool) { calls++; return 0, "exact", true }
			// No requested session: malformed history must not disappear solely
			// because its text sorts before the earliest calendar boundary.
			usd, err := st.GuardBudgetSpendPriced(context.Background(), "", day, week, month, price, GuardBudgetReadOptions{Managed: true})
			if err != nil || !usd.UnpricedWindows.Daily || calls != 0 {
				t.Fatalf("malformed row used current rate: %+v calls=%d err=%v", usd, calls, err)
			}
			tokens, err := st.GuardBudgetTokens(context.Background(), "", day, week, month, GuardBudgetReadOptions{Managed: true})
			if err != nil || !tokens.Unavailable.Daily {
				t.Fatalf("malformed row was counted as known: %+v err=%v", tokens, err)
			}
		})
	}
}

func TestManagedBudgetAcceptsCanonicalTimestampPrecision(t *testing.T) {
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "canonical")
	day, week, month := guardBudgetTestWindows()
	insertGuardBudgetUsage(t, database, "canonical", "fixture-model", "timestamp", day, 100, 0, 0)
	for _, nanos := range []int64{0, 1, 100000000, 999999999} {
		at := day.Add(time.Duration(nanos))
		_, err := database.ExecContext(context.Background(), `UPDATE token_usage SET timestamp=?,cache_read_tokens=0,cache_creation_tokens=0,reasoning_tokens=0,reliability='approximate'`, timestamp(at))
		if err != nil {
			t.Fatal(err)
		}
		usd, err := st.GuardBudgetSpendPriced(context.Background(), "", day, week, month,
			func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 0.1, "exact", true }, GuardBudgetReadOptions{Managed: true})
		if err != nil || usd.UnpricedWindows.Daily || usd.DailyUSD != 0.1 {
			t.Fatalf("canonical UTC timestamp rejected: nanos=%d result=%+v err=%v", nanos, usd, err)
		}
		tokens, err := st.GuardBudgetTokens(context.Background(), "", day, week, month, GuardBudgetReadOptions{Managed: true})
		if err != nil || tokens.Unavailable.Daily || tokens.DailyTokens != 100 {
			t.Fatalf("canonical token timestamp rejected: nanos=%d result=%+v err=%v", nanos, tokens, err)
		}
	}
}

func TestManagedBudgetFractionalWindowBoundary(t *testing.T) {
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "boundary")
	day, week, month := guardBudgetTestWindows()
	day = day.Add(125 * time.Nanosecond)
	insertGuardBudgetUsage(t, database, "boundary", "fixture-model", "before", day.Add(-time.Nanosecond), 100, 0, 0)
	insertGuardBudgetUsage(t, database, "boundary", "fixture-model", "at", day, 200, 0, 0)
	_, err := database.ExecContext(context.Background(), `UPDATE token_usage SET cache_read_tokens=0,cache_creation_tokens=0,reasoning_tokens=0,reliability='approximate'`)
	if err != nil {
		t.Fatal(err)
	}
	usd, err := st.GuardBudgetSpendPriced(context.Background(), "", day, week, month,
		func(_ string, _ time.Time, split PushTokenSplit) (float64, string, bool) {
			return float64(split.Input) / 1000, "exact", true
		}, GuardBudgetReadOptions{Managed: true})
	if err != nil || usd.UnpricedWindows.Daily || usd.DailyUSD != 0.2 {
		t.Fatalf("fractional USD boundary: %+v err=%v", usd, err)
	}
	tokens, err := st.GuardBudgetTokens(context.Background(), "", day, week, month, GuardBudgetReadOptions{Managed: true})
	if err != nil || tokens.Unavailable.Daily || tokens.DailyTokens != 200 {
		t.Fatalf("fractional token boundary: %+v err=%v", tokens, err)
	}
}

func TestManagedBudgetReportsNextWeeklyExpiry(t *testing.T) {
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "weekly")
	day, week, month := guardBudgetTestWindows()
	first := week.Add(5 * time.Nanosecond)
	for _, row := range []struct {
		id    string
		at    time.Time
		input int64
	}{
		{"expired", week.Add(-time.Nanosecond), 900},
		{"empty", week, 0},
		{"first", first, 100},
		{"later", day, 200},
	} {
		insertGuardBudgetUsage(t, database, "weekly", "fixture-model", row.id, row.at, row.input, 0, 0)
	}
	_, err := database.ExecContext(context.Background(), `UPDATE token_usage SET cache_read_tokens=0,cache_creation_tokens=0,reasoning_tokens=0,reliability='approximate'`)
	if err != nil {
		t.Fatal(err)
	}
	usd, err := st.GuardBudgetSpendPriced(context.Background(), "", day, week, month,
		func(_ string, _ time.Time, split PushTokenSplit) (float64, string, bool) {
			return float64(split.Input) / 1000, "exact", true
		}, GuardBudgetReadOptions{Managed: true})
	want := first.Add(7 * 24 * time.Hour)
	if err != nil || !usd.WeeklyExpiresAt.Equal(want) {
		t.Fatalf("USD next expiry: %+v want=%s err=%v", usd, want, err)
	}
	tokens, err := st.GuardBudgetTokens(context.Background(), "", day, week, month, GuardBudgetReadOptions{Managed: true})
	if err != nil || !tokens.WeeklyExpiresAt.Equal(want) {
		t.Fatalf("token next expiry: %+v want=%s err=%v", tokens, want, err)
	}
}
