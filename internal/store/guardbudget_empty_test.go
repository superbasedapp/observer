package store

import (
	"context"
	"testing"
	"time"
)

// TestManagedBudgetEmptyProxyDoesNotCreateAmbiguousCoverage pins the
// zero-usage exception at the managed source-overlap seam. A complete empty
// proxy row is harmless alongside a billable native row from the same session;
// a source overlap with real usage remains covered by
// TestManagedBudgetAmbiguousSourcesAreWindowScoped.
func TestManagedBudgetEmptyProxyDoesNotCreateAmbiguousCoverage(t *testing.T) {
	t.Parallel()
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "empty-mixed")
	day, week, month := guardBudgetTestWindows()

	insertGuardBudgetAPI(t, database, "empty-mixed", "empty-proxy", day, 0, 0, 0)
	if _, err := database.ExecContext(context.Background(), `
		UPDATE api_turns
		   SET cache_read_tokens=0, cache_creation_tokens=0,
		       cache_creation_1h_tokens=0, web_search_requests=0
		 WHERE session_id='empty-mixed' AND model='empty-proxy'`); err != nil {
		t.Fatalf("initialize empty proxy counters: %v", err)
	}
	insertGuardBudgetUsage(t, database, "empty-mixed", "native-real", "empty-native", day, 100, 20, 0)
	if _, err := database.ExecContext(context.Background(), `
		UPDATE token_usage
		   SET cache_read_tokens=0, cache_creation_tokens=0,
		       cache_creation_1h_tokens=0, reasoning_tokens=0,
		       web_search_requests=0, reliability='approximate'
		 WHERE source_event_id='empty-native'`); err != nil {
		t.Fatalf("initialize native counters: %v", err)
	}

	price := func(model string, _ time.Time, _ PushTokenSplit) (float64, string, bool) {
		if model == "native-real" {
			return 0.25, "exact", true
		}
		return 0, "exact", true
	}
	spend, err := st.GuardBudgetSpendPriced(context.Background(), "empty-mixed", day, week, month, price, GuardBudgetReadOptions{Managed: true})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	if spend.UnpricedWindows != (GuardBudgetUnavailableWindows{}) {
		t.Fatalf("empty proxy made USD coverage unavailable: %+v", spend)
	}
	if spend.DailyUSD != 0.25 {
		t.Fatalf("daily USD = %v, want 0.25", spend.DailyUSD)
	}

	tokens, err := st.GuardBudgetTokens(context.Background(), "empty-mixed", day, week, month, GuardBudgetReadOptions{Managed: true})
	if err != nil {
		t.Fatalf("GuardBudgetTokens: %v", err)
	}
	if tokens.Unavailable != (GuardBudgetUnavailableWindows{}) {
		t.Fatalf("empty proxy made token coverage unavailable: %+v", tokens)
	}
	if tokens.DailyTokens != 120 {
		t.Fatalf("daily tokens = %d, want 120", tokens.DailyTokens)
	}
}

func TestManagedBudgetMalformedHistorySessionScope(t *testing.T) {
	t.Parallel()
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "requested")
	guardBudgetTestSession(t, st, "unrelated")
	day, week, month := guardBudgetTestWindows()
	insertGuardBudgetUsage(t, database, "unrelated", "malformed", "malformed-history", day, 100, 0, 0)
	if _, err := database.ExecContext(context.Background(), `
		UPDATE token_usage
		   SET timestamp='not-a-timestamp', cache_read_tokens=0,
		       cache_creation_tokens=0, cache_creation_1h_tokens=0,
		       reasoning_tokens=0, web_search_requests=0,
		       reliability='approximate'
		 WHERE source_event_id='malformed-history'`); err != nil {
		t.Fatalf("malform history row: %v", err)
	}

	price := func(string, time.Time, PushTokenSplit) (float64, string, bool) {
		t.Fatal("malformed history must not reach the pricer")
		return 0, "", false
	}
	for _, tc := range []struct {
		name        string
		sessionID   string
		wantSession bool
	}{
		{name: "no requested session", sessionID: "", wantSession: false},
		{name: "unrelated requested session", sessionID: "requested", wantSession: false},
		{name: "own malformed session", sessionID: "unrelated", wantSession: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spend, err := st.GuardBudgetSpendPriced(context.Background(), tc.sessionID, day, week, month, price, GuardBudgetReadOptions{Managed: true})
			if err != nil {
				t.Fatalf("GuardBudgetSpendPriced: %v", err)
			}
			want := GuardBudgetUnavailableWindows{Session: tc.wantSession, Daily: true, Weekly: true, Monthly: true}
			if spend.UnpricedWindows != want {
				t.Fatalf("USD availability = %+v, want %+v", spend.UnpricedWindows, want)
			}

			tokens, err := st.GuardBudgetTokens(context.Background(), tc.sessionID, day, week, month, GuardBudgetReadOptions{Managed: true})
			if err != nil {
				t.Fatalf("GuardBudgetTokens: %v", err)
			}
			if tokens.Unavailable != want {
				t.Fatalf("token availability = %+v, want %+v", tokens.Unavailable, want)
			}
		})
	}
}
