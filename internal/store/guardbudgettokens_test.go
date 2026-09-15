package store

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// seedTokenBudgetFixture mirrors seedBudgetFixture's SHAPE in tokens: a
// proxy-only session, a watcher-only session, a double-observed session (whose
// two substrates must count ONCE, at the larger sum), an unattributed proxy
// turn, and rows outside the day/week windows.
func seedTokenBudgetFixture(t *testing.T, s *Store, database *sql.DB) {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/token-budget-proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	for _, sid := range []string{"t-proxy", "t-watch", "t-both", "t-old", "t-month"} {
		if _, err := database.ExecContext(ctx, `
			INSERT INTO sessions (id, project_id, tool, started_at)
			VALUES (?, ?, 'claude-code', ?)`,
			sid, pid, timestamp(time.Now().UTC())); err != nil {
			t.Fatalf("seed session %s: %v", sid, err)
		}
	}
	now := time.Now().UTC()
	turn := func(sid any, ts time.Time, in, out int64) {
		if _, err := database.ExecContext(ctx, `
			INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens,
			                       cache_read_tokens, cache_creation_tokens, cost_usd)
			VALUES (?, ?, 'anthropic', 'claude-x', ?, ?, 9999, 9999, 0)`,
			sid, timestamp(ts), in, out); err != nil {
			t.Fatalf("seed api_turn: %v", err)
		}
	}
	usage := func(sid string, ts time.Time, in, out int64) {
		if _, err := database.ExecContext(ctx, `
			INSERT INTO token_usage (session_id, timestamp, tool, input_tokens, output_tokens,
			                         cache_read_tokens, cache_creation_tokens, source, reliability)
			VALUES (?, ?, 'claude-code', ?, ?, 9999, 9999, 'jsonl', 'estimated')`,
			sid, timestamp(ts), in, out); err != nil {
			t.Fatalf("seed token_usage: %v", err)
		}
	}
	turn("t-proxy", now, 100, 50)                     // proxy-only: 150
	usage("t-watch", now, 200, 0)                     // watcher-only: 200
	turn("t-both", now, 300, 0)                       // double-observed:
	usage("t-both", now, 250, 0)                      //   MAX(300, 250) = 300
	turn(nil, now, 25, 0)                             // unattributed proxy turn: 25
	turn("t-old", now.Add(-48*time.Hour), 1000, 0)    // week/month, not today
	turn("t-month", now.Add(-10*24*time.Hour), 77, 0) // month only
}

// TestGuardBudgetTokens pins the token windows against their $ sibling's
// contract, and — the part that actually matters for the org rail — pins the
// TOKEN DEFINITION: input + output, excluding cache reads and cache creation.
// The fixture writes 9,999 cache tokens on every row precisely so a query that
// counted them would be off by a mile.
func TestGuardBudgetTokens(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	seedTokenBudgetFixture(t, s, database)
	ctx := context.Background()
	now := time.Now().UTC()
	dayStart := now.Add(-24 * time.Hour)
	weekStart := now.Add(-7 * 24 * time.Hour)
	monthStart := now.Add(-30 * 24 * time.Hour)

	cases := []struct {
		name        string
		session     string
		wantSession int64
	}{
		{"proxy-only session", "t-proxy", 150},
		{"watcher-only session", "t-watch", 200},
		{"double-observed session takes the max", "t-both", 300},
		{"unknown session", "nope", 0},
		{"empty session id skips the session half", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := s.GuardBudgetTokens(ctx, tc.session, dayStart, weekStart, monthStart)
			if err != nil {
				t.Fatalf("GuardBudgetTokens: %v", err)
			}
			if tok.SessionTokens != tc.wantSession {
				t.Errorf("session tokens = %d, want %d (cache tokens must NOT be counted — the org counts input+output)",
					tok.SessionTokens, tc.wantSession)
			}
			// Daily: 150 + 200 + 300 + 25 = 675.
			if tok.DailyTokens != 675 {
				t.Errorf("daily tokens = %d, want 675", tok.DailyTokens)
			}
			// Weekly adds t-old (-48h) 1000 -> 1675.
			if tok.WeeklyTokens != 1675 {
				t.Errorf("weekly tokens = %d, want 1675", tok.WeeklyTokens)
			}
			// Monthly adds t-month (-10d) 77 -> 1752.
			if tok.MonthlyTokens != 1752 {
				t.Errorf("monthly tokens = %d, want 1752", tok.MonthlyTokens)
			}
		})
	}

	tok, err := s.GuardBudgetTokens(ctx, "t-proxy", now.Add(time.Hour), now.Add(time.Hour), now.Add(time.Hour))
	if err != nil || tok.DailyTokens != 0 || tok.WeeklyTokens != 0 || tok.MonthlyTokens != 0 {
		t.Errorf("future window = %+v, %v; want zero windows", tok, err)
	}
}

// TestManagedTokenBudgetProxyAndNativeOverlapTotalsByMaximum is the token
// sibling of TestManagedBudgetProxyAndNativeOverlapTotalsByMaximum: it pins
// the removal of the sources==3 rule here too. A session the daemon both
// proxies and parses is the ordinary shape, per-session MAX is the
// de-duplication rule, and the window stays AVAILABLE — marking it unavailable
// denied every proxied-and-parsed tool under a managed hard cap.
func TestManagedTokenBudgetProxyAndNativeOverlapTotalsByMaximum(t *testing.T) {
	t.Parallel()
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "overlap")
	day, week, month := guardBudgetTestWindows()
	at := day.Add(3 * time.Hour)
	insertManagedGuardBudgetAPI(t, database, "overlap", "proxy-model", at, 200, 20)
	insertManagedGuardBudgetUsage(t, database, "overlap", "opencode", "native-model", "overlap-native", at, 150, 10)

	tokens, err := st.GuardBudgetTokens(context.Background(), "overlap", day, week, month,
		GuardBudgetReadOptions{Managed: true})
	if err != nil {
		t.Fatalf("GuardBudgetTokens: %v", err)
	}
	if tokens.Unavailable != (GuardBudgetUnavailableWindows{}) {
		t.Fatalf("proxy/native overlap closed the token windows: %+v", tokens.Unavailable)
	}
	for name, got := range map[string]int64{
		"session": tokens.SessionTokens, "daily": tokens.DailyTokens,
		"weekly": tokens.WeeklyTokens, "monthly": tokens.MonthlyTokens,
	} {
		if got != 220 {
			t.Fatalf("%s tokens = %d, want the larger substrate counted once (220)", name, got)
		}
	}
}

// TestManagedTokenBudgetStillRejectsUnreadableRows keeps the removal above
// narrow: dropping the overlap rule must not admit a row that is genuinely
// unreadable in the unit being compared.
func TestManagedTokenBudgetStillRejectsUnreadableRows(t *testing.T) {
	t.Parallel()
	st, database := newTestStore(t)
	guardBudgetTestSession(t, st, "unreadable")
	day, week, month := guardBudgetTestWindows()
	insertManagedGuardBudgetUsage(t, database, "unreadable", "opencode", "native-model", "bad", day.Add(time.Hour), 100, 10)
	if _, err := database.ExecContext(context.Background(),
		`UPDATE token_usage SET reliability='unreliable'`); err != nil {
		t.Fatal(err)
	}
	tokens, err := st.GuardBudgetTokens(context.Background(), "unreadable", day, week, month,
		GuardBudgetReadOptions{Managed: true})
	if err != nil {
		t.Fatalf("GuardBudgetTokens: %v", err)
	}
	if !tokens.Unavailable.Daily || !tokens.Unavailable.Session {
		t.Fatalf("unreliable row admitted: %+v", tokens.Unavailable)
	}
}
