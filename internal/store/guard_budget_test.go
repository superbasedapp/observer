package store

import (
	"context"
	"database/sql"
	"math"
	"testing"
	"time"
)

// seedBudgetFixture creates a project + sessions and inserts raw
// api_turns / token_usage cost rows at the given timestamps.
func seedBudgetFixture(t *testing.T, s *Store, database *sql.DB) {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/budget-proj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	for _, sid := range []string{"s-proxy", "s-watch", "s-both", "s-old", "s-month"} {
		if _, err := database.ExecContext(ctx, `
			INSERT INTO sessions (id, project_id, tool, started_at)
			VALUES (?, ?, 'claude-code', ?)`,
			sid, pid, timestamp(time.Now().UTC())); err != nil {
			t.Fatalf("seed session %s: %v", sid, err)
		}
	}
	now := time.Now().UTC()
	turn := func(sid any, ts time.Time, cost float64) {
		if _, err := database.ExecContext(ctx, `
			INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
			VALUES (?, ?, 'anthropic', 'claude-x', 10, 10, ?)`,
			sid, timestamp(ts), cost); err != nil {
			t.Fatalf("seed api_turn: %v", err)
		}
	}
	usage := func(sid string, ts time.Time, cost float64) {
		if _, err := database.ExecContext(ctx, `
			INSERT INTO token_usage (session_id, timestamp, tool, estimated_cost_usd, source, reliability)
			VALUES (?, ?, 'claude-code', ?, 'jsonl', 'estimated')`,
			sid, timestamp(ts), cost); err != nil {
			t.Fatalf("seed token_usage: %v", err)
		}
	}
	// twin is the transcript copy of a turn() row: the same model and token
	// shape, so the one session rule (sessionmsg.Derive, via the stored
	// verdicts) counts the turn once - as its proxy row.
	twin := func(sid string, ts time.Time, cost float64) {
		if _, err := database.ExecContext(ctx, `
			INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens,
			                         estimated_cost_usd, source, reliability, source_event_id)
			VALUES (?, ?, 'claude-code', 'claude-x', 10, 10, ?, 'jsonl', 'estimated', 'tk-twin')`,
			sid, timestamp(ts.Add(2*time.Second)), cost); err != nil {
			t.Fatalf("seed token_usage twin: %v", err)
		}
	}
	turn("s-proxy", now, 1.00)
	turn("s-proxy", now, 0.50)                    // proxy-only session: $1.50
	usage("s-watch", now, 2.00)                   // watcher-only session: $2.00
	turn("s-both", now, 3.00)                     // double-observed turn: the
	twin("s-both", now, 2.50)                     //   proxy row counts, $3.00
	turn(nil, now, 0.25)                          // unattributed proxy turn: $0.25
	turn("s-old", now.Add(-48*time.Hour), 9.99)   // in week/month, outside today
	turn("s-month", now.Add(-10*24*time.Hour), 5) // in month, outside week/today
}

// TestGuardBudgetSpend pins the §12.1 spend query: a turn observed by both
// the proxy and the watcher counts once (the stored sessionmsg dedup
// verdicts), the daily total sums every counted row including unattributed
// proxy turns, and rows before dayStart don't count.
func TestGuardBudgetSpend(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	seedBudgetFixture(t, s, database)
	ctx := context.Background()
	now := time.Now().UTC()
	dayStart := now.Add(-24 * time.Hour)
	weekStart := now.Add(-7 * 24 * time.Hour)
	monthStart := now.Add(-30 * 24 * time.Hour)

	approx := func(got, want float64) bool { return math.Abs(got-want) < 1e-9 }

	cases := []struct {
		name        string
		session     string
		wantSession float64
	}{
		{"proxy-only session", "s-proxy", 1.50},
		{"watcher-only session", "s-watch", 2.00},
		{"double-observed turn counts once", "s-both", 3.00},
		{"unknown session", "nope", 0},
		{"empty session id skips the session half", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spend, err := s.GuardBudgetSpend(ctx, tc.session, dayStart, weekStart, monthStart)
			if err != nil {
				t.Fatalf("GuardBudgetSpend: %v", err)
			}
			if !approx(spend.SessionUSD, tc.wantSession) {
				t.Errorf("session spend = %.4f, want %.2f", spend.SessionUSD, tc.wantSession)
			}
			// Daily: 1.50 + 2.00 + 3.00 + 0.25 = 6.75; s-old/s-month excluded.
			if !approx(spend.DailyUSD, 6.75) {
				t.Errorf("daily spend = %.4f, want 6.75", spend.DailyUSD)
			}
			// Weekly adds s-old (-48h) 9.99 → 16.74; s-month (-10d) excluded.
			if !approx(spend.WeeklyUSD, 16.74) {
				t.Errorf("weekly spend = %.4f, want 16.74", spend.WeeklyUSD)
			}
			// Monthly adds s-month (-10d) 5.00 → 21.74.
			if !approx(spend.MonthlyUSD, 21.74) {
				t.Errorf("monthly spend = %.4f, want 21.74", spend.MonthlyUSD)
			}
		})
	}

	// A window start in the future excludes everything.
	spend, err := s.GuardBudgetSpend(ctx, "s-proxy", now.Add(time.Hour), now.Add(time.Hour), now.Add(time.Hour))
	if err != nil || spend.DailyUSD != 0 || spend.WeeklyUSD != 0 || spend.MonthlyUSD != 0 {
		t.Errorf("future window = %+v, %v; want zero windows", spend, err)
	}
}

// TestGuardBudgetObservedStats pins the G2.4 suggestion basis on the
// same fixture: per-session totals keep the MAX-of-substrates dedup
// (s-both counts once at $3.00, never $5.50), zero-cost entities are
// excluded, and the day split separates s-old's spend from today's.
func TestGuardBudgetObservedStats(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	seedBudgetFixture(t, s, database)
	ctx := context.Background()

	obs, err := s.GuardBudgetObservedStats(ctx, time.Now().UTC().Add(-7*24*time.Hour))
	if err != nil {
		t.Fatalf("GuardBudgetObservedStats: %v", err)
	}
	// Sessions with cost in the window: s-proxy 1.50, s-watch 2.00,
	// s-both 3.00, unattributed '' 0.25, s-old 9.99 → 5 samples;
	// nearest-rank p95 of 5 = the max.
	if obs.Sessions != 5 {
		t.Errorf("sessions = %d, want 5", obs.Sessions)
	}
	if math.Abs(obs.SessionMaxUSD-9.99) > 1e-9 || math.Abs(obs.SessionP95USD-9.99) > 1e-9 {
		t.Errorf("session p95/max = %.4f/%.4f, want 9.99/9.99", obs.SessionP95USD, obs.SessionMaxUSD)
	}
	// Days: today = 1.50+2.00+3.00+0.25 = 6.75; two days ago = 9.99.
	if obs.Days != 2 {
		t.Errorf("days = %d, want 2", obs.Days)
	}
	if math.Abs(obs.DailyMaxUSD-9.99) > 1e-9 {
		t.Errorf("daily max = %.4f, want 9.99", obs.DailyMaxUSD)
	}

	// A window starting after every row → empty distributions, no error.
	obs, err = s.GuardBudgetObservedStats(ctx, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("empty window: %v", err)
	}
	if obs.Sessions != 0 || obs.Days != 0 || obs.SessionP95USD != 0 || obs.DailyP95USD != 0 {
		t.Errorf("empty window stats = %+v, want zeros", obs)
	}
}
