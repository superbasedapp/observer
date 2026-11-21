package dashboard

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// midMonthTestNow is the instant the month-to-date tests pin the server
// clock to when they are not about a boundary: far from both month
// edges, so fixtures a few hours either side of it stay in one month.
var midMonthTestNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// pinServerClock points the server's clock seam (s.now) at a fixed
// instant and returns it, so a test builds its fixtures from the same
// instant the handler under test reads. Fixtures derived from the wall
// clock while the handler also reads the wall clock disagree on "this
// month" in the first hours of the 1st (FU-231: five budget/report tests
// failed on the v1.37.0 tag run at 2026-11-01 00:36 UTC).
func pinServerClock(s *Server, at time.Time) time.Time {
	at = at.UTC()
	s.now = func() time.Time { return at }
	return at
}

// monthBoundaryCases are the clock instants the month-to-date surfaces
// (budget banner, analysis headline MTD tile, monthly statement default
// month) must agree on: the first and last hour of a month, December to
// January, and both February lengths.
var monthBoundaryCases = []struct {
	name        string
	now         time.Time
	month       string
	daysElapsed int
	daysInMonth int
}{
	{"first hour of a month", time.Date(2026, 11, 1, 0, 30, 0, 0, time.UTC), "2026-11", 1, 30},
	{"last hour of a month", time.Date(2026, 10, 31, 23, 30, 0, 0, time.UTC), "2026-10", 31, 31},
	{"last hour of December", time.Date(2026, 12, 31, 23, 30, 0, 0, time.UTC), "2026-12", 31, 31},
	{"first hour of January", time.Date(2027, 1, 1, 0, 30, 0, 0, time.UTC), "2027-01", 1, 31},
	{"last hour of a 28-day February", time.Date(2027, 2, 28, 23, 30, 0, 0, time.UTC), "2027-02", 28, 28},
	{"first hour of March after a 28-day February", time.Date(2027, 3, 1, 0, 30, 0, 0, time.UTC), "2027-03", 1, 31},
	{"last hour of a 29-day February", time.Date(2028, 2, 29, 23, 30, 0, 0, time.UTC), "2028-02", 29, 29},
	{"first hour of March after a 29-day February", time.Date(2028, 3, 1, 0, 30, 0, 0, time.UTC), "2028-03", 1, 31},
}

// seedMonthBoundaryTurns seeds one session in /live-p with recorded-cost
// api_turns around the month that contains now. Inside the month: its
// first instant ($1) and one minute before now ($2). Outside: one second
// before the month ($50, prior month). withMonthTail adds the month's
// last second ($4, inside) and the next month's first instant ($100,
// outside), which only the explicit-month statement can see without
// reading the future. Timestamps are whole seconds on purpose: the
// spend loaders compare RFC3339Nano TEXT, under which a stamp with a
// fraction in the first second of a month (00:00:00.5Z) sorts before
// the 00:00:00Z bound. That is a known, separate follow-up, not what
// these cases pin.
func seedMonthBoundaryTurns(t *testing.T, server *Server, now time.Time, withMonthTail bool) {
	t.Helper()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	nextMonth := monthStart.AddDate(0, 1, 0)
	seedLiveSession(t, server, "mb", "claude-code", monthStart.Add(-48*time.Hour), now.Add(-time.Minute), 1)
	turn := func(ts time.Time, usd float64) {
		t.Helper()
		if _, err := server.opts.DB.Exec(
			`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
			 VALUES ('mb', ?, 'anthropic', 'claude-opus-4-8', 100, 10, ?)`,
			ts.UTC().Format(time.RFC3339Nano), usd,
		); err != nil {
			t.Fatal(err)
		}
	}
	turn(monthStart, 1)
	turn(now.Add(-time.Minute), 2)
	turn(monthStart.Add(-time.Second), 50)
	if withMonthTail {
		turn(nextMonth.Add(-time.Second), 4)
		turn(nextMonth, 100)
	}
}

// TestHandleBudget_MonthBoundaries pins /api/budget's month window at
// every boundary in monthBoundaryCases: the month label, days elapsed,
// days in month, and a month-to-date total that includes the month's
// first instant and excludes the prior month's last second.
func TestHandleBudget_MonthBoundaries(t *testing.T) {
	for _, tc := range monthBoundaryCases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := wizardTestServer(t)
			now := pinServerClock(server, tc.now)
			seedMonthBoundaryTurns(t, server, now, false)
			writeBudgetConfig(t, server, 100, map[string]float64{"/live-p": 10})

			rr := httptest.NewRecorder()
			server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/budget", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
			}
			var got struct {
				Month       string `json:"month"`
				DaysElapsed int    `json:"days_elapsed"`
				DaysInMonth int    `json:"days_in_month"`
				Global      *struct {
					MTDUSD      float64 `json:"mtd_usd"`
					ForecastUSD float64 `json:"forecast_usd"`
				} `json:"global"`
				Projects []struct {
					Root   string  `json:"root"`
					MTDUSD float64 `json:"mtd_usd"`
				} `json:"projects"`
			}
			if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.Month != tc.month || got.DaysElapsed != tc.daysElapsed || got.DaysInMonth != tc.daysInMonth {
				t.Errorf("month/days: got %s %d/%d want %s %d/%d",
					got.Month, got.DaysElapsed, got.DaysInMonth, tc.month, tc.daysElapsed, tc.daysInMonth)
			}
			if got.Global == nil {
				t.Fatalf("no global scope: %s", rr.Body.String())
			}
			if math.Abs(got.Global.MTDUSD-3) > 1e-9 {
				t.Errorf("global mtd: got %v want 3 (month start $1 + now-1m $2, prior month $50 excluded)", got.Global.MTDUSD)
			}
			wantForecast := 3 * float64(tc.daysInMonth) / float64(tc.daysElapsed)
			if math.Abs(got.Global.ForecastUSD-wantForecast) > 1e-9 {
				t.Errorf("forecast: got %v want %v", got.Global.ForecastUSD, wantForecast)
			}
			if len(got.Projects) != 1 || got.Projects[0].Root != "/live-p" || math.Abs(got.Projects[0].MTDUSD-3) > 1e-9 {
				t.Errorf("projects: got %+v want /live-p at 3", got.Projects)
			}
		})
	}
}

// TestAnalysisHeadline_MonthBoundaries pins the analysis headline's MTD
// tile at every boundary in monthBoundaryCases: the same $3 the budget
// banner reports, the same days, and the budget percentage over it.
func TestAnalysisHeadline_MonthBoundaries(t *testing.T) {
	for _, tc := range monthBoundaryCases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := wizardTestServer(t)
			now := pinServerClock(server, tc.now)
			seedMonthBoundaryTurns(t, server, now, false)
			writeBudgetConfig(t, server, 100, nil)

			got := openHeadline(t, server, 30)
			if math.Abs(got.Month.ToDateUSD-3) > 1e-9 {
				t.Errorf("to_date_usd: got %v want 3 (month start $1 + now-1m $2, prior month $50 excluded)", got.Month.ToDateUSD)
			}
			if math.Abs(got.Month.BudgetPct-3) > 1e-9 {
				t.Errorf("budget_pct: got %v want 3", got.Month.BudgetPct)
			}
			if got.Month.DaysElapsed != tc.daysElapsed || got.Month.DaysInMonth != tc.daysInMonth {
				t.Errorf("days: got %d/%d want %d/%d",
					got.Month.DaysElapsed, got.Month.DaysInMonth, tc.daysElapsed, tc.daysInMonth)
			}
		})
	}
}

// TestReportMonthly_MonthBoundaries pins the monthly statement's window
// at every boundary in monthBoundaryCases, for both the explicit
// ?month= and the default month (read from the server clock): the
// month's first instant and last second are in, the prior month's last
// second and the next month's first instant are out.
func TestReportMonthly_MonthBoundaries(t *testing.T) {
	for _, tc := range monthBoundaryCases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := wizardTestServer(t)
			now := pinServerClock(server, tc.now)
			seedMonthBoundaryTurns(t, server, now, true)

			for _, url := range []string{"/api/report/monthly?month=" + tc.month, "/api/report/monthly"} {
				rr := httptest.NewRecorder()
				server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, url, nil))
				if rr.Code != http.StatusOK {
					t.Fatalf("%s: status %d body=%s", url, rr.Code, rr.Body.String())
				}
				var got struct {
					Month  string `json:"month"`
					Totals struct {
						CostUSD float64 `json:"cost_usd"`
						Turns   int64   `json:"turns"`
					} `json:"totals"`
				}
				if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
					t.Fatal(err)
				}
				if got.Month != tc.month {
					t.Errorf("%s: month got %q want %q", url, got.Month, tc.month)
				}
				if math.Abs(got.Totals.CostUSD-7) > 1e-9 || got.Totals.Turns != 3 {
					t.Errorf("%s: totals got $%v over %d turns want $7 over 3 (first instant $1 + now-1m $2 + last second $4)",
						url, got.Totals.CostUSD, got.Totals.Turns)
				}
			}
		})
	}
}
