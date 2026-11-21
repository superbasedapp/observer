package predict

import (
	"testing"
	"time"
)

func utc(y int, m time.Month, d, h, min int) time.Time {
	return time.Date(y, m, d, h, min, 0, 0, time.UTC)
}

// TestCalendarBounds is the calendar period table at its edges: a period is
// placed on the cap's own calendar (local midnight, the first of the local
// month), never on UTC's, and a daylight-saving day is as long as the local
// clock says.
func TestCalendarBounds(t *testing.T) {
	cases := []struct {
		name, window, tz string
		now              time.Time
		key              string
		start, reset     time.Time
		honoured         bool
	}{
		{"utc day", "daily", "", utc(2026, 11, 10, 12, 0), "2026-11-10", utc(2026, 11, 10, 0, 0), utc(2026, 11, 11, 0, 0), true},
		{"literal UTC", "monthly", "UTC", utc(2026, 11, 10, 12, 0), "2026-11", utc(2026, 11, 1, 0, 0), utc(2026, 12, 1, 0, 0), true},
		// 06:00Z is 22:00 the previous day in Los Angeles (PST, UTC-8).
		{"day edge west of UTC", "daily", "America/Los_Angeles", utc(2026, 11, 11, 6, 0), "2026-11-10", utc(2026, 11, 10, 8, 0), utc(2026, 11, 11, 8, 0), true},
		// One minute later than local midnight is the new local day.
		{"just past local midnight", "daily", "America/Los_Angeles", utc(2026, 11, 11, 8, 1), "2026-11-11", utc(2026, 11, 11, 8, 0), utc(2026, 11, 12, 8, 0), true},
		// 20:00Z on Nov 30 is 01:30 on Dec 1 in Kolkata (UTC+5:30).
		{"month edge east of UTC", "monthly", "Asia/Kolkata", utc(2026, 11, 30, 20, 0), "2026-12", utc(2026, 11, 30, 18, 30), utc(2026, 12, 31, 18, 30), true},
		{"last hour of the local month", "monthly", "Asia/Kolkata", utc(2026, 11, 30, 18, 0), "2026-11", utc(2026, 10, 31, 18, 30), utc(2026, 11, 30, 18, 30), true},
		// New York springs forward on 2026-03-08: a 23-hour day.
		{"dst spring day is 23h", "daily", "America/New_York", utc(2026, 3, 8, 12, 0), "2026-03-08", utc(2026, 3, 8, 5, 0), utc(2026, 3, 9, 4, 0), true},
		// And falls back on 2026-11-01: a 25-hour day.
		{"dst fall day is 25h", "daily", "America/New_York", utc(2026, 11, 1, 12, 0), "2026-11-01", utc(2026, 11, 1, 4, 0), utc(2026, 11, 2, 5, 0), true},
		// A month that crosses the change starts in EST and resets in EDT.
		{"month across dst", "monthly", "America/New_York", utc(2026, 3, 20, 12, 0), "2026-03", utc(2026, 3, 1, 5, 0), utc(2026, 4, 1, 4, 0), true},
		{"unloadable zone falls back to utc", "daily", "Not/AZone", utc(2026, 11, 11, 6, 0), "2026-11-11", utc(2026, 11, 11, 0, 0), utc(2026, 11, 12, 0, 0), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cp, ok := CalendarBounds(c.window, c.tz, c.now)
			if !ok {
				t.Fatal("not ok")
			}
			if cp.Key != c.key || !cp.Start.Equal(c.start) || !cp.Reset.Equal(c.reset) || cp.ZoneHonoured != c.honoured {
				t.Fatalf("got key %q start %s reset %s honoured %v", cp.Key, cp.Start, cp.Reset, cp.ZoneHonoured)
			}
			if cp.Start.Location() != time.UTC || cp.Reset.Location() != time.UTC {
				t.Errorf("bounds must be UTC instants")
			}
		})
	}
	if _, ok := CalendarBounds("weekly", "UTC", projNow); ok {
		t.Error("weekly is a rolling window, not a calendar period")
	}
}

// TestProjectBudgetCap is the org Budgets page's projection: the budget's
// own numbers only, nothing that needs node-local usage.
func TestProjectBudgetCap(t *testing.T) {
	la, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Skip("no tzdata")
	}
	monthStart := time.Date(2026, 11, 1, 0, 0, 0, 0, la).UTC()
	monthReset := time.Date(2026, 12, 1, 0, 0, 0, 0, la).UTC()
	cases := []struct {
		name  string
		now   time.Time
		w     BudgetWindow
		check func(t *testing.T, p Projection)
	}{
		{
			name: "monthly dollars in a local calendar run out before the reset",
			now:  monthStart.Add(10 * 24 * time.Hour),
			w:    BudgetWindow{Key: "monthly", Origin: "org", Unit: "usd", Cap: 300, Spent: 150, Start: monthStart, Reset: monthReset, Enforcement: "hard"},
			check: func(t *testing.T, p Projection) {
				if p.State != StateLive || !near(*p.UsedFrac, 0.5) || p.LeftUSD == nil || *p.LeftUSD != 150 || p.LeftUSDIsEstimate {
					t.Fatalf("%+v", p)
				}
				if p.LeftTokens != nil {
					t.Errorf("no captured usage: nothing converted to tokens, got %v", *p.LeftTokens)
				}
				// $150 in 10 days: $15/day, $150 left lasts 10 more days, before the 20 days to the reset.
				if p.Burn == nil || !near(p.Burn.USDPerDay, 15) || p.Burn.TokensPerDay != 0 {
					t.Fatalf("burn %+v", p.Burn)
				}
				if p.RunOut == nil || p.RunOut.RunsOutAtUnix == nil || !nearDur(time.Unix(*p.RunOut.RunsOutAtUnix, 0).Sub(monthStart), 20*24*time.Hour) {
					t.Fatalf("run out %+v", p.RunOut)
				}
				if p.Pace == nil || p.Pace.Verdict != "ahead" {
					t.Errorf("pace %+v", p.Pace)
				}
				if p.RunOut.SafePerDayUSD == nil || *p.RunOut.SafePerDayUSD <= 0 || p.RunOut.SafePerDayTokens != nil {
					t.Errorf("safe allowance in the cap's unit only: %+v", p.RunOut)
				}
				if p.ResetsAtUnix == nil || *p.ResetsAtUnix != monthReset.Unix() {
					t.Errorf("resets at %v, want local month end", p.ResetsAtUnix)
				}
				if p.Sessions != nil || p.Mix != nil || p.Trend != nil || p.MorePrompts != nil || p.Confidence != "" || len(p.TopModels) != 0 {
					t.Errorf("usage-derived figures must be absent: %+v", p)
				}
			},
		},
		{
			name: "tokens cap lasts the period",
			now:  monthStart.Add(20 * 24 * time.Hour),
			w:    BudgetWindow{Key: "monthly", Origin: "org", Unit: "tokens", Cap: 1_000_000, Spent: 200_000, Start: monthStart, Reset: monthReset},
			check: func(t *testing.T, p Projection) {
				if p.LeftTokens == nil || *p.LeftTokens != 800_000 || p.LeftUSD != nil {
					t.Fatalf("left %v %v", p.LeftTokens, p.LeftUSD)
				}
				if p.Burn == nil || !near(p.Burn.TokensPerDay, 10_000) || p.Burn.USDPerDay != 0 {
					t.Fatalf("burn %+v", p.Burn)
				}
				if p.RunOut == nil || !p.RunOut.LastsUntilReset || p.RunOut.ProjectedLeftAtResetFrac == nil {
					t.Fatalf("run out %+v", p.RunOut)
				}
				if p.Pace == nil || p.Pace.Verdict != "behind" {
					t.Errorf("pace %+v", p.Pace)
				}
			},
		},
		{
			name: "rolling 30 days: steady allowance, no reset",
			now:  projNow,
			w:    BudgetWindow{Key: "rolling_30d", Origin: "org", Unit: "usd", Cap: 300, Spent: 100, Start: projNow.Add(-30 * 24 * time.Hour), Rolling: true, Length: 30 * 24 * time.Hour},
			check: func(t *testing.T, p Projection) {
				if p.State != StateRolling || p.ResetsAtUnix != nil || p.Pace != nil {
					t.Fatalf("%+v", p)
				}
				if p.RunOut == nil || p.RunOut.SafePerDayUSD == nil || *p.RunOut.SafePerDayUSD != 10 || p.RunOut.RunsOutAtUnix != nil {
					t.Fatalf("run out %+v", p.RunOut)
				}
			},
		},
		{
			name: "exceeded",
			now:  monthStart.Add(5 * 24 * time.Hour),
			w:    BudgetWindow{Key: "monthly", Unit: "usd", Cap: 100, Spent: 120, Start: monthStart, Reset: monthReset},
			check: func(t *testing.T, p Projection) {
				if p.RunOut == nil || !p.RunOut.Exhausted || !hasNote(p, NoteExhausted) || *p.LeftUSD != 0 {
					t.Fatalf("%+v", p.RunOut)
				}
			},
		},
		{
			name: "nothing spent yet: no rate",
			now:  monthStart.Add(5 * 24 * time.Hour),
			w:    BudgetWindow{Key: "monthly", Unit: "usd", Cap: 100, Spent: 0, Start: monthStart, Reset: monthReset},
			check: func(t *testing.T, p Projection) {
				if p.Burn != nil || p.RunOut != nil || !hasNote(p, NoteNotEnoughData) {
					t.Fatalf("%+v", p)
				}
			},
		},
		{
			name: "zone could not be loaded: the note says so",
			now:  monthStart.Add(5 * 24 * time.Hour),
			w:    BudgetWindow{Key: "daily", Unit: "usd", Cap: 10, Spent: 1, Start: monthStart, Reset: monthStart.Add(24 * time.Hour), TimezoneAssumed: true},
			check: func(t *testing.T, p Projection) {
				if !hasNote(p, NoteTimezoneAssumed) {
					t.Fatalf("notes %v", p.Notes)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.check(t, ProjectBudgetCap(c.now, c.w)) })
	}
}

// TestProjectBudgetSharesTheCapCore pins the one-derivation rule: the node's
// projection agrees with the org's on every figure the budget's own numbers
// decide.
func TestProjectBudgetSharesTheCapCore(t *testing.T) {
	dayStart := projNow.Truncate(24 * time.Hour)
	w := BudgetWindow{Key: "daily", Origin: "org", Unit: "usd", Cap: 60, Spent: 40, Start: dayStart, Reset: dayStart.Add(24 * time.Hour)}
	node := ProjectBudget(BudgetInput{Now: projNow, Window: w, Rows: weekRows(), Message: msg})
	org := ProjectBudgetCap(projNow, w)
	if *node.UsedFrac != *org.UsedFrac || *node.LeftUSD != *org.LeftUSD || node.Burn.FracPerHour != org.Burn.FracPerHour {
		t.Fatalf("node %+v org %+v", node, org)
	}
	if *node.RunOut.RunsOutAtUnix != *org.RunOut.RunsOutAtUnix || node.Pace.Verdict != org.Pace.Verdict || *node.ResetsAtUnix != *org.ResetsAtUnix {
		t.Fatalf("run out node %+v org %+v", node.RunOut, org.RunOut)
	}
}
