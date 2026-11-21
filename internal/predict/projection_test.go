package predict

import (
	"math"
	"testing"
	"time"
)

var projNow = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func fp(v float64) *float64 { return &v }

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func nearDur(a, b time.Duration) bool { return (a - b).Abs() <= time.Second }

// weekRows is 4M counted tokens and $40 over two sessions, "this" holding a
// quarter of the dollars.
func weekRows() []UsageRow {
	return []UsageRow{
		{SessionID: "this", Model: "opus", Project: "/src/a", Input: 100_000, CacheRead: 800_000, Output: 100_000, CostUSD: 10, Turns: 20},
		{SessionID: "other", Model: "sonnet", Project: "/src/b", Input: 300_000, CacheRead: 2_400_000, CacheWrite: 200_000, Output: 100_000, CostUSD: 30, Turns: 40},
	}
}

func band(usd, all, fresh float64) MessageBand {
	return MessageBand{USD: usd, AllTokens: all, NewTokens: fresh}
}

var msg = MessageCost{Has: true, Priced: true, Low: band(0.5, 50_000, 5_000), Mid: band(1, 100_000, 10_000), High: band(2, 200_000, 20_000)}

func hasNote(p Projection, n ProjectionNote) bool {
	for _, have := range p.Notes {
		if have == n {
			return true
		}
	}
	return false
}

// TestProjectLimit is the limit-window table: one row per honesty rule.
func TestProjectLimit(t *testing.T) {
	week := 7 * 24 * time.Hour
	cases := []struct {
		name  string
		in    LimitInput
		check func(t *testing.T, p Projection)
	}{
		{
			name: "normal burn lasts until reset",
			in: LimitInput{
				Now: projNow, SessionID: "this", Window: weekRows(), Message: msg,
				Reading: LimitReading{Key: "weekly", UsedFrac: fp(0.4), ResetsAt: projNow.Add(4 * 24 * time.Hour), ObservedAt: projNow, Source: "proxy"},
			},
			check: func(t *testing.T, p Projection) {
				if p.State != StateLive {
					t.Fatalf("state %q", p.State)
				}
				if p.CapacityTokensEst == nil || *p.CapacityTokensEst != 10_000_000 {
					t.Errorf("capacity tokens %v, want 10M (4M / 0.4)", p.CapacityTokensEst)
				}
				if p.CapacityUSDEst == nil || !near(*p.CapacityUSDEst, 100) {
					t.Errorf("capacity usd %v, want 100", p.CapacityUSDEst)
				}
				if p.LeftUSD == nil || !near(*p.LeftUSD, 60) || !p.LeftUSDIsEstimate {
					t.Errorf("left usd %v est=%v", p.LeftUSD, p.LeftUSDIsEstimate)
				}
				if p.Burn == nil || !near(p.Burn.FracPerDay, 0.4/3) {
					t.Fatalf("burn %+v, want 0.1333/day", p.Burn)
				}
				if p.RunOut == nil || !p.RunOut.LastsUntilReset || p.RunOut.RunsOutAtUnix != nil {
					t.Fatalf("run out %+v, want lasts until reset", p.RunOut)
				}
				if want := 1 - (0.4 + 0.4/72*96); !near(*p.RunOut.ProjectedLeftAtResetFrac, want) {
					t.Errorf("left at reset %v, want %v", *p.RunOut.ProjectedLeftAtResetFrac, want)
				}
				if !near(*p.RunOut.SafePerDayFrac, 0.15) || !near(*p.RunOut.SafePerDayUSD, 15) {
					t.Errorf("safe per day %v / $%v, want 0.15 / $15", *p.RunOut.SafePerDayFrac, *p.RunOut.SafePerDayUSD)
				}
				if p.Pace == nil || p.Pace.Verdict != "on_pace" {
					t.Errorf("pace %+v, want on_pace (40%% used at 43%% elapsed is inside the band)", p.Pace)
				}
				if p.Sessions == nil || p.Sessions.Count != 2 || !near(*p.Sessions.ThisShare, 0.25) || !near(p.Sessions.AvgUSD, 20) {
					t.Errorf("sessions %+v", p.Sessions)
				}
				if p.MoreSessionsEst == nil || !near(*p.MoreSessionsEst, 3) {
					t.Errorf("more sessions %v, want 3 ($60 / $20)", p.MoreSessionsEst)
				}
				if p.MorePrompts == nil || p.MorePrompts.Basis != "usd" || p.MorePrompts.Mid != 60 || p.MorePrompts.Low != 30 || p.MorePrompts.High != 120 {
					t.Errorf("more prompts %+v", p.MorePrompts)
				}
				if p.FiveHourWindowsLeft == nil || *p.FiveHourWindowsLeft != 19 {
					t.Errorf("5h windows left %v, want 19 (96h / 5)", p.FiveHourWindowsLeft)
				}
				if len(p.TopModels) != 2 || p.TopModels[0].Name != "sonnet" || !near(p.TopModels[0].Share, 0.75) {
					t.Errorf("top models %+v", p.TopModels)
				}
				if p.Mix == nil || !near(p.Mix.CacheRead, 0.8) {
					t.Errorf("mix %+v, want 80%% cache reads", p.Mix)
				}
				if !hasNote(p, NoteLocalOnly) || p.Confidence != "high" {
					t.Errorf("notes %v confidence %q", p.Notes, p.Confidence)
				}
			},
		},
		{
			name: "runs out before reset",
			in: LimitInput{
				Now: projNow, Window: weekRows(),
				Reading: LimitReading{Key: "weekly", UsedFrac: fp(0.6), ResetsAt: projNow.Add(4 * 24 * time.Hour), ObservedAt: projNow},
			},
			check: func(t *testing.T, p Projection) {
				if p.RunOut == nil || p.RunOut.RunsOutAtUnix == nil || p.RunOut.LastsUntilReset {
					t.Fatalf("run out %+v, want a run-out time", p.RunOut)
				}
				if got := time.Unix(*p.RunOut.RunsOutAtUnix, 0).Sub(projNow); !nearDur(got, 48*time.Hour) {
					t.Errorf("runs out in %v, want 48h (0.4 left at 0.2/day)", got)
				}
				if p.Pace.Verdict != "ahead" {
					t.Errorf("pace %q, want ahead", p.Pace.Verdict)
				}
			},
		},
		{
			name: "weekly reading 22 days old: window reset, current window inferred, no percent",
			in: LimitInput{
				Now: projNow, Window: weekRows(),
				Reading: LimitReading{Key: "weekly", UsedFrac: fp(0.01), ResetsAt: projNow.Add(-22 * 24 * time.Hour), ObservedAt: projNow.Add(-23 * 24 * time.Hour)},
			},
			check: func(t *testing.T, p Projection) {
				if p.State != StateResetInferred || !p.WindowInferred {
					t.Fatalf("state %q inferred=%v", p.State, p.WindowInferred)
				}
				if p.UsedFrac != nil || p.LeftFrac != nil || p.CapacityTokensEst != nil || p.RunOut != nil {
					t.Errorf("a reset reading must not be projected from: %+v", p)
				}
				start := time.Unix(*p.WindowStartUnix, 0)
				if want := projNow.Add(-22 * 24 * time.Hour).Add(3 * week); !start.Equal(want) {
					t.Errorf("inferred start %v, want %v", start, want)
				}
				if !hasNote(p, NoteWindowReset) || !hasNote(p, NoteWindowInferred) || !hasNote(p, NoteReadingStale) {
					t.Errorf("notes %v", p.Notes)
				}
				if p.Used.Tokens != 4_000_000 || p.Burn == nil || p.Burn.FracPerHour != 0 {
					t.Errorf("usage %+v burn %+v: tokens and dollars only", p.Used, p.Burn)
				}
			},
		},
		{
			name: "5-hour reading reset: nothing projected",
			in: LimitInput{
				Now: projNow, Window: weekRows(),
				Reading: LimitReading{Key: "5h", UsedFrac: fp(0.5), ResetsAt: projNow.Add(-time.Hour), ObservedAt: projNow.Add(-2 * time.Hour)},
			},
			check: func(t *testing.T, p Projection) {
				if p.State != StateReset || p.Burn != nil || p.WindowStartUnix != nil || p.Used.Tokens != 0 {
					t.Fatalf("%+v", p)
				}
				if !hasNote(p, NoteWindowReset) {
					t.Errorf("notes %v", p.Notes)
				}
			},
		},
		{
			name: "zero used: not enough data",
			in: LimitInput{
				Now: projNow, Window: weekRows(),
				Reading: LimitReading{Key: "weekly", UsedFrac: fp(0), ResetsAt: projNow.Add(4 * 24 * time.Hour), ObservedAt: projNow},
			},
			check: func(t *testing.T, p Projection) {
				if p.Burn != nil || p.RunOut != nil || p.CapacityTokensEst != nil || !hasNote(p, NoteNotEnoughData) {
					t.Fatalf("%+v", p)
				}
				if p.LeftFrac == nil || *p.LeftFrac != 1 {
					t.Errorf("left %v, want 1", p.LeftFrac)
				}
			},
		},
		{
			name: "under an hour into the window: not enough data",
			in: LimitInput{
				Now: projNow, Window: weekRows(),
				Reading: LimitReading{Key: "5h", UsedFrac: fp(0.1), ResetsAt: projNow.Add(5*time.Hour - 30*time.Minute), ObservedAt: projNow},
			},
			check: func(t *testing.T, p Projection) {
				if p.Burn != nil || p.RunOut != nil || !hasNote(p, NoteNotEnoughData) || p.Confidence != "" {
					t.Fatalf("%+v", p)
				}
				if p.CapacityTokensEst == nil {
					t.Errorf("capacity is still estimable from the share used")
				}
			},
		},
		{
			name: "small share: capacity not estimated",
			in: LimitInput{
				Now: projNow, Window: weekRows(),
				Reading: LimitReading{Key: "weekly", UsedFrac: fp(0.005), ResetsAt: projNow.Add(4 * 24 * time.Hour), ObservedAt: projNow},
			},
			check: func(t *testing.T, p Projection) {
				if p.CapacityTokensEst != nil || p.LeftTokens != nil || !hasNote(p, NoteCapacityTooSmall) {
					t.Fatalf("%+v", p)
				}
			},
		},
		{
			name: "older reading carried forward with usage since",
			in: LimitInput{
				Now: projNow, Window: weekRows(),
				SinceReading: []UsageRow{{SessionID: "this", Input: 1_000_000, CostUSD: 10}},
				Reading:      LimitReading{Key: "weekly", UsedFrac: fp(0.3), ResetsAt: projNow.Add(4 * 24 * time.Hour), ObservedAt: projNow.Add(-2 * time.Hour)},
			},
			check: func(t *testing.T, p Projection) {
				// 3M tokens at the reading = 30% -> capacity 10M; +1M since -> 40%.
				if !p.UsedFracIsEstimate || p.UsedFracEst == nil || !near(*p.UsedFracEst, 0.4) {
					t.Fatalf("used est %v", p.UsedFracEst)
				}
				if *p.UsedFrac != 0.3 || !hasNote(p, NoteCarriedForward) || p.Confidence != "medium" {
					t.Errorf("reading %v notes %v confidence %q", *p.UsedFrac, p.Notes, p.Confidence)
				}
			},
		},
		{
			name: "previous window trend",
			in: LimitInput{
				Now: projNow, Window: weekRows(),
				Previous: []UsageRow{{SessionID: "x", Input: 7_000_000, CostUSD: 70}},
				Reading:  LimitReading{Key: "weekly", UsedFrac: fp(0.4), ResetsAt: projNow.Add(4 * 24 * time.Hour), ObservedAt: projNow},
			},
			check: func(t *testing.T, p Projection) {
				// This week 4M in 72h; last week 7M in 168h.
				want := (4e6/72)/(7e6/168) - 1
				if p.Trend == nil || p.Trend.RateChange == nil || !near(*p.Trend.RateChange, want) || p.Trend.PrevSessions != 1 {
					t.Fatalf("trend %+v, want rate change %v", p.Trend, want)
				}
			},
		},
		{
			name: "no reset time: reading echoed only",
			in: LimitInput{
				Now: projNow, Window: weekRows(),
				Reading: LimitReading{Key: "weekly", UsedFrac: fp(0.4), ObservedAt: projNow},
			},
			check: func(t *testing.T, p Projection) {
				if p.State != StateNoResetTime || p.Burn != nil || p.Used.Tokens != 0 {
					t.Fatalf("%+v", p)
				}
			},
		},
		{
			name: "exhausted",
			in: LimitInput{
				Now: projNow, Window: weekRows(),
				Reading: LimitReading{Key: "5h", UsedFrac: fp(1), ResetsAt: projNow.Add(time.Hour), ObservedAt: projNow},
			},
			check: func(t *testing.T, p Projection) {
				if p.RunOut == nil || !p.RunOut.Exhausted || !hasNote(p, NoteExhausted) || *p.LeftFrac != 0 {
					t.Fatalf("%+v", p.RunOut)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.check(t, ProjectLimit(c.in)) })
	}
}

// TestProjectBudget is the budget table.
func TestProjectBudget(t *testing.T) {
	dayStart := projNow.Truncate(24 * time.Hour)
	cases := []struct {
		name  string
		in    BudgetInput
		check func(t *testing.T, p Projection)
	}{
		{
			name: "daily dollar budget runs out before midnight",
			in: BudgetInput{
				Now: projNow, SessionID: "this", Rows: weekRows(), Message: msg,
				Window: BudgetWindow{Key: "daily", Origin: "node", Unit: "usd", Cap: 60, Spent: 40, Start: dayStart, Reset: dayStart.Add(24 * time.Hour)},
			},
			check: func(t *testing.T, p Projection) {
				if p.State != StateLive || !near(*p.UsedFrac, 40.0/60) || p.UsedFracIsEstimate {
					t.Fatalf("%+v", p)
				}
				if p.LeftUSD == nil || *p.LeftUSD != 20 || p.LeftUSDIsEstimate {
					t.Errorf("left usd %v (exact in the cap's unit)", p.LeftUSD)
				}
				// Captured in/out tokens: 400k in + 200k out = 600k for $40.
				if p.Used.Tokens != 600_000 || p.LeftTokens == nil || *p.LeftTokens != 300_000 || !p.LeftTokensIsEstimate {
					t.Errorf("used %d left tokens %v", p.Used.Tokens, p.LeftTokens)
				}
				// $40 in 12h -> $20 left lasts 6h, before the 12h to midnight.
				if p.RunOut == nil || p.RunOut.RunsOutAtUnix == nil || !nearDur(time.Unix(*p.RunOut.RunsOutAtUnix, 0).Sub(projNow), 6*time.Hour) {
					t.Fatalf("run out %+v", p.RunOut)
				}
				if p.MorePrompts == nil || p.MorePrompts.Mid != 20 {
					t.Errorf("prompts %+v, want 20 ($20 / $1)", p.MorePrompts)
				}
			},
		},
		{
			name: "token-only budget reads in tokens",
			in: BudgetInput{
				Now: projNow, Rows: weekRows(), Message: msg,
				Window: BudgetWindow{
					Key: "monthly", Origin: "org", Unit: "tokens", Cap: 1_000_000, Spent: 250_000, Scope: "team:x", Enforcement: "hard",
					Start: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Reset: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), TimezoneAssumed: true, OtherMachines: true,
				},
			},
			check: func(t *testing.T, p Projection) {
				if p.LeftTokens == nil || *p.LeftTokens != 750_000 || p.LeftTokensIsEstimate {
					t.Fatalf("left tokens %v", p.LeftTokens)
				}
				if p.LeftUSD == nil || !p.LeftUSDIsEstimate {
					t.Errorf("left usd %v should be an estimate", p.LeftUSD)
				}
				if p.MorePrompts == nil || p.MorePrompts.Basis != "usd" {
					t.Errorf("prompts %+v", p.MorePrompts)
				}
				if !hasNote(p, NoteTimezoneAssumed) || !hasNote(p, NoteOtherMachines) || p.TokenDef != TokensInputOutput {
					t.Errorf("notes %v def %q", p.Notes, p.TokenDef)
				}
				if p.RunOut == nil || !p.RunOut.LastsUntilReset {
					t.Errorf("run out %+v, want lasts the period", p.RunOut)
				}
			},
		},
		{
			name: "token budget with unpriced usage counts prompts in new tokens",
			in: BudgetInput{
				Now: projNow, Rows: []UsageRow{{SessionID: "a", Input: 100, Output: 100}}, Message: MessageCost{Has: true, Low: band(0, 0, 50), Mid: band(0, 0, 100), High: band(0, 0, 200)},
				Window: BudgetWindow{Key: "daily", Origin: "node", Unit: "tokens", Cap: 1000, Spent: 200, Start: dayStart, Reset: dayStart.Add(24 * time.Hour)},
			},
			check: func(t *testing.T, p Projection) {
				if p.LeftUSD != nil || !hasNote(p, NoteUnpriced) {
					t.Errorf("no dollars without prices: %v %v", p.LeftUSD, p.Notes)
				}
				if p.MorePrompts == nil || p.MorePrompts.Basis != "tokens" || p.MorePrompts.Mid != 8 {
					t.Errorf("prompts %+v, want 8 (800 / 100 new tokens)", p.MorePrompts)
				}
			},
		},
		{
			name: "no cap: nothing derived",
			in:   BudgetInput{Now: projNow, Rows: weekRows(), Window: BudgetWindow{Key: "daily", Unit: "usd", Start: dayStart, Reset: dayStart.Add(24 * time.Hour)}},
			check: func(t *testing.T, p Projection) {
				if p.UsedFrac != nil || p.Burn != nil || p.LeftUSD != nil {
					t.Fatalf("%+v", p)
				}
			},
		},
		{
			name: "under an hour into the day: not enough data",
			in: BudgetInput{
				Now: dayStart.Add(30 * time.Minute), Rows: weekRows(),
				Window: BudgetWindow{Key: "daily", Unit: "usd", Cap: 60, Spent: 1, Start: dayStart, Reset: dayStart.Add(24 * time.Hour)},
			},
			check: func(t *testing.T, p Projection) {
				if p.Burn != nil || p.RunOut != nil || !hasNote(p, NoteNotEnoughData) {
					t.Fatalf("%+v", p)
				}
			},
		},
		{
			name: "exceeded",
			in: BudgetInput{
				Now: projNow, Rows: weekRows(),
				Window: BudgetWindow{Key: "daily", Unit: "usd", Cap: 30, Spent: 40, Start: dayStart, Reset: dayStart.Add(24 * time.Hour)},
			},
			check: func(t *testing.T, p Projection) {
				if p.RunOut == nil || !p.RunOut.Exhausted || *p.LeftUSD != 0 {
					t.Fatalf("%+v", p.RunOut)
				}
			},
		},
		{
			name: "rolling weekly: no reset, even allowance",
			in: BudgetInput{
				Now: projNow, Rows: weekRows(),
				Window: BudgetWindow{Key: "weekly", Unit: "usd", Cap: 70, Spent: 35, Start: projNow.Add(-7 * 24 * time.Hour), Rolling: true, Length: 7 * 24 * time.Hour},
			},
			check: func(t *testing.T, p Projection) {
				if p.State != StateRolling || p.ResetsAtUnix != nil || p.Pace != nil {
					t.Fatalf("%+v", p)
				}
				if p.RunOut == nil || p.RunOut.RunsOutAtUnix != nil || p.RunOut.SafePerDayUSD == nil || *p.RunOut.SafePerDayUSD != 10 {
					t.Errorf("run out %+v, want $10/day steady", p.RunOut)
				}
			},
		},
		{
			name: "session cap: prompts only",
			in: BudgetInput{
				Now: projNow, SessionID: "this", Rows: weekRows()[:1], Message: msg,
				Window: BudgetWindow{Key: "session", Unit: "usd", Cap: 15, Spent: 10},
			},
			check: func(t *testing.T, p Projection) {
				if p.State != StateSession || p.Burn != nil || p.Sessions != nil || p.WindowStartUnix != nil {
					t.Fatalf("%+v", p)
				}
				if p.MorePrompts == nil || p.MorePrompts.Mid != 5 {
					t.Errorf("prompts %+v, want 5", p.MorePrompts)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.check(t, ProjectBudget(c.in)) })
	}
}

func TestLimitBoundsTable(t *testing.T) {
	cases := []struct {
		name  string
		r     LimitReading
		state ProjectionState
		since bool
	}{
		{"live fresh", LimitReading{Key: "5h", ResetsAt: projNow.Add(time.Hour), ObservedAt: projNow}, StateLive, false},
		{"live old reading", LimitReading{Key: "5h", ResetsAt: projNow.Add(time.Hour), ObservedAt: projNow.Add(-time.Hour)}, StateLive, true},
		{"reading before the window", LimitReading{Key: "5h", ResetsAt: projNow.Add(time.Hour), ObservedAt: projNow.Add(-5 * time.Hour)}, StateLive, false},
		{"weekly reset", LimitReading{Key: "weekly", ResetsAt: projNow.Add(-time.Hour)}, StateResetInferred, false},
		{"5h reset", LimitReading{Key: "5h", ResetsAt: projNow.Add(-time.Hour)}, StateReset, false},
		{"no reset", LimitReading{Key: "weekly"}, StateNoResetTime, false},
		{"unknown key", LimitReading{Key: "monthly", ResetsAt: projNow.Add(time.Hour)}, StateNoResetTime, false},
	}
	for _, c := range cases {
		b := LimitBounds(c.r, projNow)
		if b.State != c.state || b.SinceReading != c.since {
			t.Errorf("%s: state %q since %v, want %q %v", c.name, b.State, b.SinceReading, c.state, c.since)
		}
	}
}

func TestMessageCostOf(t *testing.T) {
	e := EstimateResult{HasShape: true, HasEstimate: true, PrefixTokens: 1000, Mid: Band{Turns: 2, FreshInput: 10, Output: 90, MessageUSD: 0.5}}
	m := MessageCostOf(e)
	if !m.Has || !m.Priced || m.Mid.AllTokens != 2200 || m.Mid.NewTokens != 200 || m.Mid.USD != 0.5 {
		t.Fatalf("%+v", m.Mid)
	}
	if MessageCostOf(EstimateResult{}).Has {
		t.Fatal("no shape, no band")
	}
}
