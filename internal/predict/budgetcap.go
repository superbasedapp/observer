package predict

import (
	"math"
	"time"
)

// budgetcap.go is the half of a budget's projection that the budget's own
// numbers decide: the cap, the spend measured against it, its period and the
// clock. It needs no captured usage, so it is the ONE derivation two
// surfaces share (the internal/sessionmsg precedent: one pure package, thin
// adapters):
//
//   - the node's session Cost & limits tab, through ProjectBudget, which
//     layers the node's captured usage (token mix, sessions, trend, prompts
//     left) on top of it;
//   - the org Budgets page, through ProjectBudgetCap, which has the org's
//     authored caps and the spend its rollup measured, and no node-local
//     usage rows (those never cross the push wire).
//
// It also owns the calendar of an org budget period (CalendarBounds): a daily
// cap restarts at local midnight and a monthly one on the first of the local
// month, in the cap's own timezone, the same rule the AI gateway buckets its
// reservation ledger with (aigateway.WindowValueFor) and the node's budget
// warnings name their period with (budgetwarn.PeriodKey).

// calendarKind is one row of the calendar period table.
type calendarKind struct {
	// layout renders the period key (the gateway's window_value spelling).
	layout string
	// start is the first instant of the period holding local, in its zone.
	start func(local time.Time) time.Time
	// next is the first instant of the following period.
	next func(start time.Time) time.Time
}

// calendarKinds is the calendar period table, keyed by the window name the
// node's budget windows and the org's period vocabulary both map onto.
var calendarKinds = map[string]calendarKind{
	"daily": {
		layout: "2006-01-02",
		start: func(t time.Time) time.Time {
			return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
		},
		next: func(s time.Time) time.Time {
			return time.Date(s.Year(), s.Month(), s.Day()+1, 0, 0, 0, 0, s.Location())
		},
	},
	"monthly": {
		layout: "2006-01",
		start: func(t time.Time) time.Time {
			return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
		},
		next: func(s time.Time) time.Time {
			return time.Date(s.Year(), s.Month()+1, 1, 0, 0, 0, 0, s.Location())
		},
	},
}

// CalendarPeriod is the calendar period an instant falls in.
type CalendarPeriod struct {
	// Start / Reset bound the period, in UTC. A day is 23 or 25 hours long
	// across a daylight-saving change; the bounds follow the local clock.
	Start time.Time
	Reset time.Time
	// Key is the period key ("2026-11-10" daily, "2026-11" monthly) in the
	// zone the bounds were computed in.
	Key string
	// ZoneHonoured is false when the named zone could not be loaded on this
	// machine and UTC was used instead (the gateway's and the budget
	// warnings' own fallback, so the key still agrees with theirs).
	ZoneHonoured bool
}

// CalendarBounds returns the calendar period of window ("daily" or
// "monthly") that now falls in, in timezone tz (IANA; "" and "UTC" are UTC).
// ok is false for any other window.
func CalendarBounds(window, tz string, now time.Time) (CalendarPeriod, bool) {
	k, known := calendarKinds[window]
	if !known {
		return CalendarPeriod{}, false
	}
	loc, honoured := calendarZone(tz)
	start := k.start(now.In(loc))
	return CalendarPeriod{
		Start: start.UTC(), Reset: k.next(start).UTC(),
		Key: start.Format(k.layout), ZoneHonoured: honoured,
	}, true
}

// calendarZone resolves a budget's timezone: "" and "UTC" are UTC; a name
// this machine cannot load falls back to UTC and says so.
func calendarZone(tz string) (*time.Location, bool) {
	if tz == "" || tz == "UTC" {
		return time.UTC, true
	}
	loc, err := time.LoadLocation(tz)
	if err != nil || loc == nil {
		return time.UTC, false
	}
	return loc, true
}

// ProjectBudgetCap computes the stat set of one budget from its own numbers
// alone: used and left in the cap's unit, where the window sits, the burn
// rate (as a share of the cap and in the cap's unit), pace, and when it runs
// out or how much is left at the reset. It is the org Budgets page's
// projection: there is no captured usage, so the token mix, sessions, trend,
// prompts left and the confidence level (which counts turns) are absent
// rather than zero, and nothing is converted to the other unit.
func ProjectBudgetCap(now time.Time, w BudgetWindow) Projection {
	p, _ := budgetCore(now, w, 0, false)
	return p
}

// budgetCore is the cap-only half of a budget's projection, shared by
// ProjectBudget and ProjectBudgetCap. usdPerTok converts the cap to the other
// unit (0 = no conversion, nothing estimated); unpriced adds the unpriced
// usage note in its place. It returns the hours the burn is averaged over
// (0 when there is no burn), so ProjectBudget can put its captured usage on
// the same basis.
func budgetCore(now time.Time, w BudgetWindow, usdPerTok float64, unpriced bool) (Projection, float64) {
	b := BudgetBounds(w, now)
	p := Projection{
		Kind: "budget", Key: w.Key, State: b.State, Unit: w.Unit, TokenDef: TokensInputOutput,
		Origin: w.Origin, Scope: w.Scope, Enforcement: w.Enforcement, Subject: w.Subject,
		Cap: w.Cap, Spent: w.Spent,
	}
	if w.TimezoneAssumed {
		p.addNote(NoteTimezoneAssumed)
	}
	if w.OtherMachines {
		p.addNote(NoteOtherMachines)
	}
	if w.Cap <= 0 {
		return p, 0
	}
	used := math.Max(0, w.Spent/w.Cap)
	p.UsedFrac = f64(used)
	p.UsedFracEst = f64(used)
	left := math.Max(0, 1-used)
	p.LeftFrac = f64(left)
	if b.State != StateSession {
		p.placeWindow(b, now)
		if b.State == StateRolling {
			p.ResetsAtUnix = nil
			p.SecondsToReset = nil
		}
	}
	if unpriced {
		p.addNote(NoteUnpriced)
	}

	// What is left: exact in the cap's own unit, an estimate in the other
	// (through the captured usage's dollars per token, when there is one).
	leftUnit := math.Max(0, w.Cap-w.Spent)
	switch w.Unit {
	case "tokens":
		p.LeftTokens = f64(math.Round(leftUnit))
		if usdPerTok > 0 {
			p.LeftUSD = f64(round6(leftUnit * usdPerTok))
			p.LeftUSDIsEstimate = true
		}
	default:
		p.LeftUSD = f64(round6(leftUnit))
		if usdPerTok > 0 {
			p.LeftTokens = f64(math.Round(leftUnit / usdPerTok))
			p.LeftTokensIsEstimate = true
		}
	}

	elapsed := now.Sub(w.Start)
	var hours float64
	switch {
	case used >= 1:
		p.RunOut = &RunOut{Exhausted: true}
		p.addNote(NoteExhausted)
	case b.State == StateSession:
		// No time window: only what is left.
	case elapsed < minBasis || w.Spent <= 0:
		p.addNote(NoteNotEnoughData)
	default:
		hours = elapsed.Hours()
		if b.State == StateRolling && b.Length > 0 {
			// A rolling window's spend is averaged over the whole window.
			hours = math.Min(hours, b.Length.Hours())
		}
		p.Burn = &Burn{FracPerHour: used / hours, FracPerDay: used / hours * 24, BasisHours: round1(hours)}
		// The rate in the cap's own unit, from the spend measured against it.
		switch w.Unit {
		case "tokens":
			p.Burn.TokensPerHour, p.Burn.TokensPerDay = w.Spent/hours, w.Spent/hours*24
		default:
			p.Burn.USDPerHour, p.Burn.USDPerDay = w.Spent/hours, w.Spent/hours*24
		}
		capT, capU := budgetCapacities(w, usdPerTok)
		if b.State == StateLive {
			p.pace(used, b, now)
			p.RunOut = runOut(used, p.Burn.FracPerHour, w.Reset, now, capT, capU)
		} else if b.Length > 0 {
			// Rolling: no reset. The even rate that keeps the rolling sum
			// at the cap is the cap over the window.
			days := b.Length.Hours() / 24
			ro := &RunOut{SafePerDayFrac: f64(1 / days), SafePerHourFrac: f64(1 / b.Length.Hours())}
			if capT != nil {
				ro.SafePerDayTokens = f64(*capT / days)
			}
			if capU != nil {
				ro.SafePerDayUSD = f64(round6(*capU / days))
			}
			p.RunOut = ro
		}
	}
	return p, hours
}
