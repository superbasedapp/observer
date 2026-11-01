package sandboxremote

import (
	"fmt"
	"sort"
	"time"
)

// ledger.go is the hard spend cap (lane SBX-P7, orchestrator default): every
// create sets the vendor's own timeout (never "no timeout") to the smaller
// of max_run_minutes and what is left of the day's daily_box_minutes for
// that provider, and a node-local ledger counts box-minutes per provider per
// UTC day. A launch with nothing left refuses by name. The cmd layer stores
// the ledger owner-only; this file is the arithmetic.

// LedgerVersion is the stored shape's version.
const LedgerVersion = 1

// VerdictDailyCapReached refuses a launch with no box-minutes left today.
const VerdictDailyCapReached = "daily_box_minutes_reached"

// MinRunMinutes is the shortest box a launch will create: below it the
// launch refuses rather than start a box that ends at once.
const MinRunMinutes = 5

// LedgerEntry is one run's reservation.
type LedgerEntry struct {
	Provider string `json:"provider"`
	// Day is the UTC date the box was created (YYYY-MM-DD).
	Day   string `json:"day"`
	RunID string `json:"run_id"`
	// Minutes is the reservation (the vendor timeout) until settled, then
	// the minutes the box really ran, rounded up.
	Minutes int  `json:"minutes"`
	Settled bool `json:"settled"`
	// Note says how a settlement was reached when it is not the minutes the
	// box was seen to run (a leftover whose start is unknown keeps its
	// planned charge, live run 2 finding F-B).
	Note string `json:"note,omitempty"`
}

// Ledger is the node-local spend record.
type Ledger struct {
	Version int           `json:"version"`
	Entries []LedgerEntry `json:"entries"`
}

// DayOf is the ledger day of t.
func DayOf(t time.Time) string { return t.UTC().Format("2006-01-02") }

// Used is the box-minutes counted for provider on day.
func (l Ledger) Used(provider, day string) int {
	n := 0
	for _, e := range l.Entries {
		if e.Provider == provider && e.Day == day {
			n += e.Minutes
		}
	}
	return n
}

// PlanTimeout is the vendor timeout of the next box, in minutes: the
// smaller of maxRun and what is left of daily. A result below MinRunMinutes
// refuses with VerdictDailyCapReached.
func PlanTimeout(maxRun, daily, used int) (int, error) {
	left := daily - used
	m := maxRun
	if left < m {
		m = left
	}
	if m < MinRunMinutes {
		return 0, fmt.Errorf("%s: %d of %d box-minutes used today on this provider; the next box would get %d minutes (at least %d needed)", VerdictDailyCapReached, used, daily, max(m, 0), MinRunMinutes)
	}
	return m, nil
}

// Reserve records a run's reservation before its create call (so a killed
// daemon still counts the box's whole timeout).
func (l *Ledger) Reserve(provider, day, runID string, minutes int) {
	l.Version = LedgerVersion
	for i, e := range l.Entries {
		if e.RunID == runID {
			l.Entries[i].Minutes = minutes
			return
		}
	}
	l.Entries = append(l.Entries, LedgerEntry{Provider: provider, Day: day, RunID: runID, Minutes: minutes})
}

// Settle replaces a reservation with what the box really ran (rounded up to
// whole minutes), never more than reserved: the vendor timeout stopped it
// there. It returns the minutes charged and whether an open reservation of
// the run was found.
func (l *Ledger) Settle(runID string, ran time.Duration) (int, bool) {
	if ran < 0 {
		ran = 0
	}
	m := int((ran + time.Minute - 1) / time.Minute)
	charged, found := 0, false
	for i, e := range l.Entries {
		if e.RunID != runID || e.Settled {
			continue
		}
		if m < e.Minutes {
			l.Entries[i].Minutes = m
		}
		l.Entries[i].Settled = true
		charged, found = charged+l.Entries[i].Minutes, true
	}
	return charged, found
}

// SettlePlanned closes a run's open reservation at its planned minutes,
// with a note saying why (the box's run time is not known). It returns the
// minutes charged and whether an open reservation was found.
func (l *Ledger) SettlePlanned(runID, note string) (int, bool) {
	charged, found := 0, false
	for i, e := range l.Entries {
		if e.RunID != runID || e.Settled {
			continue
		}
		l.Entries[i].Settled, l.Entries[i].Note = true, note
		charged, found = charged+e.Minutes, true
	}
	return charged, found
}

// Prune drops entries older than keepDays before today.
func (l *Ledger) Prune(today time.Time, keepDays int) {
	cut := DayOf(today.AddDate(0, 0, -keepDays))
	out := l.Entries[:0]
	for _, e := range l.Entries {
		if e.Day >= cut {
			out = append(out, e)
		}
	}
	l.Entries = out
}

// DayTotal is one provider's use on one day.
type DayTotal struct {
	Provider string   `json:"provider"`
	Day      string   `json:"day"`
	Minutes  int      `json:"minutes"`
	Estimate Estimate `json:"estimate"`
}

// Totals sums the ledger per provider per day with an estimate each,
// newest day first.
func (l Ledger) Totals() []DayTotal {
	type key struct{ p, d string }
	sum := map[key]int{}
	for _, e := range l.Entries {
		sum[key{e.Provider, e.Day}] += e.Minutes
	}
	out := make([]DayTotal, 0, len(sum))
	for k, m := range sum {
		t := DayTotal{Provider: k.p, Day: k.d, Minutes: m}
		if v, ok := VendorFor(k.p); ok {
			t.Estimate = v.EstimateCost(m)
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Day != out[j].Day {
			return out[i].Day > out[j].Day
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}
