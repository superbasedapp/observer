package orgbudget

import "time"

// Calendar anchoring for the node's budget windows (review fix round 2,
// MEDIUM-2).
//
// The org's `budgets` row carries a timezone, and the server honours it in two
// places already: the displayed percentage and the alert ladder both anchor
// calendar_day / calendar_month through rollup.BudgetWindowSince. The node's
// budget lookup used to anchor on the UTC day unconditionally, so a
// calendar_day cap in America/Los_Angeles was counted over a DIFFERENT window
// at the enforcing chokepoint than on the page the admin reads — at 23:30 PDT
// the node is 6.5 hours into a day the dashboard has not started.
//
// These two functions are the node's half of "one budget, one calendar". They
// are pure and take a *time.Location so the composition layer stays free of
// anything that can fail; Zone owns the name -> location resolution, with the
// same fail-open rule the server uses (an unloadable zone is UTC, never an
// error — a budget must keep being enforced).

// weeklyWindowDays is the rolling window B-604/B-624 compare against. It is
// ROLLING, not calendar, so no timezone applies to it: "the last 7 days" is
// the same interval in every zone.
const weeklyWindowDays = 7

// Zone resolves an IANA timezone name to a location, falling back to UTC for
// the empty name (the node's own default, and what a purely local budget has
// always used) and for any name this platform's tzdata cannot load.
//
// Fail-open on an unloadable name matches rollup.BudgetWindowSince: the name
// is validated at the WRITE seam (dashboard's budget create/update), so a bad
// value here means a tzdata gap on this machine, and silently widening the
// window to UTC is better than dropping the cap.
func Zone(name string) *time.Location {
	if name == "" {
		return time.UTC
	}
	if loc, err := time.LoadLocation(name); err == nil {
		return loc
	}
	return time.UTC
}

// CalendarWindowStarts returns the inclusive lower bounds of the node's three
// cross-session budget windows at now, each anchored in the calendar that
// window's governing cap carries.
//
// daily and monthly are CALENDAR windows and take a location each — they may
// differ, because a daily and a monthly org cap are two authored rows and each
// brings its own timezone. weekly is a rolling 7-day window and takes none.
// A nil location is UTC.
//
// The day and month boundaries are computed exactly as
// rollup.BudgetWindowSince computes them (local midnight / the first of the
// local month, expressed as an instant), so the node, the dashboard percentage
// and the alert ladder bucket the same turns.
func CalendarWindowStarts(now time.Time, daily, monthly *time.Location) (dayStart, weekStart, monthStart time.Time) {
	dayLoc, monthLoc := orUTC(daily), orUTC(monthly)
	d := now.In(dayLoc)
	m := now.In(monthLoc)
	dayStart = time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, dayLoc)
	monthStart = time.Date(m.Year(), m.Month(), 1, 0, 0, 0, 0, monthLoc)
	weekStart = now.Add(-weeklyWindowDays * 24 * time.Hour)
	return dayStart, weekStart, monthStart
}

// orUTC defaults a nil location.
func orUTC(loc *time.Location) *time.Location {
	if loc == nil {
		return time.UTC
	}
	return loc
}
