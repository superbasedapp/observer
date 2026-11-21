package reserve

import "time"

// Window is a cap's reset period.
type Window string

// The windows.
const (
	// WindowDaily resets at midnight in the cap's location.
	WindowDaily Window = "daily"
	// WindowMonthly resets on the first of the calendar month in the cap's
	// location.
	WindowMonthly Window = "monthly"
	// WindowLive never resets: it counts what is in flight now (a
	// concurrency cap goes up on a hold and down when the hold closes).
	WindowLive Window = "live"
)

// LiveKey is the one bucket key of WindowLive.
const LiveKey = "live"

// windowRule is one row of windowRules.
type windowRule struct {
	window Window
	key    func(time.Time) string
}

// windowRules key an instant per window. A function, not a package
// variable, so the table is never shared mutable state.
func windowRules() []windowRule {
	return []windowRule{
		{window: WindowDaily, key: func(t time.Time) string { return t.Format("2006-01-02") }},
		{window: WindowMonthly, key: func(t time.Time) string { return t.Format("2006-01") }},
		{window: WindowLive, key: func(time.Time) string { return LiveKey }},
	}
}

// WindowKey returns the bucket key now falls in for window w, on the
// calendar of loc (nil is UTC), and false for a window outside the
// vocabulary. Both ledgers key a cap's counters with it, so the key a hold
// is STAMPED with and the key its cap is CHECKED against are the same
// computation.
func WindowKey(now time.Time, w Window, loc *time.Location) (string, bool) {
	if loc == nil {
		loc = time.UTC
	}
	for _, r := range windowRules() {
		if r.window == w {
			return r.key(now.In(loc)), true
		}
	}
	return "", false
}
