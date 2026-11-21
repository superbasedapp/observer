package predictsvc

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarn"
	"github.com/marmutapp/superbased-observer/internal/predict"
)

func tzUTC(y int, m time.Month, d, h, min int) time.Time {
	return time.Date(y, m, d, h, min, 0, 0, time.UTC)
}

// TestOrgPeriodBounds is the org window's calendar at its edges: the period
// the daemon named in the cap's own zone is placed on that zone's calendar,
// a key that is not the current one there is dropped, and a file with no
// zone (an older daemon) keeps the old UTC reading with the assumption
// flagged.
func TestOrgPeriodBounds(t *testing.T) {
	cases := []struct {
		name                 string
		window, period, tz   string
		now                  time.Time
		wantOK, wantAssumed  bool
		wantStart, wantReset time.Time
	}{
		{
			"la day before utc midnight", "daily", "2026-11-10", "America/Los_Angeles", tzUTC(2026, 11, 11, 6, 0), true, false,
			tzUTC(2026, 11, 10, 8, 0), tzUTC(2026, 11, 11, 8, 0),
		},
		{
			"la key read as the utc day is stale", "daily", "2026-11-11", "America/Los_Angeles", tzUTC(2026, 11, 11, 6, 0), false, false,
			time.Time{},
			time.Time{},
		},
		{
			"kolkata month starts before utc's", "monthly", "2026-12", "Asia/Kolkata", tzUTC(2026, 11, 30, 20, 0), true, false,
			tzUTC(2026, 11, 30, 18, 30), tzUTC(2026, 12, 31, 18, 30),
		},
		{
			"new york 25h day", "daily", "2026-11-01", "America/New_York", tzUTC(2026, 11, 2, 3, 0), true, false,
			tzUTC(2026, 11, 1, 4, 0), tzUTC(2026, 11, 2, 5, 0),
		},
		{
			"new york 23h day", "daily", "2026-03-08", "America/New_York", tzUTC(2026, 3, 8, 23, 0), true, false,
			tzUTC(2026, 3, 8, 5, 0), tzUTC(2026, 3, 9, 4, 0),
		},
		{
			"utc cap", "monthly", "2026-11", "UTC", tzUTC(2026, 11, 30, 23, 59), true, false,
			tzUTC(2026, 11, 1, 0, 0), tzUTC(2026, 12, 1, 0, 0),
		},
		{
			"unloadable zone: utc, flagged", "daily", "2026-11-11", "Not/AZone", tzUTC(2026, 11, 11, 6, 0), true, true,
			tzUTC(2026, 11, 11, 0, 0), tzUTC(2026, 11, 12, 0, 0),
		},
		{
			"older daemon file: utc give or take a day, flagged", "daily", "2026-11-10", "", tzUTC(2026, 11, 11, 6, 0), true, true,
			tzUTC(2026, 11, 10, 0, 0), tzUTC(2026, 11, 11, 0, 0),
		},
		{
			"older daemon file: two days stale", "daily", "2026-11-08", "", tzUTC(2026, 11, 11, 6, 0), false, true,
			time.Time{},
			time.Time{},
		},
		{"unknown window", "weekly", "2026-11", "UTC", tzUTC(2026, 11, 11, 6, 0), false, false, time.Time{}, time.Time{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start, reset, assumed, ok := orgPeriodBounds(c.window, c.period, c.tz, c.now)
			if ok != c.wantOK {
				t.Fatalf("ok %v, want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if assumed != c.wantAssumed || !start.Equal(c.wantStart) || !reset.Equal(c.wantReset) {
				t.Fatalf("start %s reset %s assumed %v", start, reset, assumed)
			}
		})
	}
}

// TestOrgPeriodKeyAgreesWithTheDaemon pins one calendar: the key the daemon's
// budget warnings name a period with is the key the projection places, at
// every hour across a DST change and a month edge.
func TestOrgPeriodKeyAgreesWithTheDaemon(t *testing.T) {
	for _, tz := range []string{"UTC", "America/Los_Angeles", "America/New_York", "Asia/Kolkata", "Australia/Lord_Howe"} {
		for _, window := range []string{"daily", "monthly"} {
			for h := 0; h < 72; h++ {
				now := tzUTC(2026, 10, 31, 0, 0).Add(time.Duration(h) * time.Hour)
				key := budgetwarn.PeriodKey(window, tz, now)
				cp, ok := predict.CalendarBounds(window, tz, now)
				if !ok || cp.Key != key || now.Before(cp.Start) || !now.Before(cp.Reset) {
					t.Fatalf("%s %s at %s: daemon %q, projection %+v", tz, window, now, key, cp)
				}
				if start, _, _, ok := orgPeriodBounds(window, key, tz, now); !ok || !start.Equal(cp.Start) {
					t.Fatalf("%s %s at %s: the daemon's key is not placed", tz, window, now)
				}
			}
		}
	}
}
