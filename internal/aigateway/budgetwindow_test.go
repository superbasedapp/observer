package aigateway

import (
	"testing"
	"time"
)

// TestWindowValueFor pins the per-scope ledger bucket key: the calendar day or
// month of an instant AS SEEN IN the cap's own timezone.
//
// This is the whole of the timezone fix. Before it, the reservation row
// stamped ONE UTC day / month shared by every scope a request touched, so a
// cap authored in America/Los_Angeles was enforced on the UTC calendar and a
// 23:30 local request counted against tomorrow's budget. The key now travels
// on the SCOPE row, computed from the cap's zone, so two caps in two zones on
// the SAME request bucket differently and each is enforced on its own
// calendar.
//
// Fail-closed rule: a zone this build cannot load must never panic and must
// never silently invent a calendar. It falls back to UTC and REPORTS that it
// did (zoneHonoured=false) so a caller can flag the scope.
func TestWindowValueFor(t *testing.T) {
	t.Parallel()

	// 2026-09-07 23:30 America/Los_Angeles is 2026-09-08 06:30 UTC: the UTC
	// day has rolled over, the LA day has not. 2026-08-31 23:30 LA is
	// 2026-09-01 06:30 UTC: the UTC MONTH has rolled over, the LA month has
	// not. 2026-09-08 05:00 UTC is 2026-09-08 10:30 Asia/Kolkata (+05:30):
	// same day, but 2026-09-07 20:00 UTC is already the 8th in Kolkata.
	utc := func(y int, m time.Month, d, h, min int) time.Time {
		return time.Date(y, m, d, h, min, 0, 0, time.UTC)
	}

	cases := []struct {
		name     string
		now      time.Time
		window   BudgetWindow
		timezone string
		want     string
		wantZone bool
		needsTZ  bool
	}{
		{
			name: "utc daily, empty zone means UTC",
			now:  utc(2026, 9, 8, 6, 30), window: WindowDaily, timezone: "",
			want: "2026-09-08", wantZone: true,
		},
		{
			name: "utc daily, literal UTC",
			now:  utc(2026, 9, 8, 6, 30), window: WindowDaily, timezone: "UTC",
			want: "2026-09-08", wantZone: true,
		},
		{
			name: "utc monthly",
			now:  utc(2026, 9, 1, 6, 30), window: WindowMonthly, timezone: "UTC",
			want: "2026-09", wantZone: true,
		},
		{
			// Kolkata is +05:30 and AHEAD of UTC: 23:30 UTC on the 7th is
			// already 05:00 on the 8th locally, so the local day leads.
			name: "asia/kolkata at 23:30 UTC is already the next local day",
			now:  utc(2026, 9, 7, 23, 30), window: WindowDaily, timezone: "Asia/Kolkata",
			want: "2026-09-08", wantZone: true, needsTZ: true,
		},
		{
			// The same instant in UTC is still the 7th: the two keys differ,
			// which is exactly the divergence this arc removes.
			name: "asia/kolkata control: the same instant in UTC is the previous day",
			now:  utc(2026, 9, 7, 23, 30), window: WindowDaily, timezone: "UTC",
			want: "2026-09-07", wantZone: true,
		},
		{
			// 23:30 LA on 2026-08-31 is 06:30 UTC on 2026-09-01: the UTC
			// month has rolled, the LA month has not.
			name: "america/los_angeles across a month boundary",
			now:  utc(2026, 9, 1, 6, 30), window: WindowMonthly, timezone: "America/Los_Angeles",
			want: "2026-08", wantZone: true, needsTZ: true,
		},
		{
			name: "america/los_angeles control: UTC has already rolled the month",
			now:  utc(2026, 9, 1, 6, 30), window: WindowMonthly, timezone: "UTC",
			want: "2026-09", wantZone: true,
		},
		{
			// MEDIUM-2's own scenario, daily.
			name: "america/los_angeles at 23:30 local stays on the local day",
			now:  utc(2026, 9, 8, 6, 30), window: WindowDaily, timezone: "America/Los_Angeles",
			want: "2026-09-07", wantZone: true, needsTZ: true,
		},
		{
			// Fail CLOSED: an unloadable zone buckets on UTC and says so.
			name: "invalid zone falls back to UTC and reports it",
			now:  utc(2026, 9, 8, 6, 30), window: WindowDaily, timezone: "Mars/Olympus",
			want: "2026-09-08", wantZone: false,
		},
		{
			name: "invalid zone, monthly",
			now:  utc(2026, 9, 8, 6, 30), window: WindowMonthly, timezone: "Mars/Olympus",
			want: "2026-09", wantZone: false,
		},
		{
			// An unknown window kind buckets daily, the same default
			// committedSpendTx applies (anything that is not monthly).
			name: "unknown window kind buckets daily",
			now:  utc(2026, 9, 8, 6, 30), window: BudgetWindow("weekly"), timezone: "UTC",
			want: "2026-09-08", wantZone: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.needsTZ {
				if _, err := time.LoadLocation(c.timezone); err != nil {
					t.Skipf("tzdata unavailable on this platform: %v", err)
				}
			}
			got, zoneOK := WindowValueFor(c.now, c.window, c.timezone)
			if got != c.want {
				t.Errorf("WindowValueFor(%s, %q, %q) = %q, want %q",
					c.now.Format(time.RFC3339), c.window, c.timezone, got, c.want)
			}
			if zoneOK != c.wantZone {
				t.Errorf("WindowValueFor(%s, %q, %q) zoneHonoured = %v, want %v",
					c.now.Format(time.RFC3339), c.window, c.timezone, zoneOK, c.wantZone)
			}
		})
	}
}

// TestWindowValueForIsStableAcrossTheSameLocalDay guards the property the
// ledger depends on: every instant inside one local calendar day must produce
// the SAME key, or committed spend would be split across buckets and a cap
// would silently reset mid-day.
func TestWindowValueForIsStableAcrossTheSameLocalDay(t *testing.T) {
	t.Parallel()

	const zone = "America/Los_Angeles"
	loc, err := time.LoadLocation(zone)
	if err != nil {
		t.Skipf("tzdata unavailable on this platform: %v", err)
	}
	start := time.Date(2026, 9, 7, 0, 0, 0, 0, loc)
	want, _ := WindowValueFor(start, WindowDaily, zone)
	for h := 0; h < 24; h++ {
		at := start.Add(time.Duration(h) * time.Hour)
		got, _ := WindowValueFor(at, WindowDaily, zone)
		if got != want {
			t.Fatalf("hour %d of the %s day keyed %q, want %q — a cap must not reset mid-day", h, zone, got, want)
		}
	}
	// The hour after local midnight is a NEW day: the window really does roll.
	next, _ := WindowValueFor(start.Add(24*time.Hour), WindowDaily, zone)
	if next == want {
		t.Fatalf("the next local day keyed %q too — the window never rolls", next)
	}
}
