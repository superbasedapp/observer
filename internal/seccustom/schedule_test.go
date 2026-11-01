package seccustom

import (
	"testing"
	"time"
)

func TestDecideScheduleTable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	cases := []struct {
		name string
		f    ScheduleFacts
		want ScheduleDecision
	}{
		{"off by default", ScheduleFacts{PauseOnBattery: true, Power: "ac", Now: now}, ScheduleDecision{false, ScheduleOff}},
		{"on battery, paused", ScheduleFacts{Every: day, PauseOnBattery: true, Power: "battery", Now: now}, ScheduleDecision{false, SchedulePausedOnBatt}},
		{"power unknown, paused", ScheduleFacts{Every: day, PauseOnBattery: true, Power: "unknown", Now: now}, ScheduleDecision{false, SchedulePowerUnknown}},
		{"on battery, pause off", ScheduleFacts{Every: day, Power: "battery", Now: now}, ScheduleDecision{true, ""}},
		{"never ran, on mains", ScheduleFacts{Every: day, PauseOnBattery: true, Power: "ac", Now: now}, ScheduleDecision{true, ""}},
		{"ran an hour ago", ScheduleFacts{Every: day, PauseOnBattery: true, Power: "ac", LastRun: now.Add(-time.Hour), Now: now}, ScheduleDecision{false, ScheduleNotDue}},
		{"ran a day ago", ScheduleFacts{Every: day, PauseOnBattery: true, Power: "ac", LastRun: now.Add(-day), Now: now}, ScheduleDecision{true, ""}},
	}
	for _, tc := range cases {
		if got := DecideSchedule(tc.f); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
