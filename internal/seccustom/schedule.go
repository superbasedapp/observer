package seccustom

import "time"

// ScheduleFacts are what the scheduled-run decision reads for one driver
// and one project, resolved at the boundary (security pillar plan section
// 4.4: background only, one heavy scan at a time, paused on battery by
// default).
type ScheduleFacts struct {
	// Every is the schedule's interval; zero or less is off.
	Every time.Duration
	// PauseOnBattery holds runs on battery and while the power state is
	// unknown.
	PauseOnBattery bool
	// Power is the power state: "ac", "battery" or "unknown".
	Power string
	// LastRun is when this driver last ran over this project on the
	// schedule (zero: never since the daemon started).
	LastRun time.Time
	Now     time.Time
}

// ScheduleDecision is whether a scheduled run starts now and, when not,
// the closed reason.
type ScheduleDecision struct {
	Run    bool
	Reason string
}

// The schedule reasons.
const (
	ScheduleOff          = "schedule_off"
	SchedulePausedOnBatt = "paused_on_battery"
	SchedulePowerUnknown = "paused_power_unknown"
	ScheduleNotDue       = "not_due"
)

// scheduleRow is one row of the schedule table.
type scheduleRow struct {
	when func(ScheduleFacts) bool
	d    ScheduleDecision
}

// scheduleTable is walked top-down; the first row that holds decides. A
// power state that cannot be read counts as "may be on battery" while the
// pause is on: the conservative reading of "paused on battery by default".
var scheduleTable = []scheduleRow{
	{func(f ScheduleFacts) bool { return f.Every <= 0 }, ScheduleDecision{false, ScheduleOff}},
	{func(f ScheduleFacts) bool { return f.PauseOnBattery && f.Power == "battery" }, ScheduleDecision{false, SchedulePausedOnBatt}},
	{func(f ScheduleFacts) bool { return f.PauseOnBattery && f.Power != "ac" }, ScheduleDecision{false, SchedulePowerUnknown}},
	{func(f ScheduleFacts) bool { return !f.LastRun.IsZero() && f.Now.Sub(f.LastRun) < f.Every }, ScheduleDecision{false, ScheduleNotDue}},
	{func(ScheduleFacts) bool { return true }, ScheduleDecision{true, ""}},
}

// DecideSchedule decides one scheduled run.
func DecideSchedule(f ScheduleFacts) ScheduleDecision {
	for _, r := range scheduleTable {
		if r.when(f) {
			return r.d
		}
	}
	return ScheduleDecision{false, ScheduleOff}
}
