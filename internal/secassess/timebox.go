package secassess

import "time"

// The time box (plan W0.3): a run's time box is recorded on the run at launch,
// so a later settings change never moves its deadline. Nothing here reads a
// clock; callers pass the times.

// The actions at the deadline.
const (
	// TimeBoxStopButton: the run row offers Stop; nothing is closed for the
	// developer. The default.
	TimeBoxStopButton = "stop_button"
	// TimeBoxAutoClose: Observer closes the run's terminal at the deadline.
	TimeBoxAutoClose = "auto_close"
)

// How a run's end came about (Run.EndWhy).
const (
	// EndGone: the terminal was seen gone.
	EndGone = "terminal_gone"
	// EndTimeBox: Observer closed the terminal at the deadline.
	EndTimeBox = "time_box"
	// EndStopped: the developer pressed Stop.
	EndStopped = "stopped"
)

// Deadline is the end of a run's time box: start plus the minutes, the zero
// time when the run has no time box.
func Deadline(start time.Time, minutes int) time.Time {
	if minutes <= 0 || start.IsZero() {
		return time.Time{}
	}
	return start.Add(time.Duration(minutes) * time.Minute)
}

// OverTimeBox reports whether now is past the deadline. A run with no time box
// is never over it.
func OverTimeBox(start time.Time, minutes int, now time.Time) bool {
	d := Deadline(start, minutes)
	return !d.IsZero() && now.After(d)
}

// ResolveTimeBox returns the time box in minutes for a kind: the configured
// value when it is positive, else the kind's default.
func ResolveTimeBox(k Kind, configured int) int {
	if configured > 0 {
		return configured
	}
	return k.TimeBoxMinutes
}
