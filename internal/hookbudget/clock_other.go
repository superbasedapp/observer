//go:build !windows

package hookbudget

// platformClock has no separate counter off Windows: Go's monotonic clock
// already steps in nanoseconds there, so the harness uses it.
func platformClock() (clock, bool) { return clock{}, false }
