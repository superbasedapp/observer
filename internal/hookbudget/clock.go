package hookbudget

import (
	"sync"
	"time"
)

// The harness clock (roadmap F0-3 revision 2.1, the JSP-2 laptop half).
// Go's monotonic clock advances in steps of about 0.52 ms on Windows, a
// quarter of the 2 ms sidecar budget, so the harness times every sample
// through this seam instead: QueryPerformanceCounter on Windows
// (clock_windows.go), Go's monotonic clock elsewhere (clock_other.go),
// where its step is already nanoseconds. The report names the clock, its
// frequency and the resolution measured on the machine that ran it.

// Stamp is one clock reading, in ticks of the harness clock.
type Stamp int64

// ClockInfo describes the clock a report was timed with.
type ClockInfo struct {
	// Source names the counter: "QueryPerformanceCounter" or
	// "go monotonic".
	Source string
	// FrequencyHz is the counter's ticks per second.
	FrequencyHz int64
	// Resolution is the smallest step measured between two readings on
	// this machine.
	Resolution time.Duration
	// GoMonotonicStep is the smallest step of Go's own monotonic clock
	// measured on the same machine, for comparison (about 0.52 ms on
	// Windows, nanoseconds elsewhere).
	GoMonotonicStep time.Duration
}

// clock is the resolved counter: a platform counter when one is available,
// else Go's monotonic clock in nanosecond ticks.
type clock struct {
	source string
	freq   int64
	read   func() int64
}

// monoBase anchors the fallback counter so its ticks stay small.
var monoBase = time.Now()

// goMonotonic is the fallback counter: nanoseconds since monoBase.
var goMonotonic = clock{source: "go monotonic", freq: int64(time.Second), read: func() int64 { return int64(time.Since(monoBase)) }}

// harnessClock is the clock every sample is timed with.
var harnessClock = resolveClock(platformClock())

// resolveClock keeps the platform counter when it reported a usable
// frequency and the fallback otherwise.
func resolveClock(c clock, ok bool) clock {
	if !ok || c.freq <= 0 || c.read == nil {
		return goMonotonic
	}
	return c
}

// Now reads the harness clock.
func Now() Stamp { return Stamp(harnessClock.read()) }

// Since returns the time elapsed from start, at the clock's full
// resolution.
func Since(start Stamp) time.Duration {
	return TicksToDuration(int64(Now()-start), harnessClock.freq)
}

// TicksToDuration converts a tick count at freq ticks per second to a
// duration without overflowing for any count an hour or less long.
func TicksToDuration(ticks, freq int64) time.Duration {
	if freq <= 0 {
		return 0
	}
	sec, rem := ticks/freq, ticks%freq
	return time.Duration(sec)*time.Second + time.Duration(rem*int64(time.Second)/freq)
}

// DurationToTicks is the inverse of TicksToDuration, rounded to the
// nearest tick, for the report's tick columns.
func DurationToTicks(d time.Duration, freq int64) int64 {
	sec, rem := int64(d/time.Second), int64(d%time.Second)
	return sec*freq + (rem*freq+int64(time.Second)/2)/int64(time.Second)
}

// clockInfo is measured once per process, on first use.
var (
	clockOnce sync.Once
	clockInfo ClockInfo
)

// CurrentClock describes the harness clock on this machine, measuring its
// resolution and Go's monotonic step the first time it is called (a few
// milliseconds at most).
func CurrentClock() ClockInfo {
	clockOnce.Do(func() {
		clockInfo = ClockInfo{
			Source:          harnessClock.source,
			FrequencyHz:     harnessClock.freq,
			Resolution:      TicksToDuration(minStep(harnessClock.read), harnessClock.freq),
			GoMonotonicStep: TicksToDuration(minStep(goMonotonic.read), goMonotonic.freq),
		}
	})
	return clockInfo
}

// minStep returns the smallest nonzero difference between two successive
// readings of read, over a bounded number of transitions (and a 50 ms cap,
// so a coarse clock cannot hold the caller). Zero means no step was seen.
func minStep(read func() int64) int64 {
	const transitions = 200
	deadline := time.Now().Add(50 * time.Millisecond)
	var best int64
	prev := read()
	for seen := 0; seen < transitions && time.Now().Before(deadline); {
		cur := read()
		if d := cur - prev; d > 0 {
			if best == 0 || d < best {
				best = d
			}
			seen++
		}
		prev = cur
	}
	return best
}
