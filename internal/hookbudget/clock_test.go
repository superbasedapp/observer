package hookbudget

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

// windowsClockCeiling is the resolution the Windows harness clock must
// beat: well under the 0.52 ms step of Go's monotonic clock there, and
// fine enough for the microsecond seam rows.
const windowsClockCeiling = 10 * time.Microsecond

// TestWindowsClockResolution is the milestone's acceptance: on Windows the
// harness times with QueryPerformanceCounter and its measured resolution
// is under 10 microseconds. Off Windows Go's monotonic clock is already
// nanoseconds, so there is nothing to prove.
func TestWindowsClockResolution(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the high-resolution clock is Windows-only; Go's monotonic clock steps in nanoseconds here")
	}
	c := CurrentClock()
	if c.Source != "QueryPerformanceCounter" {
		t.Fatalf("clock source = %q, want QueryPerformanceCounter", c.Source)
	}
	if c.Resolution <= 0 || c.Resolution >= windowsClockCeiling {
		t.Fatalf("clock resolution = %s, want above zero and under %s (Go monotonic step here %s)", c.Resolution, windowsClockCeiling, c.GoMonotonicStep)
	}
	t.Logf("QueryPerformanceCounter: %d Hz, resolution %s; Go monotonic step %s", c.FrequencyHz, c.Resolution, c.GoMonotonicStep)
}

// TestClockDescribesItself: every platform reports a named clock with a
// positive frequency and a measured resolution, and Since advances.
func TestClockDescribesItself(t *testing.T) {
	c := CurrentClock()
	if c.Source == "" || c.FrequencyHz <= 0 || c.Resolution <= 0 {
		t.Fatalf("clock = %+v, want a source, a frequency and a resolution", c)
	}
	start := Now()
	time.Sleep(2 * time.Millisecond)
	if d := Since(start); d < time.Millisecond || d > time.Minute {
		t.Fatalf("Since after a 2 ms sleep = %s", d)
	}
}

func TestResolveClockFallsBack(t *testing.T) {
	read := func() int64 { return 7 }
	cases := []struct {
		name string
		in   clock
		ok   bool
		want string
	}{
		{"platform counter", clock{source: "qpc", freq: 10_000_000, read: read}, true, "qpc"},
		{"not available", clock{}, false, goMonotonic.source},
		{"zero frequency", clock{source: "qpc", read: read}, true, goMonotonic.source},
		{"no reader", clock{source: "qpc", freq: 10_000_000}, true, goMonotonic.source},
	}
	for _, tc := range cases {
		if got := resolveClock(tc.in, tc.ok).source; got != tc.want {
			t.Errorf("%s: source %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestTickConversion(t *testing.T) {
	cases := []struct {
		ticks, freq int64
		want        time.Duration
	}{
		{0, 10_000_000, 0},
		{1, 10_000_000, 100 * time.Nanosecond},
		{5_200, 10_000_000, 520 * time.Microsecond},
		{10_000_000, 10_000_000, time.Second},
		{36_000_000_000, 10_000_000, time.Hour},
		{3, 3, time.Second},
		{1, 3, 333333333 * time.Nanosecond},
		{1_500, int64(time.Second), 1500 * time.Nanosecond},
		{1, 0, 0},
	}
	for _, tc := range cases {
		if got := TicksToDuration(tc.ticks, tc.freq); got != tc.want {
			t.Errorf("TicksToDuration(%d, %d) = %s, want %s", tc.ticks, tc.freq, got, tc.want)
		}
		if tc.freq > 0 && tc.want != 0 {
			if back := DurationToTicks(tc.want, tc.freq); back != tc.ticks {
				t.Errorf("DurationToTicks(%s, %d) = %d, want %d", tc.want, tc.freq, back, tc.ticks)
			}
		}
	}
}

// TestReportCarriesTheClock: both renderings name the clock, its frequency
// and its resolution, and the JSON rows carry ticks beside nanoseconds.
func TestReportCarriesTheClock(t *testing.T) {
	r := NewReport("windows/amd64", "", map[ID][]time.Duration{Seam: {time.Microsecond}})
	r.Clock = ClockInfo{Source: "QueryPerformanceCounter", FrequencyHz: 10_000_000, Resolution: 100 * time.Nanosecond, GoMonotonicStep: 520 * time.Microsecond}
	var text bytes.Buffer
	if err := r.Text(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "clock: QueryPerformanceCounter, 10000000 Hz, resolution 100ns (Go monotonic step here 520µs)") {
		t.Errorf("text report lacks the clock line:\n%s", text.String())
	}
	var js bytes.Buffer
	if err := r.JSON(&js); err != nil {
		t.Fatal(err)
	}
	var back struct {
		Clock struct {
			Source       string `json:"source"`
			FrequencyHz  int64  `json:"frequency_hz"`
			ResolutionNs int64  `json:"resolution_ns"`
			GoStepNs     int64  `json:"go_monotonic_step_ns"`
		} `json:"clock"`
		Rows []struct {
			ID       ID    `json:"id"`
			P99      int64 `json:"p99_ns"`
			P99Ticks int64 `json:"p99_ticks"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(js.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Clock.Source != "QueryPerformanceCounter" || back.Clock.FrequencyHz != 10_000_000 || back.Clock.ResolutionNs != 100 || back.Clock.GoStepNs != 520_000 {
		t.Errorf("JSON clock = %+v", back.Clock)
	}
	for _, row := range back.Rows {
		if row.ID == Seam && (row.P99 != 1000 || row.P99Ticks != 10) {
			t.Errorf("seam row p99 = %d ns / %d ticks, want 1000 ns / 10 ticks", row.P99, row.P99Ticks)
		}
	}
}
