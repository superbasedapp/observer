package quiesce

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestGateAdmissionAndCounting walks the Gate's contract as a table: the
// counter is what a drain waits on, so an off-by-one here is an apply that
// swaps a binary out from under a live request.
func TestGateAdmissionAndCounting(t *testing.T) {
	g := NewGate()
	if !g.Enter() {
		t.Fatal("a fresh gate refused admission")
	}
	if got := g.InFlight(); got != 1 {
		t.Fatalf("InFlight = %d, want 1", got)
	}
	if g.Draining() {
		t.Fatal("a fresh gate reports draining")
	}
	g.Leave()
	if got := g.InFlight(); got != 0 {
		t.Fatalf("InFlight after Leave = %d, want 0", got)
	}
	// An unmatched Leave must floor at zero. A negative count would make a
	// later drain complete EARLY, which is the one direction that must
	// never happen silently.
	g.Leave()
	if got := g.InFlight(); got != 0 {
		t.Fatalf("InFlight after an unmatched Leave = %d, want 0 (never negative)", got)
	}
	// A nil gate admits everything, so a daemon with no proxy needs no
	// special case at the call site.
	var nilGate *Gate
	if !nilGate.Enter() {
		t.Fatal("a nil gate refused admission")
	}
	nilGate.Leave()
	if nilGate.RetryAfterSeconds() < 1 {
		t.Fatal("a nil gate produced a zero Retry-After hint")
	}
}

// TestGateRefusesWhileDrainingAndResumes is R13 at the gate level: a drain
// closes admission, and Resume reopens it — even when the drain never
// completed.
func TestGateRefusesWhileDraining(t *testing.T) {
	g := NewGate()
	if !g.Enter() {
		t.Fatal("first Enter refused")
	}
	idle := g.BeginDrain(7 * time.Second)
	if g.Enter() {
		t.Fatal("the gate admitted a new request while draining")
	}
	if !g.Draining() {
		t.Fatal("Draining() = false during a drain")
	}
	if got := g.RetryAfterSeconds(); got != 7 {
		t.Fatalf("RetryAfterSeconds = %d, want 7 (the drain's own budget)", got)
	}
	select {
	case <-idle:
		t.Fatal("the idle channel closed while a request was still in flight")
	default:
	}
	g.Leave()
	select {
	case <-idle:
	case <-time.After(time.Second):
		t.Fatal("the idle channel did not close when in-flight reached zero")
	}
	g.Resume()
	if !g.Enter() {
		t.Fatal("the gate did not reopen after Resume")
	}
	g.Leave()
}

// TestRetryAfterSecondsRoundsUp: a client that obeys the hint must never
// come back before the gate could have reopened.
func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want int
	}{
		{0, 5}, // the package default
		{500 * time.Millisecond, 1},
		{1 * time.Second, 1},
		{1500 * time.Millisecond, 2},
		{90 * time.Second, 90},
	} {
		g := NewGate()
		g.BeginDrain(tc.in)
		if got := g.RetryAfterSeconds(); got != tc.want {
			t.Errorf("RetryAfterSeconds(%s) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestDrainWaitsForInFlightThenProceeds is the happy path: the request that
// was already running finishes, and only then does the caller get its go
// ahead.
func TestDrainWaitsForInFlightThenProceeds(t *testing.T) {
	g := NewGate()
	if !g.Enter() {
		t.Fatal("Enter refused")
	}
	q := &Quiescence{Gate: g}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(60 * time.Millisecond)
		g.Leave()
	}()

	res, resume, err := q.Drain(context.Background(), DrainOptions{Timeout: 5 * time.Second})
	defer resume()
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if !res.Quiet {
		t.Fatalf("Drain result = %+v, want Quiet", res)
	}
	if res.Waited <= 0 {
		t.Error("Drain reported a zero wait even though a request was in flight")
	}
	wg.Wait()
	resume()
	if !g.Enter() {
		t.Fatal("admission was not restored by the resume func")
	}
	g.Leave()
}

// TestDrainTimeoutAbortsAndRestoresAdmission is ruling R13's whole point,
// and the plan's failing-first requirement: "a drain that never reaches zero
// aborts within drain_timeout and RESUMES admission".
func TestDrainTimeoutAbortsAndRestoresAdmission(t *testing.T) {
	g := NewGate()
	if !g.Enter() {
		t.Fatal("Enter refused")
	}
	// Nothing ever calls Leave: this request never finishes.
	q := &Quiescence{Gate: g}
	res, resume, err := q.Drain(context.Background(), DrainOptions{Timeout: 40 * time.Millisecond})
	defer resume()
	if err == nil || !errors.Is(err, ErrDrainTimeout) {
		t.Fatalf("Drain err = %v, want ErrDrainTimeout", err)
	}
	if !res.TimedOut {
		t.Fatalf("result = %+v, want TimedOut", res)
	}
	if res.InFlight != 1 {
		t.Errorf("result.InFlight = %d, want 1", res.InFlight)
	}
	// The node must NOT be left refusing traffic. This assertion is the
	// difference between a bounded drain and an outage.
	if g.Draining() {
		t.Fatal("the gate is still draining after a timed-out drain — R13 violated")
	}
	if !g.Enter() {
		t.Fatal("admission was not restored after a timed-out drain — R13 violated")
	}
	g.Leave()
}

// TestLiveWorkDefersUnlessForcedInWindow pins §3.7 step 4a's PTY rule: a live
// dashboard terminal DEFERS the apply, and only --force INSIDE an admin
// maintenance window proceeds. Neither one alone is enough.
func TestLiveWorkDefersUnlessForcedInWindow(t *testing.T) {
	ptys := 1
	mk := func() *Quiescence {
		return &Quiescence{
			Gate: NewGate(),
			Live: []LiveWork{
				{Name: "dashboard terminal sessions", Count: func() int { return ptys }, Forcible: true},
				{Name: "backfill", Count: func() int { return 0 }},
			},
		}
	}
	for _, tc := range []struct {
		name        string
		force       bool
		inWindow    bool
		wantDefer   bool
		wantBusyLen int
	}{
		{"neither", false, false, true, 1},
		{"force alone is not enough", true, false, true, 1},
		{"a window alone is not enough", false, true, true, 1},
		{"force inside a window proceeds", true, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := mk()
			res, resume, err := q.Drain(context.Background(), DrainOptions{
				Timeout: time.Second, Force: tc.force, InWindow: tc.inWindow,
			})
			defer resume()
			if tc.wantDefer {
				if err == nil || !errors.Is(err, ErrLiveWork) {
					t.Fatalf("Drain err = %v, want ErrLiveWork", err)
				}
				if !res.Deferred {
					t.Fatalf("result = %+v, want Deferred", res)
				}
				if len(res.Busy) != tc.wantBusyLen {
					t.Errorf("Busy = %v, want %d entries", res.Busy, tc.wantBusyLen)
				}
				// Deferring must not cost a single 503: admission is never
				// closed on this path.
				if q.Gate.Draining() {
					t.Error("the gate was closed for a DEFERRED apply — a live PTY must not cost the proxy a refusal")
				}
				return
			}
			if err != nil {
				t.Fatalf("Drain: %v", err)
			}
			if !res.Quiet {
				t.Fatalf("result = %+v, want Quiet", res)
			}
		})
	}
}

// TestNonForcibleLiveWorkAlwaysDefers: a backfill is not a terminal whose
// owner can be warned; --force must not run over it.
func TestNonForcibleLiveWorkAlwaysDefers(t *testing.T) {
	q := &Quiescence{
		Gate: NewGate(),
		Live: []LiveWork{{Name: "backfill", Count: func() int { return 2 }}},
	}
	_, resume, err := q.Drain(context.Background(), DrainOptions{Force: true, InWindow: true, Timeout: time.Second})
	defer resume()
	if err == nil || !errors.Is(err, ErrLiveWork) {
		t.Fatalf("Drain err = %v, want ErrLiveWork even under --force in a window", err)
	}
}

// TestBusyIsReadOnly: the status surface must be able to ask "is anything
// live?" without closing admission.
func TestBusyIsReadOnly(t *testing.T) {
	q := &Quiescence{Gate: NewGate(), Live: []LiveWork{
		{Name: "dashboard terminal sessions", Count: func() int { return 3 }, Forcible: true},
	}}
	busy := q.Busy()
	if len(busy) != 1 || busy[0] != "dashboard terminal sessions (3)" {
		t.Fatalf("Busy = %v", busy)
	}
	if q.Gate.Draining() {
		t.Fatal("Busy closed admission")
	}
	// A nil Count func reports zero rather than panicking, so a daemon
	// started with --no-dashboard needs no branch at the call site.
	q2 := &Quiescence{Gate: NewGate(), Live: []LiveWork{{Name: "terminals"}}}
	if got := q2.Busy(); len(got) != 0 {
		t.Fatalf("a nil Count func reported %v, want nothing", got)
	}
}

// TestNilQuiescenceIsQuiet: a daemon with neither proxy nor dashboard is
// trivially quiet, and the apply needs no special case for it.
func TestNilQuiescenceIsQuiet(t *testing.T) {
	var q *Quiescence
	res, resume, err := q.Drain(context.Background(), DrainOptions{})
	defer resume()
	if err != nil || !res.Quiet {
		t.Fatalf("nil Quiescence: res=%+v err=%v, want quiet", res, err)
	}
}

// TestDrainHonoursContextCancellationAndResumes: a cancelled apply must not
// leave the node refusing traffic either.
func TestDrainHonoursContextCancellationAndResumes(t *testing.T) {
	g := NewGate()
	g.Enter()
	q := &Quiescence{Gate: g}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	_, resume, err := q.Drain(ctx, DrainOptions{Timeout: 10 * time.Second})
	defer resume()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Drain err = %v, want context.Canceled", err)
	}
	if g.Draining() {
		t.Fatal("a cancelled drain left the gate closed — R13 violated")
	}
}
