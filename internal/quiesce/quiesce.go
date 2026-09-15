package quiesce

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// LiveWork is a named count of work that a drain cannot cancel and must not
// interrupt — a live dashboard PTY session, a running backfill. Unlike a
// Gate, there is no admission point to close: the honest answer is to DEFER
// the apply, not to kill someone's terminal.
type LiveWork struct {
	// Name is what the operator is told is busy ("dashboard terminal
	// sessions"). It is a fixed label, never a path or a session id.
	Name string
	// Count returns the live count. A nil Count reports zero, so a node
	// without a terminal stack (--no-dashboard) needs no special case.
	Count func() int
	// Forcible reports whether `--force` inside a maintenance window may
	// proceed despite this work being live (§3.7 step 4a: the PTY owners
	// are warned first). Work that is not forcible always defers.
	Forcible bool
}

// live reads the counter, tolerating a nil func.
func (l LiveWork) live() int {
	if l.Count == nil {
		return 0
	}
	n := l.Count()
	if n < 0 {
		return 0
	}
	return n
}

// Quiescence composes the admission gate with the live-work counters and
// performs the bounded drain of §3.7 step 4a.
//
// It is the ONE seam the apply calls. That is deliberate: the apply must not
// know that a proxy has requests and a dashboard has PTYs, only that the node
// is or is not quiet, and the counters must not know what an update is.
type Quiescence struct {
	// Gate is the proxy's admission gate. Nil means "nothing to drain",
	// which is the truth on a daemon started with the proxy disabled.
	Gate *Gate
	// Live are the counters that defer rather than drain.
	Live []LiveWork
	// Now is the clock, injected for tests. Nil uses time.Now.
	Now func() time.Time
}

// DrainOptions bounds one drain.
type DrainOptions struct {
	// Timeout is [update].drain_timeout. A non-positive value uses
	// DefaultDrainTimeout.
	Timeout time.Duration
	// Force is `observer update apply --force`: it permits an apply while
	// FORCIBLE live work is running (after its owners have been warned). It
	// never shortens the drain and never skips the in-flight wait.
	Force bool
	// InWindow reports whether an admin maintenance window currently
	// permits an apply. Force alone is not enough for forcible live work:
	// §3.7 requires BOTH, so a developer's terminal is never killed by a
	// stray flag outside a window their admin scheduled.
	InWindow bool
}

// DefaultDrainTimeout mirrors [update].drain_timeout's default.
const DefaultDrainTimeout = 90 * time.Second

// Result describes how a drain ended.
type Result struct {
	// Quiet reports that the node reached quiescence and the caller may
	// proceed with the swap.
	Quiet bool
	// Deferred reports that live work made this a DEFER rather than a
	// failure: nothing was wrong, the moment was wrong.
	Deferred bool
	// TimedOut reports that in-flight work did not reach zero within the
	// timeout. Admission has been restored before this is returned.
	TimedOut bool
	// Busy names what was live, for the operator-facing message. Fixed
	// labels only.
	Busy []string
	// InFlight is the in-flight count at the moment the drain gave up.
	InFlight int
	// Waited is how long the drain took.
	Waited time.Duration
}

// ErrDrainTimeout is returned when in-flight work never reached zero. The
// caller maps it to error_class=drain.
var ErrDrainTimeout = fmt.Errorf("quiesce: in-flight work did not reach zero within the drain timeout")

// ErrLiveWork is returned when live work defers the apply.
var ErrLiveWork = fmt.Errorf("quiesce: live work defers the apply")

// Drain closes admission, waits for in-flight work to reach zero, and
// returns a resume func the caller MUST defer.
//
// The resume func is returned on EVERY path, success included, and calling
// it is what re-opens admission after the apply finishes or fails. That is
// ruling R13 expressed as a signature rather than as a comment: a caller
// cannot obtain the drain without also obtaining the way out of it.
//
// Order matters. Live work is checked FIRST, before admission is closed:
// deferring because a developer's terminal is open must not cost that
// developer a single 503.
func (q *Quiescence) Drain(ctx context.Context, opts DrainOptions) (Result, func(), error) {
	noop := func() {}
	if q == nil {
		return Result{Quiet: true}, noop, nil
	}
	now := q.Now
	if now == nil {
		now = time.Now
	}
	started := now()

	if busy := q.busy(opts); len(busy) > 0 {
		return Result{Deferred: true, Busy: busy}, noop, fmt.Errorf("%w: %v", ErrLiveWork, busy)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultDrainTimeout
	}
	idle := q.Gate.BeginDrain(timeout)
	resume := func() { q.Gate.Resume() }

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-idle:
		return Result{Quiet: true, Waited: now().Sub(started)}, resume, nil
	case <-ctx.Done():
		resume()
		return Result{InFlight: q.Gate.InFlight(), Waited: now().Sub(started)}, noop, ctx.Err()
	case <-timer.C:
		// R13: restore admission BEFORE reporting, so the failure path can
		// never leave the node refusing traffic.
		inflight := q.Gate.InFlight()
		resume()
		return Result{
			TimedOut: true,
			InFlight: inflight,
			Waited:   now().Sub(started),
		}, noop, fmt.Errorf("%w: %d still in flight after %s", ErrDrainTimeout, inflight, timeout)
	}
}

// busy returns the labels of live work that blocks an apply right now,
// sorted so the message is stable.
func (q *Quiescence) busy(opts DrainOptions) []string {
	var busy []string
	for _, l := range q.Live {
		n := l.live()
		if n == 0 {
			continue
		}
		if l.Forcible && opts.Force && opts.InWindow {
			continue
		}
		busy = append(busy, fmt.Sprintf("%s (%d)", l.Name, n))
	}
	sort.Strings(busy)
	return busy
}

// Busy is the read-only "is anything live?" question, for `observer update
// status` and for a dry run. It never closes admission.
func (q *Quiescence) Busy() []string {
	if q == nil {
		return nil
	}
	return q.busy(DrainOptions{})
}
