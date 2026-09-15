package quiesce

import (
	"sync"
	"time"
)

// Gate is one admission point and its in-flight counter.
//
// A caller wraps the work it admits:
//
//	if !gate.Enter() {
//	    // refuse, retryably
//	    return
//	}
//	defer gate.Leave()
//
// Enter reports false only while a drain is open. Leave must be called
// exactly once for every Enter that returned true; pairing it with defer at
// the admission site is what makes the counter correct across every exit
// path a long handler has, including panics.
//
// The zero Gate is usable and admits everything.
type Gate struct {
	mu sync.Mutex
	// inFlight is the number of admitted-but-unfinished units of work.
	inFlight int
	// draining is set by BeginDrain and cleared by Resume. While it is
	// set, Enter refuses.
	draining bool
	// retryAfter is what a refusing caller should tell its client to wait.
	// It is set by BeginDrain from the apply's own budget, so the hint is
	// the truth about this drain rather than a constant.
	retryAfter time.Duration
	// idle is closed-and-replaced whenever inFlight reaches zero, so
	// WaitIdle blocks without polling.
	idle chan struct{}
}

// defaultRetryAfter is the hint used when a drain is opened without one. It
// is deliberately short: an update that cannot drain in a minute and a half
// aborts, so telling a client to come back in five seconds is honest.
const defaultRetryAfter = 5 * time.Second

// NewGate returns an open gate.
func NewGate() *Gate { return &Gate{} }

// Enter admits one unit of work, reporting whether it was admitted. A
// refusal is not an error: it is the drain doing its job, and the caller's
// contract is to answer retryably (a 503 with Retry-After), never to fail
// the client and never to hold the connection open.
func (g *Gate) Enter() bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining {
		return false
	}
	g.inFlight++
	return true
}

// Leave releases one admitted unit of work. Calling it without a matching
// admitted Enter is a caller bug; the counter is floored at zero rather than
// going negative, because a negative in-flight count would make a drain
// complete early — the one direction that must never happen silently.
func (g *Gate) Leave() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inFlight > 0 {
		g.inFlight--
	}
	if g.inFlight == 0 && g.idle != nil {
		close(g.idle)
		g.idle = nil
	}
}

// InFlight reports the current count.
func (g *Gate) InFlight() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inFlight
}

// Draining reports whether admission is currently closed.
func (g *Gate) Draining() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.draining
}

// RetryAfter is the hint a refusing caller should pass to its client. It is
// never zero, so a refusal always carries an actionable header.
func (g *Gate) RetryAfter() time.Duration {
	if g == nil {
		return defaultRetryAfter
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.retryAfter <= 0 {
		return defaultRetryAfter
	}
	return g.retryAfter
}

// RetryAfterSeconds is RetryAfter rounded UP to whole seconds, which is the
// only unit the HTTP header takes. Rounding up rather than down means a
// client that obeys the hint never returns before the gate could have
// reopened.
func (g *Gate) RetryAfterSeconds() int {
	d := g.RetryAfter()
	secs := int(d / time.Second)
	if d%time.Second != 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	return secs
}

// BeginDrain closes admission and returns the channel that is closed when
// in-flight work reaches zero. When nothing is in flight the returned
// channel is already closed, so a caller never blocks on an idle gate.
//
// retryAfter is the hint refused callers pass on; a non-positive value uses
// the package default.
func (g *Gate) BeginDrain(retryAfter time.Duration) <-chan struct{} {
	if g == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.draining = true
	if retryAfter > 0 {
		g.retryAfter = retryAfter
	}
	if g.inFlight == 0 {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	if g.idle == nil {
		g.idle = make(chan struct{})
	}
	return g.idle
}

// Resume reopens admission. It is idempotent and must be safe to call on a
// gate that was never drained, because it is always called from a defer:
// ruling R13's guarantee is that the resume path cannot be skipped by an
// early return, a timeout or a panic.
func (g *Gate) Resume() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.draining = false
}
