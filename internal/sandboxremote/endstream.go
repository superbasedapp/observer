package sandboxremote

import (
	"context"
	"errors"
	"time"
)

// HalfCloser is a Process whose stdin side can be closed on its own (the
// box reads EOF while the stream stays open for the box's answer).
type HalfCloser interface {
	CloseWrite() error
}

// ErrHalfCloseStuck is EndStream's answer when the stdin close had not
// returned even after the cut and a second bound.
var ErrHalfCloseStuck = errors.New("sandboxremote: the stdin close did not return after the cut")

// EndStream ends a long-lived exec stream cleanly at its run's end (lane
// FX6, FX6-A1). The stream must have been opened on a context that the
// run's end does not cancel (context.WithoutCancel of the run's): a stream
// whose context is a child of the run's is already reset by the time the
// run's end is seen, and the far side reads a lost node, not a clean end.
//
// The order is fixed: the stdin side is half-closed (bounded, since a
// half-close waits behind a send that flow control holds), then the stream
// is given what is left of wait to end on its own, then it is cut (Kill)
// and released (Close). Nothing EndStream starts outlives it: the
// half-close runs in a goroutine that the cut releases, and EndStream
// waits for it, at most a second wait, and says so when it did not end.
// A Process with no separate stdin close is cut and released at once.
//
// ctx carries the caller's values and bounds the wait for a clean end: a
// ctx that is done skips that wait. The caller passes one the run's end
// does not cancel (context.WithoutCancel of the run's), as for the stream.
// The cut runs on ctx without its cancellation, bounded by wait, so a done
// ctx never leaves the stream open (fold audit N6).
func EndStream(ctx context.Context, p Process, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	var half chan error
	if hc, ok := p.(HalfCloser); ok {
		half = make(chan error, 1)
		go func() { half <- hc.CloseWrite() }()
		t := time.NewTimer(wait)
		select {
		case err := <-half:
			half = nil
			if err == nil {
				wctx, cancel := context.WithDeadline(ctx, deadline)
				_, _ = p.Wait(wctx)
				cancel()
			}
		case <-t.C:
		case <-ctx.Done():
		}
		t.Stop()
	}
	// The cut is bounded too: a vendor's Kill may be an HTTP call with no
	// timeout of its own (lane FX6, FX6-R3).
	kctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), wait)
	_ = p.Kill(kctx)
	cancel()
	_ = p.Close()
	if half == nil {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-half:
		return nil
	case <-t.C:
		return ErrHalfCloseStuck
	}
}
