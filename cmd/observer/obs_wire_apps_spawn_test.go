package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/planechoice"
)

// TestReceiverEnsureStartsAGatedReceiverOnce pins POLISH-F2 finding F2-1: in
// an edition where AI Apps is compiled in but off at boot (the developer
// default) the component gate keeps the receiver goroutine stopped, so the
// first enable must start it, and only once. Before the fix nothing served
// the request and the enable answered "no answer" after the full wait.
func TestReceiverEnsureStartsAGatedReceiverOnce(t *testing.T) {
	ctl := newReceiverCtl()
	var starts atomic.Int32
	ctl.setSpawn(func() {
		starts.Add(1)
		// The started goroutine binds and reports, as runOTLPReceiver does.
		go ctl.report(planechoice.Receiver{State: planechoice.ReceiverListening, HTTPAddr: "127.0.0.1:4318"})
	})
	ctx := context.Background()
	if got := ctl.ensure(ctx, 5*time.Second); got.State != planechoice.ReceiverListening {
		t.Fatalf("first enable: receiver %q, want listening", got.State)
	}
	if got := ctl.ensure(ctx, 5*time.Second); got.State != planechoice.ReceiverListening {
		t.Fatalf("second enable: receiver %q, want listening", got.State)
	}
	if n := starts.Load(); n != 1 {
		t.Fatalf("receiver started %d times, want 1", n)
	}
}

// TestReceiverEnsureWithoutSpawnStillTimesOut keeps the no-answer path: with
// no goroutine and nothing to start, an enable reads as no answer.
func TestReceiverEnsureWithoutSpawnStillTimesOut(t *testing.T) {
	ctl := newReceiverCtl()
	if got := ctl.ensure(context.Background(), 50*time.Millisecond); got.State != planechoice.ReceiverNoAnswer {
		t.Fatalf("receiver %q, want no answer", got.State)
	}
}
