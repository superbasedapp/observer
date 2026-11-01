package sandboxrelayd

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFlushHealthWhileDeliveriesStart (SBX-P2E, P2D audit F7): a health
// delivery may start while FlushHealth waits (a WaitGroup Add from zero
// during Wait, which the race detector reports); FlushHealth still returns
// only once every delivery started before it returned is done.
func TestFlushHealthWhileDeliveriesStart(t *testing.T) {
	var delivered atomic.Int64
	d := &Daemon{OnHealth: func(RunRecord, Health) {
		time.Sleep(time.Millisecond)
		delivered.Add(1)
	}}
	const runs = 40
	var wg sync.WaitGroup
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				d.FlushHealth()
			}
		}
	}()
	for i := range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := &RunState{}
			d.lower(RunRecord{RunID: fmt.Sprintf("run-%d", i)}, st, 0, CauseRefused)
		}()
	}
	wg.Wait()
	d.FlushHealth()
	close(stop)
	if got := delivered.Load(); got != runs {
		t.Fatalf("FlushHealth returned with %d of %d deliveries done", got, runs)
	}
}

// TestFlushCounterTable: the counter's states, one row each.
func TestFlushCounterTable(t *testing.T) {
	var c flushCounter
	c.wait() // idle: returns at once
	c.start()
	c.start()
	done := make(chan struct{})
	go func() { c.wait(); close(done) }()
	c.done()
	select {
	case <-done:
		t.Fatal("wait returned with one still in flight")
	case <-time.After(20 * time.Millisecond):
	}
	c.done()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wait never returned once nothing was in flight")
	}
}
