package processobs

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// chanBackend hands the TEST the event channel, UNBUFFERED. That matters: a
// send completes only when the drain goroutine actually receives, so "the send
// returned" is direct evidence that capture is still being consumed. It is the
// shape of the real snapshot-diff backends, which block on send and stop
// ENUMERATING while nobody reads — the loss no drop counter can see.
type chanBackend struct {
	ch     chan RawEvent
	closed atomic.Bool
}

func newChanBackend() *chanBackend { return &chanBackend{ch: make(chan RawEvent)} }

func (b *chanBackend) Name() string { return "chan" }

func (b *chanBackend) Start(context.Context) (<-chan RawEvent, error) { return b.ch, nil }

func (b *chanBackend) Close() error { b.closed.Store(true); return nil }

// send delivers one event to the drain, FAILING (not hanging) if the drain is
// not reading. This is the assertion that the 31 s-flush stall is gone: under
// the old synchronous flush the drain sat inside PersistRuns and this send
// never completed.
func (b *chanBackend) send(t *testing.T, ev RawEvent) {
	t.Helper()
	select {
	case b.ch <- ev:
	case <-time.After(5 * time.Second):
		t.Fatalf("drain stalled: the backend could not deliver an event while the sink was busy — capture is coupled to the flush again")
	}
}

// gatedSink blocks inside PersistRuns until it is released, signalling each
// entry. It is the "31,179 ms flush" of the live incident, made deterministic:
// no sleeps, just a lock the test opens when it chooses.
type gatedSink struct {
	entered chan struct{} // buffered; one token per PersistRuns entry
	release chan struct{} // closed by the test to let every call through

	mu   sync.Mutex
	runs []ProcessRun
}

func newGatedSink(depth int) *gatedSink {
	return &gatedSink{entered: make(chan struct{}, depth), release: make(chan struct{})}
}

func (g *gatedSink) PersistRuns(_ context.Context, runs []ProcessRun) (int, error) {
	select {
	case g.entered <- struct{}{}:
	default: // the test only waits for the first few; never block on reporting
	}
	<-g.release
	g.mu.Lock()
	defer g.mu.Unlock()
	g.runs = append(g.runs, runs...)
	return len(runs), nil
}

// waitEntered blocks until PersistRuns has been entered, so a test can pin the
// flusher INSIDE a slow write before making its assertions.
func (g *gatedSink) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sink was never called: the flusher goroutine is not consuming hand-offs")
	}
}

func (g *gatedSink) snapshot() []ProcessRun {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]ProcessRun(nil), g.runs...)
}

// runInBackground starts Run and returns a channel closed when it returns.
func runInBackground(ctx context.Context, o *Observer) chan error {
	done := make(chan error, 1)
	go func() { done <- o.Run(ctx) }()
	return done
}

func waitRun(t *testing.T, done chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return: the shutdown barrier is deadlocked")
		return nil
	}
}

// execN builds n distinct unattributed exec events, so every one produces
// exactly one persisted run snapshot and the arithmetic in the conservation
// assertions is exact.
func execN(n int) []RawEvent {
	evs := make([]RawEvent, n)
	for i := range evs {
		pid := 1000 + i
		evs[i] = execEv("b", pid, 1, int64(pid)*10, "/bin/worker", []string{"worker"}, ts(i+1))
	}
	return evs
}

// TestObserverDrainKeepsConsumingWhileSinkBlocked is the task-9g regression.
// The measured failure was a 31,179 ms PersistRuns on the ONLY goroutine that
// drained the backend: for 31 s nothing was read, the backend stopped
// enumerating, and every process born and gone in that window was never
// observed. Here the sink is blocked for the whole test and the backend must
// still be able to hand over every event.
func TestObserverDrainKeepsConsumingWhileSinkBlocked(t *testing.T) {
	t.Parallel()
	const events = 12

	be := newChanBackend()
	sink := newGatedSink(events + 2)
	o := NewObserver(Options{
		Backend: be, Attributor: NewAttributor(nil, nil, nil), Sink: sink,
		CaptureUnattributed: true, BatchSize: 1, FlushInterval: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(ctx, o)

	all := execN(events)
	be.send(t, all[0])
	// Pin the flusher INSIDE the blocked write before sending the rest: from
	// here on, every successful send happened while persistence was stuck.
	sink.waitEntered(t)
	for _, ev := range all[1:] {
		be.send(t, ev)
	}

	// Nothing has been persisted — the sink never returned — yet the drain
	// consumed everything. That is exactly the property the coupling denied.
	if got := len(sink.snapshot()); got != 0 {
		t.Fatalf("sink persisted %d runs while blocked; the fake is not actually blocking", got)
	}

	close(sink.release)
	close(be.ch)
	if err := waitRun(t, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := len(sink.snapshot()); got != events {
		t.Errorf("persisted %d run snapshots, want %d — a slow sink must delay capture, never lose it", got, events)
	}
	h := o.Health().Snapshot()
	if len(h.Dropped) != 0 {
		t.Errorf("Dropped = %+v, want empty: the hand-off buffer absorbed the stall", h.Dropped)
	}
	if h.HandoffDepthMax == 0 {
		t.Error("HandoffDepthMax = 0, want > 0: batches queued behind the blocked sink and the watermark must show it")
	}
}

// TestObserverFlushOrderingPreserved pins the ordering contract: process_runs
// upserts on process_key, so an older snapshot applied after a newer one would
// resurrect a dead run as live. The single FIFO flusher must preserve emission
// order ACROSS a transient failure too — the retained rows go first.
func TestObserverFlushOrderingPreserved(t *testing.T) {
	t.Parallel()
	const events = 8

	be := newChanBackend()
	// FailFirst=1 forces the retained-then-incoming merge, so this also covers
	// the ordering of rows that were held back.
	sink := &flakySink{Err: errors.New("database is locked (5)"), FailFirst: 1}
	o := NewObserver(Options{
		Backend: be, Attributor: NewAttributor(nil, nil, nil), Sink: sink,
		CaptureUnattributed: true, BatchSize: 1, FlushInterval: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(ctx, o)

	for _, ev := range execN(events) {
		be.send(t, ev)
	}
	close(be.ch)
	if err := waitRun(t, done); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(sink.Runs) != events {
		t.Fatalf("persisted %d runs, want %d", len(sink.Runs), events)
	}
	for i, r := range sink.Runs {
		if want := 1000 + i; r.PID != want {
			t.Fatalf("run[%d] pid = %d, want %d — the sink saw snapshots out of order: %v",
				i, r.PID, want, pids(sink.Runs))
		}
	}
}

func pids(runs []ProcessRun) []int {
	out := make([]int, len(runs))
	for i, r := range runs {
		out[i] = r.PID
	}
	return out
}

// TestObserverShutdownIsABarrier pins the other half of decoupling: Run must
// not return until the flusher has finished. A daemon that returned early
// would leave a goroutine writing to a store the caller believes is closed,
// and the final batch would be lost on process exit with nothing counted.
func TestObserverShutdownIsABarrier(t *testing.T) {
	t.Parallel()

	be := newChanBackend()
	sink := newGatedSink(4)
	o := NewObserver(Options{
		Backend: be, Attributor: NewAttributor(nil, nil, nil), Sink: sink,
		// BatchSize 5 > the 3 events, so nothing flushes until shutdown: the
		// whole capture rides on the FINAL flush.
		CaptureUnattributed: true, BatchSize: 5, FlushInterval: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(ctx, o)

	for _, ev := range execN(3) {
		be.send(t, ev)
	}
	cancel()

	// The flusher is now inside the FINAL PersistRuns. Run must still be
	// waiting on it — a non-blocking check, so this is a fact, not a timing
	// guess.
	sink.waitEntered(t)
	select {
	case err := <-done:
		t.Fatalf("Run returned (%v) while the final flush was still in the sink — the shutdown barrier is missing", err)
	default:
	}

	close(sink.release)
	if err := waitRun(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if got := len(sink.snapshot()); got != 3 {
		t.Errorf("persisted %d runs after shutdown, want 3 — the final batch must not be lost", got)
	}
	if !be.closed.Load() {
		t.Error("backend Close not called")
	}
}

// TestObserverHandoffOverflowIsCounted pins the honesty rule on the new
// non-blocking hand-off: the drain never blocks on the flusher, but "never
// blocks" must not decay into "quietly forgets". When the hand-off buffer AND
// the drain-side backlog are both full, the OLDEST rows are released under
// DropFlushBacklog and every produced snapshot is still accounted for.
func TestObserverHandoffOverflowIsCounted(t *testing.T) {
	t.Parallel()
	const events = 21

	be := newChanBackend()
	sink := newGatedSink(4)
	// MaxRetainedRuns 2 with BatchSize 1 gives the minimum hand-off (8
	// batches) and a 1-row drain backlog, so the pipeline can absorb exactly
	// 10 runs behind a wedged sink: 1 in flight + 8 buffered + 1 held.
	o := NewObserver(Options{
		Backend: be, Attributor: NewAttributor(nil, nil, nil), Sink: sink,
		CaptureUnattributed: true, BatchSize: 1, MaxRetainedRuns: 2, FlushInterval: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(ctx, o)

	all := execN(events)
	be.send(t, all[0])
	sink.waitEntered(t) // one batch is now pinned inside the sink
	for _, ev := range all[1:] {
		be.send(t, ev) // still non-blocking for the drain, overflowing or not
	}

	close(sink.release)
	close(be.ch)
	if err := waitRun(t, done); err != nil {
		t.Fatalf("Run: %v", err)
	}

	h := o.Health().Snapshot()
	if h.FlushBacklogHits == 0 {
		t.Error("FlushBacklogHits = 0, want > 0: the hand-off buffer must have been found full")
	}
	dropped := h.Dropped[DropFlushBacklog]
	if dropped == 0 {
		t.Fatalf("Dropped = %+v, want flush_backlog > 0 once both buffers overflow", h.Dropped)
	}
	// The conservation law: every snapshot the pipeline produced is either in
	// the sink or in a NAMED counter. A run that is neither is the silent loss
	// this whole task queue exists to eliminate.
	persisted := int64(len(sink.snapshot()))
	var accounted int64
	for _, n := range h.Dropped {
		accounted += n
	}
	if persisted+accounted != events {
		t.Errorf("persisted %d + dropped %d = %d, want %d: %+v",
			persisted, accounted, persisted+accounted, events, h.Dropped)
	}
	if persisted == 0 {
		t.Error("persisted 0 runs: overflow must shed the OLDEST rows, not everything")
	}
}

// ctxRespectingSink is the sink a REAL store is: it checks the context before
// it writes anything, exactly as database/sql does on every Exec/Query. Under
// the gatedSink above (which ignores its context entirely) the shutdown path
// looked healthy while, against the actual store, it wrote nothing at all.
type ctxRespectingSink struct {
	mu       sync.Mutex
	runs     []ProcessRun
	sawCtxs  []context.Context
	failures int
}

func (s *ctxRespectingSink) PersistRuns(ctx context.Context, runs []ProcessRun) (int, error) {
	s.mu.Lock()
	s.sawCtxs = append(s.sawCtxs, ctx)
	s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		s.mu.Lock()
		s.failures++
		s.mu.Unlock()
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs = append(s.runs, runs...)
	return len(runs), nil
}

func (s *ctxRespectingSink) persisted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.runs)
}

func (s *ctxRespectingSink) failed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failures
}

// deadlines reports, per observed PersistRuns call, whether the context carried
// a deadline. The shutdown flushes must carry one; the live-path flushes
// inherit whatever the caller's context had (none, in these tests).
func (s *ctxRespectingSink) deadlines() []bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]bool, 0, len(s.sawCtxs))
	for _, c := range s.sawCtxs {
		_, ok := c.Deadline()
		out = append(out, ok)
	}
	return out
}

// TestShutdownFlushSurvivesCancellation is the 9g follow-up regression, and the
// reason it needs its own sink: TestObserverShutdownIsABarrier already covers
// the barrier, but its gatedSink never looks at the context, so it passed
// throughout the window in which the shutdown flush wrote nothing.
//
// Cancel Run with a batch still pending. Against a context-respecting sink the
// final flush must still PERSIST those runs, not count them as sink_shutdown.
//
// Mutation proof: pass the cancelled ctx to flushPending in runFlusher (the
// pre-fix code) and this fails with "persisted 0 runs after cancellation".
func TestShutdownFlushSurvivesCancellation(t *testing.T) {
	t.Parallel()

	be := newChanBackend()
	sink := &ctxRespectingSink{}
	o := NewObserver(Options{
		Backend: be, Attributor: NewAttributor(nil, nil, nil), Sink: sink,
		// BatchSize 5 > the 3 events and an hour-long tick, so nothing flushes
		// before shutdown: the whole capture rides on the final flush.
		CaptureUnattributed: true, BatchSize: 5, FlushInterval: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(ctx, o)

	for _, ev := range execN(3) {
		be.send(t, ev)
	}
	cancel()

	if err := waitRun(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if got := sink.persisted(); got != 3 {
		t.Errorf("persisted %d runs after cancellation, want 3 — the final flush is still using the cancelled context, so a real store refuses it and the batch is lost", got)
	}
	if got := sink.failed(); got != 0 {
		t.Errorf("sink refused %d calls, want 0 — no shutdown flush may arrive with an already-cancelled context", got)
	}
	h := o.Health().Snapshot()
	if n := h.Dropped[DropSinkShutdown]; n != 0 {
		t.Errorf("Dropped[sink_shutdown] = %d, want 0 — the rows were persistable; counting them honestly is not a substitute for writing them", n)
	}
	// Detached, but not unbounded: the shutdown flush must carry a deadline so
	// a wedged sink cannot hold Run's barrier open forever.
	for i, hasDeadline := range sink.deadlines() {
		if !hasDeadline {
			t.Errorf("shutdown flush #%d had no deadline — a detached context without one makes the shutdown barrier unbounded", i)
		}
	}
}

// TestShutdownFlushDrainsBufferedBatches pins the OTHER half: cancellation can
// leave batches already sitting in the hand-off buffer, and those are drained
// by the same `for range in` loop that used to hand them the cancelled context.
// They are not the "final" flush, so a fix that only detached the last call
// would still lose every one of them.
//
// Mutation proof: make shutdownAwareContext return ctx unconditionally and this
// fails with "persisted 0 of 6 buffered runs".
func TestShutdownFlushDrainsBufferedBatches(t *testing.T) {
	t.Parallel()
	const events = 6

	be := newChanBackend()
	sink := &ctxRespectingSink{}
	// BatchSize 1 hands every event off immediately, so by the time the test
	// cancels there are batches queued in the hand-off channel behind the
	// flusher rather than sitting in the drain's own slice.
	o := NewObserver(Options{
		Backend: be, Attributor: NewAttributor(nil, nil, nil), Sink: sink,
		CaptureUnattributed: true, BatchSize: 1, FlushInterval: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(ctx, o)

	for _, ev := range execN(events) {
		be.send(t, ev)
	}
	cancel()

	if err := waitRun(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if got := sink.persisted(); got != events {
		t.Errorf("persisted %d of %d buffered runs — batches already in the hand-off must survive cancellation too, not just the final one", got, events)
	}
	h := o.Health().Snapshot()
	var dropped int64
	for _, n := range h.Dropped {
		dropped += n
	}
	if dropped != 0 {
		t.Errorf("dropped %d runs on a clean cancellation: %+v", dropped, h.Dropped)
	}
}

// TestShutdownFlushTimeoutIsBounded pins the ceiling. A detached context with
// no deadline would make Run's shutdown barrier wait forever on a wedged sink —
// trading one silent failure (lost rows) for a worse one (a daemon that never
// exits). The deadline is created ONCE and shared across the whole post-cancel
// drain, so N stuck batches cost one budget, not N.
//
// Mutation proof: drop the WithTimeout (return the detached context bare) and
// this fails with "Run did not return: the shutdown barrier is deadlocked".
func TestShutdownFlushTimeoutIsBounded(t *testing.T) {
	t.Parallel()

	be := newChanBackend()
	// A sink that blocks until ITS context is done — the wedged-database case.
	sink := &blockUntilCtxDoneSink{}
	o := NewObserver(Options{
		Backend: be, Attributor: NewAttributor(nil, nil, nil), Sink: sink,
		CaptureUnattributed: true, BatchSize: 5, FlushInterval: time.Hour,
		ShutdownFlushTimeout: 50 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(ctx, o)

	for _, ev := range execN(3) {
		be.send(t, ev)
	}
	cancel()

	if err := waitRun(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	// The rows could not be written, so they must be COUNTED — the conservation
	// law survives the bound.
	h := o.Health().Snapshot()
	if n := h.Dropped[DropSinkShutdown]; n != 3 {
		t.Errorf("Dropped[sink_shutdown] = %d, want 3 — a timed-out shutdown flush must still name its losses: %+v", n, h.Dropped)
	}
}

// blockUntilCtxDoneSink stands in for a database whose write lock is held: it
// makes no progress and returns only when its own context expires.
type blockUntilCtxDoneSink struct{}

func (blockUntilCtxDoneSink) PersistRuns(ctx context.Context, _ []ProcessRun) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

// TestShutdownFlushTimeoutDefault pins the default sizing decision: the budget
// must outlast SQLite's 30 s busy_timeout, or a contended shutdown abandons the
// batch at exactly the moment the retry would have succeeded.
func TestShutdownFlushTimeoutDefault(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		set  time.Duration
		want time.Duration
	}{
		{name: "unset applies the default", set: 0, want: DefaultShutdownFlushTimeout},
		{name: "negative applies the default", set: -time.Second, want: DefaultShutdownFlushTimeout},
		{name: "explicit value is honoured", set: 3 * time.Second, want: 3 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := NewObserver(Options{
				Backend: newChanBackend(), Attributor: NewAttributor(nil, nil, nil),
				Sink: &ctxRespectingSink{}, ShutdownFlushTimeout: tc.set,
			})
			if o.shutdownFlushTimeout != tc.want {
				t.Errorf("shutdownFlushTimeout = %v, want %v", o.shutdownFlushTimeout, tc.want)
			}
		})
	}
	if DefaultShutdownFlushTimeout <= 30*time.Second {
		t.Errorf("DefaultShutdownFlushTimeout = %v, must exceed SQLite's 30s busy_timeout or a contended shutdown gives up before the lock clears",
			DefaultShutdownFlushTimeout)
	}
}

// TestHandoffCapacity pins the sizing table: the hand-off and the drain
// backlog SPLIT one MaxRetainedRuns budget rather than each claiming it, so
// the pipeline holds at most ~2× the operator's knob (the flusher's retention
// plus everything still upstream of it) instead of multiplying it.
func TestHandoffCapacity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name               string
		maxRetained, batch int
		wantBatches        int
		wantBacklogRuns    int
		wantHeldRowsAtMost int
	}{
		{
			name: "defaults split the budget", maxRetained: DefaultMaxRetainedRuns, batch: 250,
			wantBatches: 10, wantBacklogRuns: 2500, wantHeldRowsAtMost: DefaultMaxRetainedRuns,
		},
		{
			name: "tiny cap still gets the floor", maxRetained: 2, batch: 1,
			wantBatches: minHandoffBatches, wantBacklogRuns: 1, wantHeldRowsAtMost: minHandoffBatches + 1,
		},
		{
			// Retention disabled is a decision about SINK FAILURES, not about
			// the hand-off; sizing falls back to the default budget.
			name: "retention disabled still sizes the hand-off", maxRetained: -1, batch: 250,
			wantBatches: 10, wantBacklogRuns: 2500, wantHeldRowsAtMost: DefaultMaxRetainedRuns,
		},
		{
			name: "huge cap is clamped", maxRetained: 10_000_000, batch: 1,
			wantBatches: maxHandoffBatches, wantBacklogRuns: 5_000_000, wantHeldRowsAtMost: 5_000_064,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			batches, backlog := handoffCapacity(tc.maxRetained, tc.batch)
			if batches != tc.wantBatches || backlog != tc.wantBacklogRuns {
				t.Fatalf("handoffCapacity(%d,%d) = (%d,%d), want (%d,%d)",
					tc.maxRetained, tc.batch, batches, backlog, tc.wantBatches, tc.wantBacklogRuns)
			}
			if held := batches*tc.batch + backlog; held > tc.wantHeldRowsAtMost {
				t.Errorf("worst-case rows upstream of the flusher = %d, want <= %d", held, tc.wantHeldRowsAtMost)
			}
		})
	}
}
