package waltest

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ErrFull is the NEUTRAL capacity-exceeded sentinel the conformance suite
// asserts against. A store's native full error (edge wal.ErrWALFull) is mapped
// onto this by the factory's adapter closure so the neutral package need not
// import the edge package.
var ErrFull = errors.New("waltest: WAL depth cap reached")

// Record is the neutral projection of a drained WAL row the conformance suite
// inspects. It intentionally omits any disposition — that is an edge extension
// outside the common contract.
type Record struct {
	Seq          int64
	Signal       string
	DedupKey     string
	PayloadVer   int
	Payload      []byte
	AttemptCount int
}

// CommonConfig is the pinned tuning the factory receives. The suite chooses
// small values so capacity/quarantine arms need only a handful of operations,
// and derives its clock advances from BackoffMax so it is robust to either a flat
// (edge) or an exponential backoff schedule.
type CommonConfig struct {
	MaxDepth    int
	MaxAttempts int
	BackoffMin  time.Duration
	BackoffMax  time.Duration
	// DBPath is a per-store file path the factory opens (the suite generates a
	// unique path per store; the neutral suite never reopens it).
	DBPath string
}

// CommonStore is the P0-9-shaped surface both WAL stores satisfy through a
// trivial adapter. MarkFailed takes only (seq, err): a store whose native
// MarkFailed is richer maps the common form to a transient-retry failure with a
// backoff-derived next-attempt time.
type CommonStore interface {
	Enqueue(ctx context.Context, signal string, payload []byte) error
	Drain(ctx context.Context, limit int) ([]Record, error)
	MarkApplied(ctx context.Context, seq int64) error
	MarkFailed(ctx context.Context, seq int64, err error) error
	Depth(ctx context.Context) (int64, error)
	GCApplied(ctx context.Context, before time.Time) (int64, error)
}

// clock is the controllable clock the suite advances by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(base time.Time) *clock { return &clock{t: base} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Factory builds a fresh CommonStore over cfg + the injected clock.
type Factory func(cfg CommonConfig, now func() time.Time) CommonStore

// conformBase is the fixed midday anchor for every sub-test's clock.
var conformBase = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// newCommonConfig returns the pinned small config with a unique DB path.
func newCommonConfig(t *testing.T) CommonConfig {
	return CommonConfig{
		MaxDepth:    3,
		MaxAttempts: 3,
		BackoffMin:  1 * time.Second,
		BackoffMax:  60 * time.Second,
		DBPath:      filepath.Join(t.TempDir(), "wal.db"),
	}
}

// RunStorageConformance drives the shared COMMON-contract assertions against the
// store the factory builds. Each sub-test gets a fresh store, a fresh controllable
// clock, and a unique DB path, and advances the clock by hand — there are NO
// sleeps.
func RunStorageConformance(t *testing.T, factory Factory) {
	t.Helper()
	cases := []struct {
		name string
		fn   func(t *testing.T, factory Factory)
	}{
		{"EnqueueIdempotentAndDepth", conformEnqueueIdempotent},
		{"MaxDepthErrFull", conformMaxDepth},
		{"DrainEligibilityAndSeqOrder", conformDrainEligibility},
		{"BackoffDefersThenReeligible", conformBackoff},
		{"QuarantineAtMaxAttempts", conformQuarantine},
		{"GCReapsAppliedNotPending", conformGC},
		{"PayloadVerRoundTrips", conformPayloadVer},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.fn(t, factory) })
	}
}

func conformEnqueueIdempotent(t *testing.T, factory Factory) {
	ctx := context.Background()
	s := factory(newCommonConfig(t), newClock(conformBase).now)

	if err := s.Enqueue(ctx, "traces", []byte("a")); err != nil {
		t.Fatalf("enqueue a: %v", err)
	}
	if d, err := s.Depth(ctx); err != nil || d != 1 {
		t.Fatalf("depth = %d, err = %v, want 1", d, err)
	}
	// Idempotent re-enqueue of the same (signal, payload): accepted no-op.
	if err := s.Enqueue(ctx, "traces", []byte("a")); err != nil {
		t.Fatalf("duplicate enqueue: %v", err)
	}
	if d, _ := s.Depth(ctx); d != 1 {
		t.Fatalf("depth after duplicate = %d, want 1", d)
	}
	// A different payload is a distinct row.
	if err := s.Enqueue(ctx, "traces", []byte("b")); err != nil {
		t.Fatalf("enqueue b: %v", err)
	}
	if d, _ := s.Depth(ctx); d != 2 {
		t.Fatalf("depth after b = %d, want 2", d)
	}
}

func conformMaxDepth(t *testing.T, factory Factory) {
	ctx := context.Background()
	s := factory(newCommonConfig(t), newClock(conformBase).now) // MaxDepth = 3

	for _, p := range []string{"a", "b", "c"} {
		if err := s.Enqueue(ctx, "traces", []byte(p)); err != nil {
			t.Fatalf("enqueue %s under cap: %v", p, err)
		}
	}
	// A NET-NEW record over the cap is shed.
	if err := s.Enqueue(ctx, "traces", []byte("d")); !errors.Is(err, ErrFull) {
		t.Fatalf("net-new over cap: err = %v, want ErrFull", err)
	}
	// A duplicate AT capacity is an accepted no-op, NOT ErrFull.
	if err := s.Enqueue(ctx, "traces", []byte("a")); err != nil {
		t.Fatalf("duplicate at capacity: err = %v, want nil (accepted no-op)", err)
	}
	if d, _ := s.Depth(ctx); d != 3 {
		t.Fatalf("depth = %d, want 3 (d was shed)", d)
	}
}

func conformDrainEligibility(t *testing.T, factory Factory) {
	ctx := context.Background()
	s := factory(newCommonConfig(t), newClock(conformBase).now)

	for _, p := range []string{"a", "b", "c"} {
		if err := s.Enqueue(ctx, "traces", []byte(p)); err != nil {
			t.Fatalf("enqueue %s: %v", p, err)
		}
	}
	recs, err := s.Drain(ctx, 10)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("drained %d, want 3", len(recs))
	}
	// seq order is ascending and monotonic (insertion order here).
	for i := 1; i < len(recs); i++ {
		if recs[i].Seq <= recs[i-1].Seq {
			t.Fatalf("drain not in ascending seq order: %d then %d", recs[i-1].Seq, recs[i].Seq)
		}
	}
	// Applying the first excludes it from a later drain.
	if err := s.MarkApplied(ctx, recs[0].Seq); err != nil {
		t.Fatalf("mark applied: %v", err)
	}
	after, err := s.Drain(ctx, 10)
	if err != nil {
		t.Fatalf("drain after apply: %v", err)
	}
	if len(after) != 2 {
		t.Fatalf("drained %d after apply, want 2 (applied row excluded)", len(after))
	}
	// Limit is honoured.
	if lim, _ := s.Drain(ctx, 1); len(lim) != 1 {
		t.Fatalf("limited drain returned %d, want 1", len(lim))
	}
}

func conformBackoff(t *testing.T, factory Factory) {
	ctx := context.Background()
	clk := newClock(conformBase)
	cfg := newCommonConfig(t)
	s := factory(cfg, clk.now)

	if err := s.Enqueue(ctx, "traces", []byte("a")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	recs, err := s.Drain(ctx, 10)
	if err != nil || len(recs) != 1 {
		t.Fatalf("initial drain = %+v, err %v, want 1", recs, err)
	}
	if err := s.MarkFailed(ctx, recs[0].Seq, errors.New("boom")); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	// Immediately after a failure the row is backed off (next_attempt_at in the
	// future), so a drain at the SAME clock returns nothing.
	if backed, _ := s.Drain(ctx, 10); len(backed) != 0 {
		t.Fatalf("row drained while backed off: %+v", backed)
	}
	// Advancing past the max backoff makes it eligible again (attempt_count 1 <
	// MaxAttempts).
	clk.advance(cfg.BackoffMax)
	if reelig, _ := s.Drain(ctx, 10); len(reelig) != 1 {
		t.Fatalf("row not re-eligible after backoff elapsed: %+v", reelig)
	}
}

// conformQuarantine is the Phase-1 mutation-gated arm: dropping the
// `attempt_count < MaxAttempts` clause from the store's Drain re-admits the
// exhausted row here.
func conformQuarantine(t *testing.T, factory Factory) {
	ctx := context.Background()
	clk := newClock(conformBase)
	cfg := newCommonConfig(t) // MaxAttempts = 3
	s := factory(cfg, clk.now)

	if err := s.Enqueue(ctx, "traces", []byte("a")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	for i := 0; i < cfg.MaxAttempts; i++ {
		recs, err := s.Drain(ctx, 10)
		if err != nil {
			t.Fatalf("drain attempt %d: %v", i, err)
		}
		if len(recs) != 1 {
			t.Fatalf("attempt %d: drained %d rows, want 1 (row must stay drainable until MaxAttempts)", i, len(recs))
		}
		if err := s.MarkFailed(ctx, recs[0].Seq, errors.New("boom")); err != nil {
			t.Fatalf("mark failed attempt %d: %v", i, err)
		}
		clk.advance(cfg.BackoffMax) // clear the backoff for the next attempt
	}
	// After MaxAttempts transient failures the row is terminally quarantined:
	// attempt_count >= MaxAttempts excludes it from the drain scan even though its
	// backoff has elapsed and it is still pending.
	final, err := s.Drain(ctx, 10)
	if err != nil {
		t.Fatalf("final drain: %v", err)
	}
	if len(final) != 0 {
		t.Errorf("quarantine-at-MaxAttempts: row still drained after %d failures - the attempt_count < MaxAttempts clause must exclude it (got %d rows)", cfg.MaxAttempts, len(final))
	}
}

func conformGC(t *testing.T, factory Factory) {
	ctx := context.Background()
	clk := newClock(conformBase)
	s := factory(newCommonConfig(t), clk.now)

	if err := s.Enqueue(ctx, "traces", []byte("applied")); err != nil {
		t.Fatalf("enqueue applied: %v", err)
	}
	recs, err := s.Drain(ctx, 10)
	if err != nil || len(recs) != 1 {
		t.Fatalf("drain = %+v, err %v", recs, err)
	}
	if err := s.MarkApplied(ctx, recs[0].Seq); err != nil {
		t.Fatalf("mark applied: %v", err)
	}
	// A second, still-pending row.
	if err := s.Enqueue(ctx, "traces", []byte("pending")); err != nil {
		t.Fatalf("enqueue pending: %v", err)
	}
	clk.advance(time.Hour)

	reaped, err := s.GCApplied(ctx, clk.now())
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("gc reaped %d, want 1 (only the applied row)", reaped)
	}
	// The pending row survives (recovery invariant) and still drains.
	if d, _ := s.Depth(ctx); d != 1 {
		t.Fatalf("depth after gc = %d, want 1 (pending row kept)", d)
	}
	if pend, _ := s.Drain(ctx, 10); len(pend) != 1 {
		t.Fatalf("pending row not drainable after gc: %+v", pend)
	}
}

func conformPayloadVer(t *testing.T, factory Factory) {
	ctx := context.Background()
	s := factory(newCommonConfig(t), newClock(conformBase).now)

	payload := []byte("round-trip-me")
	if err := s.Enqueue(ctx, "logs", payload); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	recs, err := s.Drain(ctx, 10)
	if err != nil || len(recs) != 1 {
		t.Fatalf("drain = %+v, err %v", recs, err)
	}
	r := recs[0]
	if r.PayloadVer == 0 {
		t.Errorf("payload_ver = 0, want a non-zero stamped version")
	}
	if string(r.Payload) != string(payload) {
		t.Errorf("payload round-trip mismatch: got %q, want %q", r.Payload, payload)
	}
	if r.Signal != "logs" {
		t.Errorf("signal = %q, want %q", r.Signal, "logs")
	}
	if r.DedupKey == "" {
		t.Errorf("dedup_key empty, want a stable idempotency key")
	}
	// The row stays pending, so a SECOND drain must return the SAME persisted
	// payload_ver — a mutation that fails to persist / corrupts payload_ver is
	// caught here.
	again, err := s.Drain(ctx, 10)
	if err != nil || len(again) != 1 {
		t.Fatalf("second drain = %+v, err %v", again, err)
	}
	if again[0].PayloadVer != r.PayloadVer {
		t.Errorf("payload_ver unstable across drains: %d then %d", r.PayloadVer, again[0].PayloadVer)
	}
}
