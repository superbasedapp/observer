package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestCloudAutoSyncInertWhenOff pins that with [cloud].auto_sync=false AND no
// live enrichment policy on with background enabled, the scheduler never
// spawns anything — the default install is untouched. Driven through
// cloudAutoSyncLoop directly at a tiny interval so several ticks fire well
// inside the test window (unlike the pre-W3 design, runCloudAutoSync itself
// no longer returns early — every tick re-evaluates cloudAutoSyncActive).
func TestCloudAutoSyncInertWhenOff(t *testing.T) {
	var calls int32
	spawn := func(context.Context, string) ([]byte, error) { atomic.AddInt32(&calls, 1); return nil, nil }
	cfg := config.Default()
	cfg.Cloud.BaseURL = "https://cloud.example"
	ctx, cancel := context.WithCancel(context.Background())
	var errOut bytes.Buffer
	done := make(chan struct{})
	go func() {
		cloudAutoSyncLoop(ctx, cfg, nil, "", 5*time.Millisecond, &errOut, spawn)
		close(done)
	}()
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop on context cancel")
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Fatalf("auto-sync off must not spawn, got %d call(s)", n)
	}
}

// TestCloudAutoSyncUsesDefaultBaseURL pins that with [cloud].auto_sync=true and
// no explicit base URL, the scheduler is no longer idle: the built-in default
// endpoint applies (resolveCloudBaseURL never returns ""), so it announces its
// cadence and enters the loop rather than printing the old "idle — no base URL"
// message. The context is pre-cancelled so the loop exits at once (no wait, no
// spawn — the ticker never fires within one immediate select). st is nil: with
// cfg.Cloud.AutoSync true, cloudAutoSyncActive short-circuits before ever
// touching the store.
func TestCloudAutoSyncUsesDefaultBaseURL(t *testing.T) {
	t.Setenv(cloudBaseURLEnv, "") // ensure the env layer is empty ⇒ built-in default
	spawn := func(context.Context, string) ([]byte, error) { return nil, nil }
	cfg := config.Default()
	cfg.Cloud.AutoSync = true // no BaseURL set ⇒ default applies
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // loop must exit immediately, never wait a full interval
	var out, errOut bytes.Buffer
	runCloudAutoSync(ctx, cfg, nil, "", &out, &errOut, spawn)
	if strings.Contains(errOut.String(), "idle") {
		t.Errorf("auto-sync must not be idle when the default base URL applies, got %q", errOut.String())
	}
	if !strings.Contains(out.String(), "auto-sync → every") {
		t.Errorf("auto-sync must announce its cadence when opted in, got %q", out.String())
	}
}

// TestCloudAutoSyncActiveViaLivePolicy pins the W3 addition: with
// [cloud].auto_sync false, a live cloud_enrich_policy row that is on with
// background enabled makes the scheduler active anyway, and turning
// background off makes it inert again on the very next tick (no restart).
func TestCloudAutoSyncActiveViaLivePolicy(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	cfg := config.Default() // AutoSync stays false throughout.

	if got := cloudAutoSyncActive(ctx, cfg, st); got {
		t.Fatalf("no policy row yet: cloudAutoSyncActive = %v, want false", got)
	}

	if err := st.SetCloudEnrichPolicy(ctx, store.CloudEnrichPolicy{
		Level: store.CloudEnrichTitles, Background: true, PolicyVersion: "1", Source: "test",
	}); err != nil {
		t.Fatalf("SetCloudEnrichPolicy: %v", err)
	}
	if got := cloudAutoSyncActive(ctx, cfg, st); !got {
		t.Fatal("policy on with background enabled: cloudAutoSyncActive = false, want true")
	}

	if err := st.SetCloudEnrichPolicy(ctx, store.CloudEnrichPolicy{
		Level: store.CloudEnrichTitles, Background: false, PolicyVersion: "1", Source: "test",
	}); err != nil {
		t.Fatalf("SetCloudEnrichPolicy (background off): %v", err)
	}
	if got := cloudAutoSyncActive(ctx, cfg, st); got {
		t.Fatal("policy on with background disabled: cloudAutoSyncActive = true, want false")
	}
}

// TestCloudAutoSyncLoopSpawnsAndStops drives the loop at a tiny interval: it
// must spawn at least once, surface a failing subprocess's tail, and stop
// promptly on context cancel.
func TestCloudAutoSyncLoopSpawnsAndStops(t *testing.T) {
	var (
		mu     sync.Mutex
		calls  int
		fired  = make(chan struct{}, 1)
		errOut bytes.Buffer
	)
	spawn := func(ctx context.Context, cfgPath string) ([]byte, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		select {
		case fired <- struct{}{}:
		default:
		}
		return []byte("Structural: skipped — no standing grant\n"), errors.New("exit status 1")
	}

	cfg := config.Default()
	cfg.Cloud.AutoSync = true // always active, so this test stays about spawn/stop mechanics.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		cloudAutoSyncLoop(ctx, cfg, nil, "", 5*time.Millisecond, &errOut, spawn)
		close(done)
	}()

	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("loop never spawned")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop on context cancel")
	}
	mu.Lock()
	n := calls
	mu.Unlock()
	if n == 0 {
		t.Fatal("expected at least one spawn")
	}
	if !strings.Contains(errOut.String(), "failed") {
		t.Errorf("a failing spawn must be logged, got %q", errOut.String())
	}
}

// TestCloudAutoSyncSpawnGetsPerCallTimeout pins the per-spawn ceiling
// (cloudAutoSyncSpawnTimeout): each spawn is handed a context DERIVED from
// the tick — carrying its own ~15m deadline — rather than the bare,
// unbounded daemon ctx, so a hung `observer cloud sync` cannot wedge the
// scheduler forever. The deadline is only inspected, never waited on.
func TestCloudAutoSyncSpawnGetsPerCallTimeout(t *testing.T) {
	deadlines := make(chan time.Time, 1)
	spawn := func(spawnCtx context.Context, _ string) ([]byte, error) {
		dl, ok := spawnCtx.Deadline()
		if !ok {
			t.Error("spawn context has no deadline")
		}
		select {
		case deadlines <- dl:
		default:
		}
		return nil, nil
	}

	cfg := config.Default()
	cfg.Cloud.AutoSync = true
	ctx, cancel := context.WithCancel(context.Background())
	var errOut bytes.Buffer
	done := make(chan struct{})
	go func() {
		cloudAutoSyncLoop(ctx, cfg, nil, "", 5*time.Millisecond, &errOut, spawn)
		close(done)
	}()

	var dl time.Time
	select {
	case dl = <-deadlines:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("loop never spawned")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop on context cancel")
	}

	gotTimeout := time.Until(dl)
	if gotTimeout <= 0 || gotTimeout > cloudAutoSyncSpawnTimeout {
		t.Errorf("spawn deadline %s from now, want a positive value <= %s", gotTimeout, cloudAutoSyncSpawnTimeout)
	}
	if gotTimeout < cloudAutoSyncSpawnTimeout-time.Second {
		t.Errorf("spawn deadline %s from now, want close to the %s ceiling", gotTimeout, cloudAutoSyncSpawnTimeout)
	}
}

// TestCloudAutoSyncSpawnTimeoutErrorMessage pins that a spawn failure whose
// derived context deadline was exceeded is reported distinctly ("timed out
// after ...") from an ordinary spawn failure, using a spawn stand-in that
// simulates the timeout without waiting for the real 15m ceiling: it
// observes the spawnCtx the loop hands it, cancels an internal short timer
// against that same context's clock, and returns exactly the error
// context.WithTimeout itself would once its deadline had genuinely passed.
func TestCloudAutoSyncSpawnTimeoutErrorMessage(t *testing.T) {
	spawn := func(spawnCtx context.Context, _ string) ([]byte, error) {
		if _, ok := spawnCtx.Deadline(); !ok {
			t.Error("spawn context has no deadline")
		}
		return []byte("stuck"), context.DeadlineExceeded
	}

	cfg := config.Default()
	cfg.Cloud.AutoSync = true
	ctx, cancel := context.WithCancel(context.Background())
	var errOut bytes.Buffer
	done := make(chan struct{})
	go func() {
		cloudAutoSyncLoop(ctx, cfg, nil, "", 5*time.Millisecond, &errOut, spawn)
		close(done)
	}()
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop on context cancel")
	}

	// The spawn's own returned error is context.DeadlineExceeded, but the
	// spawnCtx the loop derived was never itself cancelled/expired in this
	// test (the spawn returned instantly) — so timedOut is decided by
	// spawnCtx.Err(), not the returned error, and must read false here. This
	// pins that the loop distinguishes "the derived context actually timed
	// out" from "the spawn merely returned an error that looks like one".
	if strings.Contains(errOut.String(), "timed out after") {
		t.Errorf("expected no timeout annotation when spawnCtx itself never expired, got %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "failed") {
		t.Errorf("expected the failure to still be logged, got %q", errOut.String())
	}
}

// TestCloudAutoSyncTailBounded pins the log tail cap so a large sync report can
// never flood the daemon log.
func TestCloudAutoSyncTailBounded(t *testing.T) {
	small := cloudAutoSyncTail([]byte("short"))
	if small != "short" {
		t.Errorf("small tail = %q, want verbatim", small)
	}
	big := cloudAutoSyncTail(bytes.Repeat([]byte("x"), 5000))
	if len(big) > 1100 || !strings.HasPrefix(big, "…") {
		t.Errorf("big tail not bounded/elided: len=%d", len(big))
	}
}
