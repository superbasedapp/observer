package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedAutoEnrichCandidate creates a personal-authority session with `actions`
// actions ending at lastActionAt, mirroring internal/store's own
// seedCandidateSession test helper (unexported there, so duplicated at this
// package boundary rather than exported just for a test).
func seedAutoEnrichCandidate(t *testing.T, st *store.Store, id string, startedAt, lastActionAt time.Time, actions int) {
	t.Helper()
	ctx := context.Background()
	pid, err := st.UpsertProject(ctx, "/tmp/auto-enrich-"+id, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := st.UpsertSession(ctx, models.Session{
		ID: id, ProjectID: pid, Tool: "codex", StartedAt: startedAt, TotalActions: actions,
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	var rows []models.Action
	for i := 0; i < actions; i++ {
		rows = append(rows, models.Action{
			SessionID: id, ProjectID: pid,
			Timestamp:     lastActionAt.Add(-time.Duration(actions-1-i) * time.Second),
			ActionType:    "tool_call",
			Tool:          "codex",
			SourceFile:    "seed",
			SourceEventID: fmt.Sprintf("%s-%d", id, i),
		})
	}
	if len(rows) > 0 {
		if _, err := st.InsertActions(ctx, rows); err != nil {
			t.Fatalf("InsertActions: %v", err)
		}
	}
	if eligible, err := st.EligibleForPersonalCloud(ctx, id); err != nil || !eligible {
		t.Fatalf("precondition: %q must be eligible (eligible=%v err=%v)", id, eligible, err)
	}
}

// TestCloudAutoEnrichIdleWithNoPolicy pins that with no cloud_enrich_policy
// row at all, the loop never spawns and announces idle exactly once.
func TestCloudAutoEnrichIdleWithNoPolicy(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()

	var spawnCalls int
	var mu sync.Mutex
	spawn := func(context.Context, string, string, string, int64) ([]byte, error) {
		mu.Lock()
		spawnCalls++
		mu.Unlock()
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	var out, errOut bytes.Buffer
	done := make(chan struct{})
	go func() {
		cloudAutoEnrichLoop(ctx, st, "", time.Hour, 10*time.Minute, 3, 25, 5*time.Millisecond, &out, &errOut, spawn)
		close(done)
	}()
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop on context cancel")
	}

	mu.Lock()
	n := spawnCalls
	mu.Unlock()
	if n != 0 {
		t.Fatalf("no policy row: expected 0 spawns, got %d", n)
	}
	if strings.Count(out.String(), "idle") != 1 {
		t.Errorf("expected exactly one idle announcement (state changes announce once), got %q", out.String())
	}
}

// TestCloudAutoEnrichIdleWhenBackgroundOff pins that a policy row with
// Background=false never spawns even though the level is on.
func TestCloudAutoEnrichIdleWhenBackgroundOff(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()

	if err := st.SetCloudEnrichPolicy(ctx, store.CloudEnrichPolicy{
		Level: store.CloudEnrichTitles, Background: false, PolicyVersion: "1", Source: "test",
	}); err != nil {
		t.Fatalf("SetCloudEnrichPolicy: %v", err)
	}
	policy, _, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil {
		t.Fatalf("GetCloudEnrichPolicy: %v", err)
	}
	seedAutoEnrichCandidate(t, st, "sess-bg-off", policy.Since, time.Now().Add(-time.Hour), 5)

	var spawnCalls int
	var mu sync.Mutex
	spawn := func(context.Context, string, string, string, int64) ([]byte, error) {
		mu.Lock()
		spawnCalls++
		mu.Unlock()
		return nil, nil
	}
	runCtx, cancel := context.WithCancel(context.Background())
	var out, errOut bytes.Buffer
	done := make(chan struct{})
	go func() {
		cloudAutoEnrichLoop(runCtx, st, "", time.Hour, 0, 1, 25, 5*time.Millisecond, &out, &errOut, spawn)
		close(done)
	}()
	time.Sleep(80 * time.Millisecond)
	cancel()
	<-done

	mu.Lock()
	n := spawnCalls
	mu.Unlock()
	if n != 0 {
		t.Fatalf("background off: expected 0 spawns, got %d", n)
	}
}

// TestCloudAutoEnrichSpawnsForQuietCandidate pins the wiring end to end: a
// policy on with background enabled, a genuinely eligible session, spawns
// `observer cloud consent` with the session id and the policy's purpose.
func TestCloudAutoEnrichSpawnsForQuietCandidate(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()

	if err := st.SetCloudEnrichPolicy(ctx, store.CloudEnrichPolicy{
		Level: store.CloudEnrichTitles, Background: true, PolicyVersion: "1", Source: "test",
	}); err != nil {
		t.Fatalf("SetCloudEnrichPolicy: %v", err)
	}
	policy, _, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil {
		t.Fatalf("GetCloudEnrichPolicy: %v", err)
	}
	// Started just after `since` (so the since floor passes) with its last
	// action already a couple of seconds in the past (quietFor=0 in this
	// test, so no additional wait is required).
	seedAutoEnrichCandidate(t, st, "sess-quiet", policy.Since, policy.Since, 3)

	type call struct{ sessionID, purpose, configPath string }
	calls := make(chan call, 4)
	spawn := func(_ context.Context, sessionID, purpose, configPath string, _ int64) ([]byte, error) {
		calls <- call{sessionID, purpose, configPath}
		return []byte("ok"), nil
	}

	runCtx, cancel := context.WithCancel(context.Background())
	var out, errOut bytes.Buffer
	done := make(chan struct{})
	go func() {
		cloudAutoEnrichLoop(runCtx, st, "some-config.toml", time.Hour, 0, 1, 25, 5*time.Millisecond, &out, &errOut, spawn)
		close(done)
	}()

	select {
	case c := <-calls:
		if c.sessionID != "sess-quiet" {
			t.Errorf("spawned session id = %q, want sess-quiet", c.sessionID)
		}
		if c.purpose != "structural_activity_insights" {
			t.Errorf("spawned purpose = %q, want structural_activity_insights", c.purpose)
		}
		if c.configPath != "some-config.toml" {
			t.Errorf("spawned config path = %q, want some-config.toml", c.configPath)
		}
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("loop never spawned for the eligible session")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop on context cancel")
	}
	if !strings.Contains(out.String(), "auto-enrich: active") {
		t.Errorf("expected an active-state announcement, got %q", out.String())
	}
}

// TestCloudAutoEnrichSkipsAfterFailedSpawn pins the hot-loop guard: a session
// whose consent spawn just failed is not retried on the very next tick.
func TestCloudAutoEnrichSkipsAfterFailedSpawn(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()

	if err := st.SetCloudEnrichPolicy(ctx, store.CloudEnrichPolicy{
		Level: store.CloudEnrichTitles, Background: true, PolicyVersion: "1", Source: "test",
	}); err != nil {
		t.Fatalf("SetCloudEnrichPolicy: %v", err)
	}
	policy, _, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil {
		t.Fatalf("GetCloudEnrichPolicy: %v", err)
	}
	seedAutoEnrichCandidate(t, st, "sess-flaky", policy.Since, policy.Since, 3)

	var mu sync.Mutex
	var calls int
	spawn := func(context.Context, string, string, string, int64) ([]byte, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return []byte("boom"), errors.New("exit status 1")
	}

	runCtx, cancel := context.WithCancel(context.Background())
	var out, errOut bytes.Buffer
	done := make(chan struct{})
	go func() {
		// Tight interval so several ticks fire well inside the test window;
		// the 1h skip-after-failure window must suppress every tick after
		// the first.
		cloudAutoEnrichLoop(runCtx, st, "", 10*time.Millisecond, 0, 1, 25, 5*time.Millisecond, &out, &errOut, spawn)
		close(done)
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop on context cancel")
	}

	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 1 {
		t.Fatalf("expected exactly one spawn attempt (later ticks must be skipped for an hour), got %d", n)
	}
	if !strings.Contains(errOut.String(), "sess-flaky") || !strings.Contains(errOut.String(), "failed") {
		t.Errorf("expected the failure to be logged with the session id, got %q", errOut.String())
	}
}

// TestCloudAutoEnrichDurableSkipSurvivesRestart pins that a failed consent
// spawn's skip is DURABLE (internal/store's cloud_enrich_skips table), not
// merely held in the scheduler's memory: a fresh cloudAutoEnrichLoop
// invocation over the SAME store (simulating a daemon restart, which starts
// with an empty in-memory scheduler state) still skips the session.
func TestCloudAutoEnrichDurableSkipSurvivesRestart(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()

	if err := st.SetCloudEnrichPolicy(ctx, store.CloudEnrichPolicy{
		Level: store.CloudEnrichTitles, Background: true, PolicyVersion: "1", Source: "test",
	}); err != nil {
		t.Fatalf("SetCloudEnrichPolicy: %v", err)
	}
	policy, _, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil {
		t.Fatalf("GetCloudEnrichPolicy: %v", err)
	}
	seedAutoEnrichCandidate(t, st, "sess-flaky-restart", policy.Since, policy.Since, 3)

	failSpawn := func(context.Context, string, string, string, int64) ([]byte, error) {
		return []byte("boom"), errors.New("exit status 1")
	}

	// First "process": one failing tick.
	runCtx, cancel := context.WithCancel(context.Background())
	var out, errOut bytes.Buffer
	done := make(chan struct{})
	go func() {
		cloudAutoEnrichLoop(runCtx, st, "", time.Hour, 0, 1, 25, 5*time.Millisecond, &out, &errOut, failSpawn)
		close(done)
	}()
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("first loop did not stop on context cancel")
	}

	if _, ok, gerr := st.GetCloudEnrichSkip(ctx, "sess-flaky-restart"); gerr != nil || !ok {
		t.Fatalf("expected a durable skip row after the failure, ok=%v err=%v", ok, gerr)
	}

	// Second "process": a fresh loop invocation (fresh in-memory state) over
	// the same store must not spawn again — the skip persisted across the
	// simulated restart.
	var (
		mu    sync.Mutex
		calls int
	)
	spawn2 := func(context.Context, string, string, string, int64) ([]byte, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil, nil
	}
	runCtx2, cancel2 := context.WithCancel(context.Background())
	var out2, errOut2 bytes.Buffer
	done2 := make(chan struct{})
	go func() {
		cloudAutoEnrichLoop(runCtx2, st, "", time.Hour, 0, 1, 25, 5*time.Millisecond, &out2, &errOut2, spawn2)
		close(done2)
	}()
	time.Sleep(80 * time.Millisecond)
	cancel2()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("second loop did not stop on context cancel")
	}

	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 0 {
		t.Fatalf("expected the durable skip to suppress a spawn across a fresh loop invocation, got %d call(s)", n)
	}
}

// TestCloudAutoEnrichSuccessClearsDurableSkip pins that a successful consent
// spawn deletes any durable skip row for that session, so a session that
// eventually recovers is not left carrying a stale skip.
func TestCloudAutoEnrichSuccessClearsDurableSkip(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()

	if err := st.SetCloudEnrichPolicy(ctx, store.CloudEnrichPolicy{
		Level: store.CloudEnrichTitles, Background: true, PolicyVersion: "1", Source: "test",
	}); err != nil {
		t.Fatalf("SetCloudEnrichPolicy: %v", err)
	}
	policy, _, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil {
		t.Fatalf("GetCloudEnrichPolicy: %v", err)
	}
	seedAutoEnrichCandidate(t, st, "sess-recovers", policy.Since, policy.Since, 3)

	// Seed an already-expired skip row directly so the session is still a
	// candidate on the next tick (its next_at has already passed).
	if err := st.RecordCloudEnrichSkip(ctx, "sess-recovers", "consent_spawn_failed", time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatalf("RecordCloudEnrichSkip (seed): %v", err)
	}

	calls := make(chan struct{}, 1)
	spawn := func(context.Context, string, string, string, int64) ([]byte, error) {
		calls <- struct{}{}
		return []byte("ok"), nil
	}
	runCtx, cancel := context.WithCancel(context.Background())
	var out, errOut bytes.Buffer
	done := make(chan struct{})
	go func() {
		cloudAutoEnrichLoop(runCtx, st, "", time.Hour, 0, 1, 25, 5*time.Millisecond, &out, &errOut, spawn)
		close(done)
	}()

	select {
	case <-calls:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("loop never spawned for the recovered session")
	}
	// The spawn signals `calls` and returns BEFORE the loop's own
	// post-spawn ClearCloudEnrichSkip call runs; give that synchronous,
	// fast DB write a moment to land before asking the loop to stop, so
	// cancel() can't race the loop's own ctx.Err() check into skipping it.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop on context cancel")
	}

	if _, ok, gerr := st.GetCloudEnrichSkip(ctx, "sess-recovers"); gerr != nil || ok {
		t.Fatalf("expected the durable skip to be cleared after a successful spawn, ok=%v err=%v", ok, gerr)
	}
}

// TestCloudAutoEnrichSpawnTimeoutRecordsDistinctErrorClass pins that the
// durable skip's error class is decided by whether the LOOP's own derived
// spawnCtx actually timed out, never by the spawn's return value alone: a
// spawn that returns context.DeadlineExceeded without its OWN spawnCtx ever
// expiring still records cloudAutoEnrichErrClassSpawnFailed, with no
// "timed out after" annotation in the log line.
func TestCloudAutoEnrichSpawnTimeoutRecordsDistinctErrorClass(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()

	if err := st.SetCloudEnrichPolicy(ctx, store.CloudEnrichPolicy{
		Level: store.CloudEnrichTitles, Background: true, PolicyVersion: "1", Source: "test",
	}); err != nil {
		t.Fatalf("SetCloudEnrichPolicy: %v", err)
	}
	policy, _, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil {
		t.Fatalf("GetCloudEnrichPolicy: %v", err)
	}
	seedAutoEnrichCandidate(t, st, "sess-lookalike", policy.Since, policy.Since, 3)

	spawn := func(spawnCtx context.Context, _, _, _ string, _ int64) ([]byte, error) {
		if _, ok := spawnCtx.Deadline(); !ok {
			t.Error("spawn context has no deadline")
		}
		return nil, context.DeadlineExceeded
	}
	runCtx, cancel := context.WithCancel(context.Background())
	var out, errOut bytes.Buffer
	done := make(chan struct{})
	go func() {
		cloudAutoEnrichLoop(runCtx, st, "", time.Hour, 0, 1, 25, 5*time.Millisecond, &out, &errOut, spawn)
		close(done)
	}()
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop on context cancel")
	}

	got, ok, gerr := st.GetCloudEnrichSkip(ctx, "sess-lookalike")
	if gerr != nil || !ok {
		t.Fatalf("expected a durable skip row, ok=%v err=%v", ok, gerr)
	}
	if got.LastErrorClass != "consent_spawn_failed" {
		t.Errorf("last_error_class = %q, want consent_spawn_failed (spawnCtx itself never expired)", got.LastErrorClass)
	}
	if strings.Contains(errOut.String(), "timed out after") {
		t.Errorf("expected no timeout annotation when spawnCtx itself never expired, got %q", errOut.String())
	}
}

// TestCloudAutoEnrichLoopStopsOnCancel pins prompt shutdown even mid-interval.
func TestCloudAutoEnrichLoopStopsOnCancel(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()

	spawn := func(context.Context, string, string, string, int64) ([]byte, error) { return nil, nil }
	ctx, cancel := context.WithCancel(context.Background())
	var out, errOut bytes.Buffer
	done := make(chan struct{})
	go func() {
		cloudAutoEnrichLoop(ctx, st, "", time.Hour, 0, 1, 25, time.Hour, &out, &errOut, spawn)
		close(done)
	}()
	cancel() // before the first (1h-delayed) tick would ever fire.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop promptly on context cancel")
	}
}
