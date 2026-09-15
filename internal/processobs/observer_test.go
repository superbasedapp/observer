package processobs

import (
	"context"
	"errors"
	"testing"
	"time"
)

func ts(n int) time.Time { return time.Unix(1_700_000_000+int64(n), 0).UTC() }

// execEvCWD is execEv with an explicit cwd (execEv hardcodes "/proj").
func execEvCWD(boot string, pid, ppid int, start int64, exe string, argv []string, cwd string, ts time.Time) RawEvent {
	ev := execEv(boot, pid, ppid, start, exe, argv, ts)
	ev.CWD = cwd
	return ev
}

// attributedSequence: root claude (pid 100, bridged) forks+execs bash
// (200), which exits, then claude exits.
func attributedSequence() []RawEvent {
	return []RawEvent{
		execEv("b", 100, 1, 1000, "/usr/bin/claude", []string{"claude"}, ts(1)),
		forkEv("b", 200, 100, 2000, ts(2)),
		execEv("b", 200, 100, 2000, "/bin/bash", []string{"bash", "-c", "npm test"}, ts(3)),
		exitEv("b", 200, 2000, 0, ts(4)),
		exitEv("b", 100, 1000, 0, ts(5)),
	}
}

func runObserver(t *testing.T, opts Options) (*SliceSink, *Observer) {
	t.Helper()
	sink := opts.Sink.(*SliceSink)
	o := NewObserver(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := o.Run(ctx); err != nil && opts.Backend.(*FakeBackend).StartErr == nil {
		t.Fatalf("Run: %v", err)
	}
	return sink, o
}

func TestObserverPipelineEndToEnd(t *testing.T) {
	t.Parallel()
	be := &FakeBackend{BackendName: "fake", Events: attributedSequence()}
	sink := &SliceSink{}
	attr := NewAttributor(bridgeSeed(100, "sess-1", "claude-code", 7), &FieldScrubber{ArgvMode: "preview", MaxPreviewBytes: 512}, nil)
	_, o := runObserver(t, Options{Backend: be, Attributor: attr, Sink: sink, BatchSize: 100, FlushInterval: time.Hour})

	// Persisted: exec(100) create, exec(200) create, exit(200) update,
	// exit(100) update = 4 run rows. Fork(200) does not persist.
	if len(sink.Runs) != 4 {
		t.Fatalf("persisted %d runs, want 4: %+v", len(sink.Runs), sink.Runs)
	}
	// Every persisted run is attributed to the session.
	for _, r := range sink.Runs {
		if r.Attribution.SessionID != "sess-1" {
			t.Errorf("run %s not attributed: %+v", r.ExeBasename, r.Attribution)
		}
	}
	// The last two are the exit updates (Exited=true).
	if !sink.Runs[2].Exited || !sink.Runs[3].Exited {
		t.Error("expected the two exit updates to carry Exited=true")
	}

	h := o.Health().Snapshot()
	if !h.BackendUp && h.BackendName != "fake" {
		// BackendUp is flipped false again by Run's deferred cleanup; that's
		// expected. We only assert the name here.
		t.Errorf("backend name = %q", h.BackendName)
	}
	if h.EventsTotal[EventExec] != 2 || h.EventsTotal[EventFork] != 1 || h.EventsTotal[EventExit] != 2 {
		t.Errorf("event counts = %+v", h.EventsTotal)
	}
	if h.AttributedByTool["claude-code"] != 4 {
		t.Errorf("attributed-by-tool = %+v, want claude-code:4", h.AttributedByTool)
	}
	if !be.Closed() {
		t.Error("backend Close not called")
	}
}

func TestObserverPersistsAttributedNetworkConnectEvent(t *testing.T) {
	t.Parallel()
	events := []RawEvent{
		execEv("b", 100, 1, 1000, "/usr/bin/claude", []string{"claude"}, ts(1)),
		{
			Type:            EventNetworkConnect,
			Timestamp:       ts(2),
			BootID:          "b",
			PID:             100,
			StartTimeTicks:  1000,
			HasStartTime:    true,
			NetworkProtocol: "tcp",
			NetworkFamily:   "ipv4",
			RemoteAddr:      "203.0.113.10",
			RemotePort:      443,
			LocalAddr:       "10.0.0.5",
			LocalPort:       53123,
			NetworkStatus:   "ok",
			NetworkBytesOut: 128,
			NetworkBytesIn:  256,
		},
	}
	sink := &SliceSink{}
	eventSink := &SliceEventSink{}
	attr := NewAttributor(bridgeSeed(100, "sess-1", "claude-code", 7), &FieldScrubber{ArgvMode: "preview"}, nil)
	_, _ = runObserver(t, Options{
		Backend:       &FakeBackend{Events: events},
		Attributor:    attr,
		Sink:          sink,
		EventSink:     eventSink,
		BatchSize:     100,
		FlushInterval: time.Hour,
	})

	if len(eventSink.Events) != 1 {
		t.Fatalf("events = %d want 1: %+v", len(eventSink.Events), eventSink.Events)
	}
	ev := eventSink.Events[0]
	if ev.Type != EventNetworkConnect {
		t.Fatalf("event type = %q", ev.Type)
	}
	if ev.ProcessKey == "" || ev.Attribution.SessionID != "sess-1" || ev.Attribution.Tool != "claude-code" {
		t.Fatalf("event attribution/key wrong: %+v", ev)
	}
	if ev.Target != "203.0.113.10:443" || ev.TargetKind != "network_endpoint" {
		t.Fatalf("target = %q/%q", ev.TargetKind, ev.Target)
	}
	if got := ev.Details["body_unavailable_reason"]; got != "metadata_only_non_plaintext" {
		t.Fatalf("unavailable = %#v", got)
	}
	if got := ev.Details["protocol"]; got != "tcp" {
		t.Fatalf("protocol detail = %#v", got)
	}
}

func TestObserverDropsUnattributedByDefault(t *testing.T) {
	t.Parallel()
	// No seed → nothing is attributed.
	events := []RawEvent{
		execEv("b", 500, 1, 1000, "/bin/bash", []string{"bash"}, ts(1)),
		exitEv("b", 500, 1000, 0, ts(2)),
	}

	// Default: unattributed dropped.
	sink := &SliceSink{}
	attr := NewAttributor(nil, nil, nil)
	_, o := runObserver(t, Options{Backend: &FakeBackend{Events: events}, Attributor: attr, Sink: sink, FlushInterval: time.Hour})
	if len(sink.Runs) != 0 {
		t.Errorf("unattributed runs leaked: %d", len(sink.Runs))
	}
	if o.Health().Snapshot().Dropped[DropUnattributed] == 0 {
		t.Error("expected a dropped-unattributed counter")
	}

	// capture_unattributed = true: now they persist.
	sink2 := &SliceSink{}
	attr2 := NewAttributor(nil, nil, nil)
	_, _ = runObserver(t, Options{Backend: &FakeBackend{Events: events}, Attributor: attr2, Sink: sink2, CaptureUnattributed: true, FlushInterval: time.Hour})
	if len(sink2.Runs) == 0 {
		t.Error("capture_unattributed=true should persist unattributed runs")
	}
}

// TestObserverCapturesUnattributedAISubtree asserts the native-host scoped
// capture: an UNATTRIBUTED codex subtree (codex → node → git) persists for the
// deferred CorrelateCrossOS pass, while an unrelated standalone process is
// still dropped. No seed/env-token → nothing is attributed at capture time.
func TestObserverCapturesUnattributedAISubtree(t *testing.T) {
	t.Parallel()
	events := []RawEvent{
		// Codex root (a distinctive AI-tool launcher).
		execEv("b", 100, 1, 1000, "/usr/bin/codex", []string{"codex"}, ts(1)),
		// Its node worker.
		forkEv("b", 200, 100, 2000, ts(2)),
		execEv("b", 200, 100, 2000, "/usr/bin/node", []string{"node", "worker.js"}, ts(3)),
		// A generic git two levels down — captured by subtree descent.
		forkEv("b", 300, 200, 3000, ts(4)),
		execEv("b", 300, 200, 3000, "/usr/bin/git", []string{"git", "status"}, ts(5)),
		// An unrelated standalone bash under init — NOT in any AI subtree.
		execEv("b", 500, 1, 5000, "/bin/bash", []string{"bash"}, ts(6)),
	}

	sink := &SliceSink{}
	attr := NewAttributor(nil, nil, nil) // no seed → unattributed
	_, o := runObserver(t, Options{
		Backend: &FakeBackend{Events: events}, Attributor: attr, Sink: sink,
		CaptureUnattributedAISubtree: true, FlushInterval: time.Hour,
	})

	// codex, node, git persist (3 exec creates); standalone bash is dropped.
	if len(sink.Runs) != 3 {
		t.Fatalf("persisted %d runs, want 3 (codex/node/git): %+v", len(sink.Runs), basenames(sink.Runs))
	}
	for _, r := range sink.Runs {
		if r.ExeBasename == "bash" {
			t.Errorf("standalone bash leaked into capture: %+v", r)
		}
		if r.Attributed() {
			t.Errorf("run %s should be unattributed at capture (joined later by CorrelateCrossOS): %+v", r.ExeBasename, r.Attribution)
		}
	}
	if o.Health().Snapshot().Dropped[DropUnattributed] == 0 {
		t.Error("expected the standalone process to count as a dropped-unattributed")
	}
}

// TestObserverCapturesUnattributedCWDMatch asserts the cwd-anchored capture:
// a generic interpreter (python) with NO AI-tool launcher anywhere in its tree
// is still captured when it runs in an active session's project root — the
// path that extends process attribution to hermes/pi/roo-code/in-IDE tools.
// A process outside the active roots is dropped.
func TestObserverCapturesUnattributedCWDMatch(t *testing.T) {
	t.Parallel()
	events := []RawEvent{
		// A hermes-style python worker in the project dir (no codex/claude root).
		execEvCWD("b", 700, 1, 7000, "/usr/bin/python", []string{"python", "-m", "hermes"}, "/home/dev/proj", ts(1)),
		// A python in an unrelated dir — must be dropped.
		execEvCWD("b", 800, 1, 8000, "/usr/bin/python", []string{"python", "x.py"}, "/tmp/other", ts(2)),
	}

	sink := &SliceSink{}
	attr := NewAttributor(nil, nil, nil) // no seed → unattributed
	o := NewObserver(Options{
		Backend: &FakeBackend{Events: events}, Attributor: attr, Sink: sink,
		CaptureUnattributedAISubtree: true, FlushInterval: time.Hour,
	})
	o.SetActiveSessionRoots([]string{"/home/dev/proj"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := o.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(sink.Runs) != 1 {
		t.Fatalf("persisted %d runs, want 1 (only the in-project python): %+v", len(sink.Runs), basenames(sink.Runs))
	}
	if sink.Runs[0].PID != 700 {
		t.Errorf("captured pid %d, want 700 (the in-project worker)", sink.Runs[0].PID)
	}
}

func TestObserverExcludesOwnBinary(t *testing.T) {
	t.Parallel()
	events := []RawEvent{
		// The observer daemon's own binary, in the active project dir.
		execEvCWD("b", 900, 1, 9000, "/usr/local/bin/observer", []string{"observer", "start"}, "/home/dev/proj", ts(1)),
		// An `observer hook` subcommand in the same dir.
		execEvCWD("b", 901, 900, 9010, "/usr/local/bin/observer", []string{"observer", "hook"}, "/home/dev/proj", ts(2)),
		// A genuine AI-tool worker in the same dir — must STILL be captured.
		execEvCWD("b", 902, 1, 9020, "/usr/bin/rg", []string{"rg", "foo"}, "/home/dev/proj", ts(3)),
	}

	sink := &SliceSink{}
	o := NewObserver(Options{
		Backend: &FakeBackend{Events: events}, Attributor: NewAttributor(nil, nil, nil), Sink: sink,
		ExcludeOwnBasenames: []string{"observer", "observer.exe"},
		FlushInterval:       time.Hour,
	})
	o.SetActiveSessionRoots([]string{"/home/dev/proj"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := o.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(sink.Runs) != 1 {
		t.Fatalf("persisted %d runs, want 1 (only rg; observer excluded): %+v", len(sink.Runs), basenames(sink.Runs))
	}
	if sink.Runs[0].ExeBasename != "rg" {
		t.Errorf("captured %q, want rg (observer's own processes must be excluded)", sink.Runs[0].ExeBasename)
	}
	if got := o.Health().Snapshot().Dropped[DropSelfExcluded]; got != 2 {
		t.Errorf("DropSelfExcluded = %d, want 2 (the two observer processes)", got)
	}
}

func basenames(runs []ProcessRun) []string {
	out := make([]string, len(runs))
	for i, r := range runs {
		out[i] = r.ExeBasename
	}
	return out
}

func TestObserverBackendStartErrorFailsOpen(t *testing.T) {
	t.Parallel()
	be := &FakeBackend{StartErr: errors.New("missing CAP_BPF")}
	sink := &SliceSink{}
	o := NewObserver(Options{Backend: be, Attributor: NewAttributor(nil, nil, nil), Sink: sink})
	err := o.Run(context.Background())
	if err == nil {
		t.Fatal("expected Start error to propagate so the caller can log degraded health")
	}
	h := o.Health().Snapshot()
	if h.BackendUp {
		t.Error("backend must report down after a Start error")
	}
	if h.LastError == "" {
		t.Error("Start error should be recorded for doctor")
	}
}

func TestObserverDropsNoStartTime(t *testing.T) {
	t.Parallel()
	events := []RawEvent{
		{Type: EventExec, BootID: "b", PID: 100, PPID: 1, HasStartTime: false, ExePath: "/bin/x", Timestamp: ts(1)},
	}
	sink := &SliceSink{}
	o := NewObserver(Options{Backend: &FakeBackend{Events: events}, Attributor: NewAttributor(bridgeSeed(100, "s", "claude-code", 1), nil, nil), Sink: sink, FlushInterval: time.Hour})
	_ = o.Run(context.Background())
	if len(sink.Runs) != 0 {
		t.Errorf("unkeyable exec persisted: %d", len(sink.Runs))
	}
	if o.Health().Snapshot().Dropped[DropNoStartTime] == 0 {
		t.Error("expected a no_start_time drop counter")
	}
}

// fakeDeepEnricher records the pids it was asked to enrich and stamps a
// sentinel onto each run, so a test can assert WHICH runs reached the
// post-attribution seam and that the stamp survives to persistence.
type fakeDeepEnricher struct {
	pids  []int
	stamp func(*ProcessRun)
}

func (f *fakeDeepEnricher) DeepEnrich(run *ProcessRun) {
	f.pids = append(f.pids, run.PID)
	if f.stamp != nil {
		f.stamp(run)
	}
}

func TestObserverDeepEnrichRunsOncePerPersistedCreate(t *testing.T) {
	t.Parallel()
	de := &fakeDeepEnricher{stamp: func(r *ProcessRun) {
		r.ExeHash = "sha256:deep"
		r.EnvPosture = map[string]string{"DEEP": "1"}
	}}
	be := &FakeBackend{Events: attributedSequence()}
	sink := &SliceSink{}
	attr := NewAttributor(bridgeSeed(100, "sess-1", "claude-code", 7), &FieldScrubber{ArgvMode: "preview", MaxPreviewBytes: 512}, nil)
	_, _ = runObserver(t, Options{Backend: be, Attributor: attr, Sink: sink, DeepEnricher: de, BatchSize: 100, FlushInterval: time.Hour})

	// Called exactly at the two exec (ChangeCreated) points — pid 100 and 200
	// — and NOT on the two exit updates (those reuse the tracked run).
	if len(de.pids) != 2 {
		t.Fatalf("DeepEnrich called %d times, want 2 (one per persisted exec): pids=%v", len(de.pids), de.pids)
	}
	got := map[int]bool{}
	for _, p := range de.pids {
		got[p] = true
	}
	if !got[100] || !got[200] {
		t.Errorf("DeepEnrich pids = %v, want {100,200}", de.pids)
	}
	// The stamp survives onto every persisted copy, including the exit updates.
	for _, r := range sink.Runs {
		if r.ExeHash != "sha256:deep" || r.EnvPosture["DEEP"] != "1" {
			t.Errorf("run pid=%d missing deep-enrich stamp: hash=%q env=%v", r.PID, r.ExeHash, r.EnvPosture)
		}
	}
}

func TestObserverDeepEnrichGatedByCapturePolicy(t *testing.T) {
	t.Parallel()
	events := []RawEvent{
		execEv("b", 500, 1, 1000, "/bin/bash", []string{"bash"}, ts(1)),
		exitEv("b", 500, 1000, 0, ts(2)),
	}
	// Unattributed + capture_unattributed=false → dropped, so the expensive
	// deep enrichment must NOT run.
	de := &fakeDeepEnricher{}
	_, _ = runObserver(t, Options{Backend: &FakeBackend{Events: events}, Attributor: NewAttributor(nil, nil, nil), Sink: &SliceSink{}, DeepEnricher: de, FlushInterval: time.Hour})
	if len(de.pids) != 0 {
		t.Errorf("DeepEnrich ran on a dropped unattributed run: pids=%v", de.pids)
	}

	// capture_unattributed=true → the unattributed exec persists, so it IS
	// enriched (once, at exec).
	de2 := &fakeDeepEnricher{}
	_, _ = runObserver(t, Options{Backend: &FakeBackend{Events: events}, Attributor: NewAttributor(nil, nil, nil), Sink: &SliceSink{}, DeepEnricher: de2, CaptureUnattributed: true, FlushInterval: time.Hour})
	if len(de2.pids) != 1 || de2.pids[0] != 500 {
		t.Errorf("DeepEnrich on captured-unattributed = %v, want [500]", de2.pids)
	}
}

func TestObserverSinkErrorIsNonFatal(t *testing.T) {
	t.Parallel()
	be := &FakeBackend{Events: attributedSequence()}
	// A PERMANENT failure: no retry can fix a constraint violation, so it is
	// dropped at once and counted under its own reason.
	sink := &SliceSink{Err: errors.New("constraint failed: process_runs.process_key")}
	o := NewObserver(Options{Backend: be, Attributor: NewAttributor(bridgeSeed(100, "s", "claude-code", 1), nil, nil), Sink: sink, FlushInterval: time.Hour})
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("sink error must not fail Run: %v", err)
	}
	if o.Health().Snapshot().Dropped[DropSinkError] == 0 {
		t.Error("permanent sink error should be recorded as a drop, not crash the daemon")
	}
}

// flakySink fails its first FailFirst PersistRuns calls with Err, then
// succeeds. It is the whole point of the 9c fix: a sink that is momentarily
// unavailable must not cost the daemon the batch it was holding.
type flakySink struct {
	Err       error
	FailFirst int

	Calls int
	Runs  []ProcessRun
}

func (f *flakySink) PersistRuns(_ context.Context, runs []ProcessRun) (int, error) {
	f.Calls++
	if f.Calls <= f.FailFirst {
		return 0, f.Err
	}
	f.Runs = append(f.Runs, runs...)
	return len(runs), nil
}

// sinkKeys is the set of process keys a sink actually persisted, so a test can
// assert on IDENTITY rather than on a count that a re-offered batch inflates.
func sinkKeys(runs []ProcessRun) map[string]bool {
	m := make(map[string]bool, len(runs))
	for _, r := range runs {
		m[r.ProcessKey] = true
	}
	return m
}

// TestObserverRetainsBatchOnTransientSinkFailure is the 9c regression: one
// `database is locked` used to destroy the entire in-flight batch (up to 250
// runs of process history) with nothing but a counter to show for it. The
// batch must now survive the failure and land on the next flush.
func TestObserverRetainsBatchOnTransientSinkFailure(t *testing.T) {
	t.Parallel()
	be := &FakeBackend{Events: attributedSequence()}
	// BatchSize 1 makes every persisted run its own flush, so the first flush
	// fails and the second carries BOTH the retained run and the new one.
	sink := &flakySink{Err: errors.New("database is locked (5)"), FailFirst: 1}
	o := NewObserver(Options{
		Backend: be, Attributor: NewAttributor(bridgeSeed(100, "s", "claude-code", 1), nil, nil),
		Sink: sink, BatchSize: 1, FlushInterval: time.Hour,
	})
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// All four runs of attributedSequence reach the sink: the one the failed
	// flush was holding, plus the three that followed.
	if got := len(sinkKeys(sink.Runs)); got != 2 {
		// attributedSequence covers two distinct processes (pid 100, pid 200),
		// each persisted twice (exec + exit).
		t.Errorf("distinct persisted process keys = %d, want 2", got)
	}
	if len(sink.Runs) != 4 {
		t.Errorf("persisted %d run snapshots, want 4 — a transient failure must lose none", len(sink.Runs))
	}
	h := o.Health().Snapshot()
	if len(h.Dropped) != 0 {
		t.Errorf("Dropped = %+v, want empty: nothing was lost, only delayed", h.Dropped)
	}
	if h.SinkRetained != 0 {
		t.Errorf("SinkRetained = %d, want 0 once the sink recovered", h.SinkRetained)
	}
}

// TestObserverRetentionIsBounded pins the other half of the contract: the
// retention must never grow without bound against a sink that never recovers,
// and every run it releases must be COUNTED — no silent loss, which is what
// made the original anomaly undiagnosable from outside the daemon.
func TestObserverRetentionIsBounded(t *testing.T) {
	t.Parallel()
	be := &FakeBackend{Events: attributedSequence()}
	sink := &SliceSink{Err: errors.New("database is locked (5)")}
	o := NewObserver(Options{
		Backend: be, Attributor: NewAttributor(bridgeSeed(100, "s", "claude-code", 1), nil, nil),
		Sink: sink, BatchSize: 1, MaxRetainedRuns: 1, FlushInterval: time.Hour,
	})
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	h := o.Health().Snapshot()
	if h.Dropped[DropSinkRetryExhausted] == 0 {
		t.Errorf("Dropped = %+v, want sink_retry_exhausted > 0 once the cap is overrun", h.Dropped)
	}
	if h.Dropped[DropSinkShutdown] == 0 {
		t.Errorf("Dropped = %+v, want sink_shutdown > 0: rows still retained at the final flush are a real loss", h.Dropped)
	}
	// The conservation law: with a sink that persisted nothing, every run
	// snapshot the pipeline produced must appear in the drop counters exactly
	// once. A retained run that is neither persisted nor counted is the class
	// of silent loss this whole task exists to eliminate.
	var accounted int64
	for _, n := range h.Dropped {
		accounted += n
	}
	if accounted != 4 {
		t.Errorf("drop counters total %d, want 4 (every run snapshot accounted for): %+v", accounted, h.Dropped)
	}
	if h.SinkRetained != 0 {
		t.Errorf("SinkRetained = %d, want 0 after the final flush released everything", h.SinkRetained)
	}
}

// TestObserverPermanentSinkErrorIsNotRetained pins the counterweight: a
// failure no retry can fix must NOT occupy the retention, or a single
// malformed batch would block rows that could still land.
func TestObserverPermanentSinkErrorIsNotRetained(t *testing.T) {
	t.Parallel()
	be := &FakeBackend{Events: attributedSequence()}
	sink := &flakySink{Err: errors.New("store.PersistRuns: exec[0]: no such table: process_runs"), FailFirst: 1}
	o := NewObserver(Options{
		Backend: be, Attributor: NewAttributor(bridgeSeed(100, "s", "claude-code", 1), nil, nil),
		Sink: sink, BatchSize: 1, FlushInterval: time.Hour,
	})
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	h := o.Health().Snapshot()
	if h.Dropped[DropSinkError] != 1 {
		t.Errorf("Dropped[sink_error] = %d, want 1 — a permanent failure is released immediately: %+v", h.Dropped[DropSinkError], h.Dropped)
	}
	if h.Dropped[DropSinkRetryExhausted] != 0 {
		t.Errorf("Dropped = %+v, want no retry_exhausted: the batch was never retained", h.Dropped)
	}
	// The three later runs still land — a permanent failure on one batch must
	// not poison the ones after it.
	if len(sink.Runs) != 3 {
		t.Errorf("persisted %d runs after the permanent failure, want 3", len(sink.Runs))
	}
}

// classifierSink declares the optional SinkErrorClassifier capability, the way
// the store does for its driver's structured codes.
type classifierSink struct {
	SliceSink
	class SinkErrorClass
}

func (c *classifierSink) ClassifySinkError(error) SinkErrorClass { return c.class }

// TestObserverSinkClassifierCapabilityOutranksTable pins the capability seam:
// a sink that KNOWS its driver's structured code decides, and the shared
// string table is only the fallback. Branching on the capability (never on the
// sink's concrete type) is what keeps this rule-compliant.
func TestObserverSinkClassifierCapabilityOutranksTable(t *testing.T) {
	t.Parallel()
	// The message reads permanent to the table ("constraint failed"), but the
	// sink itself says transient — so it must be retained, not dropped.
	sink := &classifierSink{
		SliceSink: SliceSink{Err: errors.New("constraint failed")},
		class:     SinkErrorTransient,
	}
	o := NewObserver(Options{
		Backend:    &FakeBackend{Events: attributedSequence()},
		Attributor: NewAttributor(bridgeSeed(100, "s", "claude-code", 1), nil, nil),
		Sink:       sink, BatchSize: 1, FlushInterval: time.Hour,
	})
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	h := o.Health().Snapshot()
	if h.Dropped[DropSinkError] != 0 {
		t.Errorf("Dropped = %+v, want no sink_error: the sink's own classifier said transient", h.Dropped)
	}
	if h.Dropped[DropSinkShutdown] == 0 {
		t.Errorf("Dropped = %+v, want sink_shutdown: retained rows lost at the final flush are still counted", h.Dropped)
	}
}
