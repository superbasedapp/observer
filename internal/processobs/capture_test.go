package processobs

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proccapture"
)

// captureSink records both halves of a capture flush.
type captureSink struct {
	SliceSink
	calls int
	delta []proccapture.Delta
}

func (c *captureSink) PersistCapture(_ context.Context, runs []ProcessRun, d proccapture.Delta) (int, error) {
	c.calls++
	c.Runs = append(c.Runs, runs...)
	c.delta = append(c.delta, d)
	return len(runs), nil
}

func (c *captureSink) stats() map[string]proccapture.Stats {
	out := map[string]proccapture.Stats{}
	for _, d := range c.delta {
		for k, v := range d.Stats {
			s := out[k]
			s.Add(v)
			out[k] = s
		}
	}
	return out
}

func (c *captureSink) rollupCount() int64 {
	var n int64
	for _, d := range c.delta {
		for _, r := range d.Rollups {
			n += r.Count
		}
	}
	return n
}

// buildFanOut: the bridged root, one tool-call shell, n short-lived build
// children (each with a console host), one failing child, then exits.
func buildFanOut(n int) []RawEvent {
	evs := []RawEvent{
		execEv("b", 100, 1, 1000, "/usr/bin/claude", []string{"claude"}, ts(1)),
		forkEv("b", 200, 100, 2000, ts(2)),
		execEv("b", 200, 100, 2000, "/bin/bash", []string{"bash", "-c", "go build ./..."}, ts(2)),
	}
	pid := 1000
	for i := range n {
		at := ts(3 + i%20)
		evs = append(evs,
			forkEv("b", pid, 200, int64(pid), at),
			execEv("b", pid, 200, int64(pid), "/usr/lib/go/compile", []string{"compile", "-p", fmt.Sprint("pkg", i%7)}, at),
			forkEv("b", pid+1, pid, int64(pid+1), at),
			execEv("b", pid+1, pid, int64(pid+1), `C:\Windows\System32\conhost.exe`, []string{"conhost.exe", "0xffffffff"}, at),
			exitEv("b", pid+1, int64(pid+1), 0, at.Add(time.Second)),
			exitEv("b", pid, int64(pid), map[bool]int{true: 2}[i == 5], at.Add(time.Second)),
		)
		pid += 2
	}
	return append(evs, exitEv("b", 200, 2000, 0, ts(30)), exitEv("b", 100, 1000, 0, ts(31)))
}

func newTestAttributor() *Attributor {
	return NewAttributor(bridgeSeed(100, "sess-1", "claude-code", 7), &FieldScrubber{ArgvMode: "preview", MaxPreviewBytes: 512}, nil)
}

func runCapture(t *testing.T, events []RawEvent, cfg proccapture.Config, sink Sink, attr *Attributor) *Observer {
	t.Helper()
	o := NewObserver(Options{
		Backend: &FakeBackend{Events: events}, Attributor: attr, Sink: sink,
		BatchSize: 50, FlushInterval: time.Hour, Capture: cfg,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := o.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return o
}

// TestCaptureDisabledIsByteIdentical: with capture.enabled = false the sink
// receives exactly what an Observer without the field receives, through
// PersistRuns, with no capture tags or classes, and the CaptureSink half is
// never called.
func TestCaptureDisabledIsByteIdentical(t *testing.T) {
	t.Parallel()
	events := buildFanOut(30)
	plain := &SliceSink{}
	runCapture(t, events, proccapture.Config{}, plain, newTestAttributor())

	off := proccapture.DefaultConfig()
	off.Enabled = false
	cs := &captureSink{}
	attr := newTestAttributor()
	if off.Enabled {
		attr.SetServiceTable(proccapture.NewPolicy(off).IsService)
	}
	runCapture(t, events, off, cs, attr)
	if cs.calls != 0 {
		t.Fatalf("PersistCapture called %d times with the budget off", cs.calls)
	}
	if !reflect.DeepEqual(plain.Runs, cs.Runs) {
		t.Fatalf("disabled capture diverged: %d vs %d runs", len(plain.Runs), len(cs.Runs))
	}
	for _, r := range cs.Runs {
		if r.Capture != nil || r.CaptureClass != "" || r.ServiceRootKey != "" {
			t.Fatalf("capture fields set with the budget off: %+v", r)
		}
	}
}

// TestCaptureFoldsBudgetsAndCounts: console hosts fold, the build fan-out
// past the per-tool-call budget rolls up, the failure and the tool-call root
// are kept, and observed == accounted.
func TestCaptureFoldsBudgetsAndCounts(t *testing.T) {
	t.Parallel()
	cfg := proccapture.DefaultConfig()
	cfg.PerToolCall = 10
	n := 40
	cs := &captureSink{}
	attr := newTestAttributor()
	attr.SetServiceTable(proccapture.NewPolicy(cfg).IsService)
	runCapture(t, buildFanOut(n), cfg, cs, attr)

	st := cs.stats()["sess-1"]
	observed := int64(2 + 2*n) // root + shell + n compile + n conhost
	if st.Observed != observed || st.Observed != st.Accounted() {
		t.Fatalf("stats %+v, want observed %d", st, observed)
	}
	if st.Folded != int64(n) {
		t.Fatalf("folded %d, want every console host (%d)", st.Folded, n)
	}
	if st.RolledUp == 0 || st.BudgetHits == 0 {
		t.Fatalf("the budget never hit: %+v", st)
	}
	if got := cs.rollupCount(); got != st.Folded+st.RolledUp {
		t.Fatalf("rollup count %d, counters %d", got, st.Folded+st.RolledUp)
	}
	keys := map[string]bool{}
	var folds int64
	for _, d := range cs.delta {
		for _, n := range d.Folds {
			folds += n
		}
	}
	if folds != int64(n) {
		t.Fatalf("fold increments %d, want %d", folds, n)
	}
	for _, r := range cs.Runs {
		keys[r.ProcessKey] = true
		if r.CaptureClass == "" {
			t.Fatalf("a kept row has no capture class: %+v", r)
		}
	}
	for _, want := range []string{ProcessKey("b", 100, 1000), ProcessKey("b", 200, 2000), ProcessKey("b", 1010, 1010)} {
		if !keys[want] {
			t.Fatalf("lost %s (root, tool-call root, or the failure)", want)
		}
	}
	if int64(len(keys)) != st.Kept {
		t.Fatalf("%d distinct rows, %d counted kept", len(keys), st.Kept)
	}
}

// TestCaptureEnvTokenStopsAtServiceRoot: a service started from a tool call
// keeps its children inside the service (inherited attribution, not a fresh
// env-token identity), still attributed to the session, capped at the
// service exemplar count and rolled up after that.
func TestCaptureEnvTokenStopsAtServiceRoot(t *testing.T) {
	t.Parallel()
	cfg := proccapture.DefaultConfig()
	cfg.ExemplarsPerService = 3
	attr := newTestAttributor()
	attr.SetTokenLookup(func(tok string) (Seed, bool) {
		if tok == "sess-1" {
			return Seed{SessionID: "sess-1", Tool: "claude-code"}, true
		}
		return Seed{}, false
	})
	attr.SetServiceTable(proccapture.NewPolicy(cfg).IsService)
	tok := func(ev RawEvent) RawEvent { ev.SessionToken = "sess-1"; return ev }
	evs := []RawEvent{
		execEv("b", 100, 1, 1000, "/usr/bin/claude", []string{"claude"}, ts(1)),
		forkEv("b", 200, 100, 2000, ts(2)),
		tok(execEv("b", 200, 100, 2000, "powershell.exe", []string{"powershell", "Start-Process", "Docker Desktop"}, ts(2))),
		forkEv("b", 300, 200, 3000, ts(3)),
		tok(execEv("b", 300, 200, 3000, `C:\Program Files\Docker\Docker Desktop.exe`, []string{"Docker Desktop.exe"}, ts(3))),
	}
	pid := 400
	for i := range 10 {
		at := ts(10 + i)
		evs = append(evs,
			forkEv("b", pid, 300, int64(pid), at),
			tok(execEv("b", pid, 300, int64(pid), "docker.exe", []string{"docker.exe", "stats", "--all", "--no-trunc", "--no-stream"}, at)),
			exitEv("b", pid, int64(pid), 0, at.Add(time.Second)),
		)
		pid++
	}
	cs := &captureSink{}
	runCapture(t, evs, cfg, cs, attr)

	st := cs.stats()["sess-1"]
	if st.Observed != 13 || st.Observed != st.Accounted() {
		t.Fatalf("stats %+v", st)
	}
	// Service root + 3 exemplars kept as service rows, 7 rolled up.
	if st.ServiceKept != 4 || st.ServiceRolledUp != 7 {
		t.Fatalf("service counters %+v", st)
	}
	svcRoot := ProcessKey("b", 300, 3000)
	for _, r := range cs.Runs {
		if r.ExeBasename != "docker.exe" {
			continue
		}
		if r.Attribution.SessionID != "sess-1" || r.Attribution.Source != AttrInherited {
			t.Fatalf("service child attribution %+v: the env token must not re-identify it", r.Attribution)
		}
		if r.ServiceRootKey != svcRoot || r.CaptureClass != "service" {
			t.Fatalf("service child capture fields %+v", r)
		}
	}
	for _, d := range cs.delta {
		for _, r := range d.Rollups {
			if r.Key.Kind != proccapture.GroupService || r.Key.ServiceRootKey != svcRoot || r.Key.ParentProcessKey != svcRoot {
				t.Fatalf("service rollup key %+v", r.Key)
			}
		}
	}
}

// TestCaptureRingSkippedForYoungRuns: a kept run younger than the ring
// threshold is persisted without metric samples.
func TestCaptureRingSkippedForYoungRuns(t *testing.T) {
	t.Parallel()
	cfg := proccapture.DefaultConfig()
	ev := execEv("b", 100, 1, 1000, "/usr/bin/claude", []string{"claude"}, ts(1))
	ev.HasMetrics, ev.CPUUserMs, ev.WorkingSetBytes = true, 5, 1000
	cs := &captureSink{}
	runCapture(t, []RawEvent{ev}, cfg, cs, newTestAttributor())
	if len(cs.Runs) != 1 || cs.Runs[0].MetricSamples != nil || cs.Runs[0].CPUUserMs != 5 {
		t.Fatalf("runs %+v", cs.Runs)
	}
}
