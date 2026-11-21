package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// sandbox_probe_bounded_test.go pins the bounded read of GET
// /api/terminal/sandbox (lane L2: a fresh install's Sandbox isolation card
// must never wait on the probe without end). One test per rule of
// sandboxProbeFlights.probe.

// blockingProber answers only when release closes, counting its calls.
type blockingProber struct {
	release chan struct{}
	calls   atomic.Int32
	avail   SandboxAvailability
}

func (b *blockingProber) ProbeSandbox(ctx context.Context) SandboxAvailability {
	b.calls.Add(1)
	<-b.release
	return b.avail
}

// panickingProber panics, as a broken driver probe would.
type panickingProber struct{}

func (panickingProber) ProbeSandbox(context.Context) SandboxAvailability {
	panic("driver probe exploded")
}

// Rule: a probe that answers within the deadline is passed through.
func TestSandboxProbeBoundedPassesAnAnswerThrough(t *testing.T) {
	var f sandboxProbeFlights
	p := &fakeSandboxProber{avail: SandboxAvailability{Available: true, Verdict: "available", Backend: "bwrap"}}
	av, ok := f.probe(context.Background(), p, time.Second)
	if !ok || !av.Available || av.Backend != "bwrap" {
		t.Fatalf("probe = %+v ok=%v, want the prober's answer", av, ok)
	}
}

// Rule: a probe that has not answered by the deadline answers
// probe_timed_out, with a reason, and does not hold the caller.
func TestSandboxProbeBoundedTimesOut(t *testing.T) {
	var f sandboxProbeFlights
	p := &blockingProber{release: make(chan struct{})}
	defer close(p.release)
	start := time.Now()
	av, ok := f.probe(context.Background(), p, 50*time.Millisecond)
	if !ok {
		t.Fatal("ok = false, want an answer")
	}
	if av.Available || av.Verdict != VerdictProbeTimedOut || av.Reason == "" {
		t.Fatalf("probe = %+v, want probe_timed_out with a reason", av)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("took %s, want about the deadline", took)
	}
}

// Rule: reads that arrive while a probe runs wait on that one probe, never
// start a second, and the read after it finishes gets its answer.
func TestSandboxProbeBoundedSharesOneFlight(t *testing.T) {
	var f sandboxProbeFlights
	p := &blockingProber{release: make(chan struct{}), avail: SandboxAvailability{Available: true, Verdict: "available"}}
	for i := 0; i < 3; i++ {
		if av, _ := f.probe(context.Background(), p, 10*time.Millisecond); av.Verdict != VerdictProbeTimedOut {
			t.Fatalf("read %d = %+v, want probe_timed_out while the probe runs", i, av)
		}
	}
	if n := p.calls.Load(); n != 1 {
		t.Fatalf("probe calls = %d, want 1 (one flight shared by every waiting read)", n)
	}
	close(p.release)
	av, ok := f.probe(context.Background(), p, 2*time.Second)
	if !ok || !av.Available {
		t.Fatalf("after release = %+v ok=%v, want the probe's answer", av, ok)
	}
}

// Rule: a probe that panics answers probe_failed and the slot is freed.
func TestSandboxProbeBoundedRecoversAPanic(t *testing.T) {
	var f sandboxProbeFlights
	av, ok := f.probe(context.Background(), panickingProber{}, 2*time.Second)
	if !ok || av.Available || av.Verdict != VerdictProbeFailed || av.Reason == "" {
		t.Fatalf("probe = %+v ok=%v, want probe_failed with a reason", av, ok)
	}
	f.mu.Lock()
	cur := f.cur
	f.mu.Unlock()
	if cur != nil {
		t.Fatal("the in-flight slot was not freed after the panic")
	}
}

// Rule: a reader whose request ended gets ok=false (nothing is written).
func TestSandboxProbeBoundedStopsForAGoneClient(t *testing.T) {
	var f sandboxProbeFlights
	p := &blockingProber{release: make(chan struct{})}
	defer close(p.release)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := f.probe(ctx, p, time.Second); ok {
		t.Fatal("ok = true, want false for a cancelled request")
	}
}

// The route answers 200 probe_timed_out under its deadline (the card's
// "Running daemon" line then says the check took too long).
func TestTerminalSandboxProbeRouteIsBounded(t *testing.T) {
	old := sandboxProbeDeadline
	sandboxProbeDeadline = 50 * time.Millisecond
	t.Cleanup(func() { sandboxProbeDeadline = old })
	p := &blockingProber{release: make(chan struct{})}
	defer close(p.release)
	s := newLaunchTestServerWithSandbox(t, &fakeLaunchManager{}, p)
	rec := getTerminalSandboxProbe(t, s.Handler())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var out SandboxAvailability
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Verdict != VerdictProbeTimedOut {
		t.Fatalf("verdict = %q, want probe_timed_out", out.Verdict)
	}
}

// A fresh install has no config file at all: the editor still gets a full
// default [terminal.sandbox] block, so the card renders its controls (the
// enable switch included) instead of a loading line.
func TestTerminalSandboxConfigGetDefaultsWithNoConfigFile(t *testing.T) {
	s, h := newManageServer(t)
	if err := os.Remove(s.opts.ConfigPath); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/sandbox/config", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		ConfigWritable bool                          `json:"config_writable"`
		Sandbox        *terminalSandboxConfigPayload `json:"sandbox"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Sandbox == nil {
		t.Fatalf("sandbox block missing with no config file: %s", rec.Body.String())
	}
	if !got.ConfigWritable || got.Sandbox.Enabled || got.Sandbox.Backend != "bwrap" || got.Sandbox.HomeMode != "tmpfs" {
		t.Fatalf("defaults with no config file = writable %v, %+v", got.ConfigWritable, *got.Sandbox)
	}
}
