package captureprogress

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t = t.Add(time.Second)
		return t
	}
}

func record(tr *Tracker, evs ...Event) {
	for _, ev := range evs {
		tr.Record(ev)
	}
}

func TestNilTrackerIsIdleAndAcceptsEvents(t *testing.T) {
	var tr *Tracker
	tr.Record(Event{Kind: ScanStarted})
	tr.Record(Event{Kind: FileFound, Tool: "a"})
	if got := tr.Snapshot(); got.State != ScanIdle || len(got.Tools) != 0 {
		t.Fatalf("nil tracker snapshot = %+v, want idle and empty", got)
	}
}

func TestEmptyTrackerIsIdle(t *testing.T) {
	if got := New(nil).Snapshot().State; got != ScanIdle {
		t.Fatalf("state = %q, want idle", got)
	}
}

func TestInitialScanLifecycle(t *testing.T) {
	tr := New(fixedClock())
	record(tr,
		Event{Kind: ScanStarted},
		Event{Kind: WalkStarted, Tool: "claude-code"},
		Event{Kind: WalkStarted, Tool: "codex"},
		Event{Kind: FileFound, Tool: "claude-code"},
		Event{Kind: FileFound, Tool: "claude-code"},
		Event{Kind: FileFound, Tool: "codex"},
		Event{Kind: FileProcessed, Tool: "claude-code"},
	)
	s := tr.Snapshot()
	if s.State != ScanRunning {
		t.Fatalf("mid-scan state = %q, want scanning", s.State)
	}
	if s.FilesFound != 3 || s.FilesProcessed != 1 {
		t.Fatalf("totals found=%d processed=%d, want 3/1", s.FilesFound, s.FilesProcessed)
	}
	cc, ok := s.Tool("claude-code")
	if !ok || cc.State != ToolScanning || cc.FilesFound != 2 || cc.FilesProcessed != 1 {
		t.Fatalf("claude-code = %+v", cc)
	}
	if !cc.FinishedAt.IsZero() {
		t.Fatalf("a scanning tool has no finish time, got %v", cc.FinishedAt)
	}

	record(tr,
		Event{Kind: WalkFinished, Tool: "claude-code"},
		Event{Kind: FileProcessed, Tool: "claude-code"},
		Event{Kind: WalkFinished, Tool: "codex"},
		Event{Kind: FileProcessed, Tool: "codex"},
		Event{Kind: ScanFinished},
	)
	s = tr.Snapshot()
	if s.State != ScanDone || s.FinishedAt.IsZero() {
		t.Fatalf("final state = %q finished=%v, want done with a time", s.State, s.FinishedAt)
	}
	for _, tp := range s.Tools {
		if tp.State != ToolDone || tp.Reason != "" || tp.FinishedAt.IsZero() {
			t.Fatalf("tool %+v, want done with no reason and a finish time", tp)
		}
	}
	if s.Tools[0].Tool != "claude-code" || s.Tools[1].Tool != "codex" {
		t.Fatalf("tools not sorted: %+v", s.Tools)
	}
}

func TestWalkStillOpenKeepsToolScanningEvenWhenCaughtUp(t *testing.T) {
	tr := New(fixedClock())
	record(tr,
		Event{Kind: ScanStarted},
		Event{Kind: WalkStarted, Tool: "a"},
		Event{Kind: FileFound, Tool: "a"},
		Event{Kind: FileProcessed, Tool: "a"},
	)
	if tp, _ := tr.Snapshot().Tool("a"); tp.State != ToolScanning {
		t.Fatalf("state = %q, want scanning while the walk is open", tp.State)
	}
}

func TestToolStateRules(t *testing.T) {
	cases := []struct {
		rule   string
		facts  toolFacts
		state  ToolState
		reason string
	}{
		{"stopped before finishing", toolFacts{found: 4, processed: 1, stopped: true}, ToolStopped, "continues on the next start"},
		{"still finding or reading files", toolFacts{found: 4, processed: 1}, ToolScanning, ""},
		{"still finding or reading files (walk open)", toolFacts{walking: 1}, ToolScanning, ""},
		{"every file failed", toolFacts{found: 2, failed: 2, lastErr: "permission denied"}, ToolFailed, "Could not read 2 files. Last error: permission denied"},
		{"some files failed", toolFacts{found: 5, processed: 4, failed: 1}, ToolDone, "1 of 5 files could not be read."},
		{"finished", toolFacts{found: 3, processed: 3}, ToolDone, ""},
		{"finished (stopped but complete)", toolFacts{found: 3, processed: 3, stopped: true}, ToolDone, ""},
		{"finished (nothing found)", toolFacts{}, ToolDone, ""},
	}
	for _, c := range cases {
		state, reason := decideTool(c.facts)
		if state != c.state {
			t.Errorf("%s: state = %q, want %q", c.rule, state, c.state)
		}
		if c.reason == "" && reason != "" {
			t.Errorf("%s: reason = %q, want none", c.rule, reason)
		}
		if c.reason != "" && !strings.Contains(reason, c.reason) {
			t.Errorf("%s: reason = %q, want it to contain %q", c.rule, reason, c.reason)
		}
	}
	// Every rule row is exercised by name above.
	for _, r := range toolStateRules {
		found := false
		for _, c := range cases {
			if strings.HasPrefix(c.rule, r.name) {
				found = true
			}
		}
		if !found {
			t.Errorf("rule %q has no test row", r.name)
		}
	}
}

func TestScanStateRules(t *testing.T) {
	cases := []struct {
		rule  string
		facts scanFacts
		state ScanState
	}{
		{"nothing reported", scanFacts{}, ScanIdle},
		{"stopped early", scanFacts{started: true, finished: true, cancelled: true, anyTool: true}, ScanStopped},
		{"initial scan running", scanFacts{started: true}, ScanRunning},
		{"a walk is still open", scanFacts{started: true, finished: true, anyTool: true, anyOpen: true}, ScanRunning},
		{"everything finished", scanFacts{started: true, finished: true, anyTool: true}, ScanDone},
	}
	for _, c := range cases {
		if got := decideScan(c.facts); got != c.state {
			t.Errorf("%s: state = %q, want %q", c.rule, got, c.state)
		}
	}
	if len(cases) != len(scanStateRules) {
		t.Fatalf("%d cases for %d rules", len(cases), len(scanStateRules))
	}
}

func TestCancelledScanMarksPendingToolsStopped(t *testing.T) {
	tr := New(fixedClock())
	record(tr,
		Event{Kind: ScanStarted},
		Event{Kind: WalkStarted, Tool: "a"},
		Event{Kind: WalkStarted, Tool: "b"},
		Event{Kind: FileFound, Tool: "a"},
		Event{Kind: FileProcessed, Tool: "a"},
		Event{Kind: WalkFinished, Tool: "a"},
		Event{Kind: FileFound, Tool: "b"},
		Event{Kind: FileFound, Tool: "b"},
		Event{Kind: WalkFinished, Tool: "b"},
		Event{Kind: ScanFinished, Cancelled: true},
	)
	s := tr.Snapshot()
	if s.State != ScanStopped {
		t.Fatalf("state = %q, want stopped", s.State)
	}
	if a, _ := s.Tool("a"); a.State != ToolDone {
		t.Fatalf("a = %q, want done", a.State)
	}
	if b, _ := s.Tool("b"); b.State != ToolStopped {
		t.Fatalf("b = %q, want stopped", b.State)
	}
}

func TestHotAddedWalkReopensAfterScanDone(t *testing.T) {
	tr := New(fixedClock())
	record(tr, Event{Kind: ScanStarted}, Event{Kind: ScanFinished})
	if got := tr.Snapshot().State; got != ScanDone {
		t.Fatalf("empty finished scan = %q, want done", got)
	}
	record(tr,
		Event{Kind: WalkStarted, Tool: "muse"},
		Event{Kind: FileFound, Tool: "muse"},
	)
	if got := tr.Snapshot().State; got != ScanRunning {
		t.Fatalf("after a hot-add walk opens = %q, want scanning", got)
	}
	record(tr, Event{Kind: FileProcessed, Tool: "muse"}, Event{Kind: WalkFinished, Tool: "muse"})
	s := tr.Snapshot()
	if s.State != ScanDone {
		t.Fatalf("after the hot-add walk = %q, want done", s.State)
	}
	if m, _ := s.Tool("muse"); m.State != ToolDone || m.FilesProcessed != 1 {
		t.Fatalf("muse = %+v", m)
	}
}

func TestFailureReasonIsBounded(t *testing.T) {
	tr := New(fixedClock())
	long := strings.Repeat("x", 500)
	record(tr,
		Event{Kind: WalkStarted, Tool: "a"},
		Event{Kind: FileFound, Tool: "a"},
		Event{Kind: FileFailed, Tool: "a", Err: long},
		Event{Kind: WalkFinished, Tool: "a"},
	)
	a, _ := tr.Snapshot().Tool("a")
	if a.State != ToolFailed {
		t.Fatalf("state = %q, want failed", a.State)
	}
	if len(a.Reason) > maxReason+60 {
		t.Fatalf("reason not bounded: %d bytes", len(a.Reason))
	}
}

func TestIgnoresMalformedEvents(t *testing.T) {
	tr := New(fixedClock())
	record(tr,
		Event{Kind: FileFound}, // no tool
		Event{Kind: EventKind(99), Tool: "a"},
	)
	s := tr.Snapshot()
	if s.FilesFound != 0 {
		t.Fatalf("found = %d, want 0", s.FilesFound)
	}
}

func TestConcurrentRecord(t *testing.T) {
	tr := New(nil)
	tr.Record(Event{Kind: WalkStarted, Tool: "a"})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tr.Record(Event{Kind: FileFound, Tool: "a"})
				tr.Record(Event{Kind: FileProcessed, Tool: "a"})
				_ = tr.Snapshot()
			}
		}()
	}
	wg.Wait()
	tr.Record(Event{Kind: WalkFinished, Tool: "a"})
	a, _ := tr.Snapshot().Tool("a")
	if a.FilesFound != 800 || a.FilesProcessed != 800 || a.State != ToolDone {
		t.Fatalf("a = %+v", a)
	}
}
