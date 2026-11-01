package watcher

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/captureprogress"
)

// TestInitialScanFeedsCaptureProgress pins the T-922 seam: the background
// initial scan Watch starts reports, per adapter, the files it found and
// read, and the model reaches done once both lanes finish. A file held
// mid-parse shows the tool (and the scan) as still scanning.
func TestInitialScanFeedsCaptureProgress(t *testing.T) {
	j := &parseJournal{}
	rootA, rootB := t.TempDir(), t.TempDir()
	a := &orderAdapter{
		name: "tool-a", root: rootA, ext: ".jsonl", journal: j,
		blockName: "f001.jsonl", block: make(chan struct{}), started: make(chan struct{}),
	}
	b := &orderAdapter{name: "tool-b", root: rootB, ext: ".jsonl", journal: j}
	writeFiles(t, rootA, ".jsonl", 3)
	writeFiles(t, rootB, ".jsonl", 2)
	w, _ := fairScanFixture(t, 0, a, b)
	tr := captureprogress.New(nil)
	w.SetCaptureProgress(tr)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Watch(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	select {
	case <-a.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the held parse never started")
	}
	// With a progress model the walk runs ahead of the reader (relayPaths),
	// so every file is counted as found while one parse is still held: the
	// found count is the real total, not "one ahead of the reader".
	var mid captureprogress.Snapshot
	walkDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(walkDeadline) {
		if mid = tr.Snapshot(); mid.FilesFound == 5 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if mid.FilesFound != 5 {
		t.Fatalf("found %d files while a parse was held, want all 5", mid.FilesFound)
	}
	if mid.State != captureprogress.ScanRunning {
		t.Fatalf("mid-scan state = %q, want scanning", mid.State)
	}
	if ta, ok := mid.Tool("tool-a"); !ok || ta.State != captureprogress.ToolScanning {
		t.Fatalf("tool-a mid-scan = %+v (ok=%v), want scanning", ta, ok)
	}
	close(a.block)

	deadline := time.Now().Add(10 * time.Second)
	var s captureprogress.Snapshot
	for time.Now().Before(deadline) {
		s = tr.Snapshot()
		if s.State == captureprogress.ScanDone {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.State != captureprogress.ScanDone {
		t.Fatalf("final state = %q, want done (%+v)", s.State, s)
	}
	want := map[string]int{"tool-a": 3, "tool-b": 2}
	for tool, n := range want {
		tp, ok := s.Tool(tool)
		if !ok || tp.State != captureprogress.ToolDone || tp.FilesFound != n || tp.FilesProcessed != n {
			t.Fatalf("%s = %+v (ok=%v), want done with %d found and read", tool, tp, ok, n)
		}
	}
}

// TestRelayPathsKeepsOrderAndNeverBlocksTheSender: the sender hands over
// every path without a reader, the reader then gets them in order, and out
// closes after the queue drains.
func TestRelayPathsKeepsOrderAndNeverBlocksTheSender(t *testing.T) {
	in, out := make(chan string), make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayPaths(context.Background(), in, out)
	}()
	want := []string{"a", "b", "c", "d", "e"}
	for _, p := range want {
		select {
		case in <- p:
		case <-time.After(5 * time.Second):
			t.Fatalf("sender blocked on %q with no reader", p)
		}
	}
	close(in)
	var got []string
	for p := range out {
		got = append(got, p)
	}
	<-done
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestRelayPathsStopsOnCancel: a cancelled context closes out even with
// paths still queued.
func TestRelayPathsStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	in, out := make(chan string), make(chan string)
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayPaths(ctx, in, out)
	}()
	in <- "a"
	in <- "b"
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not stop on cancel")
	}
	// out must be closed (a receive returns at once with ok=false).
	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("out delivered a path after cancel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("out was not closed after cancel")
	}
}

// TestExplicitScanDoesNotFeedCaptureProgress: Scan (the `observer scan` /
// RefreshRoots path) is not the history capture the first-run view reports.
func TestExplicitScanDoesNotFeedCaptureProgress(t *testing.T) {
	j := &parseJournal{}
	root := t.TempDir()
	a := &orderAdapter{name: "tool-a", root: root, ext: ".jsonl", journal: j}
	writeFiles(t, root, ".jsonl", 2)
	w, _ := fairScanFixture(t, 0, a)
	tr := captureprogress.New(nil)
	w.SetCaptureProgress(tr)
	if _, err := w.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := tr.Snapshot(); s.State != captureprogress.ScanIdle || len(s.Tools) != 0 {
		t.Fatalf("explicit Scan reported progress: %+v", s)
	}
}

// TestHotAddWalkFeedsCaptureProgress: a store that appears after the daemon
// started is walked by hotAddRoots, and that walk is reported too.
func TestHotAddWalkFeedsCaptureProgress(t *testing.T) {
	j := &parseJournal{}
	parent := t.TempDir()
	root := parent + string(os.PathSeparator) + "late"
	a := &orderAdapter{name: "tool-late", root: root, ext: ".jsonl", journal: j}
	w, _ := fairScanFixture(t, 0, a)
	tr := captureprogress.New(nil)
	w.SetCaptureProgress(tr)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Watch(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	// Wait for the (empty) initial scan to finish.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && tr.Snapshot().State != captureprogress.ScanDone {
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFiles(t, root, ".jsonl", 2)
	// fsw may not be live yet; retry the hot-add until the root registers.
	for time.Now().Before(deadline) {
		if w.hotAddRoots(ctx) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	tp, ok := tr.Snapshot().Tool("tool-late")
	if !ok || tp.State != captureprogress.ToolDone || tp.FilesProcessed != 2 {
		t.Fatalf("tool-late = %+v (ok=%v), want done with 2 read", tp, ok)
	}
}
