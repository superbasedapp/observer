//go:build linux

package sandboxrelayd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// finishesWithin fails the test when f takes longer than limit (it does not wait
// for a stuck f to return).
func finishesWithin(t *testing.T, limit time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s blocked for more than %v", what, limit)
	}
}

// TestConfinedTailRefusesWhatIsSwappedInAfterTheCheck (audit finding F1 of
// lane sbx-p2d): a hostile box swaps its transcript between the Lstat walk
// and the open. A FIFO never holds the open (it is opened without
// blocking) and, like a symlink, a directory or a device, it is refused by
// the opened descriptor's own fstat.
func TestConfinedTailRefusesWhatIsSwappedInAfterTheCheck(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "session.jsonl")
	for _, tc := range []struct {
		name string
		swap func(path string) error
	}{
		{"a FIFO", func(p string) error { return syscall.Mkfifo(p, 0o600) }},
		{"a symlink", func(p string) error { return os.Symlink("/etc/passwd", p) }},
		{"a directory", func(p string) error { return os.Mkdir(p, 0o700) }},
		{"a character device", func(p string) error {
			return syscall.Mknod(p, syscall.S_IFCHR|0o600, int((1<<8)|3)) // /dev/null's numbers
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.RemoveAll(target)
			if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			swapErr := error(nil)
			confineBeforeOpen = func(string, string) {
				_ = os.Remove(target)
				swapErr = tc.swap(target)
			}
			defer func() { confineBeforeOpen = nil }()
			var f hookctx.File
			var err error
			finishesWithin(t, 2*time.Second, "the confined open", func() { f, err = OpenConfinedTail([]string{dir}, target) })
			if swapErr != nil {
				if errors.Is(swapErr, syscall.EPERM) {
					t.Skipf("cannot make %s here: %v", tc.name, swapErr)
				}
				t.Fatal(swapErr)
			}
			if err == nil {
				_ = f.Close()
				t.Fatalf("%s swapped in after the check was opened", tc.name)
			}
			if !errors.Is(err, hookctx.ErrRefused) {
				t.Fatalf("not a refusal: %v", err)
			}
		})
	}
	// A FIFO there from the start is refused as well, without blocking.
	_ = os.RemoveAll(target)
	if err := syscall.Mkfifo(target, 0o600); err != nil {
		t.Fatal(err)
	}
	finishesWithin(t, 2*time.Second, "the confined open of a FIFO", func() {
		if f, err := OpenConfinedTail([]string{dir}, target); err == nil {
			_ = f.Close()
			t.Error("a FIFO was opened")
		}
	})
	// A regular file still reads.
	_ = os.Remove(target)
	if err := os.WriteFile(target, []byte("line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenConfinedTail([]string{dir}, target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 16)
	if n, err := f.Read(buf); err != nil || string(buf[:n]) != "line\n" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
}

// TestFIFOTranscriptStallsNeitherAnswerNorTicker (audit finding F1): a box
// that swaps its transcript for a FIFO stalls neither the answer to its
// next hook event nor the drift comparison, and another run's drift is
// still found in the same comparison.
func TestFIFOTranscriptStallsNeitherAnswerNorTicker(t *testing.T) {
	tr := newBindTree(t)
	hostile := filepath.Join(tr.ws, "hostile.jsonl")
	honest := filepath.Join(tr.ws, "honest.jsonl")
	appendFile(t, hostile, "")
	appendFile(t, honest, "")
	runH, runK := bindRun(t, "run-h", tr), bindRun(t, "run-k", tr)
	d := &Daemon{SweepInterval: -1, Drift: claudeDrift(time.Minute)}
	// The hostile run's read is bounded by the real deadline clock.
	d.Drift.ReadDeadline, d.Drift.after = 2*time.Second, nil
	h := startBindHarness(t, d, runH, runK)
	gate := func(rec RunRecord, path, id string) {
		t.Helper()
		body := fmt.Sprintf(`{"transcript_path":%q,"tool_use_id":%q}`, path, id)
		h.send(t, rec, sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}, Stdin: []byte(body)})
	}
	gate(runH, hostile, "tu_h")
	gate(runK, honest, "tu_k")
	// The honest run shows a call that never reached the gate.
	appendFile(t, honest, resultLine("tu_k", false)+resultLine("tu_missed", false))
	// The hostile run swaps its transcript for a FIFO nobody writes.
	if err := os.Remove(hostile); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(hostile, 0o600); err != nil {
		t.Fatal(err)
	}
	finishesWithin(t, 2*time.Second, "the answer naming the swapped transcript", func() { gate(runH, hostile, "tu_h2") })
	// A new transcript that is a FIFO from the start: the answer path opens
	// it to learn its size, and must not wait for a writer.
	fifo := filepath.Join(tr.ws, "fifo.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	finishesWithin(t, 2*time.Second, "the answer naming a FIFO transcript", func() { gate(runH, fifo, "tu_h3") })
	t0 := time.Now()
	finishesWithin(t, 3*time.Second, "the drift comparison", func() {
		if n := d.CheckDrift(t0); n != 0 {
			t.Errorf("drift inside the window: %d", n)
		}
	})
	finishesWithin(t, 3*time.Second, "the drift comparison", func() {
		if n := d.CheckDrift(t0.Add(2 * time.Minute)); n != 1 {
			t.Errorf("lowered %d runs, want 1 (the honest run's missed call)", n)
		}
	})
	if got := d.DriftStatus(runK.RunID); got != DriftDrifted {
		t.Fatalf("the honest run: %q", got)
	}
	if got := d.DriftStatus(runH.RunID); got != DriftCompared {
		t.Fatalf("the hostile run: %q", got)
	}
}

// assistantLine is a claude-code transcript line with one tool call.
func assistantLine(id, ts string) string {
	stamp := ""
	if ts != "" {
		stamp = fmt.Sprintf(`"timestamp":%q,`, ts)
	}
	return fmt.Sprintf(`{"type":"assistant",%s"message":{"role":"assistant","content":[{"type":"tool_use","id":%q,"name":"Bash"}]}}`+"\n", stamp, id)
}

// stampedResult is resultLine with a timestamp.
func stampedResult(id, ts string) string {
	return fmt.Sprintf(`{"type":"user","timestamp":%q,"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":%q,"content":"ok","is_error":false}]}}`+"\n", ts, id)
}

// TestCopiedHistoryInANewTranscriptDoesNotDrift (audit finding F2): a
// resumed or forked session whose transcript did not exist when the run
// named it is read from its start; its copied history (older than the run,
// or results whose call was never read in it) never counts, while a call
// made after the run started that never reached the gate still drifts.
func TestCopiedHistoryInANewTranscriptDoesNotDrift(t *testing.T) {
	tr := newBindTree(t)
	transcript := filepath.Join(tr.ws, "fork.jsonl")
	run := bindRun(t, "run-f", tr)
	d := &Daemon{SweepInterval: -1, Drift: claudeDrift(time.Minute)}
	h := startBindHarness(t, d, run)
	// Named before it exists; the first gate event carries a call id.
	body := fmt.Sprintf(`{"transcript_path":%q,"tool_use_id":"tu_first"}`, transcript)
	h.send(t, run, sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}, Stdin: []byte(body)})

	old := run.CreatedAt.Add(-time.Hour).Format(time.RFC3339Nano)
	appendFile(t, transcript,
		assistantLine("tu_old", old)+stampedResult("tu_old", old)+ // copied, timestamped
			resultLine("tu_orphan", false)+ // copied, no timestamp, its call never read here
			assistantLine("tu_old2", old)+resultLine("tu_old2", false)) // its call is history
	t0 := run.CreatedAt // the injected clock: the run's own start, never the wall clock
	if n := d.CheckDrift(t0); n != 0 {
		t.Fatalf("drift inside the window: %d", n)
	}
	if n := d.CheckDrift(t0.Add(3 * time.Minute)); n != 0 {
		t.Fatalf("copied history drifted: %d", n)
	}
	if got := d.DriftStatus(run.RunID); got != DriftCompared {
		t.Fatalf("status %q", got)
	}

	// A call made in the run, gated: fine. One that never reached the gate:
	// drift.
	fresh := run.CreatedAt.Add(time.Second).UTC().Format(time.RFC3339Nano)
	body = fmt.Sprintf(`{"transcript_path":%q,"tool_use_id":"tu_gated"}`, transcript)
	h.send(t, run, sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}, Stdin: []byte(body)})
	appendFile(t, transcript, assistantLine("tu_gated", "")+resultLine("tu_gated", false)+
		assistantLine("tu_new", fresh)+stampedResult("tu_new", fresh))
	t1 := t0.Add(4 * time.Minute)
	if n := d.CheckDrift(t1); n != 0 {
		t.Fatalf("drift inside the window: %d", n)
	}
	if n := d.CheckDrift(t1.Add(2 * time.Minute)); n != 1 {
		t.Fatalf("a new call that never reached the gate: lowered %d, want 1", n)
	}
	if got := d.DriftStatus(run.RunID); got != DriftDrifted {
		t.Fatalf("status %q", got)
	}
}

// TestGatePayloadWithoutCallIDNeverDrifts (audit finding F2): a tool build
// whose gate events carry no call id is not compared at all (recorded as
// such), so its calls never mark the run drifted.
func TestGatePayloadWithoutCallIDNeverDrifts(t *testing.T) {
	tr := newBindTree(t)
	transcript := filepath.Join(tr.ws, "session.jsonl")
	appendFile(t, transcript, "")
	run := bindRun(t, "run-n", tr)
	d := &Daemon{SweepInterval: -1, Drift: claudeDrift(time.Minute)}
	h := startBindHarness(t, d, run)
	body := fmt.Sprintf(`{"transcript_path":%q,"tool_name":"Bash"}`, transcript)
	h.send(t, run, sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}, Stdin: []byte(body)})
	appendFile(t, transcript, resultLine("tu_1", false)+resultLine("tu_2", false))
	t0 := run.CreatedAt
	for _, at := range []time.Duration{0, 3 * time.Minute, time.Hour} {
		if n := d.CheckDrift(t0.Add(at)); n != 0 {
			t.Fatalf("a run whose gate events carry no call id drifted at +%v", at)
		}
	}
	if got := d.DriftStatus(run.RunID); got != DriftNoCallID {
		t.Fatalf("status %q, want %q", got, DriftNoCallID)
	}
	st, _ := d.Run(run.RunID)
	if st.Health().Degraded() {
		t.Fatalf("lowered: %+v", st.Health())
	}
}

// TestRunPartialLineBudget (audit finding F5): one transcript's partial
// line is capped at maxDriftLine (a longer line is skipped and the next one
// still read), and a run's partial lines together at maxDriftRunPartial,
// the oldest dropped first and counted.
func TestRunPartialLineBudget(t *testing.T) {
	var tails []tailRef
	for i := range 6 {
		tails = append(tails, tailRef{fmt.Sprint(i), &driftTail{partial: make([]byte, maxDriftLine)}})
	}
	if n := budgetPartials(tails); n != 2 {
		t.Fatalf("dropped %d, want 2", n)
	}
	for i, tr := range tails {
		if dropped := i < 2; dropped != (tr.t.partial == nil && tr.t.skip) {
			t.Fatalf("tail %d: partial %d skip %v", i, len(tr.t.partial), tr.t.skip)
		}
	}

	tr := newBindTree(t)
	transcript := filepath.Join(tr.ws, "long.jsonl")
	appendFile(t, transcript, "")
	run := bindRun(t, "run-l", tr)
	d := &Daemon{SweepInterval: -1, Drift: claudeDrift(time.Minute)}
	h := startBindHarness(t, d, run)
	body := fmt.Sprintf(`{"transcript_path":%q,"tool_use_id":"tu_first"}`, transcript)
	h.send(t, run, sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}, Stdin: []byte(body)})
	appendFile(t, transcript, strings.Repeat("x", maxDriftLine+maxDriftLine/2)+"\n"+resultLine("tu_after", false))
	t0 := run.CreatedAt
	for i := range 4 { // one read of at most maxDriftRead per comparison
		if n := d.CheckDrift(t0.Add(time.Duration(i) * time.Second)); n != 0 {
			t.Fatalf("drift inside the window: %d", n)
		}
	}
	if n := d.CheckDrift(t0.Add(3 * time.Minute)); n != 1 {
		t.Fatalf("the line after an over-long one was not read: lowered %d", n)
	}
	st, _ := d.Run(run.RunID)
	d.mu.Lock()
	ds := st.drift
	d.mu.Unlock()
	ds.checking.Lock()
	defer ds.checking.Unlock()
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if ds.tails[transcript].partial != nil {
		t.Fatalf("a partial line was kept: %d bytes", len(ds.tails[transcript].partial))
	}
}

// TestSweepRemovesStaleTemporaryLockFiles (audit finding F6): a helper
// killed between creating its temporary lock file and renaming it leaves
// ".<run>.alive" behind; the sweep removes it once it is old and nobody
// holds it, and never one that is held or still fresh.
func TestSweepRemovesStaleTemporaryLockFiles(t *testing.T) {
	obs := shortDir(t)
	dir := RunsDir(obs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mk := func(run string, age time.Duration) string {
		t.Helper()
		p := filepath.Join(dir, "."+run+aliveSuffix)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := mk("run-stale", time.Hour)
	fresh := mk("run-fresh", 0)
	held := mk("run-held", time.Hour)
	f, err := os.Open(held)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor number
		t.Fatal(err)
	}
	if n, err := PruneDeadRuns(obs); err != nil || n != 0 {
		t.Fatalf("pruned %d runs: %v", n, err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("a stale temporary lock file is still there: %v", err)
	}
	for _, p := range []string{fresh, held} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s was removed: %v", filepath.Base(p), err)
		}
	}
}
