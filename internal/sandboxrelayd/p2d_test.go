//go:build linux

package sandboxrelayd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// TestSlowHealthWriteHoldsNoAnswerOrHeartbeat (P-040, milestone 1b): the
// health write (a database write of up to five seconds) runs off the answer
// path, so a replayed event's heartbeats start at once (none is counted
// missed) and a refusal is answered while the write is still running.
func TestSlowHealthWriteHoldsNoAnswerOrHeartbeat(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	log := &healthLog{}
	m := startMultiRelay(t, 4, 4, false, func(d *Daemon, f *Forwarder) {
		d.Heartbeat = 100 * time.Millisecond
		f.Heartbeat = 100 * time.Millisecond
		d.Gated = func(sandboxrelay.HookRequest) bool { return false }
		d.OnHealth = func(rec RunRecord, h Health) {
			<-release // a slow writer: it returns only when the test says so
			log.on(rec, h)
		}
		d.Exec = func(_ context.Context, _ RunRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			time.Sleep(600 * time.Millisecond)
			return sandboxrelay.HookResponse{Stdout: req.Stdin}, nil
		}
	})
	box := fastConn()
	box.IdleTimeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A replay lowers the run before it runs: the heartbeats must not wait
	// for the write.
	req := hookReq("late")
	req.Replay = true
	if _, err := BoxRoundTrip(ctx, m.sock, m.box(t), req, box); err != nil {
		t.Fatalf("a replayed event while the health write is slow: %v", err)
	}
	// A refusal is answered at once, the write still running.
	start := time.Now()
	resp, err := BoxRoundTrip(ctx, m.sock, m.box(t), hookReq(`{"cwd":"/etc"}`), box)
	if err != nil || resp.Refused == "" {
		t.Fatalf("a refusal while the health write is slow: %+v %v", resp, err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the refusal waited %v for the health write", d)
	}
	// The helper's own health report, if it owes one, is handed over once
	// both box connections finished: wait for that, not for a fixed time.
	waitUntil(t, 3*time.Second, "the helper finished both connections and has nothing to report", func() bool {
		return m.fw.served.Load() >= 2 && m.fw.pending.idle()
	})
	once.Do(func() { close(release) })
	m.daemon.FlushHealth()
	st, _ := m.daemon.Run("run-a")
	h := st.Health()
	if h.MissedHeartbeats != 0 || h.Has(CauseHeartbeatMissed) || h.Has(CauseDropped) {
		t.Fatalf("the slow write cost heartbeats or events: %+v", h)
	}
	if !h.Has(CauseReplayed) || !h.Has(CauseRefused) {
		t.Fatalf("health %+v", h)
	}
	if got := log.last(); !got.Has(CauseReplayed) || !got.Has(CauseRefused) {
		t.Fatalf("the writer never got the latest health: %+v", got)
	}
}

// TestRunEndHookFollowsTheLastHealthWrite (P-040, milestone 1c): ending a
// run calls OnRunEnd once the run's last health write returned, so a write
// in flight cannot leave per-run state behind; across many runs the state
// kept beside the handler stays empty once they end.
func TestRunEndHookFollowsTheLastHealthWrite(t *testing.T) {
	tr := newBindTree(t)
	var mu sync.Mutex
	live := map[string]bool{}
	d := &Daemon{
		SweepInterval: -1,
		OnHealth: func(rec RunRecord, _ Health) {
			time.Sleep(5 * time.Millisecond)
			mu.Lock()
			live[rec.RunID] = true
			mu.Unlock()
		},
		OnRunEnd: func(rec RunRecord) {
			mu.Lock()
			delete(live, rec.RunID)
			mu.Unlock()
		},
	}
	const runs = 60
	recs := make([]RunRecord, runs)
	for i := range recs {
		recs[i] = bindRun(t, fmt.Sprintf("run-%d", i), tr)
	}
	h := startBindHarness(t, d, recs...)
	for _, rec := range recs {
		if r := h.send(t, rec, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + tr.other + `"}`)}); r.Refused == "" {
			t.Fatalf("%s: not refused", rec.RunID)
		}
		if err := RemoveRun(h.obs, rec.RunID); err != nil {
			t.Fatal(err)
		}
	}
	if n := d.Sweep(); n != runs {
		t.Fatalf("the sweep ended %d runs, want %d", n, runs)
	}
	d.FlushHealth()
	mu.Lock()
	left := len(live)
	mu.Unlock()
	if left != 0 {
		t.Fatalf("%d runs kept state after they ended", left)
	}
	d.mu.Lock()
	held := len(d.runs)
	d.mu.Unlock()
	if held != 0 {
		t.Fatalf("the handler kept %d ended runs", held)
	}
}

// aliveEnv names the observer directory and run a helper-process child
// holds the liveness lock for.
const aliveEnv = "SBX_P2D_ALIVE"

// TestAliveHelperProcess is not a test: run as a child with aliveEnv set,
// it takes the run's liveness lock, says so, and waits to be killed.
func TestAliveHelperProcess(t *testing.T) {
	spec := os.Getenv(aliveEnv)
	if spec == "" {
		t.Skip("a helper child for TestHelperKilledWithSIGKILLReleasesClaims")
	}
	dir, run, _ := strings.Cut(spec, "|")
	if _, err := HoldRun(dir, run); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println("held")
	time.Sleep(time.Minute)
	os.Exit(0)
}

// TestHelperKilledWithSIGKILLReleasesClaims (P-040, milestone 1d): a helper
// killed with SIGKILL cannot remove its run record, but its liveness lock
// goes with it, so the next sweep ends the run (record, lock file, session
// claims) with no daemon restart; while the helper lives nothing is ended.
func TestHelperKilledWithSIGKILLReleasesClaims(t *testing.T) {
	tr := newBindTree(t)
	runK, runL := bindRun(t, "run-k", tr), bindRun(t, "run-l", tr)
	d := &Daemon{SweepInterval: -1}
	h := startBindHarness(t, d, runK, runL)
	session := func(run RunRecord) sandboxrelay.Refusal {
		t.Helper()
		return h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + tr.ws + `","session_id":"s-k"}`)}).Refused
	}

	child := exec.Command(os.Args[0], "-test.run=^TestAliveHelperProcess$", "-test.count=1") //nolint:gosec // G204: this test binary
	child.Env = append(os.Environ(), aliveEnv+"="+h.obs+"|"+runK.RunID)
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "held" {
		t.Fatalf("the helper child: %q %v", line, err)
	}

	if r := session(runK); r != "" {
		t.Fatalf("run k's own session: %q", r)
	}
	if r := session(runL); r != sandboxrelay.RefusedSession {
		t.Fatalf("run l took a live run's session: %q", r)
	}
	if n := d.Sweep(); n != 0 {
		t.Fatalf("the sweep ended %d runs while the helper lives", n)
	}

	if err := child.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	if _, err := os.Stat(alivePath(h.obs, runK.RunID)); err != nil {
		t.Fatalf("SIGKILL should leave the lock file behind: %v", err)
	}
	if n := d.Sweep(); n != 1 {
		t.Fatalf("the sweep ended %d runs after the helper died, want 1", n)
	}
	if _, err := ReadRun(h.obs, runK.RunID); err == nil {
		t.Fatal("a dead helper's record is still there")
	}
	if _, err := os.Stat(alivePath(h.obs, runK.RunID)); !os.IsNotExist(err) {
		t.Fatalf("a dead helper's lock file is still there: %v", err)
	}
	if r := session(runL); r != "" {
		t.Fatalf("run l still refused the dead run's session: %q", r)
	}
}

// TestHoldRunLockIsNeverSeenUnheld: a held lock reads held, a released one
// leaves no file, and a run with no lock file keeps the record rule.
func TestHoldRunLockIsNeverSeenUnheld(t *testing.T) {
	obs := shortDir(t)
	if helperOf(obs, "run-x") != helperUnknown {
		t.Fatal("no lock file must read unknown")
	}
	release, err := HoldRun(obs, "run-x")
	if err != nil {
		t.Fatal(err)
	}
	if got := helperOf(obs, "run-x"); got != helperHeld {
		t.Fatalf("a held lock reads %v", got)
	}
	if n, err := PruneDeadRuns(obs); err != nil || n != 0 {
		t.Fatalf("pruned a live run: %d %v", n, err)
	}
	release()
	if _, err := os.Stat(alivePath(obs, "run-x")); !os.IsNotExist(err) {
		t.Fatalf("release left the lock file: %v", err)
	}
	if _, err := HoldRun(obs, "../x"); err == nil {
		t.Fatal("a bad run id was held")
	}
}

// claudeDrift is the registry's comparison for claude-code, with the gate
// event the hook command names PreToolUse.
func claudeDrift(window time.Duration) *GateDrift {
	return &GateDrift{
		Spec: func(tool string) (integration.TranscriptGateSpec, bool) {
			c, ok := integration.For(tool)
			return c.Sandbox.GateDrift, ok
		},
		IsGate:   func(req sandboxrelay.HookRequest) bool { return len(req.Args) > 1 && req.Args[1] == "PreToolUse" },
		Window:   window,
		Interval: -1,
		// Each comparison waits for its reads: under a loaded race run the
		// default deadline can pass, and the next comparison would then skip
		// a run whose read is still going (SBX-P2E). The deadline's clock is
		// injected and never fires (a nil channel), so no comparison here
		// depends on the wall clock (lane LEFT-SBX); a test of the deadline
		// sets its own.
		ReadDeadline: time.Minute,
		after:        func(time.Duration) <-chan time.Time { return nil },
	}
}

// resultLine is a claude-code transcript line with one tool result.
func resultLine(id string, failed bool) string {
	return fmt.Sprintf(`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":%q,"content":"ok","is_error":%v}]}}`+"\n", id, failed)
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

// TestTranscriptCallTheGateNeverSawDrifts (P-040, milestone 2a; sandbox
// plan section 5.2 (2)): a tool call the run's transcript shows as run,
// whose gate event the relay never saw within the lag window, marks the run
// hooks_drifted. A call whose gate event arrives late but within the window,
// a failed call, and the transcript's history from before the run named it
// do not.
func TestTranscriptCallTheGateNeverSawDrifts(t *testing.T) {
	tr := newBindTree(t)
	transcript := filepath.Join(tr.ws, "session.jsonl")
	appendFile(t, transcript, resultLine("tu_history", false))
	run := bindRun(t, "run-t", tr)
	clean := bindRun(t, "run-c", tr)
	cleanTranscript := filepath.Join(tr.ws, "clean.jsonl")
	appendFile(t, cleanTranscript, "")
	log := &healthLog{}
	d := &Daemon{SweepInterval: -1, OnHealth: log.on, Drift: claudeDrift(time.Minute)}
	h := startBindHarness(t, d, run, clean)
	gate := func(rec RunRecord, path, id string) {
		t.Helper()
		body := fmt.Sprintf(`{"transcript_path":%q,"tool_use_id":%q,"tool_name":"Bash"}`, path, id)
		if r := h.send(t, rec, sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}, Stdin: []byte(body)}); r.Refused != "" {
			t.Fatalf("gate %s refused: %q", id, r.Refused)
		}
	}
	// The run names its transcript (a capture-only event), then gates a.
	h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(fmt.Sprintf(`{"transcript_path":%q}`, transcript))})
	gate(run, transcript, "tu_a")
	appendFile(t, transcript, resultLine("tu_a", false)+resultLine("tu_b", false)+resultLine("tu_c", true))
	// d's result is in the transcript before its gate event: lag.
	appendFile(t, transcript, resultLine("tu_d", false))
	// The clean run gates every call it runs.
	gate(clean, cleanTranscript, "tu_x")
	appendFile(t, cleanTranscript, resultLine("tu_x", false))

	t0 := run.CreatedAt // the injected clock: the run's own start
	if n := d.CheckDrift(t0); n != 0 {
		t.Fatalf("drift inside the lag window: %d", n)
	}
	gate(run, transcript, "tu_d") // late, within the window
	if n := d.CheckDrift(t0.Add(30 * time.Second)); n != 0 {
		t.Fatalf("drift inside the lag window: %d", n)
	}
	if n := d.CheckDrift(t0.Add(2 * time.Minute)); n != 1 {
		t.Fatalf("runs lowered after the window: %d, want 1 (tu_b never reached the gate)", n)
	}
	d.FlushHealth()
	st, _ := d.Run(run.RunID)
	if !st.Health().Has(CauseHooksDrifted) || !log.last().Has(CauseHooksDrifted) {
		t.Fatalf("the run is not marked hooks_drifted: %+v", st.Health())
	}
	if cst, _ := d.Run(clean.RunID); cst.Health().Degraded() {
		t.Fatalf("the clean run was lowered: %+v", cst.Health())
	}
	if n := d.CheckDrift(t0.Add(5 * time.Minute)); n != 0 {
		t.Fatalf("a drifted run was lowered again: %d", n)
	}
}

// TestTranscriptOutsideTheRunIsNotRead: a transcript path outside the run's
// roots is refused by the binding and never compared.
func TestTranscriptOutsideTheRunIsNotRead(t *testing.T) {
	tr := newBindTree(t)
	outside := filepath.Join(tr.other, "session.jsonl")
	appendFile(t, outside, "")
	run := bindRun(t, "run-o", tr)
	d := &Daemon{SweepInterval: -1, Drift: claudeDrift(time.Second)}
	h := startBindHarness(t, d, run)
	if r := h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(fmt.Sprintf(`{"transcript_path":%q}`, outside))}); r.Refused == "" {
		t.Fatal("a transcript outside the run was not refused")
	}
	appendFile(t, outside, resultLine("tu_z", false))
	if n := d.CheckDrift(time.Now().Add(time.Hour)); n != 0 {
		t.Fatalf("a transcript outside the run was compared: %d", n)
	}
}

// TestRanCallIDsTable walks the registry's claude-code rule over the line
// shapes a transcript holds.
func TestRanCallIDsTable(t *testing.T) {
	c, _ := integration.For("claude-code")
	spec := c.Sandbox.GateDrift
	if !spec.Compared() {
		t.Fatal("claude-code declares no comparison")
	}
	for _, tc := range []struct {
		name, line string
		want       []string
	}{
		{"a result that ran", strings.TrimSpace(resultLine("tu_1", false)), []string{"tu_1"}},
		{"a failed result", strings.TrimSpace(resultLine("tu_2", true)), nil},
		{"the call itself (assistant)", `{"type":"assistant","message":{"content":[{"type":"tool_use","id":"tu_3","name":"Bash"}]}}`, nil},
		{"two results", `{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"a"},{"type":"text","text":"x"},{"type":"tool_result","tool_use_id":"b"}]}}`, []string{"a", "b"}},
		{"a user prompt", `{"type":"user","message":{"content":"hello"}}`, nil},
		{"not JSON", `garbage`, nil},
		{"no message", `{"type":"user"}`, nil},
	} {
		if got := RanCallIDs(spec, []byte(tc.line)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if (integration.TranscriptGateSpec{}).Compared() {
		t.Error("the zero spec compares")
	}
}

// waitUntil polls cond until it holds, failing after limit.
func waitUntil(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestPruneDeadRunRecordsReturnsTheRecord (live check 2026-10-22, D7): a
// dead helper's record is returned as it was (its bound terminal run
// included) so the daemon can end the row it left behind; a live run is
// neither pruned nor returned.
func TestPruneDeadRunRecordsReturnsTheRecord(t *testing.T) {
	obs := t.TempDir()
	ws := t.TempDir()
	for _, id := range []string{"run-dead", "run-live"} {
		rec, err := NewRunRecord(RunRecord{RunID: id, Tool: "claude-code", ProjectRoot: ws, WorkspaceDir: ws, Roots: []string{ws}})
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteRun(obs, rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := BindTerminalRun(obs, "run-dead", "termrun-0001"); err != nil {
		t.Fatal(err)
	}
	// A lock file nobody holds: the helper is gone.
	if err := os.WriteFile(alivePath(obs, "run-dead"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pruned, err := PruneDeadRunRecords(obs)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 1 || pruned[0].RunID != "run-dead" || pruned[0].TerminalRunID != "termrun-0001" {
		t.Fatalf("pruned %+v", pruned)
	}
	if _, err := ReadRun(obs, "run-dead"); err == nil {
		t.Fatal("the dead run's record is still there")
	}
	if _, err := ReadRun(obs, "run-live"); err != nil {
		t.Fatalf("the live run's record went: %v", err)
	}
}
