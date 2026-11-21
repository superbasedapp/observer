//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxadopt"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestReadoptDecidesBeforeAnyPrune (tracker F-045): the N1-L1 live pass
// (2026-11-03) saw no offer after a daemon restart or a helper SIGKILL on
// rootful Docker with live-restore. No Decide row fired: a prune outside
// the oci reaper (the relay's start prune at a restart, its own sweep while
// the daemon runs, the oci start sweep) removed the run's record and lock
// first, the re-adoption step then skipped a run with no lock and no
// offer, and the orphan rule removed the container. One case per prune
// path: with the dead-run hold the run survives that prune and the reaper's
// sweep offers it. The rows where the hold lets the prune go on (component
// off, a CLI run) still reap as before.
func TestReadoptDecidesBeforeAnyPrune(t *testing.T) {
	prunes := []struct {
		name  string
		prune func(obs string)
	}{
		{"the relay's start prune (daemon restart)", func(obs string) { _, _ = sandboxrelayd.PruneDeadRunRecords(obs) }},
		{"the relay daemon's own sweep (helper killed, daemon running)", func(obs string) { (&sandboxrelayd.Daemon{ObserverDir: obs}).Sweep() }},
		{"the oci start sweep", func(obs string) { pruneGoneRelayRuns(obs) }},
	}
	for i, p := range prunes {
		t.Run(p.name, func(t *testing.T) {
			f := newRAFake(t)
			raSettings(t, true, 0)
			ra := raSetup(t, f, "run00000000000001"+string(rune('0'+i))+"0")
			raEnder(t)
			p.prune(ra.obs)
			if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err != nil {
				t.Fatalf("the prune removed a re-adoptable run's record before the re-adoption step: %v", err)
			}
			(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
			if len(f.removed) != 0 {
				t.Fatalf("the container was reaped without an offer: %v", f.removed)
			}
			e := readoptRead(ra.obs, ra.runID)
			if !e.hasOffer || e.offer.Code != sandboxadopt.CodeOffered || e.offer.Row != sandboxadopt.RowOffer {
				t.Fatalf("offer = %+v (has %v)", e.offer, e.hasOffer)
			}
			// A later prune leaves the offered run alone (its lock is gone).
			p.prune(ra.obs)
			if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err != nil {
				t.Fatalf("a prune after the offer removed the re-keyed record: %v", err)
			}
		})
	}

	notHeld := []struct {
		name  string
		setup func(t *testing.T, f *raFake) raRun
		// row is the decision line the prune logs ("": none, nothing was
		// kept; fix round 1, FU10-A4). The prune writes no ended.json entry:
		// the oci reaper's sweep is that file's one writer (fix round 2,
		// FU10-R1).
		row string
	}{
		{"component off at launch", func(t *testing.T, f *raFake) raRun {
			raSettings(t, false, 0)
			return raSetup(t, f, "run0000000000000190")
		}, ""},
		{"component turned off after launch", func(t *testing.T, f *raFake) raRun {
			raSettings(t, true, 0)
			ra := raSetup(t, f, "run0000000000000189")
			raSettings(t, false, 0)
			return ra
		}, "component"},
		{"a CLI run", func(t *testing.T, f *raFake) raRun {
			raSettings(t, true, 0)
			const term = "cli-run-0191"
			ra := raSetupWith(t, f, "run0000000000000191", func(r *sandboxrelayd.RunRecord) { r.TerminalRunID = term })
			watch, _ := sandboxCLIEndPaths(ra.obs, term)
			if err := os.MkdirAll(filepath.Dir(watch), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(watch, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return ra
		}, "cli-run"},
	}
	for _, c := range notHeld {
		t.Run(c.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			prev := processOCIReaper.logger.Load()
			processOCIReaper.logger.Store(slog.New(slog.NewJSONHandler(&logBuf, nil)))
			t.Cleanup(func() { processOCIReaper.logger.Store(prev) })
			f := newRAFake(t)
			ra := c.setup(t, f)
			raEnder(t)
			if _, err := sandboxrelayd.PruneDeadRunRecords(ra.obs); err != nil {
				t.Fatal(err)
			}
			if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err == nil {
				t.Fatal("the prune kept a record the hold must not hold")
			}
			lines := raDecisionLines(t, &logBuf)
			if (len(lines) == 1) != (c.row != "") || (c.row != "" && lines[0]["row"] != c.row) {
				t.Fatalf("decision lines %v, want one with row %q (or none)", lines, c.row)
			}
			if _, err := os.Lstat(filepath.Join(readoptDir(ra.obs), readoptEndedFile)); err == nil {
				t.Fatal("a prune wrote ended.json; its one writer is the oci reaper's sweep")
			}
			(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
			if len(f.removed) != 1 {
				t.Fatalf("the container was not reaped as before: %v", f.removed)
			}
		})
	}
}

// TestReadoptHoldLiftsWhenTheContainerIsGone: a held run whose container
// the engine no longer lists has its entry removed by the next sweep (row
// container-gone, kept for `observer sandbox runs`), so the hold lifts and
// the prune ends the run in the same sweep.
func TestReadoptHoldLiftsWhenTheContainerIsGone(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, 0)
	ra := raSetup(t, f, "run0000000000000192")
	ended := raEnder(t)
	f.mu.Lock()
	delete(f.running, ra.cid)
	delete(f.bodies, ra.cid)
	f.mu.Unlock()
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if _, err := os.Lstat(readoptRunDir(ra.obs, ra.runID)); err == nil {
		t.Fatal("the entry of a run with no container was kept")
	}
	if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err == nil {
		t.Fatal("the hold did not lift: the record is still there")
	}
	if len(*ended) != 1 || (*ended)[0] != ra.runID {
		t.Fatalf("ended = %v", *ended)
	}
	if x, ok := readoptEndedFor(ra.obs, ra.runID); !ok || x.Row != sandboxadopt.RowContainerGone {
		t.Fatalf("kept decision = %+v %v", x, ok)
	}
}

// TestReadoptDecisionIsLoggedAndShown (F-046): every decision is one
// structured log line naming the run and the row, logged once per change;
// a reaped run's row is kept and shown by `observer sandbox runs` (text and
// JSON) and by `readopt` on that run; an offer shows its row.
func TestReadoptDecisionIsLoggedAndShown(t *testing.T) {
	var logBuf bytes.Buffer
	prev := processOCIReaper.logger.Load()
	processOCIReaper.logger.Store(slog.New(slog.NewJSONHandler(&logBuf, nil)))
	t.Cleanup(func() { processOCIReaper.logger.Store(prev) })

	f := newRAFake(t)
	raSettings(t, true, time.Minute)
	ra := raSetup(t, f, "run0000000000000193")
	raEnder(t)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	lines := raDecisionLines(t, &logBuf)
	if len(lines) != 1 || lines[0]["run"] != ra.runID || lines[0]["row"] != sandboxadopt.RowOffer || lines[0]["code"] != string(sandboxadopt.CodeOffered) {
		t.Fatalf("offer decision lines = %v (want one, logged once)", lines)
	}
	var out bytes.Buffer
	if err := renderReadoptRuns(&out, ra.obs, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "decided by row offer (readopt_offered)") {
		t.Fatalf("runs output does not show the offer's row:\n%s", out.String())
	}

	// Past the bound: reaped by row bound, logged, kept and shown.
	logBuf.Reset()
	old := readoptNow
	readoptNow = func() time.Time { return time.Now().UTC().Add(2 * time.Minute) }
	defer func() { readoptNow = old }()
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	lines = raDecisionLines(t, &logBuf)
	if len(lines) != 1 || lines[0]["row"] != "bound" || lines[0]["action"] != string(sandboxadopt.ActionReap) {
		t.Fatalf("reap decision lines = %v", lines)
	}
	out.Reset()
	if err := renderReadoptRuns(&out, ra.obs, false); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, ra.runID+"  ended ") || !strings.Contains(s, "row bound (bound_expired)") {
		t.Fatalf("runs output does not show the ended run's row:\n%s", s)
	}
	out.Reset()
	if err := renderReadoptRuns(&out, ra.obs, true); err != nil {
		t.Fatal(err)
	}
	var js struct {
		Ended []readoptEnded `json:"ended"`
	}
	if err := json.Unmarshal(out.Bytes(), &js); err != nil || len(js.Ended) != 1 || js.Ended[0].Row != "bound" {
		t.Fatalf("runs --json ended = %+v (%v)", js.Ended, err)
	}
	if err := readoptNotOffered(ra.obs, ra.runID); err == nil || !strings.Contains(err.Error(), "by row bound (bound_expired)") {
		t.Fatalf("readopt refusal = %v", err)
	}
	if err := readoptNotOffered(ra.obs, "run0000000000000999"); err == nil || !strings.Contains(err.Error(), "see observer sandbox runs") {
		t.Fatalf("readopt refusal for an unknown run = %v", err)
	}
}

// TestReadoptEndedListIsBounded: the kept decisions are newest first, one
// per run, at most readoptEndedCap.
func TestReadoptEndedListIsBounded(t *testing.T) {
	obs := t.TempDir()
	if err := os.MkdirAll(readoptDir(obs), 0o700); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC)
	for i := 0; i < readoptEndedCap+5; i++ {
		id := "run" + strings.Repeat("0", 12) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		readoptRecordEnded(obs, readoptEnded{RunID: id, Row: "bound", Code: sandboxadopt.CodeBoundExpired, At: at.Add(time.Duration(i) * time.Minute)})
	}
	first := "run" + strings.Repeat("0", 12) + "aa"
	readoptRecordEnded(obs, readoptEnded{RunID: first, Row: "read-back", Code: sandboxadopt.CodeBuiltBelowPlan, At: at.Add(time.Hour)})
	list := readoptEndedList(obs)
	if len(list) != readoptEndedCap || list[0].RunID != first || list[0].Row != "read-back" {
		t.Fatalf("list = %d entries, first %+v", len(list), list[0])
	}
	seen := map[string]bool{}
	for _, x := range list {
		if seen[x.RunID] {
			t.Fatalf("run %s kept twice", x.RunID)
		}
		seen[x.RunID] = true
	}
}

// raDecisionLines are the re-adoption decision lines of a JSON log.
func raDecisionLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line %q: %v", l, err)
		}
		if m["msg"] == "terminal_sandbox: re-adoption decision" {
			out = append(out, m)
		}
	}
	return out
}

// TestReadoptLoggedReasonCarriesNoRunFacts (fix round 1, audit FU10-A2):
// the protected row's full reason names the run's socket dir; the logged
// line and the kept decision carry the row's fact-free line instead.
func TestReadoptLoggedReasonCarriesNoRunFacts(t *testing.T) {
	var logBuf bytes.Buffer
	prev := processOCIReaper.logger.Load()
	processOCIReaper.logger.Store(slog.New(slog.NewJSONHandler(&logBuf, nil)))
	t.Cleanup(func() { processOCIReaper.logger.Store(prev) })

	f := newRAFake(t)
	raSettings(t, true, 0)
	ra := raSetup(t, f, "run0000000000000194")
	raEnder(t)
	_ = os.RemoveAll(ra.sockDir)
	if err := os.Symlink(t.TempDir(), ra.sockDir); err != nil {
		t.Fatal(err)
	}
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	lines := raDecisionLines(t, &logBuf)
	if len(lines) != 1 || lines[0]["row"] != "protected" {
		t.Fatalf("decision lines = %v", lines)
	}
	if r, _ := lines[0]["reason"].(string); r == "" || strings.Contains(r, ra.sockDir) {
		t.Fatalf("the logged reason %q carries the socket dir path", r)
	}
	x, ok := readoptEndedFor(ra.obs, ra.runID)
	if !ok || x.Row != "protected" || x.Reason == "" || strings.Contains(x.Reason, ra.sockDir) {
		t.Fatalf("kept decision %+v (%v) carries the socket dir path or no line", x, ok)
	}
}
