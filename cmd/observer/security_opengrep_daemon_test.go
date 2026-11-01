//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/powerstate"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_opengrep_daemon_test.go is lane SEC-G2 milestone 3: the code
// rules' daemon triggers, each through the loop's real pass with the scan,
// git and power seams swapped.

// loopConfig writes a selected config with [security.scan.opengrep] keys.
func loopConfig(t *testing.T, opengrepKeys string) string {
	t.Helper()
	cfg := selectedCodeConfig(t)
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("\n[security.scan.opengrep]\nfeed = false\n" + opengrepKeys)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// testLoop returns a loop over cfg whose scans are recorded in *got.
func testLoop(t *testing.T, cfg string, got *[]secscan.Target) *codeLoop {
	t.Helper()
	l, err := newCodeLoop(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.close)
	l.installed = func(context.Context, *codeEnv) bool { return true }
	l.power = func() powerstate.State { return powerstate.AC }
	l.head = func(context.Context, string) string { return "" }
	l.mergeBase = func(_ context.Context, _, a, _ string) string { return a }
	l.scan = func(_ context.Context, _ *codeEnv, tg secscan.Target) error {
		*got = append(*got, tg)
		return nil
	}
	return l
}

// codeProject makes a main checkout the store knows.
func codeProject(t *testing.T, l *codeLoop, files ...string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x = 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.st.UpsertProject(context.Background(), root, ""); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCodeLoopPostWriteIsDebouncedOverWrittenFiles(t *testing.T) {
	var got []secscan.Target
	l := testLoop(t, loopConfig(t, ""), &got)
	root := codeProject(t, l, "a.py")
	t0 := time.Now()
	l.deb.Add(root, "a.py", t0)
	l.deb.Add(root, "gone.py", t0) // deleted since: not scanned
	l.pass(context.Background(), t0.Add(10*time.Second))
	if len(got) != 0 {
		t.Fatalf("scanned inside the quiet window: %+v", got)
	}
	l.pass(context.Background(), t0.Add(31*time.Second))
	if len(got) != 1 || got[0].Scope != policy.FindingScopePostWrite || len(got[0].Paths) != 1 || got[0].Paths[0] != "a.py" || got[0].ProjectRoot != root {
		t.Fatalf("post-write scans %+v", got)
	}
	// Another scan holds the lease: the batch is kept for the next pass.
	got = nil
	busy := true
	l.scan = func(_ context.Context, _ *codeEnv, tg secscan.Target) error {
		if busy {
			busy = false
			return errCodeScanBusy
		}
		got = append(got, tg)
		return nil
	}
	l.deb.Add(root, "a.py", t0)
	l.pass(context.Background(), t0.Add(31*time.Second))
	l.pass(context.Background(), t0.Add(32*time.Second))
	if len(got) != 1 {
		t.Fatalf("a busy batch was lost: %+v", got)
	}
}

func TestCodeLoopRunsNothingWithoutAnEngineOrWithTheTriggerOff(t *testing.T) {
	var got []secscan.Target
	l := testLoop(t, loopConfig(t, "post_write = false\ncommit_diff = false\n"), &got)
	root := codeProject(t, l, "a.py")
	l.deb.Add(root, "a.py", time.Now().Add(-time.Hour))
	l.installed = func(context.Context, *codeEnv) bool { return false }
	l.head = func(context.Context, string) string { t.Fatal("HEAD read with no engine"); return "" }
	l.pass(context.Background(), time.Now())
	if len(got) != 0 {
		t.Fatalf("scanned with no engine installed: %+v", got)
	}
	l.installed = func(context.Context, *codeEnv) bool { return true }
	l.deb = opengrep.Debouncer{}
	l.readWrites(context.Background(), time.Now(), false)
	l.pass(context.Background(), time.Now())
	if len(got) != 0 || l.deb.Pending() != 0 {
		t.Fatalf("post-write and commit diff off still scanned: %+v", got)
	}
}

func TestCodeLoopCommitDiffOnANewHead(t *testing.T) {
	var got []secscan.Target
	l := testLoop(t, loopConfig(t, ""), &got)
	root := codeProject(t, l)
	heads := []string{"aaaaaaa1", "aaaaaaa1", "bbbbbbb2", "ccccccc3"}
	i := 0
	l.head = func(context.Context, string) string { h := heads[i]; return h }
	t0 := time.Now()
	step := func(at time.Duration) {
		l.pass(context.Background(), t0.Add(at))
		if i < len(heads)-1 {
			i++
		}
	}
	step(0) // first sighting: remembered, nothing scanned
	if len(got) != 0 {
		t.Fatalf("a daemon start scanned: %+v", got)
	}
	step(3 * time.Minute) // unchanged
	step(6 * time.Minute) // moved: a diff against the previous HEAD
	if len(got) != 1 || got[0].Scope != policy.FindingScopeCommit || got[0].BaseRev != "aaaaaaa1" || got[0].HeadRev != "bbbbbbb2" || got[0].ProjectRoot != root {
		t.Fatalf("commit diff %+v", got)
	}
	// Busy: the previous HEAD is kept and retried.
	l.scan = func(context.Context, *codeEnv, secscan.Target) error { return errCodeScanBusy }
	step(9 * time.Minute)
	got = nil
	l.scan = func(_ context.Context, _ *codeEnv, tg secscan.Target) error { got = append(got, tg); return nil }
	l.pass(context.Background(), t0.Add(12*time.Minute))
	if len(got) != 1 || got[0].BaseRev != "bbbbbbb2" || got[0].HeadRev != "ccccccc3" {
		t.Fatalf("retry after busy %+v", got)
	}
}

func TestCodeLoopScheduleSurvivesARestartAndPausesOnBattery(t *testing.T) {
	cfg := loopConfig(t, "schedule_hours = 24\npost_write = false\ncommit_diff = false\n")
	var got []secscan.Target
	l := testLoop(t, cfg, &got)
	root := codeProject(t, l)
	l.started = time.Now().Add(-time.Hour)
	l.power = func() powerstate.State { return powerstate.Battery }
	l.pass(context.Background(), time.Now())
	if len(got) != 0 {
		t.Fatalf("scheduled on battery: %+v", got)
	}
	l.power = func() powerstate.State { return powerstate.AC }
	l.scan = func(ctx context.Context, e *codeEnv, tg secscan.Target) error {
		got = append(got, tg)
		_, err := recordCodeScan(ctx, e.st, tg, secscan.Result{Coverage: secscan.Coverage{Outcome: secscan.OutcomeClean}, Engine: secscan.EngineIdentity{Name: opengrep.DriverID}}, opengrep.Scanned{}, time.Now(), nil)
		return err
	}
	l.pass(context.Background(), time.Now())
	if len(got) != 1 || got[0].Scope != policy.FindingScopeScheduled || got[0].ProjectRoot != root {
		t.Fatalf("scheduled scans %+v", got)
	}
	// A restarted daemon reads the last scheduled run from the store.
	l.close()
	var again []secscan.Target
	l2 := testLoop(t, cfg, &again)
	l2.started = time.Now().Add(-time.Hour)
	l2.pass(context.Background(), time.Now())
	if len(again) != 0 {
		t.Fatalf("a restart scanned a project scanned an hour ago: %+v", again)
	}
	l2.pass(context.Background(), time.Now().Add(25*time.Hour))
	if len(again) != 1 {
		t.Fatalf("the next day's scan did not run: %+v", again)
	}
}

// TestCommitDiffFindingsReachTheCommitGate: what a commit-diff run records
// is what the commit gate (S-791) reads at the agent's next commit or push:
// a new, high-confidence, high-severity finding from a rule that may block
// is in the blocking set; the flag-only findings every rule gives today
// are not.
func TestCommitDiffFindingsReachTheCommitGate(t *testing.T) {
	var got []secscan.Target
	l := testLoop(t, loopConfig(t, ""), &got)
	root := codeProject(t, l)
	hash := secposture.ProjectRootHash(root)
	mk := func(key string, conf policy.FindingConfidence) secfinding.Finding {
		return secfinding.Normalize(secfinding.Finding{
			LocalKey: key, Rule: secfinding.Rule{ID: "python.sql-string-concat", Pack: secrulepack.PackID}, Category: policy.FindingCodeVuln,
			Severity: policy.FindingSeverityHigh, Confidence: conf, Baseline: policy.FindingBaselineNew, Scope: policy.FindingScopeCommit,
			Project: secfinding.Project{RootHash: hash}, Location: secfinding.Location{RelPath: "a.py", StartLine: 3, EndLine: 3},
			Engine: secfinding.Engine{Driver: opengrep.DriverID},
		})
	}
	tg := secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeCommit, BaseRev: "aaaaaaa1", HeadRev: "bbbbbbb2"}
	res := secscan.Result{
		Findings: []secfinding.Finding{mk("blocks", policy.FindingConfidenceHigh), mk("flags", policy.FindingConfidenceMedium)},
		Coverage: secscan.Coverage{Outcome: secscan.OutcomeFindings}, Engine: secscan.EngineIdentity{Name: opengrep.DriverID},
	}
	if _, err := recordCodeScan(context.Background(), l.st, tg, res, opengrep.Scanned{}, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	keys, err := l.st.SecBlockingKeys(context.Background(), store.SecBlockingQuery{ProjectRootHash: hash, Severities: []secfinding.Severity{policy.FindingSeverityHigh, policy.FindingSeverityCritical}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "blocks" {
		t.Fatalf("blocking keys %v: want only the high-confidence finding", keys)
	}
}
