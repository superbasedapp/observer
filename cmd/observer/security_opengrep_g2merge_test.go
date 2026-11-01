//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
)

// security_opengrep_g2merge_test.go pins the SEC-G2 merge fixes: ruling
// P-061 (no engine, no feed request) and audit finding 4 (a run that never
// executed is not a scan).

// feedOnConfig is a selected config with the feed on.
func feedOnConfig(t *testing.T) string {
	t.Helper()
	cfg := selectedCodeConfig(t)
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("\n[security.scan.opengrep]\nfeed = true\n")
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestCodeFeedNeedsAnInstalledEngine: plans decision log P-061. A node
// with the component selected and the feed on but no engine installed
// makes no feed request, from the daemon loop or from refresh; once an
// engine is installed the loop fetches.
func TestCodeFeedNeedsAnInstalledEngine(t *testing.T) {
	var got []secscan.Target
	l := testLoop(t, feedOnConfig(t), &got)
	feed := &fakeFeed{}
	useFeed(t, feed)
	l.installed = func(context.Context, *codeEnv) bool { return false }
	l.started = time.Now().Add(-time.Hour)
	l.pass(context.Background(), time.Now())
	if feed.calls != 0 {
		t.Fatalf("%d feed requests with no engine installed", feed.calls)
	}
	e, err := codeEnvForDash(l.configPath, l.db)
	if err != nil || e == nil {
		t.Fatalf("env: %v", err)
	}
	if !e.cfg.Security.Scan.Opengrep.Feed {
		t.Fatal("the test config does not turn the feed on")
	}
	// The real presence check: nothing is installed in this test's cache.
	if rep := e.refreshCodeContent(context.Background()); feed.calls != 0 || rep.Err != nil {
		t.Fatalf("refresh with no engine: %d feed requests, %v (%+v)", feed.calls, rep.Err, rep)
	}
	// With an engine the loop's fetch goes ahead (the check above is not
	// vacuous).
	prev := codeContentEngineInstalled
	codeContentEngineInstalled = func(context.Context, *codeEnv) bool { return true }
	t.Cleanup(func() { codeContentEngineInstalled = prev })
	l.installed = func(context.Context, *codeEnv) bool { return true }
	l.pass(context.Background(), time.Now())
	if feed.calls == 0 {
		t.Fatal("no feed request with an engine installed and the feed on")
	}
}

// TestCodeRunThatNeverRanIsNotAScan: lane SEC-G2 audit finding 4, through
// SEC-POLISH's one store filter. A refused run is recorded (the schedule
// reads its time) but is neither the project's last scan nor the card's
// last run; a run that crashed after the engine started still is.
func TestCodeRunThatNeverRanIsNotAScan(t *testing.T) {
	var got []secscan.Target
	l := testLoop(t, loopConfig(t, ""), &got)
	root := codeProject(t, l, "a.py")
	ctx := context.Background()
	tg := secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeScheduled}
	started := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	refused := secscan.Result{Engine: secscan.EngineIdentity{Name: opengrep.DriverID}, Coverage: secscan.Coverage{Outcome: secscan.OutcomeFailed, Reason: opengrep.ReasonIsolation}}
	if _, err := recordCodeScan(ctx, l.st, tg, refused, opengrep.Scanned{}, started, nil); err != nil {
		t.Fatal(err)
	}
	hash := secposture.ProjectRootHash(root)
	if last, err := l.st.SecLastScan(ctx, hash); err != nil || !last.IsZero() {
		t.Fatalf("SecLastScan after a refused run: %v %v", last, err)
	}
	if _, ok, err := l.st.SecLatestRun(ctx, opengrep.DriverID); err != nil || ok {
		t.Fatalf("SecLatestRun shows a refused run: %v %v", ok, err)
	}
	if last, err := l.st.SecLastDriverRun(ctx, hash, opengrep.DriverID, policy.FindingScopeScheduled); err != nil || !last.Equal(started) {
		t.Fatalf("SecLastDriverRun %v %v, want the refused run's time (the schedule)", last, err)
	}
	crashed := secscan.Result{Engine: secscan.EngineIdentity{Name: opengrep.DriverID}, Coverage: secscan.Coverage{Outcome: secscan.OutcomeFailed, Reason: opengrep.ReasonCrashed}}
	later := started.Add(30 * time.Second)
	if _, err := recordCodeScan(ctx, l.st, tg, crashed, opengrep.Scanned{}, later, nil); err != nil {
		t.Fatal(err)
	}
	if last, _ := l.st.SecLastScan(ctx, hash); !last.Equal(later) {
		t.Fatalf("SecLastScan after a crashed run: %v", last)
	}
	if r, ok, _ := l.st.SecLatestRun(ctx, opengrep.DriverID); !ok || r.Outcome != string(secscan.OutcomeFailed) {
		t.Fatalf("SecLatestRun after a crashed run: %+v %v", r, ok)
	}
}
