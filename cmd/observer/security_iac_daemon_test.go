//go:build !sbo_omit_security && !sbo_omit_security_scan_trivy

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/powerstate"
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// security_iac_daemon_test.go: the IaC loop's triggers through its real
// pass, the scan and power seams swapped.

func iacTestLoop(t *testing.T, keys string, got *[]secscan.Target) *iacLoop {
	t.Helper()
	cfgPath := iacConfig(t, "[components]\nadd = [\"security.scan.trivy\", \"security.code\"]\n\n[security.scan.trivy]\n"+keys)
	_, database, cleanup, err := loadConfigAndDB(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	l := newIaCLoop(seciac.Trivy, cfgPath, database, newLogger("error"))
	l.installed = func(context.Context, *iacEnv) bool { return true }
	l.power = func() powerstate.State { return powerstate.AC }
	l.scan = func(_ context.Context, _ *iacEnv, tg secscan.Target) error {
		*got = append(*got, tg)
		return nil
	}
	return l
}

func iacProject(t *testing.T, l *iacLoop) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := l.st.UpsertProject(context.Background(), root, ""); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestIaCLoopPostWriteOnlyOnIaCPaths: with post_write on, a write to an IaC
// file scans the project once quiet; a write to any other file scans
// nothing; with post_write off (the default) nothing is queued.
func TestIaCLoopPostWriteOnlyOnIaCPaths(t *testing.T) {
	var got []secscan.Target
	l := iacTestLoop(t, "post_write = true\n", &got)
	root := iacProject(t, l)
	t0 := time.Now()
	l.deb.Add(root, "main.go", t0)
	l.pass(context.Background(), t0.Add(time.Minute))
	if len(got) != 0 {
		t.Fatalf("a non-IaC write scanned: %+v", got)
	}
	l.deb.Add(root, "k8s/pod.yaml", t0)
	l.pass(context.Background(), t0.Add(time.Second))
	if len(got) != 0 {
		t.Fatalf("scanned inside the quiet window: %+v", got)
	}
	l.pass(context.Background(), t0.Add(seciac.PostWriteQuiet))
	if len(got) != 1 || got[0].Scope != policy.FindingScopePostWrite || got[0].ProjectRoot != root {
		t.Fatalf("post-write scans %+v", got)
	}
	// Default (off): the feed is drained but nothing queued.
	var none []secscan.Target
	off := iacTestLoop(t, "", &none)
	off.readWrites(context.Background(), time.Now(), false)
	if len(off.deb.Due(time.Now().Add(time.Hour))) != 0 {
		t.Fatal("post_write off queued a scan")
	}
}

// TestIaCLoopScheduleHeldOnBatteryAndWithoutAnEngine: the schedule scans
// active projects once per period on AC power, holds on battery, and
// nothing runs while no engine is installed.
func TestIaCLoopScheduleHeldOnBatteryAndWithoutAnEngine(t *testing.T) {
	var got []secscan.Target
	l := iacTestLoop(t, "schedule_hours = 24\n", &got)
	root := iacProject(t, l)
	later := time.Now().Add(iacScheduleFirst + time.Minute)
	l.power = func() powerstate.State { return powerstate.Battery }
	l.pass(context.Background(), later)
	if len(got) != 0 {
		t.Fatalf("scheduled on battery: %+v", got)
	}
	l.installed = func(context.Context, *iacEnv) bool { return false }
	l.power = func() powerstate.State { return powerstate.AC }
	l.pass(context.Background(), later)
	if len(got) != 0 {
		t.Fatalf("scheduled with no engine: %+v", got)
	}
	l.installed = func(context.Context, *iacEnv) bool { return true }
	l.pass(context.Background(), later)
	if len(got) != 1 || got[0].Scope != policy.FindingScopeScheduled || got[0].ProjectRoot != root {
		t.Fatalf("scheduled scans %+v", got)
	}
}
