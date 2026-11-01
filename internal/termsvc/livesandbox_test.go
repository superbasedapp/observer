package termsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// liveSandboxService launches one sandboxed run (handle "S1", bwrap) and one
// unsandboxed run (handle "U1") on a fixed clock.
func liveSandboxService(t *testing.T) (*Service, *fakeLauncher) {
	t.Helper()
	root := t.TempDir()
	validated, err := ValidateProjectRoot(root, []string{root})
	if err != nil {
		t.Fatalf("ValidateProjectRoot: %v", err)
	}
	l := &fakeLauncher{handle: "S1"}
	at := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	svc := New(Options{
		Policy:   Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{root}},
		Recorder: newFakeRecorder(),
		Launcher: l,
		Sandboxer: &fakeSandboxer{result: PrepareResult{
			Dir:       validated,
			Isolation: termrun.Isolation{Class: "process", Stack: []string{"bwrap"}},
		}},
		Now: func() time.Time { return at },
	})
	if _, err := svc.LaunchFresh(context.Background(), FreshRequest{
		Tool: "claude-code", Subcommand: "claude", Sandbox: true, ProjectRoot: root, WorkspaceSource: "live",
	}); err != nil {
		t.Fatalf("sandboxed LaunchFresh: %v", err)
	}
	l.handle = "U1"
	if _, err := svc.LaunchFresh(context.Background(), FreshRequest{
		Tool: "claude-code", Subcommand: "claude", ProjectRoot: root,
	}); err != nil {
		t.Fatalf("unsandboxed LaunchFresh: %v", err)
	}
	return svc, l
}

// TestLiveSandboxedRunsListsOnlyLiveSandboxedRuns: the list carries the
// sandboxed run only, with its backend, start time and native resume, and
// agrees with the count before and after the run ends.
func TestLiveSandboxedRunsListsOnlyLiveSandboxedRuns(t *testing.T) {
	svc, _ := liveSandboxService(t)
	runs := svc.LiveSandboxedRuns()
	if len(runs) != 1 || svc.LiveSandboxedCount() != 1 {
		t.Fatalf("runs = %+v, count %d; want exactly the sandboxed run", runs, svc.LiveSandboxedCount())
	}
	r := runs[0]
	if r.Handle != "S1" || r.Tool != "claude-code" || r.Backend != "bwrap" || r.RunID == "" {
		t.Fatalf("run = %+v", r)
	}
	if !r.NativeResume {
		t.Fatal("NativeResume = false for claude-code, want true (the registry grounds its native resume)")
	}
	if r.StartedAt.IsZero() {
		t.Fatal("StartedAt is zero")
	}
	svc.EndRunByHandle(context.Background(), "S1", 0)
	if got := svc.LiveSandboxedRuns(); len(got) != 0 {
		t.Fatalf("after the run ended: %+v, want none", got)
	}
}

// TestEndLiveSandboxedStampsThenCloses: every live sandboxed run is stamped
// with the reason BEFORE its terminal is closed, the unsandboxed run is left
// alone, and a stamp failure is reported but the run still ends.
func TestEndLiveSandboxedStampsThenCloses(t *testing.T) {
	svc, _ := liveSandboxService(t)
	var order []string
	stamp := func(_ context.Context, runID, reason string) error {
		order = append(order, "stamp:"+reason)
		return errors.New("disk full")
	}
	var reported []string
	closeRun := func(handle, notice string) {
		order = append(order, "close:"+handle)
		if notice == "" {
			t.Error("closed without a notice")
		}
		svc.EndRunByHandle(context.Background(), handle, 0)
	}
	ended := svc.EndLiveSandboxed(context.Background(), "daemon_shutdown", "bye", stamp, closeRun,
		func(runID string, err error) { reported = append(reported, runID+":"+err.Error()) })
	if len(ended) != 1 {
		t.Fatalf("ended = %v, want one run", ended)
	}
	if len(order) != 2 || order[0] != "stamp:daemon_shutdown" || order[1] != "close:S1" {
		t.Fatalf("order = %v, want stamp then close of S1 only", order)
	}
	if len(reported) != 1 {
		t.Fatalf("stamp errors reported = %v, want one", reported)
	}
	if svc.LiveSandboxedCount() != 0 {
		t.Fatalf("count after ending = %d", svc.LiveSandboxedCount())
	}
	// A nil closer ends nothing.
	if got := svc.EndLiveSandboxed(context.Background(), "x", "y", nil, nil, nil); got != nil {
		t.Fatalf("nil closer ended %v", got)
	}
}
