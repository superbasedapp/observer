//go:build !sbo_omit_org_update

package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_handshake_warmup_test.go: the Windows warm-up after `observer
// update` (lane shr-hookseam2, milestone 3), one test per path.

func TestWarmUpRules(t *testing.T) {
	cases := []struct {
		goos    string
		started bool
		want    bool
	}{
		{"windows", false, true},
		{"windows", true, false},
		{"linux", false, false},
		{"linux", true, false},
		{"darwin", false, false},
	}
	for _, tc := range cases {
		got, why := warmUpNeeded(tc.goos, handshakeResult{Ready: true, Started: tc.started})
		if got != tc.want || why == "" {
			t.Errorf("warmUpNeeded(%s, started=%v) = %v (%q), want %v with a reason", tc.goos, tc.started, got, why, tc.want)
		}
	}
}

// warmUpProbe records what the warm-up was asked to run and what file was
// at that path when it ran.
type warmUpProbe struct {
	calls []string
	saw   string
}

func (p *warmUpProbe) fn(_ context.Context, exePath string) {
	p.calls = append(p.calls, exePath)
	if b, err := os.ReadFile(exePath); err == nil {
		p.saw = string(b)
	}
}

// TestCLIApplyWarmsUpTheSwappedInBinaryOnWindows: the CLI apply with no
// daemon has no handshake child, so on Windows it runs the swapped-in file
// itself (the path the hooks exec) once, after the swap.
func TestCLIApplyWarmsUpTheSwappedInBinaryOnWindows(t *testing.T) {
	f := newApplyFixture(t)
	f.deps.GOOS = "windows"
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		return handshakeResult{Ready: true, Detail: "no daemon was running, so the --version probe was the acceptance gate"}, nil
	}
	var p warmUpProbe
	f.deps.WarmUp = p.fn
	out, err := f.run()
	if err != nil || !out.Applied {
		t.Fatalf("apply: %v (%+v)", err, out)
	}
	if len(p.calls) != 1 || p.calls[0] != f.exePath {
		t.Fatalf("warm-up calls = %v, want exactly one run of %s", p.calls, f.exePath)
	}
	if !strings.Contains(p.saw, "NEW") {
		t.Errorf("the warm-up ran %q, not the swapped-in binary", p.saw)
	}
}

// TestDaemonHandshakeIsTheWarmUp: the daemon apply's handshake child is the
// swapped-in file at the installed path, the one the hooks exec, started
// before any hook can run it; so it is the warm-up and nothing else runs.
func TestDaemonHandshakeIsTheWarmUp(t *testing.T) {
	f := newApplyFixture(t)
	f.deps.GOOS = "windows"
	var supervised, sawThere string
	f.deps.Supervise = func(_ context.Context, exe, _ string, _ time.Duration) (handshakeResult, error) {
		supervised = exe
		if b, err := os.ReadFile(exe); err == nil {
			sawThere = string(b)
		}
		return handshakeResult{Ready: true, Detail: "self-check passed", ChildPID: 4242, Started: true}, nil
	}
	var p warmUpProbe
	f.deps.WarmUp = p.fn
	out, err := f.run()
	if err != nil || !out.Applied {
		t.Fatalf("apply: %v (%+v)", err, out)
	}
	if supervised != f.exePath || !strings.Contains(sawThere, "NEW") {
		t.Fatalf("the handshake started %q holding %q, want the swapped-in binary at %s", supervised, sawThere, f.exePath)
	}
	if len(p.calls) != 0 {
		t.Errorf("warm-up ran %v although the handshake child already ran the binary", p.calls)
	}
}

// TestWarmUpIsANoOpOffWindows: no first-run scan elsewhere, so the CLI
// apply runs nothing extra.
func TestWarmUpIsANoOpOffWindows(t *testing.T) {
	f := newApplyFixture(t)
	f.deps.GOOS = "linux"
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		return handshakeResult{Ready: true}, nil
	}
	var p warmUpProbe
	f.deps.WarmUp = p.fn
	if out, err := f.run(); err != nil || !out.Applied {
		t.Fatalf("apply: %v (%+v)", err, out)
	}
	if len(p.calls) != 0 {
		t.Errorf("warm-up ran %v off Windows", p.calls)
	}
}

// TestWarmUpNeverRunsOnARollback: a failed handshake restores the old
// binary and runs no warm-up of the new one.
func TestWarmUpNeverRunsOnARollback(t *testing.T) {
	f := newApplyFixture(t)
	f.deps.GOOS = "windows"
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		return handshakeResult{Detail: "the new binary exited before completing its self-check"}, context.Canceled
	}
	var p warmUpProbe
	f.deps.WarmUp = p.fn
	_, _ = f.run()
	if len(p.calls) != 0 {
		t.Errorf("warm-up ran %v on a rolled-back apply", p.calls)
	}
}

// TestWarmUpRunsAfterTheHistoryEvent (audit finding 1): the applied event
// is already in the ledger when the warm-up starts, so its DurationMS
// leaves the warm-up out, and one notice line is printed before it runs.
func TestWarmUpRunsAfterTheHistoryEvent(t *testing.T) {
	f := newApplyFixture(t)
	f.deps.GOOS = "windows"
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		return handshakeResult{Ready: true, Detail: "no daemon was running, so the --version probe was the acceptance gate"}, nil
	}
	var notice bytes.Buffer
	f.deps.WarmUpNotice = &notice
	clock := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	f.deps.Now = func() time.Time { return clock }
	var appliedBefore bool
	var noticeBefore string
	f.deps.WarmUp = func(context.Context, string) {
		for _, ev := range f.st.events {
			if ev.State == update.StateApplied {
				appliedBefore = true
			}
		}
		noticeBefore = notice.String()
		clock = clock.Add(25 * time.Second) // a slow first-run scan
	}
	out, err := f.run()
	if err != nil || !out.Applied {
		t.Fatalf("apply: %v (%+v)", err, out)
	}
	if !appliedBefore {
		t.Fatal("the warm-up ran before the applied event was recorded")
	}
	if noticeBefore != warmUpNoticeLine+"\n" {
		t.Errorf("notice before the warm-up = %q, want exactly one line %q", noticeBefore, warmUpNoticeLine)
	}
	for _, ev := range f.st.events {
		if ev.State == update.StateApplied && ev.DurationMS >= (25*time.Second).Milliseconds() {
			t.Errorf("applied DurationMS = %d, includes the warm-up", ev.DurationMS)
		}
	}
	if notice.String() != noticeBefore {
		t.Errorf("more output after the warm-up: %q", notice.String())
	}
}

// TestNoWarmUpNoticeWhenNothingRuns: the daemon path (its handshake child
// is the warm-up) and the non-Windows path print nothing.
func TestNoWarmUpNoticeWhenNothingRuns(t *testing.T) {
	for _, tc := range []struct {
		goos    string
		started bool
	}{{"windows", true}, {"linux", false}} {
		f := newApplyFixture(t)
		f.deps.GOOS = tc.goos
		started := tc.started
		f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
			return handshakeResult{Ready: true, Started: started}, nil
		}
		var notice bytes.Buffer
		f.deps.WarmUpNotice = &notice
		f.deps.WarmUp = func(context.Context, string) {}
		if out, err := f.run(); err != nil || !out.Applied {
			t.Fatalf("%s: apply: %v (%+v)", tc.goos, err, out)
		}
		if notice.Len() != 0 {
			t.Errorf("%s started=%v: printed %q with no warm-up", tc.goos, tc.started, notice.String())
		}
	}
}
