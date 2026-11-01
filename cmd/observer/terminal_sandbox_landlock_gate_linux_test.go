//go:build linux && !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// terminal_sandbox_landlock_gate_linux_test.go: the host helper's start gate
// with the process_lite exec step as its child (Linux live check 2026-10-23,
// LIN-1 F2: the gate put --block-fd after argv[0], so the verb never reached
// main's dispatch).

// TestStartGateArgvPerChild pins the exact argv for both children: bwrap
// takes the flag after its program path; the Landlock exec step takes it
// after its verb, which stays argv[1] for main's dispatch, and the step's
// own parser reads the gate, the plan and the launch from what follows.
func TestStartGateArgvPerChild(t *testing.T) {
	g := &startGate{}
	if got := g.argv([]string{"/usr/bin/bwrap", "--ro-bind", "/", "/", "--", "/usr/bin/observer", "claude"}); !reflect.DeepEqual(got,
		[]string{"/usr/bin/bwrap", "--block-fd", "4", "--ro-bind", "/", "/", "--", "/usr/bin/observer", "claude"}) {
		t.Fatalf("bwrap child argv %q", got)
	}
	got := g.argv([]string{"/opt/observer", landlockExecVerb, "--plan", "/p.json", "--", "/opt/observer", "claude", "-p", "hi"})
	want := []string{"/opt/observer", landlockExecVerb, "--block-fd", "4", "--plan", "/p.json", "--", "/opt/observer", "claude", "-p", "hi"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("landlock exec child argv %q, want %q", got, want)
	}
	if _, ok := sandboxHelperFuncs[got[1]]; !ok {
		t.Fatalf("main's dispatch does not see the verb at argv[1]: %q", got)
	}
	fd, rest, err := landlockExecGate(got[2:])
	if err != nil || fd != startGateFD {
		t.Fatalf("gate %d %v", fd, err)
	}
	plan, launch, err := parseLandlockExecArgs(rest)
	if err != nil || plan != "/p.json" || !reflect.DeepEqual(launch, []string{"/opt/observer", "claude", "-p", "hi"}) {
		t.Fatalf("plan %q launch %q err %v", plan, launch, err)
	}
	// Without the gate the step parses as before.
	if fd, rest, err := landlockExecGate([]string{"--plan", "/p.json", "--", "x"}); err != nil || fd != -1 || len(rest) != 4 {
		t.Fatalf("no gate: %d %q %v", fd, rest, err)
	}
	for _, bad := range [][]string{{"--block-fd"}, {"--block-fd", "x", "--plan"}, {"--block-fd", "1", "--plan"}} {
		if _, _, err := landlockExecGate(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// TestStartGateHoldsTheLandlockExecChild: a child shaped like the exec step
// (argv[1] the verb, then --block-fd 4) blocks on the gate, so a refused
// re-check kills it before it runs anything and a passed one lets it run.
// A shell script stands in for the observer binary.
func TestStartGateHoldsTheLandlockExecChild(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake-observer")
	script := "#!/bin/sh\n[ \"$1\" = " + landlockExecVerb + " ] && [ \"$2\" = --block-fd ] && [ \"$3\" = 4 ] || exit 9\nhead -c1 <&4 >/dev/null || exit 8\ntouch \"$5\"\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, refuse bool) (int, bool) {
		t.Helper()
		marker := filepath.Join(t.TempDir(), "ran")
		g, err := newStartGate()
		if err != nil {
			t.Fatal(err)
		}
		defer g.close()
		code := runSupervisedChild(g.argv([]string{fake, landlockExecVerb, "--plan", marker}), nil, g.files(), func(int) error {
			time.Sleep(200 * time.Millisecond)
			if _, err := os.Stat(marker); err == nil {
				t.Error("the exec step ran before the re-check finished")
			}
			if refuse {
				return errors.New("built_below_plan: test")
			}
			return g.release()
		})
		_, err = os.Stat(marker)
		return code, err == nil
	}
	if code, ran := run(t, true); code != sandboxHelperFailCode || ran {
		t.Fatalf("refused: exit %d ran %v", code, ran)
	}
	if code, ran := run(t, false); code != 0 || !ran {
		t.Fatalf("released: exit %d ran %v", code, ran)
	}
}

// TestLandlockAwaitRelease: the step proceeds on the release byte and
// refuses when the pipe closes without one.
func TestLandlockAwaitRelease(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if err := landlockAwaitRelease(int(r.Fd())); err != nil {
		t.Fatalf("released: %v", err)
	}
	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = w2.Close()
	if err := landlockAwaitRelease(int(r2.Fd())); err == nil || !strings.Contains(err.Error(), "did not release") {
		t.Fatalf("closed without a byte: %v", err)
	}
}

// TestLandlockRecheckPieces: the status parser, the namespace comparison,
// and the re-check of a real child: one that never sets no_new_privs is not
// measured (with its state named), one that ended is a child that exited,
// and one with no_new_privs set in the helper's namespaces matches.
func TestLandlockRecheckPieces(t *testing.T) {
	status := "Name:\tobserver\nState:\tS (sleeping)\nNoNewPrivs:\t1\nSeccomp:\t0\n"
	if procStatusField(status, "NoNewPrivs") != "1" || !strings.HasPrefix(procStatusField(status, "State"), "S") || procStatusField(status, "Missing") != "" {
		t.Fatal("procStatusField")
	}
	host := []string{"mnt:[1]", "pid:[2]", "net:[3]"}
	if err := landlockCompareNS(host, append([]string(nil), host...)); err != nil {
		t.Fatalf("same namespaces: %v", err)
	}
	if err := landlockCompareNS(host, []string{"mnt:[1]", "pid:[9]", "net:[3]"}); err == nil || !strings.Contains(err.Error(), "pid namespace") {
		t.Fatalf("another pid namespace: %v", err)
	}

	if self, err := os.ReadFile("/proc/self/status"); err != nil || procStatusField(string(self), "NoNewPrivs") == "1" {
		t.Skip("this test process runs with no_new_privs (or has no /proc), so the child's flag proves nothing here")
	}
	prev := recheckChildTimeout
	recheckChildTimeout = 300 * time.Millisecond
	t.Cleanup(func() { recheckChildTimeout = prev })

	sleeper := exec.Command("sleep", "5")
	if err := sleeper.Start(); err != nil {
		t.Skip("no sleep binary")
	}
	defer func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() }()
	if err := landlockRecheck(sleeper.Process.Pid); !errors.Is(err, errRecheckNotMeasured) || !strings.Contains(err.Error(), recheckStateLandlockNotReady) {
		t.Fatalf("a child without no_new_privs: %v", err)
	}

	quick := exec.Command("true")
	if err := quick.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // exited, not yet reaped
	if err := landlockRecheck(quick.Process.Pid); !errors.Is(err, errRecheckChildExited) {
		t.Fatalf("an exited child: %v", err)
	}
	_ = quick.Wait()

	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Log("no setpriv: the measured match is left to the live check")
		return
	}
	held := exec.Command(setpriv, "--no-new-privs", "sleep", "5")
	if err := held.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Process.Kill(); _ = held.Wait() }()
	if err := landlockRecheck(held.Process.Pid); err != nil {
		t.Fatalf("a held child with no_new_privs in the helper's namespaces: %v", err)
	}
}
