//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestSandboxRecheckRefusesAHostNamespaceChild: a "sandbox" whose child
// shares the host's mount and pid namespaces (a plain shell standing in for
// a bwrap that built nothing) is measured and refused, never passed.
func TestSandboxRecheckRefusesAHostNamespaceChild(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 5 & wait")
	if err := cmd.Start(); err != nil {
		t.Skipf("no /bin/sh: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	err := sandboxRecheck(true, cmd.Process.Pid)
	if err == nil {
		t.Fatal("a child in the host namespaces passed the re-check")
	}
	if errors.Is(err, errRecheckNotMeasured) {
		t.Skipf("namespaces not readable here: %v", err)
	}
}

// TestSandboxRecheckNotMeasured: a process that never gets a child is not
// measured, which is reported distinctly so the helper does not refuse a
// run it could not inspect.
func TestSandboxRecheckNotMeasured(t *testing.T) {
	old := recheckChildTimeout
	recheckChildTimeout = 100 * time.Millisecond
	defer func() { recheckChildTimeout = old }()
	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skipf("no /bin/sleep: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if err := sandboxRecheck(true, cmd.Process.Pid); !errors.Is(err, errRecheckNotMeasured) {
		t.Fatalf("err %v, want not measured", err)
	}
}

// TestRunSupervisedChildKillsOnPostStartRefusal: a refused re-check kills
// the started child and fails the helper with the helper failure code.
func TestRunSupervisedChildKillsOnPostStartRefusal(t *testing.T) {
	start := time.Now()
	code := runSupervisedChild([]string{"/bin/sleep", "30"}, nil, nil, func(int) error { return errors.New("built_below_plan: test") })
	if code != sandboxHelperFailCode {
		t.Fatalf("exit %d, want %d", code, sandboxHelperFailCode)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the refused child was not killed")
	}
}

// TestStartGateRunsTheCheckBeforeTheCommand (P-017 (d)): the command the
// gate wraps blocks on the release pipe, so a refused check kills it before
// it runs anything, and a passed check lets it run. A shell script stands in
// for bwrap's --block-fd handling.
func TestStartGateRunsTheCheckBeforeTheCommand(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake-bwrap")
	script := "#!/bin/sh\n[ \"$1\" = --block-fd ] && [ \"$2\" = 4 ] || exit 9\nhead -c1 <&4 >/dev/null || exit 8\n[ -s /dev/stdin ] 2>/dev/null; touch \"$3\"\n"
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
		code := runSupervisedChild(g.argv([]string{fake, marker}), nil, g.files(), func(int) error {
			// Give the command time to run if the gate did not hold it.
			time.Sleep(200 * time.Millisecond)
			if _, err := os.Stat(marker); err == nil {
				t.Error("the command ran before the check finished")
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
	g := &startGate{}
	if got := g.argv([]string{"/usr/bin/bwrap", "--ro-bind", "/", "/"}); !reflect.DeepEqual(got, []string{"/usr/bin/bwrap", "--block-fd", "4", "--ro-bind", "/", "/"}) {
		t.Fatalf("argv %v", got)
	}
}

// TestGuestStagedDiff (M7 A side): the one-shot prints the staged diff, or
// with --all the tracked working-tree diff, and refuses any other argument.
func TestGuestStagedDiff(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = dir
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "a")
	run("commit", "-q", "-m", "init")
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("STAGED\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "a")
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("WORKTREE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	diff := func(args ...string) (string, int) {
		t.Helper()
		c := exec.Command(exe, append([]string{"sandbox-guest", "staged-diff"}, args...)...) //nolint:gosec // G204: this test binary as the guest helper
		c.Dir = dir
		out, err := c.Output()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		return string(out), code
	}
	if out, code := diff(); code != 0 || !strings.Contains(out, "+STAGED") || strings.Contains(out, "WORKTREE") {
		t.Fatalf("staged: %d %q", code, out)
	}
	if out, code := diff("--all"); code != 0 || !strings.Contains(out, "+WORKTREE") {
		t.Fatalf("--all: %d %q", code, out)
	}
	if _, code := diff("--output=/tmp/x"); code != sandboxHelperFailCode {
		t.Fatalf("an unknown argument exited %d", code)
	}
}

// recordedBwrapStats is a live process shape: a non-setuid bwrap 0.4.0 on
// WSL2 (6.18.33) started with --block-fd and --unshare-all, read while its
// child waited on the block pipe. bwrap (1990) forked once; the child
// (1993, ppid 1990) holds the new namespaces and is what the re-check
// measures. 1987 is the launching shell.
var recordedBwrapStats = map[int]string{
	1987: "1987 (bash) S 1986 1987 1987 34816 1987 4194560 1200 0 0 0 1 0 0 0 20 0 1 0 24840 9000000 900 18446744073709551615 0 0 0 0 0 0 65536 4 65538 1 0 0 17 2 0 0 0 0 0 0 0 0 0 0 0 0 0",
	1990: "1990 (bwrap) S 1987 1987 1987 34816 1987 4194560 139 0 0 0 0 0 0 0 20 0 1 0 24850 3612672 510 18446744073709551615 109551417163776 109551417193653 140729791724592 0 0 0 65536 6 0 1 0 0 17 1 0 0 0 0 0 109551417219472 109551417221352 109551759470592 140729791733512 140729791733630 140729791733630 140729791737833 0",
	1993: "1993 (bwrap) S 1990 1987 1987 34816 1987 4194624 45 0 0 0 0 0 0 0 20 0 1 0 24850 3612672 300 18446744073709551615 109551417163776 109551417193653 140729791724592 0 0 0 65536 6 0 1 0 0 17 3 0 0 0 0 0 109551417219472 109551417221352 109551759470592 140729791733512 140729791733630 140729791733630 140729791737833 0",
}

// TestRecheckChildFromStat (live check 2026-10-22, D3): the /proc ppid scan
// finds bwrap's child on the recorded non-setuid shape, reads a command
// name holding spaces and parentheses, and says 0 when there is no child.
func TestRecheckChildFromStat(t *testing.T) {
	if got := childFromStat(1990, recordedBwrapStats); got != 1993 {
		t.Fatalf("child of the recorded bwrap = %d, want 1993", got)
	}
	if got := childFromStat(1993, recordedBwrapStats); got != 0 {
		t.Fatalf("the blocked child has no child yet, got %d", got)
	}
	odd := map[int]string{
		50: "50 (my (odd) tool) S 40 50 50 0 -1 0",
		51: "51 (x) R 50 50 50 0 -1 0",
		52: "52 garbled",
	}
	if p, ok := statPPID(odd[50]); !ok || p != 40 {
		t.Fatalf("ppid of a parenthesised name = %d %v", p, ok)
	}
	if got := childFromStat(50, odd); got != 51 {
		t.Fatalf("child = %d, want 51", got)
	}
	if _, ok := statPPID(odd[52]); ok {
		t.Fatal("a garbled stat line parsed")
	}
}

// TestSandboxRecheckNamesTheState: a re-check that measured nothing names
// its posture state in the error the notice prints.
func TestSandboxRecheckNamesTheState(t *testing.T) {
	old := recheckChildTimeout
	recheckChildTimeout = 100 * time.Millisecond
	defer func() { recheckChildTimeout = old }()
	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skipf("no /bin/sleep: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	err := sandboxRecheck(true, cmd.Process.Pid)
	if !errors.Is(err, errRecheckNotMeasured) || !strings.Contains(err.Error(), recheckStateNoChild) {
		t.Fatalf("err %v, want the %s state named", err, recheckStateNoChild)
	}
}

// TestSandboxRecheckLiveBwrapWithoutChildrenFiles runs a real bwrap held on
// --block-fd and measures it with the /proc children files switched off,
// the shape of a kernel without CONFIG_PROC_CHILDREN: the ppid scan finds
// the child and the namespaces are read and pass. Skipped where bwrap
// cannot build a sandbox.
func TestSandboxRecheckLiveBwrapWithoutChildrenFiles(t *testing.T) {
	bw, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not installed")
	}
	if err := exec.Command(bw, "--unshare-all", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "--", "true").Run(); err != nil {
		t.Skipf("bwrap cannot build a sandbox here: %v", err)
	}
	old := recheckReadChildrenFiles
	recheckReadChildrenFiles = false
	defer func() { recheckReadChildrenFiles = old }()
	g, err := newStartGate()
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	var recheckErr error
	code := runSupervisedChild(g.argv([]string{bw, "--unshare-all", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "--die-with-parent", "--", "true"}), nil, g.files(), func(pid int) error {
		if recheckErr = sandboxRecheck(true, pid); recheckErr != nil {
			return recheckErr
		}
		return g.release()
	})
	if recheckErr != nil || code != 0 {
		t.Fatalf("the live bwrap was not measured (exit %d): %v", code, recheckErr)
	}
}

// TestBwrapCanaryKeepsStderr (live checks 2026-10-22, D3): the canary keeps
// bwrap's own stderr, so the probe can name the real cause instead of
// always blaming the user-namespace sysctls. A bwrap refusing a missing
// bind source stands in for a canary that fails.
func TestBwrapCanaryKeepsStderr(t *testing.T) {
	bw, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not installed")
	}
	err = runBwrapCanary(exec.Command(bw, "--ro-bind", "/nonexistent-observer-canary", "/x", "--", "true"))
	var cf *sandbox.CanaryFailure
	if !errors.As(err, &cf) || !strings.Contains(cf.Stderr, "Can't find source path") {
		t.Fatalf("err %v, want bwrap's stderr kept", err)
	}
	if strings.Contains(err.Error(), "/nonexistent-observer-canary") {
		t.Fatalf("a path outside the canary's plan was echoed: %v", err)
	}
	if err := runBwrapCanary(exec.Command(bw, "--ro-bind", "/", "/", "--", "true")); err != nil {
		t.Skipf("bwrap cannot run here: %v", err)
	}
}

// TestRecheckNoticeLines (live check 2026-10-22, D3 follow-up): a measured
// match prints one positive line, a not-measured outcome names its state
// and lets the run go on, a measured refusal prints nothing and is
// returned.
func TestRecheckNoticeLines(t *testing.T) {
	cases := []struct {
		name    string
		in      error
		line    string
		refused bool
	}{
		{"measured match", nil, "the launch re-check measured the sandbox's mnt, pid, net namespaces and they match the plan", false},
		{"not measured", fmt.Errorf("%w, state %s: no child", errRecheckNotMeasured, recheckStateNoChild), "did not run (namespaces not measured, state recheck_no_child", false},
		{"measured refusal", errors.New("built_below_plan: the sandbox shares the host's net namespace"), "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b strings.Builder
			err := recheckNotice(c.in, &b)
			if (err != nil) != c.refused {
				t.Fatalf("err %v, refused %v", err, c.refused)
			}
			got := b.String()
			if c.line == "" {
				if got != "" {
					t.Fatalf("a refusal printed %q", got)
				}
				return
			}
			if !strings.Contains(got, c.line) || strings.Count(got, "\n") != 1 {
				t.Fatalf("line %q, want one line with %q", got, c.line)
			}
		})
	}
}
