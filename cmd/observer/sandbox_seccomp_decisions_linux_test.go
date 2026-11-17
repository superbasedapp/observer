//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandboxseccomp"
)

// The kernel side of the seccomp decisions of lane FU4 (audits N2-A7 and
// N2-A8): what a tool sees under the filter when it runs one of the
// programs the decisions are about. One row per decision outcome; a row is
// skipped when its program is missing or fails here even unfiltered (an
// unprivileged host without user namespaces, for example). A row with seize
// set runs under a profile that lifts PTRACE_SEIZE (the strace opt-in, lane
// ptrace, PT-96) instead of observer_default.
var seccompDecisionProbes = []struct {
	name    string
	argv    []string
	allowed bool
	// expect, when set, replaces allowed with the outcome this host's copy
	// of the program shows under the filter, decided from a property of
	// that program measured here (its release), and says why. An error
	// skips the row, naming what could not be measured.
	expect func() (allowed bool, why string, err error)
	// seize: the row runs under the seize profile.
	seize bool
}{
	// N2-A8: user namespaces stay open (a browser sandbox needs one) ...
	{name: "user namespace", argv: []string{"unshare", "-U", "true"}, allowed: true},
	// ... but mount stays denied inside it, so a nested bwrap fails.
	// The mount target is a test-owned empty dir (seccompDecisionDir), in
	// a private mount namespace either way.
	{name: "mount in a nested user namespace", argv: []string{"unshare", "-Urm", "mount", "-t", "tmpfs", "none", seccompDecisionDir}, allowed: false},
	{name: "nested bwrap", argv: []string{"bwrap", "--ro-bind", "/", "/", "--", "true"}, allowed: false},
	// N2-A7: PTRACE_SEIZE stays denied on any pid. Whether strace on a
	// child it starts still works depends on the strace release (see
	// straceChildExpectation). Attaching to a process that already exists
	// is the EPERM probe of TestSeccompKernelEPERM.
	{name: "strace on its own child", argv: []string{"strace", "-f", "-o", "/dev/null", "true"}, expect: straceChildExpectation},
	// Lane ptrace: with the strace opt-in's profile, strace on a child it
	// starts works on every release, 6.14 and later included.
	{name: "strace on its own child, strace switch on", argv: []string{"strace", "-f", "-o", "/dev/null", "true"}, expect: straceSeizeExpectation, seize: true},
	{name: "strace -f on its own child that forks, strace switch on", argv: []string{"strace", "-f", "-o", "/dev/null", "sh", "-c", "true; true"}, expect: straceSeizeExpectation, seize: true},
}

// straceSelfProbeRelease is the first strace release (6.14, 2025-03-25)
// whose startup check of PTRACE_SEIZE (test_ptrace_seize in src/strace.c)
// seizes strace itself instead of a forked child. Seizing oneself always
// fails with EPERM on a kernel that has PTRACE_SEIZE, so that check takes
// the filter's EPERM for "PTRACE_SEIZE works" (its own comment leaves a
// syscall filter out of its scope), never falls back to PTRACE_TRACEME,
// and its PTRACE_SEIZE of the child it starts then gets the filter's
// EPERM: "strace: attach: ptrace(PTRACE_SEIZE, <pid>): Operation not
// permitted". Releases before it (5.5 and 6.8 measured) seize a forked
// child, see the filter's EPERM there, and have the child call
// PTRACE_TRACEME instead, so strace on its own child works under the
// filter. v6.13 is the last release with the forked-child check.
var straceSelfProbeRelease = [2]int{6, 14}

// straceVersionRE finds the release in `strace -V` ("strace -- version 6.8").
var straceVersionRE = regexp.MustCompile(`\bversion (\d+)\.(\d+)`)

// parseStraceRelease returns the major and minor release `strace -V`
// printed, or false when out names none.
func parseStraceRelease(out string) (major, minor int, ok bool) {
	m := straceVersionRE.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// straceRelease reads this host's strace release.
func straceRelease() (major, minor int, err error) {
	out, err := exec.Command("strace", "-V").Output()
	if err != nil {
		return 0, 0, fmt.Errorf("strace -V: %w", err)
	}
	major, minor, ok := parseStraceRelease(string(out))
	if !ok {
		return 0, 0, fmt.Errorf("strace -V named no release: %q", strings.TrimSpace(string(out)))
	}
	return major, minor, nil
}

// straceChildExpectation is the strace row's expected outcome on this
// host: allowed for a strace that falls back to PTRACE_TRACEME, denied
// for one that cannot (straceSelfProbeRelease).
func straceChildExpectation() (bool, string, error) {
	major, minor, err := straceRelease()
	if err != nil {
		return false, "", err
	}
	return straceChildAllowed(major, minor)
}

// straceSeizeExpectation is the strace rows' expected outcome under the
// seize profile: allowed on every release (6.14 and later seize their child
// directly; earlier ones see their probe succeed and seize too).
func straceSeizeExpectation() (bool, string, error) {
	major, minor, err := straceRelease()
	if err != nil {
		return false, "", err
	}
	return straceSeizeAllowed(major, minor)
}

// straceChildAllowed is the strace row's expected outcome for a release.
func straceChildAllowed(major, minor int) (bool, string, error) {
	rel := fmt.Sprintf("strace %d.%d", major, minor)
	if major < straceSelfProbeRelease[0] || (major == straceSelfProbeRelease[0] && minor < straceSelfProbeRelease[1]) {
		return true, rel + " probes PTRACE_SEIZE on a forked child, sees the filter's EPERM and falls back to PTRACE_TRACEME", nil
	}
	return false, rel + " probes PTRACE_SEIZE on itself, takes the filter's EPERM for support and seizes its child, which the filter refuses", nil
}

// straceSeizeAllowed is the seize rows' expected outcome for a release.
func straceSeizeAllowed(major, minor int) (bool, string, error) {
	rel := fmt.Sprintf("strace %d.%d", major, minor)
	return true, rel + " seizes the child it starts, which the strace switch's profile allows (PTRACE_ATTACH stays denied)", nil
}

// seccompDecisionDir stands for the probes' mount target; envDecisionDir
// carries the test's own empty dir to the child.
const (
	seccompDecisionDir = "{dir}"
	envDecisionDir     = "OBSERVER_TEST_SECCOMP_DIR"
)

// runDecisionProbe runs one probe, true when it exits 0. On a failure, why
// is the run error and the last line the program wrote to stderr, so a
// filtered outcome that disagrees with its decision names what the program
// saw.
func runDecisionProbe(argv []string, dir string) (ok bool, why string) {
	argv = append([]string(nil), argv...)
	for i, a := range argv {
		if a == seccompDecisionDir {
			argv[i] = dir
		}
	}
	var stderr strings.Builder
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // G204: fixed test argv
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, &stderr
	err := cmd.Run()
	if err == nil {
		return true, ""
	}
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	return false, err.Error() + ": " + strings.TrimSpace(lines[len(lines)-1])
}

// seccompDecisionChild loads profile and prints one line per probe whose
// seize field equals seize: "<index> ok" or "<index> fail <why>". It exits;
// it never returns.
func seccompDecisionChild(profile sandboxseccomp.ProfileID, seize bool) {
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		os.Stdout.WriteString("SKIP no_new_privs: " + err.Error() + "\n")
		os.Exit(0)
	}
	if err := applySeccompSelf(string(profile)); err != nil {
		os.Stdout.WriteString("SKIP load: " + err.Error() + "\n")
		os.Exit(0)
	}
	var b strings.Builder
	for i, p := range seccompDecisionProbes {
		if p.seize != seize {
			continue
		}
		res := "ok"
		if ok, why := runDecisionProbe(p.argv, os.Getenv(envDecisionDir)); !ok {
			res = "fail " + strings.ReplaceAll(why, "\n", " ")
		}
		b.WriteString(strconv.Itoa(i) + " " + res + "\n")
	}
	os.Stdout.WriteString(b.String())
	os.Exit(0)
}

// TestSeccompKernelDecisions runs each decision probe unfiltered (its
// baseline) and under its profile, and checks the filtered outcome is the
// one the decision records: the observer_default rows, then the strace
// switch's rows under a profile that lifts PTRACE_SEIZE.
func TestSeccompKernelDecisions(t *testing.T) {
	switch os.Getenv(envSeccompChild) {
	case "decisions":
		seccompDecisionChild(sandboxseccomp.ProfileObserverDefault, false)
	case "decisions-seize":
		seccompDecisionChild(sandboxseccomp.ProfileObserverSeizeYama, true)
	}
	dir := t.TempDir()
	t.Setenv(envDecisionDir, dir)
	t.Run("observer_default", func(t *testing.T) { runDecisionTable(t, dir, "decisions", false) })
	t.Run("strace switch on", func(t *testing.T) { runDecisionTable(t, dir, "decisions-seize", true) })
}

// runDecisionTable is TestSeccompKernelDecisions for the rows whose seize
// field equals seize, under the child mode's profile.
func runDecisionTable(t *testing.T, dir, mode string, seize bool) {
	var idx []int
	baseline := map[int]bool{}
	anyRan := false
	for i, p := range seccompDecisionProbes {
		if p.seize != seize {
			continue
		}
		idx = append(idx, i)
		if _, err := exec.LookPath(p.argv[0]); err != nil {
			continue
		}
		baseline[i], _ = runDecisionProbe(p.argv, dir)
		anyRan = anyRan || baseline[i]
	}
	if !anyRan {
		t.Skip("no decision probe runs on this host even unfiltered")
	}
	cmd, out := startSeccompChild(t, "TestSeccompKernelDecisions", mode)
	b, rerr := io.ReadAll(out)
	err := cmd.Wait()
	got := string(b)
	if strings.HasPrefix(got, "SKIP") {
		t.Skipf("this kernel or sandbox refuses an unprivileged seccomp filter: %s", strings.TrimSpace(got))
	}
	if rerr != nil || err != nil {
		t.Fatalf("child: %v %v: %s", rerr, err, got)
	}
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != len(idx) {
		t.Fatalf("child printed %d lines, want %d: %q", len(lines), len(idx), got)
	}
	for k, i := range idx {
		p := seccompDecisionProbes[i]
		if !strings.HasPrefix(lines[k], strconv.Itoa(i)+" ") {
			t.Fatalf("child line %q is not probe %d", lines[k], i)
		}
		if !baseline[i] {
			t.Logf("%s: skipped (missing or fails unfiltered here)", p.name)
			continue
		}
		want, why := p.allowed, "as decided"
		if p.expect != nil {
			var err error
			if want, why, err = p.expect(); err != nil {
				t.Logf("%s: skipped (its expected outcome could not be measured here: %v)", p.name, err)
				continue
			}
		}
		filtered := strings.HasSuffix(lines[k], " ok")
		if filtered != want {
			t.Errorf("%s: under the filter ok=%v, expected %v because %s (child: %q)", p.name, filtered, want, why, lines[k])
			continue
		}
		t.Logf("%s: ok unfiltered, ok=%v under the filter (%s)", p.name, filtered, why)
	}
}

// TestStraceChildAllowed pins the strace row's expectation per release,
// either side of straceSelfProbeRelease, and the `strace -V` parse; under
// the strace switch's profile every release is allowed.
func TestStraceChildAllowed(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want bool
	}{
		{"strace -- version 5.5\nCopyright", true},
		{"strace -- version 6.8\n", true},
		{"strace -- version 6.13\n", true},
		{"strace -- version 6.14\n", false},
		{"strace -- version 6.19\n", false},
		{"strace -- version 7.0\n", false},
	} {
		major, minor, ok := parseStraceRelease(tc.out)
		if !ok {
			t.Fatalf("%q: no release parsed", tc.out)
		}
		got, why, err := straceChildAllowed(major, minor)
		if err != nil || got != tc.want || why == "" {
			t.Errorf("%q: allowed=%v (%q, %v), want %v", tc.out, got, why, err, tc.want)
		}
		if got, why, err := straceSeizeAllowed(major, minor); err != nil || !got || why == "" {
			t.Errorf("%q with the strace switch: allowed=%v (%q, %v), want true", tc.out, got, why, err)
		}
	}
	if _, _, ok := parseStraceRelease("strace: unknown"); ok {
		t.Error("a release was parsed from output that names none")
	}
}
