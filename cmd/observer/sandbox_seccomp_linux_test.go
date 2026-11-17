//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxseccomp"
)

// envSeccompChild turns the test binary into a seccomp child: it loads the
// filter (after no_new_privs) and either probes denied syscalls or holds.
const envSeccompChild = "OBSERVER_TEST_SECCOMP_CHILD"

// seccompProbes are denied syscalls called with arguments that have no
// side effect; most fail with something other than EPERM unfiltered, so
// the filter's EPERM is visible.
var seccompProbes = []struct {
	name string
	call func() error
}{
	{"keyctl", func() error {
		_, _, e := unix.Syscall(unix.SYS_KEYCTL, unix.KEYCTL_GET_KEYRING_ID, uintptr(0xfffffffd), 0) //nolint:gosec // G115: KEY_SPEC_SESSION_KEYRING (-3)
		return errnoErr(e)
	}},
	{"io_uring_setup", func() error {
		_, _, e := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, 0, 0)
		return errnoErr(e)
	}},
	{"name_to_handle_at", func() error {
		_, _, err := unix.NameToHandleAt(unix.AT_FDCWD, "/", 0)
		return err
	}},
	{"bpf", func() error {
		_, _, e := unix.Syscall(unix.SYS_BPF, 0, 0, 0)
		return errnoErr(e)
	}},
	{"ptrace attach", func() error {
		_, _, e := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_ATTACH, uintptr(1<<22), 0, 0, 0, 0)
		return errnoErr(e)
	}},
	{"mount", func() error { return unix.Mount("none", "/nonexistent-observer-n2", "tmpfs", 0, "") }},
	// Audit N2-A7 (lane FU4): the non-ptrace routes into another process.
	// Unfiltered they fail ESRCH (no such pid) and EBADF (no such pidfd).
	{"process_vm_readv", func() error {
		_, _, e := unix.Syscall6(unix.SYS_PROCESS_VM_READV, uintptr(1<<22), 0, 0, 0, 0, 0)
		return errnoErr(e)
	}},
	{"pidfd_getfd", func() error {
		_, _, e := unix.Syscall(unix.SYS_PIDFD_GETFD, ^uintptr(0), 0, 0)
		return errnoErr(e)
	}},
}

// seccompChildMain is the child's body, run from the test it was re-exec'd
// for. It exits; it never returns.
func seccompChildMain(mode string) {
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		os.Stdout.WriteString("SKIP no_new_privs: " + err.Error() + "\n")
		os.Exit(0)
	}
	before := make([]error, len(seccompProbes))
	if mode == "probe" {
		for i, p := range seccompProbes {
			before[i] = p.call()
		}
	}
	if mode != "hold-unfiltered" {
		if err := applySeccompSelf(string(sandboxseccomp.ProfileObserverDefault)); err != nil {
			os.Stdout.WriteString("SKIP load: " + err.Error() + "\n")
			os.Exit(0)
		}
	}
	if strings.HasPrefix(mode, "hold") {
		os.Stdout.WriteString("READY\n")
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	var fails, shown []string
	for i, p := range seccompProbes {
		err := p.call()
		if !errors.Is(err, unix.EPERM) {
			fails = append(fails, p.name+": "+errString(err))
			continue
		}
		if !errors.Is(before[i], unix.EPERM) {
			shown = append(shown, p.name+" ("+errString(before[i])+" -> EPERM)")
		}
	}
	// Allowed syscalls still work.
	if unix.Getpid() <= 0 {
		fails = append(fails, "getpid")
	}
	if _, err := os.ReadFile("/proc/self/status"); err != nil {
		fails = append(fails, "read: "+err.Error())
	}
	if len(shown) < 2 {
		fails = append(fails, "fewer than two probes changed to EPERM under the filter: "+strings.Join(shown, ", "))
	}
	if len(fails) > 0 {
		os.Stdout.WriteString("FAIL " + strings.Join(fails, "; ") + "\n")
		os.Exit(1)
	}
	os.Stdout.WriteString("OK " + strings.Join(shown, ", ") + "\n")
	os.Exit(0)
}

func errnoErr(e unix.Errno) error {
	if e == 0 {
		return nil
	}
	return e
}

func errString(err error) string {
	if err == nil {
		return "allowed"
	}
	return err.Error()
}

// startSeccompChild re-execs the test binary as a seccomp child in mode.
// Its stdout comes back as the pipe itself (no buffer the exec copy
// goroutine writes while the test reads); read it before cmd.Wait.
func startSeccompChild(t *testing.T, test, mode string) (*exec.Cmd, io.Reader) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.count=1") //nolint:gosec // G204: the test binary itself
	cmd.Env = append(os.Environ(), envSeccompChild+"="+mode)
	cmd.Stderr = io.Discard
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return cmd, out
}

// TestSeccompKernelEPERM loads the profile in a re-exec'd child and shows
// each denied syscall fails with EPERM while ordinary ones still work.
func TestSeccompKernelEPERM(t *testing.T) {
	if m := os.Getenv(envSeccompChild); m != "" {
		seccompChildMain(m)
	}
	cmd, out := startSeccompChild(t, "TestSeccompKernelEPERM", "probe")
	b, rerr := io.ReadAll(out)
	err := cmd.Wait()
	got := string(b)
	if strings.HasPrefix(got, "SKIP") {
		t.Skipf("this kernel or sandbox refuses an unprivileged seccomp filter: %s", strings.TrimSpace(got))
	}
	if rerr != nil || err != nil || !strings.HasPrefix(got, "OK") {
		t.Fatalf("child: %v %v: %s", rerr, err, got)
	}
	t.Log(strings.TrimSpace(got))
}

// waitReady waits for the child's READY line (or a SKIP). The one reader
// goroutine owns the pipe and hands the finished line over a channel.
func waitReady(t *testing.T, out io.Reader) string {
	t.Helper()
	ch := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(out).ReadString('\n')
		ch <- line
	}()
	select {
	case s := <-ch:
		if !strings.HasSuffix(s, "\n") {
			t.Fatalf("the child ended before it became ready: %q", s)
		}
		return s
	case <-time.After(10 * time.Second):
		t.Fatal("the child never became ready")
		return ""
	}
}

// TestHostSeccompReadBackHeldChild reads back a gated child that holds with
// the filter loaded (matched) and one that holds without it (refused).
func TestHostSeccompReadBackHeldChild(t *testing.T) {
	if m := os.Getenv(envSeccompChild); m != "" {
		seccompChildMain(m)
	}
	old := seccompReadBackTimeout
	seccompReadBackTimeout = 500 * time.Millisecond
	t.Cleanup(func() { seccompReadBackTimeout = old })
	self, err := readSeccompStatus("self")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		mode    string
		matched bool
	}{{"hold", true}, {"hold-unfiltered", false}} {
		cmd, out := startSeccompChild(t, "TestHostSeccompReadBackHeldChild", c.mode)
		line := waitReady(t, out)
		if strings.HasPrefix(line, "SKIP") {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Skipf("this kernel or sandbox refuses an unprivileged seccomp filter: %s", strings.TrimSpace(line))
		}
		sc := &hostSeccomp{profile: string(sandboxseccomp.ProfileObserverDefault), gated: true, self: self}
		err := sc.beforeRelease(cmd.Process.Pid)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if c.matched && err != nil {
			t.Fatalf("%s: %v", c.mode, err)
		}
		if !c.matched && (err == nil || !strings.Contains(err.Error(), "built_below_plan")) {
			t.Fatalf("%s: got %v, want a refusal", c.mode, err)
		}
		// A bwrap launch reads back after the release instead.
		if err := sc.afterRelease(cmd.Process.Pid); err != nil {
			t.Fatalf("a gated child is never read after the release: %v", err)
		}
	}
}

// TestHostSeccompEndedChild: a child that ended before the read-back is not
// a refusal (its own exit status stands).
func TestHostSeccompEndedChild(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Skip("no true(1)")
	}
	sc := &hostSeccomp{profile: "observer_default", gated: true}
	if err := sc.beforeRelease(cmd.Process.Pid); !errors.Is(err, errSeccompTreeEnded) {
		t.Fatalf("got %v", err)
	}
}

// TestNewHostSeccomp is the host helper's consistency table: the profile
// flag and bwrap's --seccomp go together, on sandbox.SeccompFD.
func TestNewHostSeccomp(t *testing.T) {
	stubYamaScope(t, 1, true)
	bw := func(extra ...string) []string {
		return append(append([]string{"/usr/bin/bwrap", "--ro-bind", "/", "/"}, extra...), "--", "observer", "claude")
	}
	// The gated verb of the process_lite driver, when this build has it.
	const gatedVerb = "sandbox-landlock-exec"
	_, haveGated := sandboxGatedHelpers[gatedVerb]
	gated := []string{"/o/observer", gatedVerb, "--plan", "/p", "--", "observer", "claude"}
	for _, c := range []struct {
		name    string
		profile string
		cmd     []string
		wantErr bool
		pipe    bool
	}{
		{"off, plain bwrap", "", bw(), false, false},
		{"off, bwrap asks for a program", "", bw("--seccomp", "5"), true, false},
		{"on, bwrap reads fd 5", "observer_default", bw("--seccomp", "5"), false, true},
		{"on, bwrap without --seccomp", "observer_default", bw(), true, false},
		{"on, bwrap reads another fd", "observer_default", bw("--seccomp", "6"), true, false},
		{"on, unknown profile", "nope", bw("--seccomp", "5"), true, false},
		{"off, an option the scan does not know", "", bw("--frobnicate"), false, false},
		{"on, an option the scan does not know", "observer_default", bw("--frobnicate", "--seccomp", "5"), true, false},
		// Audit FU4-A7: with the key off, an option the scan does not know
		// hides a later --seccomp from it, so the launch is not refused here;
		// but no program is handed over (no extra file, so descriptor 5 is
		// not open in bwrap), and bwrap then fails reading --seccomp 5 and
		// never runs the command, filtered or not. pipe=false pins that
		// nothing lands on the descriptor.
		{"off, an unknown option hides --seccomp: nothing on fd 5", "", bw("--frobnicate", "--seccomp", "5"), false, false},
		{"on, gated helper", "observer_default", gated, false, false},
		{"off, gated helper", "", gated, false, false},
		// The strace opt-in (lane ptrace): a seize profile needs its ground
		// to hold here (Yama reads 1 in this table, see below).
		{"seize on a pid namespace, bwrap unshares pid", "observer_seize_pidns", bw("--unshare-pid", "--seccomp", "5"), false, true},
		{"seize on a pid namespace, bwrap without --unshare-pid", "observer_seize_pidns", bw("--seccomp", "5"), true, false},
		{"seize on a pid namespace, --unshare-pid only as an operand", "observer_seize_pidns", bw("--setenv", "X", "--unshare-pid", "--seccomp", "5"), true, false},
		{"seize on a pid namespace, gated helper (no pid namespace)", "observer_seize_pidns", gated, true, false},
		{"seize on Yama, gated helper", "observer_seize_yama", gated, false, false},
		{"seize on Yama, bwrap", "observer_seize_yama", bw("--seccomp", "5"), false, true},
	} {
		if c.cmd[1] == gatedVerb && !haveGated {
			continue
		}
		sc, err := newHostSeccomp(sandbox.HostArgs{SeccompProfile: c.profile, Command: c.cmd})
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err %v", c.name, err)
			continue
		}
		if err != nil {
			continue
		}
		files := sc.files([]*os.File{os.Stdin, os.Stdin})
		if c.pipe != (len(files) == 3) {
			t.Errorf("%s: %d extra files", c.name, len(files))
		}
		if c.pipe {
			got, rerr := io.ReadAll(sc.r)
			want, _ := sandboxseccomp.Build(sandboxseccomp.ProfileID(c.profile), runtime.GOARCH)
			if rerr != nil || !bytes.Equal(got, want.Bytes()) {
				t.Errorf("%s: the pipe holds %d bytes, want the %d-byte program (%v)", c.name, len(got), len(want.Bytes()), rerr)
			}
		}
		sc.close()
	}
}

// TestNewHostSeccompSeizeYamaLost: a profile lifting PTRACE_SEIZE on the
// Yama ground is refused before the box starts when ptrace_scope reads 0 or
// cannot be read (lane ptrace, fail closed).
func TestNewHostSeccompSeizeYamaLost(t *testing.T) {
	const gatedVerb = "sandbox-landlock-exec"
	if _, ok := sandboxGatedHelpers[gatedVerb]; !ok {
		t.Skip("this build has no process_lite exec step")
	}
	gated := []string{"/o/observer", gatedVerb, "--plan", "/p", "--", "observer", "claude"}
	for _, c := range []struct {
		scope int
		known bool
	}{{0, true}, {0, false}} {
		stubYamaScope(t, c.scope, c.known)
		if _, err := newHostSeccomp(sandbox.HostArgs{SeccompProfile: "observer_seize_yama", Command: gated}); err == nil {
			t.Errorf("Yama %d (known %v): the seize profile was accepted", c.scope, c.known)
		}
		if _, err := newHostSeccomp(sandbox.HostArgs{SeccompProfile: "observer_default", Command: gated}); err != nil {
			t.Errorf("Yama %d (known %v): observer_default refused: %v", c.scope, c.known, err)
		}
	}
}

// TestDescendantsOf walks the /proc parent links breadth first.
func TestDescendantsOf(t *testing.T) {
	stats := map[int]string{
		10: "10 (bwrap) S 1 ...",
		11: "11 (bwrap) S 10 ...",
		12: "12 (observer x) S 11 ...",
		13: "13 (claude) S 12 ...",
		20: "20 (other) S 1 ...",
	}
	got := descendantsOf(10, stats)
	if len(got) != 3 || got[0] != 11 || got[1] != 12 || got[2] != 13 {
		t.Fatalf("got %v", got)
	}
	if got := descendantsOf(20, stats); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}
