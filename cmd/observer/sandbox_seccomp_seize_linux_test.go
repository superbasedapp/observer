//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxseccomp"
)

// The kernel side of the strace opt-in (lane ptrace, PT-96): the requests
// strace's seize mode makes on its own tracee, measured under a profile that
// lifts PTRACE_SEIZE. Checked, not assumed: PTRACE_SEIZE is the only request
// the default profile denies that seize mode needs; the rest were never
// denied, process_vm_readv stays denied (strace falls back to
// PTRACE_PEEKDATA on its EPERM), and PTRACE_ATTACH stays denied.

// The ptrace requests x/sys does not name on every release.
const (
	ptraceGetSyscallInfo = 0x420e // PTRACE_GET_SYSCALL_INFO (linux 5.3)
	ntPRStatus           = 1      // NT_PRSTATUS
)

// seizeRequest is one request of strace's seize mode on its own tracee.
type seizeRequest struct {
	name string
	// wantEPERM: the profile denies it (and strace copes); every other
	// request must not be refused with EPERM.
	wantEPERM bool
	// optional: a kernel too old for the request answers EIO or EINVAL,
	// which strace handles; only EPERM is a failure.
	optional bool
}

// seizeRequests are the rows, in the order the child runs them.
var seizeRequests = []seizeRequest{
	{name: "PTRACE_SEIZE"},
	{name: "PTRACE_INTERRUPT"},
	{name: "wait for the stop"},
	{name: "PTRACE_SETOPTIONS"},
	{name: "PTRACE_GETEVENTMSG"},
	{name: "PTRACE_GETREGSET"},
	{name: "PTRACE_GET_SYSCALL_INFO", optional: true},
	{name: "PTRACE_PEEKDATA"},
	{name: "process_vm_readv", wantEPERM: true},
	{name: "PTRACE_SYSCALL"},
	{name: "PTRACE_DETACH"},
	{name: "PTRACE_ATTACH", wantEPERM: true},
}

// strace's seize options (src/strace.c ptrace_setoptions plus TRACESYSGOOD).
const straceSeizeOptions = unix.PTRACE_O_TRACESYSGOOD | unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_TRACEEXIT |
	unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK

func ptraceRaw(req, pid int, addr, data uintptr) error {
	_, _, e := unix.Syscall6(unix.SYS_PTRACE, uintptr(req), uintptr(pid), addr, data, 0, 0) //nolint:gosec // G115: a child's pid and fixed requests
	return errnoErr(e)
}

// tracedTextAddr is the start of the tracee's first mapping, a readable
// address for PTRACE_PEEKDATA and process_vm_readv.
func tracedTextAddr(pid int) (uintptr, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "maps")) //nolint:gosec // G304: a /proc path of this test's own child
	if err != nil {
		return 0, err
	}
	start, _, _ := strings.Cut(string(b), "-")
	v, err := strconv.ParseUint(start, 16, 64)
	return uintptr(v), err
}

// seizeRequestsChild runs strace's seize-mode requests on a child it starts
// and prints "<index> <result>" per request; filtered loads the seize
// profile first. It exits; it never returns.
func seizeRequestsChild(filtered bool) {
	runtime.LockOSThread()
	if filtered {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			os.Stdout.WriteString("SKIP no_new_privs: " + err.Error() + "\n")
			os.Exit(0)
		}
		if err := applySeccompSelf(string(sandboxseccomp.ProfileObserverSeizeYama)); err != nil {
			os.Stdout.WriteString("SKIP load: " + err.Error() + "\n")
			os.Exit(0)
		}
	}
	tracee := exec.Command("sleep", "30")
	if err := tracee.Start(); err != nil {
		os.Stdout.WriteString("SKIP sleep: " + err.Error() + "\n")
		os.Exit(0)
	}
	pid := tracee.Process.Pid
	var b strings.Builder
	report := func(i int, err error) {
		b.WriteString(strconv.Itoa(i) + " " + errString(err) + "\n")
	}
	stop := func() error {
		var ws unix.WaitStatus
		if _, err := unix.Wait4(pid, &ws, unix.WALL, nil); err != nil {
			return err
		}
		if !ws.Stopped() {
			return errors.New("not stopped")
		}
		return nil
	}
	addr, aerr := tracedTextAddr(pid)
	for i, r := range seizeRequests {
		var err error
		switch r.name {
		case "PTRACE_SEIZE":
			err = ptraceRaw(unix.PTRACE_SEIZE, pid, 0, straceSeizeOptions)
		case "PTRACE_INTERRUPT":
			err = ptraceRaw(unix.PTRACE_INTERRUPT, pid, 0, 0)
		case "wait for the stop":
			err = stop()
		case "PTRACE_SETOPTIONS":
			err = ptraceRaw(unix.PTRACE_SETOPTIONS, pid, 0, straceSeizeOptions)
		case "PTRACE_GETEVENTMSG":
			_, err = unix.PtraceGetEventMsg(pid)
		case "PTRACE_GETREGSET":
			buf := make([]byte, 4096)
			iov := unix.Iovec{Base: &buf[0]}
			iov.SetLen(len(buf))
			err = ptraceRaw(unix.PTRACE_GETREGSET, pid, ntPRStatus, uintptr(unsafe.Pointer(&iov))) //nolint:gosec // G103: the uapi iovec
			runtime.KeepAlive(buf)
		case "PTRACE_GET_SYSCALL_INFO":
			buf := make([]byte, 128)
			err = ptraceRaw(ptraceGetSyscallInfo, pid, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0]))) //nolint:gosec // G103: the uapi buffer
			runtime.KeepAlive(buf)
		case "PTRACE_PEEKDATA":
			if err = aerr; err == nil {
				_, err = unix.PtracePeekData(pid, addr, make([]byte, 8))
			}
		case "process_vm_readv":
			if err = aerr; err == nil {
				buf := make([]byte, 8)
				local := unix.Iovec{Base: &buf[0]}
				local.SetLen(len(buf))
				remote := unix.RemoteIovec{Base: addr, Len: len(buf)}
				_, err = unix.ProcessVMReadv(pid, []unix.Iovec{local}, []unix.RemoteIovec{remote}, 0)
			}
		case "PTRACE_SYSCALL":
			if err = ptraceRaw(unix.PTRACE_SYSCALL, pid, 0, 0); err == nil {
				// Stop it again (a syscall stop or the interrupt's), so the
				// detach below finds it stopped.
				if err = ptraceRaw(unix.PTRACE_INTERRUPT, pid, 0, 0); err == nil {
					err = stop()
				}
			}
		case "PTRACE_DETACH":
			err = ptraceRaw(unix.PTRACE_DETACH, pid, 0, 0)
		case "PTRACE_ATTACH":
			// The same child, now untraced: PTRACE_ATTACH stays denied under
			// the seize profile. Unfiltered it succeeds; detach again.
			if err = ptraceRaw(unix.PTRACE_ATTACH, pid, 0, 0); err == nil {
				_ = stop()
				_ = ptraceRaw(unix.PTRACE_DETACH, pid, 0, 0)
			}
		}
		report(i, err)
	}
	os.Stdout.WriteString(b.String())
	_ = tracee.Process.Kill()
	_, _ = tracee.Process.Wait()
	os.Exit(0)
}

// runSeizeRequests runs the child in mode and returns one result per row.
func runSeizeRequests(t *testing.T, mode string) ([]string, bool) {
	t.Helper()
	cmd, out := startSeccompChild(t, "TestSeccompKernelSeizeRequests", mode)
	b, rerr := io.ReadAll(out)
	err := cmd.Wait()
	got := string(b)
	if strings.HasPrefix(got, "SKIP") {
		t.Skipf("%s: %s", mode, strings.TrimSpace(got))
		return nil, false
	}
	if rerr != nil || err != nil {
		t.Fatalf("%s child: %v %v: %s", mode, rerr, err, got)
	}
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != len(seizeRequests) {
		t.Fatalf("%s child printed %d lines, want %d: %q", mode, len(lines), len(seizeRequests), got)
	}
	res := make([]string, len(lines))
	for i, l := range lines {
		_, res[i], _ = strings.Cut(l, " ")
	}
	return res, true
}

// TestSeccompKernelSeizeRequests runs strace's seize-mode requests on a
// child, unfiltered (the baseline: a host whose ptrace is closed anyway,
// Yama 2 or 3 or a container, skips) and under a seize profile, and checks
// each against its row.
func TestSeccompKernelSeizeRequests(t *testing.T) {
	switch os.Getenv(envSeccompChild) {
	case "seize-unfiltered":
		seizeRequestsChild(false)
	case "seize-filtered":
		seizeRequestsChild(true)
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("the seccomp assembler targets amd64 and arm64")
	}
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("no sleep to trace")
	}
	base, ok := runSeizeRequests(t, "seize-unfiltered")
	if !ok {
		return
	}
	if base[0] != "allowed" {
		t.Skipf("PTRACE_SEIZE of a child fails here even unfiltered (%s): ptrace is closed on this host", base[0])
	}
	got, ok := runSeizeRequests(t, "seize-filtered")
	if !ok {
		return
	}
	eperm := unix.EPERM.Error()
	for i, r := range seizeRequests {
		switch {
		case r.wantEPERM:
			if got[i] != eperm {
				t.Errorf("%s under the seize profile: %s, want EPERM (unfiltered: %s)", r.name, got[i], base[i])
			}
		case got[i] == eperm:
			t.Errorf("%s under the seize profile: EPERM, strace's seize mode needs it (unfiltered: %s)", r.name, base[i])
		case got[i] != base[i] && !r.optional:
			t.Errorf("%s under the seize profile: %s, unfiltered %s", r.name, got[i], base[i])
		}
		t.Logf("%s: unfiltered %s, seize profile %s", r.name, base[i], got[i])
	}
}

// TestBwrapWrapArgvSeize (lane ptrace) composes a bwrap launch whose run
// recorded the pid-namespace seize profile: the host helper names it, the
// bwrap command gives the box its own pid namespace, and the host helper
// accepts it; the same record with the opt-in off plans observer_default.
func TestBwrapWrapArgvSeize(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("the seccomp assembler targets amd64 and arm64")
	}
	stubYamaScope(t, 0, true)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "bwrap"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306: a test stand-in that must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, c := range []struct {
		optIn bool
		want  string
	}{{true, "observer_seize_pidns"}, {false, "observer_default"}} {
		home := t.TempDir()
		setTestHome(t, home)
		if real, err := filepath.EvalSymlinks(home); err == nil {
			home = real
		}
		_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
		ws := filepath.Join(home, "proj")
		_ = os.MkdirAll(ws, 0o700)
		cfg := config.Default()
		cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
		cfg.Terminal.Sandbox.Enabled = true
		cfg.Terminal.Sandbox.Seccomp = true
		cfg.Terminal.Sandbox.SeccompAllowSeize = c.optIn
		exe, _ := os.Executable()
		rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, filepath.Join(home, ".observer"), exe, nil)
		if err != nil {
			t.Fatal(err)
		}
		rt.applyDaemonConfig(cfg)
		wrap, err := rt.buildWrapArgv("claude-code", ws, "runbwrapseize000001", true, "observer_seize_pidns")
		if err != nil {
			t.Fatal(err)
		}
		i := slices.Index(wrap, sandbox.HostVerb)
		if i < 0 {
			t.Fatalf("no host helper in %v", wrap)
		}
		host, err := sandbox.ParseHostArgs(wrap[i+1:])
		if err != nil {
			t.Fatal(err)
		}
		if host.SeccompProfile != c.want {
			t.Fatalf("opt-in %v: host profile %q, want %q", c.optIn, host.SeccompProfile, c.want)
		}
		if own, err := sandbox.BwrapUnsharesPID(host.Command); err != nil || !own {
			t.Fatalf("the bwrap command gives no pid namespace of its own (%v): %v", err, host.Command)
		}
		sc, err := newHostSeccomp(host)
		if err != nil {
			t.Fatalf("opt-in %v: the host helper refuses the planned command: %v", c.optIn, err)
		}
		sc.close()
	}
}
