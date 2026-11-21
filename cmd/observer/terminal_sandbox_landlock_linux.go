//go:build linux && !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxlandlock"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// terminal_sandbox_landlock_linux.go is the process_lite driver's Linux side
// (lane SBX-P3B): the probe's one fact (the kernel's Landlock ABI, read with
// landlock_create_ruleset and the VERSION flag), and the exec step that
// creates the run's TMPDIR, builds the ruleset from the plan file, applies
// it to itself (no_new_privs, then landlock_restrict_self), checks it and
// execs the agent. Built and unit-tested on Linux; its live proof on a 7.1+
// host is register entry LIN-1.

// init points the hook client inside a process_lite box at the run's own
// socket dir. The box shares the host's /tmp, so the box record cannot sit
// at the fixed guest path bwrap and a container use; the exec step names
// the dir in landlockEnvSocketDir, honoured only with the sandbox marker
// (an unsandboxed host process never carries it: isInternalChildEnv strips
// the marker from inherited environments).
func init() {
	if os.Getenv(sandboxEnvMarker) != "1" {
		return
	}
	d := os.Getenv(landlockEnvSocketDir)
	if d == "" || !filepath.IsAbs(d) || filepath.Clean(d) != d {
		return
	}
	boxSocketDir = d
	boxRecordPath = filepath.Join(d, sandboxrelayd.BoxRecordName)
	relaySpoolDir = filepath.Join(os.TempDir(), ".observer-relay-spool")
}

// init registers the exec step with the host helper's start gate (LIN-1
// F2): the gate's --block-fd goes after the verb, and the host helper's
// re-check of the held step is landlockRecheck.
func init() {
	sandboxGatedHelpers[landlockExecVerb] = sandboxGatedHelper{recheck: landlockRecheck, matched: landlockRecheckMatched}
}

// landlockRecheckMatched is the line a measured process_lite match prints.
const landlockRecheckMatched = "observer sandbox: the launch re-check found the process_lite exec step holding its ruleset (no_new_privs set) in the host's namespaces, as planned"

// The process_lite re-check's not-measured posture states.
const (
	// recheckStateLandlockNotReady: the held exec step did not set
	// no_new_privs in time.
	recheckStateLandlockNotReady = "recheck_landlock_not_ready"
	// recheckStateNNPInherited: the host helper itself already runs with
	// no_new_privs, so the child's flag proves nothing.
	recheckStateNNPInherited = "recheck_nnp_inherited"
)

// landlockRecheck is the host helper's re-check of a held process_lite exec
// step. The step applies its ruleset and passes its own self-test before it
// waits on the start gate, and it sets no_new_privs immediately before
// landlock_restrict_self (a failed restrict ends the step), so the held
// process must show NoNewPrivs 1, and it must share the helper's
// namespaces (process_lite plans none). A step that ended on its own
// returns errRecheckChildExited; what cannot be read is not measured, with
// its state named, as for bwrap.
func landlockRecheck(pid int) error {
	if self, err := os.ReadFile("/proc/self/status"); err == nil && procStatusField(string(self), "NoNewPrivs") == "1" {
		return fmt.Errorf("%w, state %s: the host helper already runs with no_new_privs", errRecheckNotMeasured, recheckStateNNPInherited)
	}
	deadline := time.Now().Add(recheckChildTimeout)
	status := filepath.Join("/proc", strconv.Itoa(pid), "status")
	for {
		b, err := os.ReadFile(status) //nolint:gosec // G304: a /proc path composed from a pid this helper started
		if errors.Is(err, fs.ErrNotExist) {
			return errRecheckChildExited
		}
		if err != nil {
			return fmt.Errorf("%w, state %s: exec step pid %d: %w", errRecheckNotMeasured, recheckStateUnreadable, pid, err)
		}
		if st := procStatusField(string(b), "State"); strings.HasPrefix(st, "Z") || strings.HasPrefix(st, "X") {
			return errRecheckChildExited
		}
		if procStatusField(string(b), "NoNewPrivs") == "1" {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w, state %s: the exec step pid %d did not set no_new_privs within %s", errRecheckNotMeasured, recheckStateLandlockNotReady, pid, recheckChildTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
	host, err := readNSLinks("self")
	if err != nil {
		return fmt.Errorf("%w, state %s: host: %w", errRecheckNotMeasured, recheckStateUnreadable, err)
	}
	inner, err := readNSLinks(strconv.Itoa(pid))
	if err != nil {
		return fmt.Errorf("%w, state %s: exec step pid %d: %w", errRecheckNotMeasured, recheckStateUnreadable, pid, err)
	}
	return landlockCompareNS(host, inner)
}

// landlockCompareNS refuses a held exec step whose namespace links differ
// from the host helper's: process_lite plans none, so a difference means
// the held process is not the planned build.
func landlockCompareNS(host, inner []string) error {
	if slices.Equal(host, inner) {
		return nil
	}
	for i := range host {
		if i >= len(inner) || host[i] != inner[i] {
			return fmt.Errorf("built_below_plan: the held process_lite exec step is not the planned build (its %s namespace differs from the host helper's)", recheckNamespaces[min(i, len(recheckNamespaces)-1)])
		}
	}
	return fmt.Errorf("built_below_plan: the held process_lite exec step is not the planned build (its namespaces differ from the host helper's)")
}

// procStatusField returns the value of one "Name:<tab>value" line of a
// /proc/<pid>/status text, "" when the line is missing.
func procStatusField(status, name string) string {
	for _, line := range strings.Split(status, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && k == name {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// landlockAwaitRelease blocks on the start gate (the host helper's
// --block-fd) until the release byte arrives, then closes the descriptor so
// the agent never inherits it. No byte (the helper closed the pipe, ended,
// or refused the launch) refuses the exec.
func landlockAwaitRelease(fd int) error {
	f := os.NewFile(uintptr(fd), "observer-start-gate") //nolint:gosec // G115: a small descriptor number
	if f == nil {
		return fmt.Errorf("the start gate descriptor %d is not open", fd)
	}
	defer func() { _ = f.Close() }()
	var b [1]byte
	n, err := f.Read(b[:])
	if n != 1 {
		return fmt.Errorf("the host helper did not release the launch (its re-check refused it, or it ended): %w", err)
	}
	return nil
}

// landlockABI reads the kernel's Landlock ABI version.
func landlockABI() (int, error) {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, errno
	}
	return int(v), nil //nolint:gosec // G115: a small ABI number
}

// landlockProbeEnv reads the probe's facts.
func landlockProbeEnv() sandboxlandlock.ProbeEnv {
	host := sandboxlandlock.HostLinux
	if sandboxHostKind() == sandboxbackend.HostWSL2 {
		// The probe names WSL2's ABI 7 when it refuses.
		host = sandboxlandlock.HostWSL2
	}
	return sandboxlandlock.ProbeEnv{Host: host, ABI: landlockABI}
}

// runLandlockExec is the exec step: `observer sandbox-landlock-exec --plan
// <file> -- <launch>`. Any failure before the exec refuses the launch; the
// agent never runs without the ruleset.
func runLandlockExec(args []string) int {
	gateFD, args, err := landlockExecGate(args)
	if err != nil {
		return helperFail("observer sandbox (process_lite): %v", err)
	}
	planPath, launch, err := parseLandlockExecArgs(args)
	if err != nil {
		return helperFail("observer sandbox (process_lite): %v", err)
	}
	plan, err := readLandlockPlan(planPath)
	_ = os.Remove(planPath) //nolint:gosec // G703: the plan file the daemon wrote for this run, read no-follow and owner-checked
	if err != nil {
		return helperFail("observer sandbox (process_lite): %v", err)
	}
	abi, err := landlockABI()
	if err != nil {
		return helperFail("observer sandbox (process_lite): %s: %v", sandboxlandlock.VerdictLandlockUnavailable, err)
	}
	if abi < plan.MinABI {
		return helperFail("observer sandbox (process_lite): %s: the kernel's ABI is %d, below %d", sandboxlandlock.VerdictLandlockABITooOld, abi, plan.MinABI)
	}
	in := plan.Plan
	in.ABI = abi
	if err := os.Mkdir(in.TempDir, 0o700); err != nil {
		return helperFail("observer sandbox (process_lite): create the run's TMPDIR: %v", err)
	}
	// The sockets the self-test must fail to reach, found before the
	// ruleset applies (audit SBX-P3B F2).
	targets, err := landlockConnectTargets(in.DaemonSockets, landlockEngineSockets(os.Getenv("XDG_RUNTIME_DIR")), landlockIsSocket)
	if err != nil {
		return helperFail("observer sandbox (process_lite): %s: %v", "built_below_plan", err)
	}
	rs, err := sandboxlandlock.BuildRuleset(in)
	if err != nil {
		return helperFail("observer sandbox (process_lite): %v", err)
	}
	// The ruleset applies to this thread and what it execs; keep the exec
	// on it.
	runtime.LockOSThread()
	if err := applyLandlock(rs); err != nil {
		return helperFail("observer sandbox (process_lite): %v", err)
	}
	// The seccomp filter, after no_new_privs (applyLandlock set it) and
	// before the self-tests, so they run under it as the agent will (lane
	// N2). It is read back from /proc/self/status here, and again by the
	// host helper on this held step.
	if plan.Seccomp != "" {
		if err := applySeccompSelf(plan.Seccomp); err != nil {
			return helperFail("observer sandbox (process_lite): %s: seccomp: %v", "built_below_plan", err)
		}
	}
	if err := landlockSelfTest(in.ObserverDir); err != nil {
		return helperFail("observer sandbox (process_lite): %s: %v", "built_below_plan", err)
	}
	if err := landlockCheckConnects(targets, landlockConnectFn); err != nil {
		return helperFail("observer sandbox (process_lite): %s: %v", "built_below_plan", err)
	}
	// Held until the host helper's re-check of this process releases it
	// (LIN-1 F2): the ruleset is applied and checked, the agent not started.
	if gateFD >= 0 {
		if err := landlockAwaitRelease(gateFD); err != nil {
			return helperFail("observer sandbox (process_lite): %v", err)
		}
	}
	env := landlockEnv(os.Environ(), in, plan.TempDirEnv)
	bin := launch[0]
	//nolint:gosec // G204: the planned inner launch (the observer launcher), never client input
	if err := syscall.Exec(bin, launch, env); err != nil {
		return helperFail("observer sandbox (process_lite): exec %s: %v", filepath.Base(bin), err)
	}
	return 0
}

// readLandlockPlan reads the plan file: owned by this user, no symlink,
// capped.
func readLandlockPlan(p string) (landlockPlanFile, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: the plan path the daemon composed
	if err != nil {
		return landlockPlanFile{}, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return landlockPlanFile{}, err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() || !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return landlockPlanFile{}, errors.New("the plan file is not a small regular file this user owns")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return landlockPlanFile{}, err
	}
	var plan landlockPlanFile
	if err := json.Unmarshal(b, &plan); err != nil {
		return landlockPlanFile{}, fmt.Errorf("landlock plan: %w", err)
	}
	if err := checkLandlockPlanVersion(plan); err != nil {
		return landlockPlanFile{}, err
	}
	return plan, nil
}

// landlockRulesetAttr is struct landlock_ruleset_attr (uapi).
type landlockRulesetAttr struct {
	handledFS  uint64
	handledNet uint64
	scoped     uint64
}

// landlockNetPortAttr is struct landlock_net_port_attr (uapi, ABI 4).
type landlockNetPortAttr struct {
	allowedAccess uint64
	port          uint64
}

// landlockRuleNetPort is LANDLOCK_RULE_NET_PORT (uapi).
const landlockRuleNetPort = 2

// applyLandlock creates the ruleset, adds every path and port rule, sets
// no_new_privs and restricts this thread. A required path that cannot be
// opened refuses; an optional one (a system tree this host lacks) is
// skipped.
func applyLandlock(rs sandboxlandlock.Ruleset) error {
	attr := landlockRulesetAttr{handledFS: rs.HandledFS, handledNet: rs.HandledNet, scoped: rs.Scoped}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0) //nolint:gosec // G103: the uapi struct
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	defer func() { _ = unix.Close(int(fd)) }() //nolint:gosec // G115: a descriptor
	for _, r := range rs.Paths {
		if r.Access == 0 {
			continue
		}
		pfd, err := unix.Open(r.Path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			if r.Optional {
				continue
			}
			return fmt.Errorf("open %s for its rule: %w", r.Path, err)
		}
		access := r.Access
		var st unix.Stat_t
		if unix.Fstat(pfd, &st) == nil && st.Mode&unix.S_IFMT != unix.S_IFDIR {
			// A file rule may carry only the file rights.
			access &= sandboxlandlock.AccessFSExecute | sandboxlandlock.AccessFSWriteFile | sandboxlandlock.AccessFSReadFile |
				sandboxlandlock.AccessFSTruncate | sandboxlandlock.AccessFSIoctlDev
		}
		pb := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(pfd)}                                                    //nolint:gosec // G115: a descriptor
		_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&pb)), 0, 0, 0) //nolint:gosec // G103: the uapi struct
		_ = unix.Close(pfd)
		if errno != 0 {
			return fmt.Errorf("landlock_add_rule %s: %w", r.Path, errno)
		}
	}
	for _, pr := range rs.Ports {
		for p := int(pr.Low); p <= int(pr.High); p++ {
			na := landlockNetPortAttr{allowedAccess: rs.HandledNet, port: uint64(p)}                                                 //nolint:gosec // G115: 1..65535
			_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, landlockRuleNetPort, uintptr(unsafe.Pointer(&na)), 0, 0, 0) //nolint:gosec // G103: the uapi struct
			if errno != 0 {
				return fmt.Errorf("landlock_add_rule port %d: %w", p, errno)
			}
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

// landlockSelfTest reads the ruleset back the only way a process can: the
// observer directory, which no rule grants, must now be unreadable. A
// kernel that accepted the rules but enforces nothing is refused here,
// before the agent starts.
func landlockSelfTest(observerDir string) error {
	f, err := os.Open(observerDir) //nolint:gosec // G304: the daemon's own observer dir, opened only to prove it is denied
	if err == nil {
		_ = f.Close()
		return fmt.Errorf("the observer directory %s is still readable under the ruleset", observerDir)
	}
	if !errors.Is(err, unix.EACCES) && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("the self-test could not tell: %w", err)
	}
	return nil
}

// landlockIsSocket reports whether p exists as a unix socket.
func landlockIsSocket(p string) bool {
	st, err := os.Lstat(p) //nolint:gosec // G703: a metadata read of a socket path from the run's own plan
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// landlockConnectFn connects a fresh unix stream socket to p and closes it:
// the self-test's syscall seam (a variable so a test can stand in for the
// kernel).
var landlockConnectFn = func(p string) error {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.Connect(fd, &unix.SockaddrUnix{Name: p})
}

// landlockEnv is the agent's environment: the helper's own, with the run's
// TMPDIR, its socket dir for the hook client and the sandbox marker, and
// every name in tempEnv (the tool's own temp-dir variables,
// sandboxenv.TempDirEnv) set to that TMPDIR: the ruleset grants no other
// temp folder (D-UC1).
func landlockEnv(environ []string, in sandboxlandlock.PlanInput, tempEnv []string) []string {
	// The allow-list first (WINFIX2, ledger SBX-WIN-ENV-1); the drops below stay.
	environ = sandboxBoxEnv("linux", environ)
	drop := map[string]bool{"TMPDIR": true, landlockEnvSocketDir: true, sandboxEnvMarker: true}
	out := make([]string, 0, len(environ)+3)
	for _, kv := range environ {
		if k, _, _ := strings.Cut(kv, "="); !drop[k] {
			out = append(out, kv)
		}
	}
	out = append(out, "TMPDIR="+in.TempDir, landlockEnvSocketDir+"="+in.SocketDir, sandboxEnvMarker+"=1")
	return sandboxenv.WithTempDir(out, tempEnv, in.TempDir)
}
