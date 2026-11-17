//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxseccomp"
)

// sandbox_seccomp_linux.go loads and reads back the seccomp filter of the
// bwrap and process_lite rows (gap G16, lane N2). The program and the
// read-back verdict are internal/sandboxseccomp's; this file owns the
// syscalls and the /proc reads.
//
// bwrap: the host helper builds the program, hands it to bwrap on
// sandbox.SeccompFD (bwrap's own --seccomp, which bwrap loads right before
// it execs the inner argv), and after the start gate releases the box it
// reads the status of bwrap's descendants until one shows the filter.
// process_lite: the exec step loads the program itself after no_new_privs
// (with SECCOMP_FILTER_FLAG_TSYNC, so every thread and the exec'd agent
// carry it), reads its own status back, and the host helper reads the held
// step's status before it releases the start gate. Either read failing
// refuses the run.

// seccompReadBackTimeout bounds the wait for the filter to show (a variable
// so tests can shorten it).
var seccompReadBackTimeout = 3 * time.Second

// errSeccompTreeEnded means every process the read-back could look at ended
// before it was read: the run is over and its own exit status stands.
var errSeccompTreeEnded = errors.New("the launched processes ended before the seccomp read-back")

// loadSeccomp loads prog for this process: every thread now (TSYNC) and
// whatever it execs. no_new_privs must already be set (the kernel refuses
// an unprivileged filter otherwise).
func loadSeccomp(prog sandboxseccomp.Program) error {
	if len(prog) == 0 {
		return errors.New("an empty seccomp program")
	}
	filters := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filters[i] = unix.SockFilter{Code: in.Code, Jt: in.JT, Jf: in.JF, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}                                                                      //nolint:gosec // G115: the assembler caps a program at 4096 instructions
	r, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog))) //nolint:gosec // G103: the uapi struct
	runtime.KeepAlive(filters)
	if errno != 0 {
		return fmt.Errorf("seccomp(SET_MODE_FILTER, TSYNC): %w", errno)
	}
	if r != 0 {
		return fmt.Errorf("seccomp(SET_MODE_FILTER, TSYNC): thread %d could not be synchronized", r)
	}
	return nil
}

// readSeccompStatus reads one process's seccomp lines ("self" or a pid).
func readSeccompStatus(who string) (sandboxseccomp.Status, error) {
	b, err := os.ReadFile(filepath.Join("/proc", who, "status")) //nolint:gosec // G304: a /proc path of this process or a pid this helper started
	if err != nil {
		return sandboxseccomp.Status{}, err
	}
	return sandboxseccomp.ParseStatus(string(b)), nil
}

// applySeccompSelf builds profile, loads it into this process and reads
// /proc/self/status back against the status before the load. Any failure
// is returned; the caller refuses the exec.
func applySeccompSelf(profile string) error {
	prog, err := sandboxseccomp.Build(sandboxseccomp.ProfileID(profile), runtime.GOARCH)
	if err != nil {
		return err
	}
	before, err := readSeccompStatus("self")
	if err != nil {
		return fmt.Errorf("read the seccomp state before the filter: %w", err)
	}
	if err := loadSeccomp(prog); err != nil {
		return err
	}
	after, err := readSeccompStatus("self")
	if err != nil {
		return fmt.Errorf("read the seccomp state back: %w", err)
	}
	return sandboxseccomp.ReadBack(before, after)
}

// hostSeccomp is the host helper's part of a launch's filter: the program
// it hands bwrap and the read-back of its child.
type hostSeccomp struct {
	profile string
	// gated: the child is a gated observer helper that loads the filter
	// itself (the process_lite exec step).
	gated bool
	// r is the program's read end, bwrap's SeccompFD (nil when the helper
	// hands nothing).
	r *os.File
	// self is the helper's own seccomp state, the read-back's baseline.
	self sandboxseccomp.Status
}

// newHostSeccomp checks the helper's command against its --seccomp-profile
// and, for a bwrap child, builds the program into a pipe. A bwrap command
// whose --seccomp disagrees with the profile (one without the other, or
// another descriptor) is refused: bwrap would read a descriptor nobody
// filled, or run unfiltered.
func newHostSeccomp(h sandbox.HostArgs) (*hostSeccomp, error) {
	_, gated := gatedHelperFor(h.Command)
	sc := &hostSeccomp{profile: h.SeccompProfile, gated: gated}
	if !gated {
		fd, found, err := sandbox.BwrapSeccompFD(h.Command)
		// An option the scan does not know matters only when a profile is
		// planned (audit N2-A11): without one, nothing is handed to bwrap
		// and a --seccomp past it would read an empty descriptor and fail.
		if errors.Is(err, sandbox.ErrBwrapFlagUnknown) && h.SeccompProfile == "" {
			err = nil
		}
		if err != nil {
			return nil, fmt.Errorf("seccomp: %w", err)
		}
		switch {
		case h.SeccompProfile == "" && found:
			return nil, errors.New("seccomp: the sandbox command asks for a seccomp program but no profile was planned")
		case h.SeccompProfile != "" && (!found || fd != sandbox.SeccompFD):
			return nil, fmt.Errorf("seccomp: profile %s was planned but the sandbox command does not read it from descriptor %d", h.SeccompProfile, sandbox.SeccompFD)
		}
	}
	if h.SeccompProfile == "" {
		return sc, nil
	}
	// The strace opt-in's second look (lane ptrace, PT-96): a profile that
	// lifts PTRACE_SEIZE needs its containment ground to hold now, or the
	// launch is refused before the box starts.
	if err := checkSeizeGround(h.SeccompProfile, h.Command, gated); err != nil {
		return nil, fmt.Errorf("seccomp: %w", err)
	}
	self, err := readSeccompStatus("self")
	if err != nil {
		return nil, fmt.Errorf("seccomp: read the host helper's own state: %w", err)
	}
	// A host whose read-back could never pass is refused here, before the
	// box starts (audit N2-A6): the bwrap read-back runs after the release,
	// so a refusal there ends an agent that already started.
	if err := sandboxseccomp.Preflight(self); err != nil {
		return nil, fmt.Errorf("seccomp: %w", err)
	}
	sc.self = self
	if gated {
		return sc, nil
	}
	prog, err := sandboxseccomp.Build(sandboxseccomp.ProfileID(h.SeccompProfile), runtime.GOARCH)
	if err != nil {
		return nil, fmt.Errorf("seccomp: %w", err)
	}
	b := prog.Bytes()
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("seccomp: %w", err)
	}
	// The program is small (a few hundred bytes, under any pipe's buffer),
	// so it is written whole before bwrap starts; bwrap reads to EOF.
	_, werr := w.Write(b)
	if cerr := w.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = r.Close()
		return nil, fmt.Errorf("seccomp: write the program: %w", werr)
	}
	sc.r = r
	return sc, nil
}

// checkSeizeGround re-checks the containment ground a profile lifting
// PTRACE_SEIZE names: for the pid-namespace ground, the bwrap command must
// carry --unshare-pid (a gated child, the process_lite exec step, has no
// pid namespace of its own); for the Yama ground, ptrace_scope must read 1
// or more now. Any other profile passes.
func checkSeizeGround(profile string, command []string, gated bool) error {
	id := sandboxseccomp.ProfileID(profile)
	if _, ok := sandboxseccomp.SeizeGroundOf(id); !ok {
		return nil
	}
	var f sandboxseccomp.SeizeFacts
	if !gated {
		own, err := sandbox.BwrapUnsharesPID(command)
		if err != nil {
			return err
		}
		f.OwnPIDNamespace = own
	}
	f.YamaScope, f.YamaKnown = readYamaScope()
	return sandboxseccomp.CheckSeizeGround(id, f)
}

// files appends the program's read end to the child's ExtraFiles, so it
// lands on sandbox.SeccompFD (base is the start gate's fd 3 and fd 4).
func (sc *hostSeccomp) files(base []*os.File) []*os.File {
	if sc.r == nil {
		return base
	}
	return append(append([]*os.File(nil), base...), sc.r)
}

// beforeRelease reads back a gated child held on the start gate (it loads
// the filter before it waits). nil when no profile was planned or the
// child is bwrap (read after the release instead).
func (sc *hostSeccomp) beforeRelease(pid int) error {
	if sc.profile == "" || !sc.gated {
		return nil
	}
	return sc.waitReadBack(pid, func() []int { return []int{pid} })
}

// afterRelease reads back a bwrap launch once released: bwrap loads the
// filter in the process that execs the inner argv, a descendant of bwrap.
func (sc *hostSeccomp) afterRelease(pid int) error {
	if sc.profile == "" || sc.gated {
		return nil
	}
	return sc.waitReadBack(pid, func() []int { return descendantsOf(pid, readProcStats()) })
}

// release wraps the start gate's release with the read-backs: a gated child
// is read before the gate opens, a bwrap child after (bwrap loads the filter
// only once released). A tree that ended before it could be read is not a
// refusal: the run is over and its own exit status stands. One call site in
// the host helper's release closure (audit N2-A4: the N1-owned file keeps a
// one-line hunk there).
func (sc *hostSeccomp) release(pid int, open func() error) error {
	if err := sc.beforeRelease(pid); err != nil && !errors.Is(err, errSeccompTreeEnded) {
		return err
	}
	if err := open(); err != nil {
		return err
	}
	if err := sc.afterRelease(pid); err != nil && !errors.Is(err, errSeccompTreeEnded) {
		return err
	}
	return nil
}

// waitReadBack polls the candidates until one carries the filter (nil),
// root and every candidate are gone (errSeccompTreeEnded, nothing to
// refuse), or the wait times out (the last verdict, a refusal). For bwrap
// this runs after the release, so the agent may already have started when
// a refusal kills it (up to seccompReadBackTimeout). The states a host can
// never pass are refused before the launch by sandboxseccomp.Preflight
// (audit N2-A6), so a post-start refusal is a filter measured absent, or
// a status that could not be read at all (fail closed, named apart). bwrap
// itself exits rather than run its argv when it cannot load the program,
// so the window matters only for a refusal of a run bwrap did filter. A
// count above the helper's says a filter was added, not which one; a tool
// that loaded its own filter could satisfy it, but bwrap loads Observer's
// before it execs the tool, so the tool's own would come on top of it.
func (sc *hostSeccomp) waitReadBack(root int, candidates func() []int) error {
	deadline := time.Now().Add(seccompReadBackTimeout)
	last := errors.New("no process to read")
	// measured: at least one status was read and judged, so a timeout is a
	// measured mismatch, not a read that could not happen.
	measured := false
	for {
		pids := candidates()
		alive := 0
		for _, p := range pids {
			st, err := readSeccompStatus(strconv.Itoa(p))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			alive++
			if err != nil {
				last = err
				continue
			}
			measured = true
			if last = sandboxseccomp.ReadBack(sc.self, st); last == nil {
				return nil
			}
		}
		if alive == 0 && !procAlive(root) {
			return errSeccompTreeEnded
		}
		if time.Now().After(deadline) {
			if !measured {
				return fmt.Errorf("built_below_plan: the seccomp filter (profile %s) could not be read on any launched process within %s (no /proc status was readable, so nothing was measured): %w", sc.profile, seccompReadBackTimeout, last)
			}
			return fmt.Errorf("built_below_plan: the seccomp filter (profile %s) was measured absent on the launched process within %s: %w", sc.profile, seccompReadBackTimeout, last)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// procAlive reports whether pid still has a /proc entry that is not a
// zombie.
func procAlive(pid int) bool {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status")) //nolint:gosec // G304: a /proc path of a pid this helper started
	if err != nil {
		return false
	}
	// The State line, read here rather than with the process_lite file's
	// helper, which a build without that driver omits.
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && k == "State" {
			v = strings.TrimSpace(v)
			return !strings.HasPrefix(v, "Z") && !strings.HasPrefix(v, "X")
		}
	}
	return true
}

// close drops the helper's copy of the program's read end.
func (sc *hostSeccomp) close() {
	if sc != nil && sc.r != nil {
		_ = sc.r.Close()
	}
}

// descendantsOf lists every process under root (not root itself), from the
// /proc stat parent links (the same scan the namespace re-check uses).
func descendantsOf(root int, stats map[int]string) []int {
	children := map[int][]int{}
	for n, line := range stats {
		if p, ok := statPPID(line); ok && n != p {
			children[p] = append(children[p], n)
		}
	}
	var out []int
	seen := map[int]bool{root: true}
	queue := []int{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, c := range children[p] {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
				queue = append(queue, c)
			}
		}
	}
	return out
}
