//go:build linux

package host

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// systemdRunPaths are the only places systemd-run is taken from: a fixed
// absolute path, never a PATH lookup (the runner's own rule).
var systemdRunPaths = []string{"/usr/bin/systemd-run", "/bin/systemd-run"}

// The host facts the cgroup sources read. Vars so a test can point them at
// a fixture.
var (
	systemdBootedPath = "/run/systemd/system"
	lookupEnv         = os.LookupEnv
	getuid            = os.Getuid
)

// cgroupSource is one row of the cgroup-source table: where a run's cgroup
// comes from, when that source is there, and how a run is set up under it.
type cgroupSource struct {
	name      string
	available func(e *Executor) bool
	setup     func(e *Executor, p extrun.Plan) (rungSetup, error)
}

// cgroupSources is walked top-down; the first available source is used.
var cgroupSources = []cgroupSource{
	{extrun.CgroupSourceConfigured, configuredAvailable, setupConfigured},
	{extrun.CgroupSourceUserScope, func(e *Executor) bool { return getuid() != 0 && scopeAvailable(e, true) }, setupScope},
	{extrun.CgroupSourceSystemScope, func(e *Executor) bool { return getuid() == 0 && scopeAvailable(e, false) }, setupScope},
}

// pickCgroupSource returns the first available cgroup source, or nil.
func (e *Executor) pickCgroupSource() *cgroupSource {
	if cgroup2Mount() == "" {
		return nil
	}
	for i := range cgroupSources {
		if cgroupSources[i].available(e) {
			return &cgroupSources[i]
		}
	}
	return nil
}

// containmentFacts resolves, at the boundary, which rungs this run could
// use. The cgroup rung needs the trampoline (it joins the cgroup before
// exec) and a cgroup source.
func (e *Executor) containmentFacts(p extrun.Plan, tramp bool) extrun.ContainmentFacts {
	return extrun.ContainmentFacts{
		Cgroup:       tramp && e.pickCgroupSource() != nil,
		PIDNamespace: p.PIDNamespace,
		ProcessGroup: true,
	}
}

// setupRung prepares one rung.
func (e *Executor) setupRung(r extrun.Rung, p extrun.Plan, tramp bool) (rungSetup, error) {
	switch r {
	case extrun.RungCgroup:
		src := e.pickCgroupSource()
		if src == nil {
			return rungSetup{}, errors.New("no cgroup v2 source is available")
		}
		s, err := src.setup(e, p)
		if err != nil {
			return rungSetup{}, err
		}
		s.mode = modeExec
		s.cont.CgroupSource = src.name
		if own, _ := ownCgroupDir(); own != "" {
			s.notUnder = own
		}
		return s, nil
	case extrun.RungProcessGroup:
		// The subreaper sweep needs the trampoline (the supervisor is this
		// binary in its supervise mode).
		if tramp {
			return rungSetup{mode: modeSupervise}, nil
		}
		return rungSetup{mode: modeExec}, nil
	default:
		return rungSetup{mode: modeExec}, nil
	}
}

// configuredAvailable: the operator's cgroup parent exists, is a cgroup v2
// directory, and this user may create children in it.
func configuredAvailable(e *Executor) bool {
	if e.CgroupParent == "" || !filepath.IsAbs(e.CgroupParent) {
		return false
	}
	if _, err := os.Stat(filepath.Join(e.CgroupParent, "cgroup.procs")); err != nil {
		return false
	}
	return unix.Access(e.CgroupParent, unix.W_OK) == nil
}

// randomName returns a short random name for a per-run cgroup or scope.
func randomName() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "sbo-extrun-" + hex.EncodeToString(b)
}

// setupConfigured creates the run's child cgroup under the configured
// parent and writes its caps. A write that fails is not an error here: the
// trampoline reads the cgroup back and falls back to the rlimits for any cap
// the cgroup does not carry.
func setupConfigured(e *Executor, p extrun.Plan) (rungSetup, error) {
	// Enable the controllers for children; this fails harmlessly when the
	// parent already has them, or holds processes itself.
	_ = os.WriteFile(filepath.Join(e.CgroupParent, "cgroup.subtree_control"), []byte("+memory +pids"), 0)
	dir := filepath.Join(e.CgroupParent, randomName())
	if err := os.Mkdir(dir, 0o755); err != nil {
		return rungSetup{}, fmt.Errorf("create the run cgroup: %w", err)
	}
	writeCgroupCaps(dir, p.Limits)
	return rungSetup{
		cgroupJoin: dir,
		cleanup:    func() { removeCgroup(dir) },
	}, nil
}

// writeCgroupCaps writes the memory and task caps of a run cgroup:
// memory.max always with memory.swap.max = 0 (JSP-12 laptop half).
func writeCgroupCaps(dir string, l extrun.Limits) {
	if l.MemoryBytes > 0 {
		_ = os.WriteFile(filepath.Join(dir, "memory.max"), []byte(strconv.FormatInt(l.MemoryBytes, 10)), 0)
		_ = os.WriteFile(filepath.Join(dir, "memory.swap.max"), []byte("0"), 0)
	}
	if l.Children > 0 {
		_ = os.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.Itoa(l.Children)), 0)
	}
}

// removeCgroup kills whatever is left in dir, waits for it to empty and
// removes it. The kernel can refuse the rmdir with EBUSY for a moment after
// cgroup.procs reads empty (the last task is still finishing its exit), so
// a busy cgroup is retried for a bounded time instead of being left behind
// (the flaky TestCgroupRungContainsAnEscaper, P-172).
func removeCgroup(dir string) {
	killCgroup(dir)
	waitCgroupEmpty(dir, 2*time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := os.Remove(dir)
		if err == nil || !errors.Is(err, syscall.EBUSY) || time.Now().After(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// scopeAvailable: systemd-run is at a fixed path and the matching manager
// is reachable (the user manager's socket under XDG_RUNTIME_DIR, or a host
// booted with systemd for the system manager).
func scopeAvailable(e *Executor, user bool) bool {
	if e.NoSystemdScope || systemdRun() == "" {
		return false
	}
	if !user {
		_, err := os.Stat(systemdBootedPath)
		return err == nil
	}
	rt, ok := lookupEnv("XDG_RUNTIME_DIR")
	if !ok || !filepath.IsAbs(rt) {
		return false
	}
	_, err := os.Stat(filepath.Join(rt, "systemd", "private"))
	return err == nil
}

// systemdRun returns the first systemd-run on the fixed path list, or "".
func systemdRun() string {
	for _, p := range systemdRunPaths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// setupScope puts the trampoline behind systemd-run: a transient scope with
// Delegate=yes per run, its caps as unit properties (systemd then enables
// the controllers on the way down), collected when it empties.
func setupScope(_ *Executor, p extrun.Plan) (rungSetup, error) {
	run := systemdRun()
	if run == "" {
		return rungSetup{}, errors.New("systemd-run is not installed")
	}
	user := getuid() != 0
	argv := scopeArgv(run, user, randomName(), p.Limits)
	var env []string
	if user {
		for _, name := range []string{"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
			if v, ok := lookupEnv(name); ok {
				env = append(env, name+"="+v)
			}
		}
	}
	return rungSetup{launcher: argv, launcherEnv: env}, nil
}

// scopeArgv is the systemd-run argv in front of the trampoline. It is pure:
// the scope is per run (its own unit name), delegated, quiet, collected when
// it empties, and carries the memory and task caps as properties.
func scopeArgv(run string, user bool, unit string, l extrun.Limits) []string {
	argv := []string{run}
	if user {
		argv = append(argv, "--user")
	}
	argv = append(argv, "--scope", "--quiet", "--collect", "--unit="+unit+".scope", "-p", "Delegate=yes")
	if l.MemoryBytes > 0 {
		argv = append(argv, "-p", "MemoryMax="+strconv.FormatInt(l.MemoryBytes, 10), "-p", "MemorySwapMax=0")
	}
	if l.Children > 0 {
		argv = append(argv, "-p", "TasksMax="+strconv.Itoa(l.Children))
	}
	return append(argv, "--")
}

// cgroupGroup is a run held by its own cgroup v2: the kill is cgroup.kill
// (Linux 5.14 and later; older kernels get every member killed by pid), and
// the process group kill too, for good measure.
type cgroupGroup struct {
	linuxGroup
	dir string
}

func (g cgroupGroup) kill() {
	killCgroup(g.dir)
	g.linuxGroup.kill()
}

// count returns the cgroup's members beside the leader: a process that left
// the process group is still counted.
func (g cgroupGroup) count() (int, bool) {
	n := 0
	for _, pid := range cgroupMembers(g.dir) {
		if pid != g.pid {
			n++
		}
	}
	return n, true
}

// close waits for the cgroup to empty, so the scope can be collected.
func (g cgroupGroup) close() { waitCgroupEmpty(g.dir, 2*time.Second) }

// settle waits, after the kill, until the cgroup has no members left.
func (g cgroupGroup) settle() { waitCgroupEmpty(g.dir, 2*time.Second) }

// cgroupMembers lists the pids in a cgroup.
func cgroupMembers(dir string) []int {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var out []int
	for _, f := range strings.Fields(string(data)) {
		if pid, err := strconv.Atoi(f); err == nil {
			out = append(out, pid)
		}
	}
	return out
}

// killCgroup kills every process in dir: cgroup.kill where the kernel has
// it, else each member by pid until none is left.
func killCgroup(dir string) {
	if os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0) == nil {
		return
	}
	for round := 0; round < 20; round++ {
		pids := cgroupMembers(dir)
		if len(pids) == 0 {
			return
		}
		for _, pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitCgroupEmpty waits up to d for dir to have no members.
func waitCgroupEmpty(dir string, d time.Duration) {
	deadline := time.Now().Add(d)
	for len(cgroupMembers(dir)) > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
}

// supervisedGroup is the not-contained rung with the trampoline: the leader
// is the supervisor, which on SIGTERM kills the program, sweeps every
// process re-parented to it and reports; only then is the group killed.
type supervisedGroup struct {
	linuxGroup
}

// count excludes the program itself: the leader is the supervisor.
func (g supervisedGroup) count() (int, bool) {
	n, ok := g.linuxGroup.count()
	if n > 0 {
		n--
	}
	return n, ok
}

func (g supervisedGroup) softStop() {
	if g.proc != nil {
		_ = g.proc.Signal(syscall.SIGTERM)
	}
}

// groupFor builds the group of a started run. For the cgroup rung it reads
// the run's cgroup from the trampoline's ready message and records what the
// run got: the path, whether the subtree is this user's (delegated) and its
// controllers.
func (e *Executor) groupFor(l *launch, _ extrun.Plan) (procGroup, error) {
	pid := l.cmd.Process.Pid
	if pid <= 0 {
		return nil, errors.New("extrun/host: no process id")
	}
	base := linuxGroup{unixGroup{pid: pid, proc: l.cmd.Process}}
	switch {
	case l.rung == extrun.RungCgroup:
		ready, _ := l.status.last(evReady)
		mnt := cgroup2Mount()
		if ready.Cgroup == "" || mnt == "" {
			return nil, errors.New("extrun/host: the run's cgroup is unknown")
		}
		dir := filepath.Join(mnt, ready.Cgroup)
		l.setup.cont.CgroupPath = ready.Cgroup
		l.setup.cont.Delegated = ownedByMe(dir)
		l.setup.cont.Controllers = readControllers(dir)
		return cgroupGroup{linuxGroup: base, dir: dir}, nil
	case l.rung == extrun.RungProcessGroup && l.setup.mode == modeSupervise:
		return supervisedGroup{base}, nil
	default:
		return base, nil
	}
}

// ownedByMe reports whether dir is owned by this process's user: the
// cgroup subtree was delegated to the runner.
func ownedByMe(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == getuid()
}

// readControllers lists a cgroup's controllers.
func readControllers(dir string) []string {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return nil
	}
	return strings.Fields(string(data))
}
