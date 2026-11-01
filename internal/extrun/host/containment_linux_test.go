//go:build linux

package host

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

func TestCgroupIsSafe(t *testing.T) {
	t.Parallel()
	cases := []struct {
		run, daemon string
		want        bool
	}{
		{"/user.slice/u@1000.service/app.slice/sbo-extrun-1.scope", "/user.slice/u@1000.service/app.slice/observer.service", true},
		{"/a/b/run", "/a/b", true},
		{"/a/b", "/a/b", false}, // the daemon's own cgroup
		{"/a", "/a/b", false},   // an ancestor of the daemon
		{"/a/", "/a/b", false},  // the same, with a trailing slash
		{"/", "/a/b", false},    // the root is everyone's ancestor
		{"", "/a/b", false},     // unknown
		{"/ab", "/a/b", true},   // a sibling prefix is not an ancestor
		{"/run", "", true},      // daemon unknown: only the root is refused
		{"/", "", false},
	}
	for _, tc := range cases {
		if got := cgroupIsSafe(tc.run, tc.daemon); got != tc.want {
			t.Errorf("cgroupIsSafe(%q, %q) = %v, want %v", tc.run, tc.daemon, got, tc.want)
		}
	}
}

func TestScopeArgv(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		user bool
		l    extrun.Limits
		want []string
	}{
		{
			name: "user scope with both caps",
			user: true,
			l:    extrun.Limits{MemoryBytes: 512 << 20, Children: 64},
			want: []string{
				"/usr/bin/systemd-run", "--user", "--scope", "--quiet", "--collect", "--unit=u1.scope", "-p", "Delegate=yes",
				"-p", "MemoryMax=536870912", "-p", "MemorySwapMax=0", "-p", "TasksMax=64", "--",
			},
		},
		{
			name: "system scope, no caps",
			want: []string{"/usr/bin/systemd-run", "--scope", "--quiet", "--collect", "--unit=u1.scope", "-p", "Delegate=yes", "--"},
		},
	}
	for _, tc := range cases {
		if got := scopeArgv("/usr/bin/systemd-run", tc.user, "u1", tc.l); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

func TestParseProcStat(t *testing.T) {
	t.Parallel()
	line := "4242 (a (weird) name) S 17 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 3 0 98765 1000 50"
	st, ok := parseProcStat([]byte(line))
	if !ok || st.state != 'S' || st.ppid != 17 || st.pgrp != 4242 || st.start != 98765 || !st.alive() {
		t.Fatalf("parsed %+v %v", st, ok)
	}
	if st, ok := parseProcStat([]byte("1 (x) Z 0 1")); !ok || st.alive() || st.start != 0 {
		t.Fatalf("zombie line: %+v %v", st, ok)
	}
}

// writableCgroup2Parent makes a cgroup v2 directory this test may create
// children in, or skips (not root and no delegated subtree here).
func writableCgroup2Parent(t *testing.T) string {
	t.Helper()
	mnt := cgroup2Mount()
	if mnt == "" {
		t.Skip("no cgroup v2 mount")
	}
	dir := filepath.Join(mnt, "sbo-extrun-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		t.Skipf("no writable cgroup v2 directory: %v", err)
	}
	t.Cleanup(func() {
		for _, sub := range mustGlob(filepath.Join(dir, "sbo-extrun-*")) {
			removeCgroup(sub)
		}
		_ = os.Remove(dir)
	})
	return dir
}

func mustGlob(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	return m
}

// TestCgroupRungContainsAnEscaper: under a configured cgroup parent the
// run gets its own cgroup, joined before exec; a setsid grandchild is in it
// and dies with the cgroup.kill after the program exits.
func TestCgroupRungContainsAnEscaper(t *testing.T) {
	parent := writableCgroup2Parent(t)
	r := NewRunner(Options{Executor: &Executor{DrainTimeout: 300 * time.Millisecond, CgroupParent: parent, NoSystemdScope: true}})
	res := r.Run(context.Background(), helperRequest(t, "escape"))
	pid := firstPid(t, res.Stdout)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	c := res.Containment
	if res.Outcome != extrun.OutcomeOK || c.Rung != extrun.RungCgroup || !c.Contained {
		t.Fatalf("outcome %s, containment %+v (%s)", res.Outcome, c, res.Detail)
	}
	if c.CgroupSource != extrun.CgroupSourceConfigured || !strings.HasPrefix(filepath.Join(cgroup2Mount(), c.CgroupPath), parent+"/") || !c.Delegated {
		t.Fatalf("cgroup record %+v", c)
	}
	if !gone(pid) || res.Leftover {
		t.Fatalf("the setsid grandchild %d outlived the cgroup kill (leftover %v)", pid, res.Leftover)
	}
	if c.Swept < 1 {
		t.Fatalf("the grandchild left behind was not counted as swept: %+v", c)
	}
	if left := mustGlob(filepath.Join(parent, "sbo-extrun-*")); len(left) != 0 {
		t.Fatalf("run cgroups left behind: %v", left)
	}
}

// TestCgroupRungTimeoutKillsTheWholeCgroup: the wall cap kills through
// cgroup.kill, grandchild included.
func TestCgroupRungTimeoutKillsTheWholeCgroup(t *testing.T) {
	parent := writableCgroup2Parent(t)
	r := NewRunner(Options{Executor: &Executor{DrainTimeout: 300 * time.Millisecond, CgroupParent: parent, NoSystemdScope: true}})
	req := helperRequest(t, "grandchild")
	req.Limits.Wall = 700 * time.Millisecond
	res := r.Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeTimeout || res.Containment.Rung != extrun.RungCgroup {
		t.Fatalf("outcome %s rung %s (%s)", res.Outcome, res.Containment.Rung, res.Detail)
	}
	if pid := firstPid(t, res.Stdout); !gone(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("grandchild %d outlived the timeout", pid)
	}
}

// TestCgroupRungMemoryCapHolder: the memory cap is the cgroup's when its
// memory controller is there (memory.max with memory.swap.max = 0), and
// RLIMIT_DATA otherwise; the record names which.
func TestCgroupRungMemoryCapHolder(t *testing.T) {
	parent := writableCgroup2Parent(t)
	r := NewRunner(Options{Executor: &Executor{DrainTimeout: 300 * time.Millisecond, CgroupParent: parent, NoSystemdScope: true}})
	req := helperRequest(t, "limits")
	req.Limits.MemoryBytes = 1 << 40
	res := r.Run(context.Background(), req)
	if res.Outcome != extrun.OutcomeOK || res.Containment.Rung != extrun.RungCgroup {
		t.Fatalf("outcome %s rung %s (%s)", res.Outcome, res.Containment.Rung, res.Detail)
	}
	hasMemory := false
	for _, c := range res.Containment.Controllers {
		hasMemory = hasMemory || c == "memory"
	}
	mem := capOf(t, res, extrun.CapMemory)
	switch {
	case hasMemory && (mem.Mechanism != extrun.MechCgroup || mem.State != extrun.CapEnforced):
		t.Fatalf("memory controller present but cap %+v", mem)
	case !hasMemory && mem.Mechanism != extrun.MechRlimitData:
		t.Fatalf("no memory controller, cap %+v, want the RLIMIT_DATA fallback", mem)
	}
}

// TestCgroupRungFallsThroughWhenUnsafe: a "cgroup parent" that is not a
// cgroup at all leaves the trampoline in the test's own cgroup; it refuses
// (never a cgroup.kill that could reach the daemon), and the run falls to
// the next rung with the reason recorded.
func TestCgroupRungFallsThroughWhenUnsafe(t *testing.T) {
	t.Parallel()
	if cgroup2Mount() == "" {
		t.Skip("no cgroup v2 mount")
	}
	fake := t.TempDir()
	if err := os.WriteFile(filepath.Join(fake, "cgroup.procs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(Options{Executor: &Executor{DrainTimeout: 300 * time.Millisecond, CgroupParent: fake, NoSystemdScope: true}})
	res := r.Run(context.Background(), helperRequest(t, "exit", "0"))
	c := res.Containment
	if res.Outcome != extrun.OutcomeOK || c.Rung != extrun.RungProcessGroup {
		t.Fatalf("outcome %s containment %+v (%s)", res.Outcome, c, res.Detail)
	}
	if len(c.Skipped) != 1 || c.Skipped[0].Rung != extrun.RungCgroup || !strings.Contains(c.Skipped[0].Reason, "cgroup_safety") {
		t.Fatalf("skipped %+v", c.Skipped)
	}
}

func TestPickCgroupSource(t *testing.T) {
	if cgroup2Mount() == "" {
		t.Skip("no cgroup v2 mount")
	}
	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, "cgroup.procs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if src := (&Executor{CgroupParent: parent}).pickCgroupSource(); src == nil || src.name != extrun.CgroupSourceConfigured {
		t.Fatalf("configured parent not picked: %+v", src)
	}
	for _, bad := range []string{"", "relative/dir", filepath.Join(parent, "missing")} {
		e := &Executor{CgroupParent: bad, NoSystemdScope: true}
		if src := e.pickCgroupSource(); src != nil {
			t.Errorf("parent %q picked %s", bad, src.name)
		}
	}
}

// pidnsProvider stands in for the isolation component: it leaves the plan
// as is and declares a pid namespace.
type pidnsProvider struct{}

func (pidnsProvider) Name() string { return "test.pidns" }
func (pidnsProvider) Wrap(_ context.Context, p extrun.Plan) (extrun.Plan, error) {
	return p, nil
}
func (pidnsProvider) PIDNamespace() bool { return true }

// TestPIDNamespaceRungIsChosenWithoutACgroup: with no cgroup source, a plan
// an isolation provider put in its own pid namespace is held by that rung,
// and the record says contained.
func TestPIDNamespaceRungIsChosenWithoutACgroup(t *testing.T) {
	t.Parallel()
	r := NewRunner(Options{
		Executor:  &Executor{DrainTimeout: 300 * time.Millisecond, NoSystemdScope: true},
		Isolation: pidnsProvider{},
	})
	res := r.Run(context.Background(), helperRequest(t, "exit", "0"))
	c := res.Containment
	if res.Outcome != extrun.OutcomeOK || c.Rung != extrun.RungPIDNamespace || !c.Contained || res.Isolation != "test.pidns" {
		t.Fatalf("outcome %s containment %+v isolation %q", res.Outcome, c, res.Isolation)
	}
}
