package sandbox

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestBuildPlanSeccompGolden pins where bwrap's --seccomp lands: right
// before --chdir, always on SeccompFD, and nowhere without a profile (the
// untouched TestBuildPlanArgvGolden pins the no-profile argv exactly).
func TestBuildPlanSeccompGolden(t *testing.T) {
	t.Parallel()
	req := canonicalReq()
	req.Seccomp = "observer_default"
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	got := plan.Argv([]string{"observer", "claude"})
	want := []string{
		"--unsetenv", "OBSERVER_LOC_EDITOR_TOKEN",
		"--seccomp", "5",
		"--chdir", "/home/dev/.observer/workspaces/abc/repo",
		"--die-with-parent",
		"--", "observer", "claude",
	}
	if tail := got[len(got)-len(want):]; !reflect.DeepEqual(tail, want) {
		t.Fatalf("argv tail\n got: %#v\nwant: %#v", tail, want)
	}
	if n := countFlagOperand(got, "--seccomp", "5"); n != 1 {
		t.Fatalf("--seccomp appears %d times", n)
	}
	base, err := BuildPlan(canonicalReq())
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(base.Argv([]string{"observer", "claude"}), "--seccomp") {
		t.Fatal("a plan without a profile carries --seccomp")
	}
}

// TestBuildPlanSeccompRefusesBadProfile: a profile id of the wrong shape is
// refused, never emitted.
func TestBuildPlanSeccompRefusesBadProfile(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"Observer", "--x", "a b", "observer-default", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		req := canonicalReq()
		req.Seccomp = p
		if _, err := BuildPlan(req); err == nil {
			t.Fatalf("profile %q accepted", p)
		}
	}
}

// TestPlanHostArgvSeccomp: a profile always runs the host helper (even on
// the host tier with no relay, where it otherwise would not run), names the
// profile, and round-trips through ParseHostArgs.
func TestPlanHostArgvSeccomp(t *testing.T) {
	t.Parallel()
	req := canonicalReq()
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := plan.HostArgv("/o/observer"); err != nil || h != nil {
		t.Fatalf("no-profile host argv = %v, %v; want nil", h, err)
	}
	req.Seccomp = "observer_default"
	plan, err = BuildPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	h, err := plan.HostArgv("/o/observer")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/o/observer", HostVerb, "--seccomp-profile", "observer_default", "--"}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("host argv\n got: %#v\nwant: %#v", h, want)
	}
	full := append(append(append([]string(nil), h[2:]...), "/usr/bin/bwrap"), plan.Argv([]string{"observer", "claude"})...)
	args, err := ParseHostArgs(full)
	if err != nil {
		t.Fatal(err)
	}
	if args.SeccompProfile != "observer_default" || args.Command[0] != "/usr/bin/bwrap" {
		t.Fatalf("parsed %+v", args)
	}
	fd, ok, err := BwrapSeccompFD(args.Command)
	if err != nil || !ok || fd != SeccompFD {
		t.Fatalf("BwrapSeccompFD = %d, %v, %v", fd, ok, err)
	}
	if _, err := ParseHostArgs([]string{"--seccomp-profile", "Bad!", "--", "x"}); err == nil {
		t.Fatal("a malformed profile parsed")
	}
}

// TestHostArgvWithSeccomp: the process_lite host argv gains the flag right
// before its "--"; anything that is not a host argv, or names a profile
// already, is refused.
func TestHostArgvWithSeccomp(t *testing.T) {
	t.Parallel()
	host, err := RelayHostArgv("/o/observer", NetRequest{Egress: EgressHost, HostSocketDir: "/tmp/observer-sbx-r1"}, nil, RelayRequest{RunID: "r1", HostObserverDir: "/home/u/.observer"})
	if err != nil {
		t.Fatal(err)
	}
	same, err := HostArgvWithSeccomp(host, "")
	if err != nil || !reflect.DeepEqual(same, host) {
		t.Fatalf("empty profile changed the argv: %v, %v", same, err)
	}
	got, err := HostArgvWithSeccomp(host, "observer_default")
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]string(nil), host[:len(host)-1]...), "--seccomp-profile", "observer_default", "--")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
	args, err := ParseHostArgs(append(got[2:], "/o/observer", "sandbox-landlock-exec"))
	if err != nil || args.SeccompProfile != "observer_default" || args.RelayRun != "r1" {
		t.Fatalf("parsed %+v, %v", args, err)
	}
	for name, in := range map[string][]string{
		"not a host argv": {"/o/observer", "claude", "--"},
		"no separator":    host[:len(host)-1],
		"twice":           got,
	} {
		if _, err := HostArgvWithSeccomp(in, "observer_default"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := HostArgvWithSeccomp(host, "BAD"); err == nil {
		t.Fatal("bad profile accepted")
	}
}

// TestBwrapSeccompFD is the host helper's consistency read, one case per
// row.
func TestBwrapSeccompFD(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		cmd     []string
		fd      int
		found   bool
		wantErr bool
	}{
		{"none", []string{"/usr/bin/bwrap", "--ro-bind", "/", "/", "--", "x"}, 0, false, false},
		{"present", []string{"/usr/bin/bwrap", "--seccomp", "5", "--", "x"}, 5, true, false},
		{"after separator is the inner argv", []string{"/usr/bin/bwrap", "--", "x", "--seccomp", "5"}, 0, false, false},
		{"twice", []string{"/usr/bin/bwrap", "--seccomp", "5", "--seccomp", "6", "--", "x"}, 0, false, true},
		{"no value", []string{"/usr/bin/bwrap", "--seccomp"}, 0, false, true},
		// Audit N2-A11 (lane FU4): operands are skipped by arity.
		{"a setenv value equal to the flag", []string{"/usr/bin/bwrap", "--setenv", "X", "--seccomp", "--", "y"}, 0, false, false},
		{"a bind path equal to the flag", []string{"/usr/bin/bwrap", "--ro-bind", "--seccomp", "/x", "--seccomp", "5", "--", "y"}, 5, true, false},
		{"a non-option ends the options", []string{"/usr/bin/bwrap", "--ro-bind", "/", "/", "true", "--seccomp", "5"}, 0, false, false},
		{"an operand missing", []string{"/usr/bin/bwrap", "--ro-bind", "/"}, 0, false, true},
		{"an unknown option", []string{"/usr/bin/bwrap", "--frobnicate", "--seccomp", "5", "--", "y"}, 0, false, true},
		{"--args is unknown", []string{"/usr/bin/bwrap", "--args", "7", "--", "y"}, 0, false, true},
		{"bad value", []string{"/usr/bin/bwrap", "--seccomp", "x", "--", "y"}, 0, false, true},
		{"empty", nil, 0, false, false},
	} {
		fd, found, err := BwrapSeccompFD(c.cmd)
		if (err != nil) != c.wantErr || fd != c.fd || found != c.found {
			t.Errorf("%s: got %d, %v, %v", c.name, fd, found, err)
		}
	}
}

// plannerBwrapFlags reads the planner's bwrap flag vocabulary from its one
// owner, the const block of plan.go ("bwrap flag vocabulary"), plus
// seccomp.go's --seccomp, by source: every const whose name starts with
// "flag" and whose value is a "--" option. A flag added to the planner is
// found here without anyone listing it (audit FU4-A6).
func plannerBwrapFlags(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, file := range []string{"plan.go", "seccomp.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, sp := range g.Specs {
				v := sp.(*ast.ValueSpec)
				for k, n := range v.Names {
					if k >= len(v.Values) || !strings.HasPrefix(n.Name, "flag") {
						continue
					}
					lit, ok := v.Values[k].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					val, err := strconv.Unquote(lit.Value)
					if err == nil && strings.HasPrefix(val, "--") && val != flagSeccompProfile {
						out = append(out, val)
					}
				}
			}
		}
	}
	return out
}

// TestBwrapFlagArityCoversPlanner: every bwrap option the planner can emit
// is in the arity table, so the scan never refuses a planned launch (audit
// N2-A11, FU4-A6): the vocabulary read from plan.go's own const block, and
// a plan with every optional step set (every tier, sweeps with a symlink,
// host masks and keeps, overlays, pins, extra binds, a relay and a
// profile), whose whole argv scans cleanly.
func TestBwrapFlagArityCoversPlanner(t *testing.T) {
	t.Parallel()
	flags := plannerBwrapFlags(t)
	if len(flags) < 15 {
		t.Fatalf("read %d planner flags from plan.go, the const block moved: %v", len(flags), flags)
	}
	for _, f := range flags {
		if _, ok := bwrapFlagArity[f]; !ok {
			t.Errorf("planner flag %s is not in bwrapFlagArity", f)
		}
	}
	for _, mode := range []Egress{EgressHost, EgressInternet, EgressProxyOnly, EgressNone} {
		req := netReq(mode)
		req.Seccomp = "observer_default"
		req.SocketSweeps = []DirRebuild{{Path: "/run", Keep: []RebuildEntry{{Name: "user"}, {Name: "shm", Symlink: "/dev/shm"}}}}
		req.HostMasks = []Overlay{{Path: "/run/user/1000", Kind: OverlayHideDir}, {Path: "/mnt/wsl", Kind: OverlayHideDir}}
		req.HostMaskKeep = []string{"/mnt/wsl/resolv.conf"}
		req.ExtraRO = []string{"/opt/ro"}
		req.ExtraRW = []string{"/opt/rw"}
		req.Relay = RelayRequest{RunID: "r1", HostObserverDir: req.ObserverDir}
		plan, err := BuildPlan(req)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		argv := append([]string{"/usr/bin/bwrap"}, plan.Argv([]string{"observer", "claude"})...)
		fd, found, err := BwrapSeccompFD(argv)
		if err != nil || !found || fd != SeccompFD {
			t.Fatalf("%s: the planned argv scans as %d, %v, %v", mode, fd, found, err)
		}
		// Every token in option position is a known option.
		for i := 1; i < len(argv) && argv[i] != argSep; i++ {
			n, ok := bwrapFlagArity[argv[i]]
			if !ok {
				t.Fatalf("%s: %q at %d is not a known option", mode, argv[i], i)
			}
			i += n
		}
	}
}
