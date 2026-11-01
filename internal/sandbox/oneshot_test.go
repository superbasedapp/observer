package sandbox

import (
	"strings"
	"testing"
)

// oneshot_test.go pins the four properties of the isolation engine's
// one-shot request shape (sandbox plan v2 section 11.1, roadmap F0-11,
// JSP-12), one test each, plus the refusals.

func baseOneShot() OneShotRequest {
	return OneShotRequest{
		Home:        "/home/u",
		ObserverDir: "/home/u/.observer",
		ProjectRoot: "/home/u/src/proj",
		OutputDir:   "/tmp/obs-run-1/out",
		CacheDir:    "/home/u/.cache/observer-engines/gosec",
		ProgramDirs: []string{"/opt/scanners/bin", "/home/u/.local/bin"},
		MaskPaths:   []string{"/mnt/c"},
	}
}

// bindOp is one mount operation of a rendered argv.
type bindOp struct {
	flag, src, dst string
}

// parseOps walks the bwrap flags (everything before "--") into mount
// operations, in order. One-argument flags carry their path in dst.
func parseOps(t *testing.T, argv []string) []bindOp {
	t.Helper()
	two := map[string]bool{flagROBind: true, flagROBindTry: true, flagBind: true, flagBindTry: true, flagSymlink: true}
	one := map[string]bool{flagTmpfs: true, flagProc: true, flagDev: true, flagChdir: true, flagUnsetenv: true}
	none := map[string]bool{flagUnsharePid: true, flagUnshareNet: true, flagDieWithParent: true, flagNewSession: true}
	var ops []bindOp
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == argSep:
			return ops
		case two[a]:
			ops = append(ops, bindOp{flag: a, src: argv[i+1], dst: argv[i+2]})
			i += 2
		case one[a]:
			ops = append(ops, bindOp{flag: a, dst: argv[i+1]})
			i++
		case none[a]:
			ops = append(ops, bindOp{flag: a})
		default:
			t.Fatalf("unknown bwrap token %q at %d (not in the 0.4.0 flag set the planner uses)", a, i)
		}
	}
	t.Fatalf("no %q end-of-options marker", argSep)
	return nil
}

func buildOneShot(t *testing.T, req OneShotRequest) []bindOp {
	t.Helper()
	p, err := BuildOneShot(req)
	if err != nil {
		t.Fatalf("BuildOneShot: %v", err)
	}
	argv := p.Argv([]string{"/opt/scanners/bin/gosec", "-fmt", "sarif"})
	if argv == nil {
		t.Fatal("Argv returned nil")
	}
	return parseOps(t, argv)
}

func isBind(flag string) bool {
	return flag == flagROBind || flag == flagROBindTry || flag == flagBind || flag == flagBindTry
}

func isRW(flag string) bool { return flag == flagBind || flag == flagBindTry }

// Property 1: no ~/.observer bind at all. The only bind that reaches it is
// the read-only whole root, and a tmpfs (the home, or its own) covers it
// before any other bind; nothing after reaches it.
func TestOneShotHasNoObserverDirBind(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  func(*OneShotRequest)
	}{
		{"observer dir under home", func(*OneShotRequest) {}},
		{"observer dir outside home", func(r *OneShotRequest) { r.ObserverDir = "/srv/observer" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := baseOneShot()
			tc.req(&req)
			ops := buildOneShot(t, req)
			covered := false
			for _, op := range ops {
				if op.flag == flagTmpfs && isWithin(req.ObserverDir, op.dst) && op.dst != "/tmp" {
					covered = true
				}
				if !isBind(op.flag) {
					continue
				}
				if op.src == "/" && op.dst == "/" && op.flag == flagROBind {
					continue
				}
				if overlaps(op.dst, req.ObserverDir) || overlaps(op.src, req.ObserverDir) {
					t.Fatalf("bind %v reaches the observer dir %q", op, req.ObserverDir)
				}
				if !covered {
					t.Fatalf("bind %v comes before the observer dir is hidden", op)
				}
			}
			if !covered {
				t.Fatalf("the observer dir %q is never hidden", req.ObserverDir)
			}
		})
	}
}

// Property 2: the project is read-only and is the working directory.
func TestOneShotProjectIsReadOnly(t *testing.T) {
	req := baseOneShot()
	ops := buildOneShot(t, req)
	var roProject, chdir bool
	for _, op := range ops {
		if isBind(op.flag) && overlaps(op.dst, req.ProjectRoot) && op.dst != "/" {
			if isRW(op.flag) {
				t.Fatalf("project bound writable: %v", op)
			}
			if op.flag == flagROBind && op.dst == req.ProjectRoot {
				roProject = true
			}
		}
		if op.flag == flagChdir {
			chdir = op.dst == req.ProjectRoot
		}
	}
	if !roProject || !chdir {
		t.Fatalf("project read-only bind %v, chdir into it %v", roProject, chdir)
	}
}

// Property 3: exactly two writable binds, the output and the cache
// directory.
func TestOneShotHasExactlyOutputAndCacheWritable(t *testing.T) {
	req := baseOneShot()
	ops := buildOneShot(t, req)
	var rw []string
	for _, op := range ops {
		if isRW(op.flag) {
			if op.src != op.dst {
				t.Fatalf("writable bind with a different source: %v", op)
			}
			rw = append(rw, op.dst)
		}
	}
	if strings.Join(rw, ",") != req.OutputDir+","+req.CacheDir {
		t.Fatalf("writable binds = %v, want exactly [%s %s]", rw, req.OutputDir, req.CacheDir)
	}
}

// Property 4: egress none: a private network namespace, nothing forwarded
// in, and no guest helper in front of the program.
func TestOneShotHasNoNetwork(t *testing.T) {
	req := baseOneShot()
	p, err := BuildOneShot(req)
	if err != nil {
		t.Fatal(err)
	}
	if p.Egress.Mode != EgressNone || p.Egress.ForwardProxy || p.Egress.Gateway || !p.Egress.UnshareNet {
		t.Fatalf("egress = %+v, want the none tier", p.Egress)
	}
	inner := []string{"/opt/scanners/bin/gosec"}
	argv := p.Argv(inner)
	if argv[len(argv)-1] != inner[0] || argv[len(argv)-2] != argSep {
		t.Fatalf("a guest helper sits in front of the program: %v", argv[len(argv)-4:])
	}
	unshare := 0
	for _, op := range parseOps(t, argv) {
		if op.flag == flagUnshareNet {
			unshare++
		}
		if strings.Contains(op.dst, GuestSocketDir) {
			t.Fatalf("a network socket dir is bound in: %v", op)
		}
	}
	if unshare != 1 {
		t.Fatalf("--unshare-net appears %d times, want 1", unshare)
	}
}

// The terminal planner and the one-shot share the hardening a terminal
// already has: a private pid namespace, death with the caller, the home
// blinded and the environment scrub.
func TestOneShotKeepsTheHardening(t *testing.T) {
	ops := buildOneShot(t, baseOneShot())
	want := map[string]bool{flagUnsharePid: false, flagDieWithParent: false}
	homeBlind, unset := false, 0
	for _, op := range ops {
		if _, ok := want[op.flag]; ok {
			want[op.flag] = true
		}
		if op.flag == flagTmpfs && op.dst == "/home/u" {
			homeBlind = true
		}
		if op.flag == flagUnsetenv {
			unset++
		}
	}
	for f, ok := range want {
		if !ok {
			t.Errorf("%s missing", f)
		}
	}
	if !homeBlind || unset != len(GuestUnsetEnv) {
		t.Errorf("home blinded %v, unsetenv %d of %d", homeBlind, unset, len(GuestUnsetEnv))
	}
}

// Property 5 (audit finding P-006 (4)): the program runs in a new terminal
// session, so a hostile scanner cannot inject keystrokes into the caller's
// terminal with TIOCSTI. The flag is in bwrap 0.4.0's set, and it comes
// before the end-of-options marker exactly once.
func TestOneShotStartsANewSession(t *testing.T) {
	p, err := BuildOneShot(baseOneShot())
	if err != nil {
		t.Fatal(err)
	}
	argv := p.Argv([]string{"/opt/scanners/bin/gosec"})
	n, sep := 0, -1
	for i, a := range argv {
		if a == argSep && sep < 0 {
			sep = i
		}
		if a == flagNewSession {
			if sep >= 0 {
				t.Fatalf("%s after the end-of-options marker", flagNewSession)
			}
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%s appears %d times, want 1: %v", flagNewSession, n, argv)
	}
}

func TestOneShotRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*OneShotRequest)
		want string
	}{
		{"output is the observer dir", func(r *OneShotRequest) { r.OutputDir = "/home/u/.observer" }, "observer dir"},
		{"output under the observer dir", func(r *OneShotRequest) { r.OutputDir = "/home/u/.observer/scan-out" }, "observer dir"},
		{"cache contains the observer dir", func(r *OneShotRequest) { r.CacheDir = "/srv"; r.ObserverDir = "/srv/obs" }, "observer dir"},
		{"project contains the observer dir", func(r *OneShotRequest) { r.ProjectRoot = "/srv"; r.ObserverDir = "/srv/obs" }, "observer dir"},
		{"program dir under the observer dir", func(r *OneShotRequest) { r.ProgramDirs = []string{"/home/u/.observer/engines"} }, "observer dir"},
		{"program dir is the root", func(r *OneShotRequest) { r.ProgramDirs = []string{"/"} }, "observer dir"},
		{"output inside the project", func(r *OneShotRequest) { r.OutputDir = "/home/u/src/proj/out" }, "project"},
		{"cache contains the project", func(r *OneShotRequest) { r.CacheDir = "/home/u/src" }, "project"},
		{"output and cache nested", func(r *OneShotRequest) { r.CacheDir = r.OutputDir + "/c" }, "overlap"},
		{"output is the whole home", func(r *OneShotRequest) { r.OutputDir = "/home/u" }, "home"},
		{"project is the whole home", func(r *OneShotRequest) { r.ProjectRoot = "/home/u" }, "home"},
		{"relative project", func(r *OneShotRequest) { r.ProjectRoot = "src/proj" }, "absolute"},
		{"flag-shaped output", func(r *OneShotRequest) { r.OutputDir = "-x" }, "'-'"},
		{"output with a dotdot", func(r *OneShotRequest) { r.OutputDir = "/tmp/../home/u/.observer" }, ".."},
		{"output is the root", func(r *OneShotRequest) { r.OutputDir = "/" }, "whole-root"},
		{"empty observer dir", func(r *OneShotRequest) { r.ObserverDir = "" }, "observer dir"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := baseOneShot()
			tc.mut(&req)
			_, err := BuildOneShot(req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
		})
	}
}
