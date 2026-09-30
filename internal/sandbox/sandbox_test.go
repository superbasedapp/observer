package sandbox

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// canonicalReq is the one request the golden argv is pinned against; the
// composition/ordering tests reuse or mutate it.
func canonicalReq() Request {
	return Request{
		Home:          "/home/dev",
		ObserverDir:   "/home/dev/.observer",
		WorkspaceRoot: "/home/dev/.observer/workspaces/abc/repo",
		ObserverBin:   "/home/dev/.local/bin/observer",
		ToolBinDirs: []string{
			"/home/dev/.local/bin",
			"/home/dev/.local/share/claude/versions/2.1.226",
		},
		StateRW:       []string{".claude", ".claude.json"},
		StateRO:       []string{".local/share/claude"},
		RuntimeLadder: []string{".nvm"},
		MaskPaths:     []string{"/mnt/c"},
		HomeMode:      "tmpfs",
		Net:           NetRequest{Egress: EgressHost},
	}
}

// TestBuildPlanArgvGolden is the strongest regression pin: the EXACT argv the
// canonical request must produce, in order.
func TestBuildPlanArgvGolden(t *testing.T) {
	t.Parallel()

	plan, err := BuildPlan(canonicalReq())
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	got := plan.Argv([]string{"observer", "claude"})

	want := []string{
		"--ro-bind", "/", "/",
		"--unshare-pid",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--tmpfs", "/home/dev",
		"--tmpfs", "/mnt/c",
		"--ro-bind-try", "/home/dev/.local/bin", "/home/dev/.local/bin",
		"--ro-bind-try", "/home/dev/.local/share/claude/versions/2.1.226", "/home/dev/.local/share/claude/versions/2.1.226",
		"--ro-bind-try", "/home/dev/.local/bin/observer", "/home/dev/.local/bin/observer",
		"--ro-bind-try", "/home/dev/.nvm", "/home/dev/.nvm",
		"--ro-bind-try", "/home/dev/.local/share/claude", "/home/dev/.local/share/claude",
		"--bind", "/home/dev/.observer", "/home/dev/.observer",
		"--tmpfs", "/home/dev/.observer/workspaces",
		"--bind", "/home/dev/.observer/workspaces/abc/repo", "/home/dev/.observer/workspaces/abc/repo",
		"--bind-try", "/home/dev/.claude", "/home/dev/.claude",
		"--bind-try", "/home/dev/.claude.json", "/home/dev/.claude.json",
		"--unsetenv", "WSL_INTEROP",
		"--unsetenv", "WSLENV",
		"--unsetenv", "DBUS_SESSION_BUS_ADDRESS",
		"--unsetenv", "DBUS_SYSTEM_BUS_ADDRESS",
		"--unsetenv", "SSH_AUTH_SOCK",
		"--unsetenv", "SSH_AGENT_PID",
		"--unsetenv", "GPG_AGENT_INFO",
		"--unsetenv", "DOCKER_HOST",
		"--unsetenv", "CONTAINER_HOST",
		"--unsetenv", "DISPLAY",
		"--unsetenv", "WAYLAND_DISPLAY",
		"--unsetenv", "XAUTHORITY",
		"--unsetenv", "PULSE_SERVER",
		"--unsetenv", "OBSERVER_LOC_EDITOR_TOKEN",
		"--chdir", "/home/dev/.observer/workspaces/abc/repo",
		"--die-with-parent",
		"--", "observer", "claude",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("golden argv mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if plan.HomeMode != "tmpfs" {
		t.Errorf("HomeMode = %q, want tmpfs", plan.HomeMode)
	}
}

// findFlagOperand returns the index of the first occurrence of flag whose next
// token equals operand, or -1.
func findFlagOperand(argv []string, flag, operand string) int {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag && argv[i+1] == operand {
			return i
		}
	}
	return -1
}

// countFlagOperand counts occurrences of a flag/operand pair.
func countFlagOperand(argv []string, flag, operand string) int {
	n := 0
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag && argv[i+1] == operand {
			n++
		}
	}
	return n
}

func TestBuildPlanComposition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  Request
		// check runs assertions over the produced argv (inner = ["true"]).
		check func(t *testing.T, argv []string, plan Plan)
	}{
		{
			name: "tmpfs home mode blinds home",
			req:  canonicalReq(),
			check: func(t *testing.T, argv []string, plan Plan) {
				if findFlagOperand(argv, flagTmpfs, "/home/dev") < 0 {
					t.Errorf("expected --tmpfs /home/dev")
				}
				if plan.HomeMode != homeModeTmpfs {
					t.Errorf("HomeMode = %q", plan.HomeMode)
				}
			},
		},
		{
			name: "readonly home mode omits home tmpfs",
			req: func() Request {
				r := canonicalReq()
				r.HomeMode = "readonly"
				return r
			}(),
			check: func(t *testing.T, argv []string, plan Plan) {
				if findFlagOperand(argv, flagTmpfs, "/home/dev") >= 0 {
					t.Errorf("readonly mode must NOT tmpfs the home")
				}
				if plan.HomeMode != homeModeReadonly {
					t.Errorf("HomeMode = %q, want readonly", plan.HomeMode)
				}
			},
		},
		{
			name: "workspace outside home still bound rw and chdir'd",
			req: func() Request {
				r := canonicalReq()
				r.WorkspaceRoot = "/srv/managed/ws/repo"
				return r
			}(),
			check: func(t *testing.T, argv []string, plan Plan) {
				if findFlagOperand(argv, flagBind, "/srv/managed/ws/repo") < 0 {
					t.Errorf("expected --bind of out-of-home workspace")
				}
				if findFlagOperand(argv, flagChdir, "/srv/managed/ws/repo") < 0 {
					t.Errorf("expected --chdir into workspace")
				}
			},
		},
		{
			name: "StateRW uses bind-try, StateRO uses ro-bind-try",
			req:  canonicalReq(),
			check: func(t *testing.T, argv []string, plan Plan) {
				if findFlagOperand(argv, flagBindTry, "/home/dev/.claude") < 0 {
					t.Errorf("StateRW must be --bind-try (tolerate missing)")
				}
				if findFlagOperand(argv, flagROBindTry, "/home/dev/.local/share/claude") < 0 {
					t.Errorf("StateRO must be --ro-bind-try")
				}
			},
		},
		{
			name: "dedup collapses ladder/tool-dir overlap to one ro-bind-try",
			req: func() Request {
				r := canonicalReq()
				// RuntimeLadder repeats a path already in ToolBinDirs.
				r.RuntimeLadder = []string{".local/bin", ".nvm"}
				return r
			}(),
			check: func(t *testing.T, argv []string, plan Plan) {
				if got := countFlagOperand(argv, flagROBindTry, "/home/dev/.local/bin"); got != 1 {
					t.Errorf("--ro-bind-try /home/dev/.local/bin appeared %d times, want 1 (dedup)", got)
				}
			},
		},
		{
			name: "mask path emitted as tmpfs",
			req:  canonicalReq(),
			check: func(t *testing.T, argv []string, plan Plan) {
				if findFlagOperand(argv, flagTmpfs, "/mnt/c") < 0 {
					t.Errorf("expected --tmpfs /mnt/c (A1 foreign-OS mask)")
				}
			},
		},
		{
			name: "extra ro/rw escape hatches",
			req: func() Request {
				r := canonicalReq()
				r.ExtraRO = []string{"/opt/shared-cache"}
				r.ExtraRW = []string{"/srv/scratch"}
				return r
			}(),
			check: func(t *testing.T, argv []string, plan Plan) {
				if findFlagOperand(argv, flagROBind, "/opt/shared-cache") < 0 {
					t.Errorf("expected --ro-bind /opt/shared-cache")
				}
				if findFlagOperand(argv, flagBind, "/srv/scratch") < 0 {
					t.Errorf("expected --bind /srv/scratch")
				}
			},
		},
		{
			name: "observer dir always bound rw",
			req:  canonicalReq(),
			check: func(t *testing.T, argv []string, plan Plan) {
				if findFlagOperand(argv, flagBind, "/home/dev/.observer") < 0 {
					t.Errorf("expected --bind of ~/.observer (the observed-invariant)")
				}
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.req.Net.Egress == "" {
				tc.req.Net.Egress = EgressHost
			}
			plan, err := BuildPlan(tc.req)
			if err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}
			tc.check(t, plan.Argv([]string{"true"}), plan)
		})
	}
}

// TestBuildPlanOrdering backs mutation proof #2: the home tmpfs must precede
// every under-home bind, and the workspaces tmpfs must precede the workspace
// bind.
func TestBuildPlanOrdering(t *testing.T) {
	t.Parallel()

	req := canonicalReq()
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	argv := plan.Argv([]string{"true"})

	homeIdx := findFlagOperand(argv, flagTmpfs, req.Home)
	if homeIdx < 0 {
		t.Fatalf("no --tmpfs %s", req.Home)
	}

	bindFlags := map[string]bool{
		flagBind:      true,
		flagBindTry:   true,
		flagROBind:    true,
		flagROBindTry: true,
	}
	underHome := func(p string) bool {
		return p == req.Home || strings.HasPrefix(p, req.Home+"/")
	}
	for i := 0; i+1 < len(argv); i++ {
		if bindFlags[argv[i]] && underHome(argv[i+1]) {
			if i <= homeIdx {
				t.Errorf("under-home bind %s %s at index %d precedes/collides with --tmpfs home at %d",
					argv[i], argv[i+1], i, homeIdx)
			}
		}
	}

	wsTmpfsIdx := findFlagOperand(argv, flagTmpfs, "/home/dev/.observer/workspaces")
	wsBindIdx := findFlagOperand(argv, flagBind, req.WorkspaceRoot)
	if wsTmpfsIdx < 0 || wsBindIdx < 0 {
		t.Fatalf("missing workspaces tmpfs (%d) or workspace bind (%d)", wsTmpfsIdx, wsBindIdx)
	}
	if wsTmpfsIdx >= wsBindIdx {
		t.Errorf("workspaces tmpfs at %d must precede workspace bind at %d", wsTmpfsIdx, wsBindIdx)
	}

	// The mask tmpfs must land after the home tmpfs and before the punch-backs.
	maskIdx := findFlagOperand(argv, flagTmpfs, "/mnt/c")
	obsBindIdx := findFlagOperand(argv, flagBind, req.ObserverDir)
	if !(homeIdx < maskIdx && maskIdx < obsBindIdx) {
		t.Errorf("mask tmpfs (%d) must sit between home tmpfs (%d) and the punch-backs (observer bind %d)",
			maskIdx, homeIdx, obsBindIdx)
	}
}

func TestBuildPlanInjectionGuards(t *testing.T) {
	t.Parallel()

	base := Request{
		Home:          "/home/dev",
		ObserverDir:   "/home/dev/.observer",
		WorkspaceRoot: "/home/dev/ws",
		HomeMode:      "tmpfs",
		Net:           NetRequest{Egress: EgressHost},
	}
	mut := func(f func(r *Request)) Request {
		r := base
		f(&r)
		return r
	}

	tests := []struct {
		name    string
		req     Request
		wantErr bool
	}{
		{"valid base", base, false},
		{"non-absolute extra ro", mut(func(r *Request) { r.ExtraRO = []string{"relative/path"} }), true},
		{"dotdot extra rw", mut(func(r *Request) { r.ExtraRW = []string{"/foo/../bar"} }), true},
		{"leading dash mask", mut(func(r *Request) { r.MaskPaths = []string{"-x"} }), true},
		{"space in extra ro", mut(func(r *Request) { r.ExtraRO = []string{"/foo bar"} }), true},
		{"nul in extra ro", mut(func(r *Request) { r.ExtraRO = []string{"/foo\x00bar"} }), true},
		{"control char in extra ro", mut(func(r *Request) { r.ExtraRO = []string{"/foo\tbar"} }), true},
		{"root as rw bind", mut(func(r *Request) { r.ExtraRW = []string{"/"} }), true},
		{"absolute state rw rel", mut(func(r *Request) { r.StateRW = []string{"/etc"} }), true},
		{"dotdot state ro rel", mut(func(r *Request) { r.StateRO = []string{"../etc"} }), true},
		{"leading dash runtime ladder", mut(func(r *Request) { r.RuntimeLadder = []string{"-x"} }), true},
		{"empty observer dir", mut(func(r *Request) { r.ObserverDir = "" }), true},
		{"empty workspace root", mut(func(r *Request) { r.WorkspaceRoot = "" }), true},
		{"non-absolute tool bin dir", mut(func(r *Request) { r.ToolBinDirs = []string{"bin"} }), true},
		{"tmpfs home mode requires absolute home", mut(func(r *Request) { r.Home = "dev" }), true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := BuildPlan(tc.req)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestArgvInnerGuard(t *testing.T) {
	t.Parallel()

	plan, err := BuildPlan(canonicalReq())
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	if got := plan.Argv(nil); got != nil {
		t.Errorf("Argv(nil) = %#v, want nil", got)
	}
	if got := plan.Argv([]string{}); got != nil {
		t.Errorf("Argv(empty) = %#v, want nil", got)
	}
	if got := plan.Argv([]string{"-rf", "/"}); got != nil {
		t.Errorf("Argv(flag-shaped inner[0]) = %#v, want nil", got)
	}

	argv := plan.Argv([]string{"observer", "claude"})
	if len(argv) < 3 {
		t.Fatalf("argv too short: %#v", argv)
	}
	// `--` must sit immediately before the inner argv.
	sepIdx := -1
	for i, tok := range argv {
		if tok == argSep {
			sepIdx = i
			break
		}
	}
	if sepIdx < 0 || sepIdx != len(argv)-3 {
		t.Errorf("`--` at index %d, want immediately before inner (len-3 = %d)", sepIdx, len(argv)-3)
	}
	if argv[sepIdx+1] != "observer" || argv[sepIdx+2] != "claude" {
		t.Errorf("inner argv misplaced: %#v", argv[sepIdx:])
	}
}

func TestProbe(t *testing.T) {
	t.Parallel()

	ok := func(path string) func() (string, error) {
		return func() (string, error) { return path, nil }
	}
	ver := func(v string) func() (string, error) {
		return func() (string, error) { return v, nil }
	}

	tests := []struct {
		name        string
		env         Env
		wantVerdict string
		wantAvail   bool
		wantVersion string
	}{
		{
			name: "net canary fails -> netns_denied",
			env: Env{
				GOOS: "linux", LookBwrap: ok("/usr/bin/bwrap"), Version: ver("bubblewrap 0.4.0"),
				Canary: func() error { return nil }, NetCanary: func() error { return errors.New("EPERM") },
			},
			wantVerdict: VerdictNetNSDenied,
			wantVersion: "0.4.0",
		},
		{
			name: "net canary passes -> available",
			env: Env{
				GOOS: "linux", LookBwrap: ok("/usr/bin/bwrap"), Version: ver("bubblewrap 0.4.0"),
				Canary: func() error { return nil }, NetCanary: func() error { return nil },
			},
			wantVerdict: VerdictAvailable,
			wantAvail:   true,
			wantVersion: "0.4.0",
		},
		{
			name:        "non-linux platform",
			env:         Env{GOOS: "darwin", LookBwrap: ok("/usr/bin/bwrap"), Version: ver("0.11.0")},
			wantVerdict: VerdictUnsupportedPlatform,
		},
		{
			name:        "nil lookup",
			env:         Env{GOOS: "linux"},
			wantVerdict: VerdictBackendMissing,
		},
		{
			name:        "bwrap not found",
			env:         Env{GOOS: "linux", LookBwrap: func() (string, error) { return "", errors.New("not found") }},
			wantVerdict: VerdictBackendMissing,
		},
		{
			name:        "empty bwrap path",
			env:         Env{GOOS: "linux", LookBwrap: ok("   ")},
			wantVerdict: VerdictBackendMissing,
		},
		{
			name:        "version below floor",
			env:         Env{GOOS: "linux", LookBwrap: ok("/usr/bin/bwrap"), Version: ver("0.3.9")},
			wantVerdict: VerdictBackendTooOld,
			wantVersion: "0.3.9",
		},
		{
			name:        "version unreadable",
			env:         Env{GOOS: "linux", LookBwrap: ok("/usr/bin/bwrap"), Version: func() (string, error) { return "", errors.New("boom") }},
			wantVerdict: VerdictBackendTooOld,
		},
		{
			name:        "nil version func fails closed",
			env:         Env{GOOS: "linux", LookBwrap: ok("/usr/bin/bwrap")},
			wantVerdict: VerdictBackendTooOld,
		},
		{
			name:        "userns canary fails",
			env:         Env{GOOS: "linux", LookBwrap: ok("/usr/bin/bwrap"), Version: ver("bubblewrap 0.11.0"), Canary: func() error { return errors.New("EPERM") }},
			wantVerdict: VerdictUserNSDenied,
			wantVersion: "0.11.0",
		},
		{
			name:        "available at floor",
			env:         Env{GOOS: "linux", LookBwrap: ok("/usr/bin/bwrap"), Version: ver("0.4.0"), Canary: func() error { return nil }},
			wantVerdict: VerdictAvailable,
			wantAvail:   true,
			wantVersion: "0.4.0",
		},
		{
			name:        "available above floor, prefixed version, nil canary skipped",
			env:         Env{GOOS: "linux", LookBwrap: ok("/usr/bin/bwrap"), Version: ver("bubblewrap 0.11.0")},
			wantVerdict: VerdictAvailable,
			wantAvail:   true,
			wantVersion: "0.11.0",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Probe(tc.env)
			if got.Verdict != tc.wantVerdict {
				t.Errorf("Verdict = %q, want %q (reason: %s)", got.Verdict, tc.wantVerdict, got.Reason)
			}
			if got.Available != tc.wantAvail {
				t.Errorf("Available = %v, want %v", got.Available, tc.wantAvail)
			}
			if got.BackendVersion != tc.wantVersion {
				t.Errorf("BackendVersion = %q, want %q", got.BackendVersion, tc.wantVersion)
			}
			if got.Backend != BackendBwrap {
				t.Errorf("Backend = %q, want %q", got.Backend, BackendBwrap)
			}
			if !tc.wantAvail && got.Reason == "" {
				t.Errorf("unavailable verdict %q must carry a Reason", got.Verdict)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want int
	}{
		{"0.4.0", "0.4.0", 0},
		{"0.11.0", "0.4.0", 1},
		{"0.4.0", "0.11.0", -1},
		{"0.3.9", "0.4.0", -1},
		{"0.4", "0.4.0", 0},
		{"1.0.0", "0.99.99", 1},
	}
	for _, tc := range tests {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"0.4.0", "0.4.0"},
		{"bubblewrap 0.4.0", "0.4.0"},
		{"bubblewrap 0.11.0\n", "0.11.0"},
		{"  0.6.2  ", "0.6.2"},
		{"no digits here", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := parseVersion(tc.in); got != tc.want {
			t.Errorf("parseVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEnvMarker(t *testing.T) {
	t.Parallel()
	if EnvMarker != "OBSERVER_SANDBOX" {
		t.Errorf("EnvMarker = %q, want OBSERVER_SANDBOX", EnvMarker)
	}
}
