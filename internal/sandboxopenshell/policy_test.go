package sandboxopenshell

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// Sentinel identities: no real user, path or id.
const (
	testHome   = "/home/dev"
	testObsDir = "/home/dev/.observer"
	// testOutsideObsDir is an observer dir outside the home (an
	// OBSERVER_HOME elsewhere), the only shape home_mode readonly compiles.
	testOutsideObsDir = "/var/lib/dev-observer"
	testRun           = "-RunSENTINEL0000_aa"
	testInstall       = "0123456789abcdef"
)

// claudeBinds is a Claude Code run's bind plan: the workspace under the
// home, its protected .git state as nested read-only binds (U-31), the tool
// state dir, the tool's single-file state (rewritten by temp-and-rename),
// the observer binary and the relay socket dir.
func claudeBinds() []Bind {
	return []Bind{
		{Source: "/home/dev/src/app", Target: "/home/dev/src/app"},
		{Source: "/home/dev/src/app/.git/config", Target: "/home/dev/src/app/.git/config", ReadOnly: true, File: true},
		{Source: "/home/dev/src/app/.git/hooks", Target: "/home/dev/src/app/.git/hooks", ReadOnly: true},
		{Source: "/home/dev/.claude", Target: "/home/dev/.claude"},
		{Source: "/home/dev/.claude.json", Target: "/home/dev/.claude.json", File: true},
		{Source: "/home/dev/.observer/bin/observer", Target: "/home/dev/.observer/bin/observer", ReadOnly: true, File: true},
		{Source: "/tmp/observer-sbx-RUN", Target: "/tmp/observer-sbx-RUN", ReadOnly: true},
	}
}

func baseInput() Input {
	return Input{
		Settings:    Settings{HomeMode: HomeTmpfs, Egress: vocab.TierProxyOnly},
		Home:        testHome,
		UID:         1000,
		GID:         1000,
		ObserverDir: testObsDir,
		Scope: Scope{
			Workspace: "/home/dev/src/app", SocketDir: "/tmp/observer-sbx-RUN",
			ToolState: []string{"/home/dev/.claude", "/home/dev/.claude.json", "/home/dev/.codex", "/home/dev/.config/tool"},
			BinPaths:  []string{"/home/dev/.observer/bin/observer"},
		},
		Binds: claudeBinds(),
		Env:   []string{"ANTHROPIC_BASE_URL=http://127.0.0.1:8820", "TERM=xterm-256color"},
	}
}

// goldenCases are the compiler's golden fixtures (testdata/<name>.golden):
// the policy document, the driver config, the copied files and the create
// argv, exactly as the driver will pass them.
var goldenCases = []struct {
	name string
	in   func() Input
}{
	// The home is a tmpfs with binds nested under it: mode 01777 (fact 1),
	// as on every tmpfs home.
	{"claude-tmpfs-home", baseInput},
	// No mount under the home: the tmpfs still carries mode 1023 and the
	// shared-home disclosure (a bare tmpfs comes up 1777 on its own,
	// o0-receipts.md OB-033 probe; audit finding O1A-A2).
	{"bare-tmpfs-home", func() Input {
		in := baseInput()
		in.Settings.Egress = vocab.TierNone
		in.Scope = Scope{Workspace: "/srv/work", SocketDir: "/tmp/observer-sbx-RUN"}
		in.Binds = []Bind{
			{Source: "/srv/work", Target: "/srv/work"},
			{Source: "/tmp/observer-sbx-RUN", Target: "/tmp/observer-sbx-RUN", ReadOnly: true},
		}
		in.Env = nil
		return in
	}},
	// home_mode readonly with the observer dir outside the home (rule K9
	// refuses it inside): the home is a read-only bind and the writable
	// binds nest under it.
	{"readonly-home", func() Input {
		in := baseInput()
		in.Settings.HomeMode = HomeReadonly
		in.ObserverDir = testOutsideObsDir
		in.Binds = []Bind{
			{Source: "/home/dev/src/app", Target: "/home/dev/src/app"},
			{Source: "/home/dev/.codex", Target: "/home/dev/.codex"},
			{Source: "/tmp/observer-sbx-RUN", Target: "/tmp/observer-sbx-RUN", ReadOnly: true},
		}
		return in
	}},
}

func renderGolden(t *testing.T, p Plan) string {
	t.Helper()
	labels, err := RunLabels(testInstall, testRun)
	if err != nil {
		t.Fatal(err)
	}
	argv, err := CreateArgv(CreateInput{
		Target: Target{Gateway: "openshell"}, Name: SandboxName(testRun),
		PolicyPath: "/home/dev/.observer/sandbox-openshell/runs/RUN/policy.yaml", DriverConfigJSON: p.DriverConfigJSON,
		Labels: labels, Env: p.Env, Command: []string{"/home/dev/.observer/bin/observer", "sandbox-guest", "--", "claude"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("# policy.yaml\n")
	b.Write(p.PolicyYAML)
	b.WriteString("# driver-config-json\n" + p.DriverConfigJSON + "\n")
	b.WriteString("# copy-sync\n")
	for _, c := range p.CopySync {
		b.WriteString(c.Source + " -> " + c.Target + "\n")
	}
	b.WriteString("# shared-home\n")
	if p.SharedHome {
		b.WriteString("true\n")
	} else {
		b.WriteString("false\n")
	}
	b.WriteString("# create-argv\n")
	for _, a := range argv {
		b.WriteString(a + "\n")
	}
	return b.String()
}

func TestCompileGolden(t *testing.T) {
	t.Parallel()
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Compile(tc.in())
			if err != nil {
				t.Fatal(err)
			}
			got := renderGolden(t, p)
			file := filepath.Join("testdata", tc.name+".golden")
			if *update {
				if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/sandboxopenshell -run TestCompileGolden -update)", err)
			}
			if got != string(want) {
				t.Fatalf("%s drifted:\n--- got\n%s\n--- want\n%s", file, got, want)
			}
		})
	}
}

// TestHomeTmpfsModeAlways pins fact 1 of lane O0's verdict and audit
// finding O1A-A2: every tmpfs home carries mode 1023 (01777) and the
// shared-home disclosure, with binds nested under it or none; a readonly
// home is a bind with neither; Docker's refused string options never
// appear.
func TestHomeTmpfsModeAlways(t *testing.T) {
	t.Parallel()
	bare := baseInput()
	bare.Binds = []Bind{{Source: "/tmp/observer-sbx-RUN", Target: "/tmp/observer-sbx-RUN", ReadOnly: true}}
	readonly := baseInput()
	readonly.Settings.HomeMode = HomeReadonly
	readonly.ObserverDir = testOutsideObsDir
	readonly.Binds = nil
	cases := []struct {
		name   string
		in     Input
		tmpfs  bool
		shared bool
	}{
		{"binds nested under the home", baseInput(), true, true},
		{"nothing under the home", bare, true, true},
		{"empty home_mode is tmpfs", func() Input { in := bare; in.Settings.HomeMode = ""; return in }(), true, true},
		{"readonly home", readonly, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Compile(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			h := p.Mounts[0]
			if h.Target != testHome || p.SharedHome != tc.shared {
				t.Fatalf("home %+v shared %v", h, p.SharedHome)
			}
			wantJSON := `{"type":"tmpfs","target":"/home/dev","mode":1023}`
			if tc.tmpfs != (h.Type == "tmpfs" && h.Mode == 1023) || tc.tmpfs != strings.Contains(p.DriverConfigJSON, wantJSON) {
				t.Fatalf("home %+v json %s", h, p.DriverConfigJSON)
			}
			for _, refused := range []string{"uid=", "gid=", "mode="} {
				if strings.Contains(p.DriverConfigJSON, refused) {
					t.Fatalf("driver config carries the refused tmpfs option %s", refused)
				}
			}
		})
	}
}

// TestBindTable: one case per row of the bind table (U-32): directories
// are bound either way, a read-only file is bound, a writable single file is
// copied in and synced back, never bound (fact 3).
func TestBindTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		b    Bind
		kind bindKind
	}{
		{Bind{Source: "/home/dev/.claude", Target: "/home/dev/.claude"}, kindDirBind},
		{Bind{Source: "/home/dev/src/app/.git/hooks", Target: "/home/dev/src/app/.git/hooks", ReadOnly: true}, kindDirBind},
		{Bind{Source: "/home/dev/src/app/.git/config", Target: "/home/dev/src/app/.git/config", ReadOnly: true, File: true}, kindFileRO},
		{Bind{Source: "/home/dev/.claude.json", Target: "/home/dev/.claude.json", File: true}, kindCopySync},
	}
	if len(cases) != len(bindRules) {
		t.Fatalf("%d cases for %d bind rows", len(cases), len(bindRules))
	}
	for _, tc := range cases {
		if got := classify(tc.b); got != tc.kind {
			t.Errorf("%+v: %s, want %s", tc.b, got, tc.kind)
		}
		in := baseInput()
		in.Binds = []Bind{{Source: "/home/dev/src/app", Target: "/home/dev/src/app"}, tc.b}
		p, err := Compile(in)
		if err != nil {
			t.Fatalf("%+v: %v", tc.b, err)
		}
		bound, copied := false, false
		for _, m := range p.Mounts {
			bound = bound || m.Target == tc.b.Target
		}
		for _, c := range p.CopySync {
			copied = copied || c.Target == tc.b.Target
		}
		if bound == (tc.kind == kindCopySync) || copied != (tc.kind == kindCopySync) {
			t.Errorf("%+v: bound %v copied %v for %s", tc.b, bound, copied, tc.kind)
		}
	}
}

// TestCompileRefusals: one case per refusal row.
func TestCompileRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(*Input)
		want error
	}{
		{"root uid", func(in *Input) { in.UID = 0 }, ErrRoot},
		{"root gid", func(in *Input) { in.GID = 0 }, ErrRoot},
		{"host tier", func(in *Input) { in.Settings.Egress = vocab.TierHost }, ErrTier},
		{"internet tier with no host list", func(in *Input) { in.Settings.Egress = vocab.TierInternet }, ErrNetAllowList},
		{"unknown home mode", func(in *Input) { in.Settings.HomeMode = "hidden" }, ErrHomeMode},
		{"unknown driver", func(in *Input) { in.Settings.Driver = "kubernetes" }, ErrDriver},
		{"relative home", func(in *Input) { in.Home = "home/dev" }, ErrPath},
		{"root home", func(in *Input) { in.Home = "/" }, ErrPath},
		{"unclean bind", func(in *Input) { in.Binds = append(in.Binds, Bind{Source: "/srv/../etc", Target: "/srv/../etc"}) }, ErrPath},
		{"control char", func(in *Input) { in.Binds = append(in.Binds, Bind{Source: "/srv/a\nb", Target: "/srv/a\nb"}) }, ErrPath},
		{"reserved target", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/opt/openshell/bin", Target: "/opt/openshell/bin"})
		}, ErrReserved},
		{"ancestor of a reserved root", func(in *Input) { in.Binds = append(in.Binds, Bind{Source: "/run", Target: "/run"}) }, ErrReserved},
		{"the openshell workspace root", func(in *Input) { in.Binds = append(in.Binds, Bind{Source: "/sandbox", Target: "/sandbox"}) }, ErrReserved},
		{"duplicate target", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/.claude", Target: "/home/dev/.claude", ReadOnly: true})
		}, ErrDuplicate},
		{"bind at the home", func(in *Input) {
			in.ObserverDir = testOutsideObsDir
			in.Binds = append(in.Binds, Bind{Source: testHome, Target: testHome})
		}, ErrCredential},
		{"duplicate target outside the home", func(in *Input) {
			in.Scope.ToolState = append(in.Scope.ToolState, "/srv/state")
			in.Binds = append(in.Binds, Bind{Source: "/srv/state", Target: "/srv/state"}, Bind{Source: "/srv/state", Target: "/srv/state", ReadOnly: true})
		}, ErrDuplicate},
		{"observer dir whole", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: testObsDir, Target: testObsDir, ReadOnly: true})
		}, ErrObserverDir},
		{"an ancestor of the observer dir", func(in *Input) { in.Binds = []Bind{{Source: "/home", Target: "/home", ReadOnly: true}} }, ErrObserverDir},
		{"writable under the observer dir", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/.observer/x", Target: "/home/dev/.observer/x"})
		}, ErrObserverDir},
		{"a bind of the resolved observer dir's parent", func(in *Input) {
			in.ObserverDirResolved = "/data/observer"
			in.Scope.BinPaths = append(in.Scope.BinPaths, "/data")
			in.Binds = append(in.Binds, Bind{Source: "/data", Target: "/data", ReadOnly: true})
		}, ErrObserverDir},
		{"writable under the resolved observer dir", func(in *Input) {
			in.ObserverDirResolved = "/data/observer"
			in.Scope.BinPaths = append(in.Scope.BinPaths, "/data/observer/run")
			in.Binds = append(in.Binds, Bind{Source: "/data/observer/run", Target: "/data/observer/run"})
		}, ErrObserverDir},
		{"readonly home holds the resolved observer dir", func(in *Input) {
			in.Settings.HomeMode = HomeReadonly
			in.ObserverDir = testOutsideObsDir
			in.ObserverDirResolved = "/home/dev/.observer"
			in.Binds = nil
		}, ErrObserverDir},
		{"a relative resolved observer dir", func(in *Input) { in.ObserverDirResolved = "data/observer" }, ErrPath},
		{"a colon in a bind source", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/src/app/a:b", Target: "/home/dev/src/app/a:b", ReadOnly: true})
		}, ErrPath},
		{"a comma in a bind target", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/src/app/a,ro", Target: "/home/dev/src/app/a,ro", ReadOnly: true})
		}, ErrPath},
		{"a colon in the home", func(in *Input) { in.Home = "/home/dev:x" }, ErrPath},
		{"the docker socket as a read-only file bind", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/var/run/docker.sock", Target: "/var/run/docker.sock", ReadOnly: true, File: true})
		}, ErrScope},
		{"a source outside the scope", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/srv/data", Target: "/srv/data", ReadOnly: true})
		}, ErrScope},
		{"a sibling of the workspace outside the home", func(in *Input) {
			in.Scope = Scope{Workspace: "/srv/app", SocketDir: "/tmp/observer-sbx-RUN"}
			in.Binds = []Bind{{Source: "/srv/app", Target: "/srv/app"}, {Source: "/srv/app2", Target: "/srv/app2"}}
		}, ErrScope},
		{"a different-path bind", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/src/app/sub", Target: "/home/dev/elsewhere"})
		}, ErrSamePath},
		{"a different-path read-only file bind", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/.observer/bin/observer", Target: "/usr/local/bin/observer", ReadOnly: true, File: true})
		}, ErrSamePath},
		{"no workspace in the scope", func(in *Input) { in.Scope.Workspace = "" }, ErrScope},
		{"no socket dir in the scope", func(in *Input) { in.Scope.SocketDir = "" }, ErrScope},
		{"the root directory as a bin path", func(in *Input) { in.Scope.BinPaths = []string{"/"} }, ErrScope},
		{"a relative scope root", func(in *Input) { in.Scope.SocketDir = "tmp/observer-sbx-RUN" }, ErrPath},
		{"readonly home holds the observer dir", func(in *Input) { in.Settings.HomeMode = HomeReadonly }, ErrObserverDir},
		{"readonly home is the observer dir", func(in *Input) {
			in.Settings.HomeMode = HomeReadonly
			in.ObserverDir = testHome
			in.Binds = nil
		}, ErrObserverDir},
		{"copied file outside a writable mount", func(in *Input) {
			in.Settings.HomeMode = HomeReadonly
			in.ObserverDir = testOutsideObsDir
			in.Binds = []Bind{{Source: "/home/dev/.claude.json", Target: "/home/dev/.claude.json", File: true}}
		}, ErrCopyTarget},
		{"copied file under a read-only bind under the tmpfs home", func(in *Input) {
			in.Binds = append(in.Binds,
				Bind{Source: "/home/dev/.config/tool", Target: "/home/dev/.config/tool", ReadOnly: true},
				Bind{Source: "/home/dev/.config/tool/state.json", Target: "/home/dev/.config/tool/state.json", File: true})
		}, ErrCopyTarget},
		// Audit finding O1A-R1: the home is not a scope root; a subtree of it
		// enters only through a named tool-state root, and never a
		// credential path.
		{"a writable bind of ~/.ssh", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/.ssh", Target: "/home/dev/.ssh"})
		}, ErrCredential},
		{"a read-only bind of Docker Desktop's socket under the home", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/.docker/desktop/docker.sock", Target: "/home/dev/.docker/desktop/docker.sock", ReadOnly: true, File: true})
		}, ErrCredential},
		{"a home subtree no tool-state row names", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/Documents", Target: "/home/dev/Documents", ReadOnly: true})
		}, ErrScope},
		{"a bind that holds a credential path", func(in *Input) {
			in.Scope.ToolState = append(in.Scope.ToolState, "/home/dev/.config/tool2")
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/.config", Target: "/home/dev/.config", ReadOnly: true})
		}, ErrCredential},
		{"~/.ssh named as a tool-state root", func(in *Input) {
			in.Scope.ToolState = append(in.Scope.ToolState, "/home/dev/.ssh")
		}, ErrCredential},
		{"the openshell client certificates named as a tool-state root", func(in *Input) {
			in.Scope.ToolState = append(in.Scope.ToolState, "/home/dev/.config/openshell/gateways")
		}, ErrCredential},
		// Audit finding O1A-R2: under the observer dir only a read-only bind
		// of an exact bin path.
		{"a read-only bind of observer.db", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/.observer/observer.db", Target: "/home/dev/.observer/observer.db", ReadOnly: true, File: true})
		}, ErrObserverDir},
		{"a read-only bind of the attach socket's dir", func(in *Input) {
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/.observer/run", Target: "/home/dev/.observer/run", ReadOnly: true})
		}, ErrObserverDir},
		{"a read-only bind of the resolved observer dir's socket dir", func(in *Input) {
			in.ObserverDirResolved = "/data/observer"
			in.Binds = append(in.Binds, Bind{Source: "/data/observer/run", Target: "/data/observer/run", ReadOnly: true})
		}, ErrObserverDir},
		// Audit finding O1B-A9: a dir under the observer dir is never a bin
		// path, even read-only and named.
		{"the attach socket's dir named as a bin path", func(in *Input) {
			in.Scope.BinPaths = append(in.Scope.BinPaths, "/home/dev/.observer/run")
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/.observer/run", Target: "/home/dev/.observer/run", ReadOnly: true})
		}, ErrObserverDir},
		{"the observer dir named as a bin path", func(in *Input) {
			in.Scope.BinPaths = append(in.Scope.BinPaths, "/home/dev/.observer")
		}, ErrObserverDir},
		{"a file beside the observer binary", func(in *Input) {
			in.Scope.BinPaths = append(in.Scope.BinPaths, "/home/dev/.observer/bin")
			in.Binds = append(in.Binds, Bind{Source: "/home/dev/.observer/bin/token", Target: "/home/dev/.observer/bin/token", ReadOnly: true, File: true})
		}, ErrObserverDir},
		// Audit finding O1A-R3: bin paths are exact; system roots, kernel
		// and runtime trees and the home's ancestors are never scope roots.
		{"a file beneath a bin path dir", func(in *Input) {
			in.Scope.BinPaths = append(in.Scope.BinPaths, "/opt/tool")
			in.Binds = append(in.Binds, Bind{Source: "/opt/tool/secret", Target: "/opt/tool/secret", ReadOnly: true, File: true})
		}, ErrScope},
		{"/var as a bin path", func(in *Input) { in.Scope.BinPaths = append(in.Scope.BinPaths, "/var") }, ErrScope},
		{"/usr as a bin path", func(in *Input) { in.Scope.BinPaths = append(in.Scope.BinPaths, "/usr") }, ErrScope},
		{"/etc as a bin path", func(in *Input) { in.Scope.BinPaths = append(in.Scope.BinPaths, "/etc") }, ErrScope},
		{"a socket under /run as a bin path", func(in *Input) {
			in.Scope.BinPaths = append(in.Scope.BinPaths, "/run/docker.sock")
		}, ErrScope},
		{"a socket under /var/run as a bin path", func(in *Input) {
			in.Scope.BinPaths = append(in.Scope.BinPaths, "/var/run/docker.sock")
		}, ErrScope},
		{"the workspace at /home", func(in *Input) {
			in.ObserverDir = testOutsideObsDir
			in.Scope.Workspace = "/home"
			in.Binds = []Bind{{Source: "/home", Target: "/home"}}
		}, ErrScope},
		{"the workspace at the home itself", func(in *Input) {
			in.ObserverDir = testOutsideObsDir
			in.Scope.Workspace = testHome
			in.Binds = []Bind{{Source: "/tmp/observer-sbx-RUN", Target: "/tmp/observer-sbx-RUN", ReadOnly: true}}
		}, ErrScope},
		{"a tool-state root at an ancestor of the home", func(in *Input) {
			in.Scope.ToolState = append(in.Scope.ToolState, "/srv/homes")
			in.Home = "/srv/homes/dev"
		}, ErrScope},
		{"env without =", func(in *Input) { in.Env = []string{"NOVALUE"} }, ErrEnv},
		{"env sets HOME", func(in *Input) { in.Env = []string{"HOME=/root"} }, ErrEnv},
		{"env bad key", func(in *Input) { in.Env = []string{"1X=y"} }, ErrEnv},
		{"too many paths", func(in *Input) {
			in.Scope.ToolState = append(in.Scope.ToolState, "/srv/many")
			for i := 0; i < 260; i++ {
				p := "/srv/many/" + strings.Repeat("d", 1+i%20) + "/" + string(rune('a'+i%26)) + string(rune('a'+i/26))
				in.Binds = append(in.Binds, Bind{Source: p, Target: p, ReadOnly: true})
			}
		}, ErrTooManyPaths},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			tc.mut(&in)
			if _, err := Compile(in); !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
		})
	}
}

// TestCompileRulesHaveCases keeps the input rows and their refusal cases in
// step.
func TestCompileRulesHaveCases(t *testing.T) {
	t.Parallel()
	want := []string{"K1 root", "K2 tier", "K6 home mode", "K7 driver", "K8 home and observer dir", "K9 readonly home holds the observer dir", "K10 scope roots"}
	if len(compileRules) != len(want) {
		t.Fatalf("%d compile rows, TestCompileRefusals covers %v", len(compileRules), want)
	}
	for i, r := range compileRules {
		if r.id != want[i] {
			t.Errorf("row %d is %q, want %q", i, r.id, want[i])
		}
	}
}

// TestCompileAccepts: the base input compiles to a policy with Landlock as
// a hard requirement and no network rule, HOME first in the environment.
func TestCompileAccepts(t *testing.T) {
	t.Parallel()
	in := baseInput()
	in.Settings.Driver = "docker"
	p, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(p.PolicyYAML), "compatibility: hard_requirement") || strings.Contains(string(p.PolicyYAML), "network_policies") {
		t.Fatalf("policy %s", p.PolicyYAML)
	}
	if p.Env[0] != "HOME="+testHome {
		t.Fatalf("env %v", p.Env)
	}
}

// TestCompileAcceptsLowRows: the accepting side of audit findings O1A-A4
// and O1A-A5: a second observer-dir spelling that no bind reaches compiles,
// and a copied file whose innermost mount is a writable bind nested in a
// read-only one compiles.
func TestCompileAcceptsLowRows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(*Input)
	}{
		{"both observer-dir spellings", func(in *Input) { in.ObserverDirResolved = "/data/observer" }},
		{"the same spelling twice", func(in *Input) { in.ObserverDirResolved = testObsDir }},
		{"copy under a writable bind under a read-only bind", func(in *Input) {
			in.Binds = append(in.Binds,
				Bind{Source: "/home/dev/.config/tool", Target: "/home/dev/.config/tool", ReadOnly: true},
				Bind{Source: "/home/dev/.config/tool/rw", Target: "/home/dev/.config/tool/rw"},
				Bind{Source: "/home/dev/.config/tool/rw/state.json", Target: "/home/dev/.config/tool/rw/state.json", File: true})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			tc.mut(&in)
			if _, err := Compile(in); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestNestedReadOnlyAfterParent: a read-only bind nested in a writable one
// is mounted after it (U-31), whatever the bind plan's order.
func TestNestedReadOnlyAfterParent(t *testing.T) {
	t.Parallel()
	in := baseInput()
	in.Binds = []Bind{
		{Source: "/home/dev/src/app/.git/hooks", Target: "/home/dev/src/app/.git/hooks", ReadOnly: true},
		{Source: "/home/dev/src/app", Target: "/home/dev/src/app"},
	}
	p, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	idx := map[string]int{}
	for i, m := range p.Mounts {
		idx[m.Target] = i
	}
	if idx["/home/dev/src/app"] >= idx["/home/dev/src/app/.git/hooks"] {
		t.Fatalf("mount order %+v", p.Mounts)
	}
}

// TestCheckScopeRootExported: the driver's pre-filter answers like K10.
func TestCheckScopeRootExported(t *testing.T) {
	t.Parallel()
	cases := []struct {
		root string
		file bool
		want error
	}{
		{"/home/dev/.local/share/claude/versions/2.1.0", false, nil},
		{"/opt/tool/bin", false, nil},
		{"/usr/bin", false, ErrScope},
		{"/home/dev", false, ErrScope},
		{"/home/dev/.local/share", false, ErrCredential},
		{"/run/user/1000", false, ErrScope},
		{"rel/dir", false, ErrPath},
		// Audit finding O1B-A9: under the observer dir only a regular file.
		{"/home/dev/.observer/bin/observer", true, nil},
		{"/home/dev/.observer/run", false, ErrObserverDir},
		{"/home/dev/.observer/bin", false, ErrObserverDir},
		{"/home/dev/.observer", false, ErrObserverDir},
		{"/home/dev/.observer", true, ErrObserverDir},
		{"/data/observer/run", false, ErrObserverDir},
	}
	in := Input{Home: testHome, ObserverDir: testObsDir, ObserverDirResolved: "/data/observer"}
	for _, tc := range cases {
		if err := CheckScopeRoot(in, tc.root, tc.file); !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Errorf("%s (file %v): %v, want %v", tc.root, tc.file, err, tc.want)
		}
	}
}

// TestSharedHomeAgreesWithCompile: SharedHome, which the driver's posture
// note reads before the compile, is the compiled Plan.SharedHome for every
// home_mode that compiles.
func TestSharedHomeAgreesWithCompile(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"", HomeTmpfs, HomeReadonly} {
		in := baseInput()
		in.Settings.HomeMode = mode
		if mode == HomeReadonly {
			in.ObserverDir = testOutsideObsDir
			in.Scope.BinPaths = nil
			in.Binds = []Bind{{Source: "/tmp/observer-sbx-RUN", Target: "/tmp/observer-sbx-RUN", ReadOnly: true}}
		}
		p, err := Compile(in)
		if err != nil {
			t.Fatalf("%q: %v", mode, err)
		}
		if p.SharedHome != SharedHome(mode) {
			t.Errorf("%q: compiled %v, SharedHome %v", mode, p.SharedHome, SharedHome(mode))
		}
	}
}
