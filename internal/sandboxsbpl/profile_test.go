package sandboxsbpl

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

var update = flag.Bool("update", false, "rewrite the golden profiles")

// baseRequest is a fixed macOS-shaped request the golden and oracle tests
// share (paths as the cmd seam would resolve them).
func baseRequest(tier sandbox.Egress) Request {
	return Request{
		Home:            "/Users/dev",
		ObserverDir:     "/Users/dev/.observer",
		WorkspaceRoot:   "/Users/dev/src/app",
		ObserverBin:     "/opt/homebrew/bin/observer",
		ObserverRealDir: "/opt/homebrew/Cellar/observer/1.40.0/bin",
		TempDir:         "/private/var/folders/xy/abc/T/obsbx-tmp/run1",
		SocketParent:    "/private/var/folders/xy/abc/T/obsbx",
		SocketDir:       "/private/var/folders/xy/abc/T/obsbx/run1",
		ToolBinDirs:     []string{"/Users/dev/.local/bin", "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code"},
		StateRW:         []string{".claude", ".claude.json"},
		StateRO:         []string{".gitconfig"},
		RuntimeLadder:   []string{".nvm"},
		Overlays: []sandbox.Overlay{
			{Path: "/Users/dev/.observer/config.toml", Kind: sandbox.OverlayReadOnly},
			{Path: "/Users/dev/src/app/.git/config", Kind: sandbox.OverlayReadOnly},
			{Path: "/Users/dev/src/app/.git/hooks", Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderDir},
			{Path: "/Users/dev/.claude/.credentials.json", Kind: sandbox.OverlayHideFile},
		},
		TempRoots: []string{"/private/var/folders/xy/abc/T", "/private/tmp"},
		TTY:       "/dev/ttys004",
		Net:       Net{Egress: tier, ProxyPort: 8820, GatewayPort: 50123},
		// Every path above is already resolved: identity stands in for the
		// filesystem (resolve_test.go covers resolution itself).
		Resolve: identity,
	}
}

func identity(p string) string { return p }

func TestGoldenProfiles(t *testing.T) {
	cases := map[string]func() Request{
		"internet":   func() Request { return baseRequest(sandbox.EgressInternet) },
		"proxy_only": func() Request { return baseRequest(sandbox.EgressProxyOnly) },
		"none": func() Request {
			r := baseRequest(sandbox.EgressNone)
			r.TTY = ""
			return r
		},
		"readonly_home_keychain": func() Request {
			r := baseRequest(sandbox.EgressInternet)
			r.HomeMode = HomeModeReadonly
			r.MachServices = KeychainMachServices
			return r
		},
		// Lane SHR-FOLLOWUPS (ledger SBX-BE-10): the pins of a launch
		// whose tool may write its config (no .git overlay, so no
		// anchor from the protect table) under an org write bind holding
		// a repository: each pin and the entries above it inside the
		// grant refuse writes at their literal.
		"pins": func() Request {
			r := baseRequest(sandbox.EgressProxyOnly)
			r.ExtraRW = []string{"/Users/dev/build-org"}
			r.Overlays = r.Overlays[:1]
			r.Pins = []string{"/Users/dev/src/app/.git", "/Users/dev/build-org/team/repo", "/Users/dev/build-org/team/repo/.git"}
			return r
		},
		"workspace_is_home": func() Request {
			r := baseRequest(sandbox.EgressProxyOnly)
			r.WorkspaceRoot = "/Users/dev"
			r.Overlays = nil
			return r
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := Build(mk())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Check(p.Text, p.ParamMap()); err != nil {
				t.Fatalf("the generated profile fails the checker: %v\n%s", err, p.Text)
			}
			var params strings.Builder
			for _, x := range p.Params {
				params.WriteString(x.Name + "=" + x.Value + "\n")
			}
			golden(t, filepath.Join("testdata", "golden", name+".sb"), p.Text)
			golden(t, filepath.Join("testdata", "golden", name+".params"), params.String())
		})
	}
}

func golden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: a fixed testdata path
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the generated profile (run with -update after reviewing):\n%s", path, got)
	}
}

func TestBuildRefusals(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Request)
		want string
	}{
		{"host tier", func(r *Request) { r.Net.Egress = sandbox.EgressHost }, "not offered on Seatbelt"},
		{"empty tier", func(r *Request) { r.Net.Egress = "" }, ""},
		{"unknown tier", func(r *Request) { r.Net.Egress = "open" }, "not in"},
		{"relative workspace", func(r *Request) { r.WorkspaceRoot = "src/app" }, "absolute"},
		{"unclean path", func(r *Request) { r.TempDir = "/tmp/../etc" }, "clean"},
		{"control char", func(r *Request) { r.ExtraRO = []string{"/a\nb"} }, "control"},
		{"dotdot state", func(r *Request) { r.StateRW = []string{"../x"} }, ".."},
		{"absolute state", func(r *Request) { r.StateRO = []string{"/etc"} }, "relative"},
		{"rw shows observer dir", func(r *Request) { r.ExtraRW = []string{"/Users/dev"} }, "observer directory"},
		{"rw inside observer dir", func(r *Request) { r.StateRW = []string{".observer/secrets"} }, "observer directory"},
		{"workspace in observer dir", func(r *Request) { r.WorkspaceRoot = "/Users/dev/.observer/other" }, "managed workspaces"},
		{"whole root rw", func(r *Request) { r.ExtraRW = []string{"/"} }, ""},
		{"socket dir outside parent", func(r *Request) { r.SocketDir = "/private/tmp/x" }, "inside the socket parent"},
		{"socket path too long", func(r *Request) {
			r.SocketParent = "/private/var/" + strings.Repeat("d", 80)
			r.SocketDir = r.SocketParent + "/run1"
		}, "too long"},
		{"temp in socket parent", func(r *Request) { r.TempDir = r.SocketParent + "/t" }, "overlaps"},
		{"bad tty", func(r *Request) { r.TTY = "/dev/console" }, "tty"},
		{"bad mach name", func(r *Request) { r.MachServices = []string{"a\") (allow default"} }, "mach"},
		{"bad overlay kind", func(r *Request) { r.Overlays = []sandbox.Overlay{{Path: "/x", Kind: "weird"}} }, "kind"},
		{"proxy port", func(r *Request) { r.Net.ProxyPort = 0 }, "proxy port"},
		{"gateway equals proxy", func(r *Request) { r.Net.GatewayPort = 8820 }, "gateway port"},
		{"bad home mode", func(r *Request) { r.HomeMode = "open" }, "home mode"},
		{"whole-root temp root", func(r *Request) { r.TempRoots = []string{"/"} }, "temp root"},
		{"no resolver", func(r *Request) { r.Resolve = nil }, ReasonUnresolvedPath},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := baseRequest(sandbox.EgressInternet)
			c.mut(&r)
			_, err := Build(r)
			if err == nil {
				t.Fatal("Build accepted the request")
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestPathsAreParametersNeverText(t *testing.T) {
	r := baseRequest(sandbox.EgressInternet)
	r.WorkspaceRoot = "/Users/dev/My Projects/app \"quoted\""
	r.Overlays = nil
	p, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Text, "/Users/dev") || strings.Contains(p.Text, "quoted") {
		t.Fatalf("a path reached the profile text:\n%s", p.Text)
	}
	if p.ParamMap()["WS"] != r.WorkspaceRoot {
		t.Fatalf("WS = %q", p.ParamMap()["WS"])
	}
	if _, err := Check(p.Text, p.ParamMap()); err != nil {
		t.Fatal(err)
	}
}

func TestArgv(t *testing.T) {
	p, err := Build(baseRequest(sandbox.EgressNone))
	if err != nil {
		t.Fatal(err)
	}
	argv := p.Argv(SandboxExecPath, []string{"/opt/homebrew/bin/observer", "claude"})
	if argv[0] != SandboxExecPath || argv[1] != "-p" || argv[2] != p.Text || argv[len(argv)-1] != "claude" {
		t.Fatalf("argv = %q", argv[:3])
	}
	if n := strings.Count(strings.Join(argv, "\x00"), "\x00-D\x00"); n != len(p.Params) {
		t.Fatalf("%d -D flags for %d params", n, len(p.Params))
	}
	if p.Argv(SandboxExecPath, nil) != nil || p.Argv(SandboxExecPath, []string{"-f", "x"}) != nil {
		t.Fatal("an empty or flag-shaped inner argv was accepted")
	}
}

func TestTTYName(t *testing.T) {
	if TTYName(4) != "/dev/ttys004" || TTYName(1234) != "/dev/ttys1234" {
		t.Fatal(TTYName(4), TTYName(1234))
	}
	for _, ok := range []string{"/dev/ttys000", "/dev/ttys1234"} {
		if !ValidTTYPath(ok) {
			t.Error(ok)
		}
	}
	for _, bad := range []string{"/dev/tty", "/dev/ttys", "/dev/ttys0a1", "/dev/ttyp1", "/dev/ttys00"} {
		if ValidTTYPath(bad) {
			t.Error(bad)
		}
	}
}

// TestPinsAnchorRenameAndUnlink (lane SHR-FOLLOWUPS): every pin is a
// write-denied literal (rename and unlink are writes of the entry), so the
// golden above changes when the pins are removed.
func TestPinsAnchorRenameAndUnlink(t *testing.T) {
	r := baseRequest(sandbox.EgressProxyOnly)
	r.ExtraRW = []string{"/Users/dev/build-org"}
	r.Overlays = r.Overlays[:1]
	r.Pins = []string{"/Users/dev/src/app/.git", "/Users/dev/build-org/team/repo/.git", "/Users/elsewhere/.git"}
	p, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	params := p.ParamMap()
	denied := map[string]bool{}
	for _, line := range strings.Split(p.Text, "\n") {
		if !strings.HasPrefix(line, "(deny file-write* (literal (param \"ANCHOR") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(line, "(deny file-write* (literal (param \""), "\")))")
		denied[params[name]] = true
	}
	for _, want := range []string{"/Users/dev/src/app/.git", "/Users/dev/build-org/team/repo/.git", "/Users/dev/build-org/team/repo", "/Users/dev/build-org/team"} {
		if !denied[want] {
			t.Errorf("%s is not a write-denied literal (anchors %v)", want, denied)
		}
	}
	for _, not := range []string{"/Users/elsewhere/.git", "/Users/dev/build-org", "/Users/dev/src/app"} {
		if denied[not] {
			t.Errorf("%s is write-denied; a pin outside a grant or a grant root is not anchored", not)
		}
	}
	r.Pins = nil
	p2, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Text == p.Text {
		t.Fatal("the profile does not depend on the pins")
	}
	if _, err := Build(Request{Pins: []string{"rel/.git"}}); err == nil {
		t.Fatal("a relative pin accepted")
	}
}
