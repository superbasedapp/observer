package sandbox

import (
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// skipUnlessPOSIXPlanner skips a test that builds a whole bwrap plan from
// /home/... literals: the planner is Linux-only and validates with
// filepath.IsAbs, which refuses a bare /home/dev on Windows (the same reason
// the older BuildPlan tests of this package fail there). The walk and the
// rule table are tested without it, on every host.
func skipUnlessPOSIXPlanner(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("bwrap plans are POSIX-only: filepath.IsAbs rejects /home/... on Windows")
	}
}

const maskWS = "/home/dev/.observer/workspaces/abc/repo"

// maskTree is a small workspace: a .env and its committed example, a source
// folder holding a key, a .git, and a node_modules, plus a file that is not a
// secret.
func maskTree() *fakeDirs {
	return &fakeDirs{entries: map[string][]MaskDirEntry{
		maskWS:                   {file("README.md"), file(".env"), file(".env.example"), dir("app"), dir(".git"), dir("node_modules")},
		maskWS + "/app":          {file("main.go"), file("server.key")},
		maskWS + "/.git":         {file("secret.pem")},
		maskWS + "/node_modules": {file(".env")},
	}}
}

// defaultGoldenArgv is the argv canonicalReq() has always produced (the
// request of TestBuildPlanArgvGolden), restated here so the default and the
// opted-in plans are pinned side by side: with the option off nothing about
// the plan moved.
func defaultGoldenArgv() []string {
	return []string{
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
}

// TestSecretMaskOffLeavesTheArgvUnchanged: no option means the argv every
// existing launch builds, byte for byte, and a zero report.
func TestSecretMaskOffLeavesTheArgvUnchanged(t *testing.T) {
	skipUnlessPOSIXPlanner(t)
	t.Parallel()
	plan, err := BuildPlan(canonicalReq())
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	got := plan.Argv([]string{"observer", "claude"})
	if want := defaultGoldenArgv(); !reflect.DeepEqual(got, want) {
		t.Fatalf("default argv moved\n got: %#v\nwant: %#v", got, want)
	}
	if slices.Contains(got, devNull) {
		t.Fatal("the default argv carries a /dev/null bind")
	}
	if r := plan.SecretMaskReport(); r.Enabled || len(r.Masked) != 0 || len(r.Gaps) != 0 || r.Complete() {
		t.Fatalf("default report = %+v, want the zero report", r)
	}
}

// TestSecretMaskOnGolden: the exact argv with the option on over maskTree:
// the default argv plus one --ro-bind /dev/null per secret file, after every
// overlay and before the environment drops.
func TestSecretMaskOnGolden(t *testing.T) {
	skipUnlessPOSIXPlanner(t)
	t.Parallel()
	req := canonicalReq()
	req.SecretMask = &SecretMaskOption{ReadDir: maskTree().read}
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	got := plan.Argv([]string{"observer", "claude"})

	off := defaultGoldenArgv()
	at := slices.Index(off, "--unsetenv")
	want := slices.Concat(off[:at],
		[]string{
			"--ro-bind", "/dev/null", "/home/dev/.observer/workspaces/abc/repo/.env",
			"--ro-bind", "/dev/null", "/home/dev/.observer/workspaces/abc/repo/app/server.key",
		},
		off[at:])
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("masked argv mismatch\n got: %#v\nwant: %#v", got, want)
	}
	rep := plan.SecretMaskReport()
	if !rep.Enabled || !rep.Complete() || !reflect.DeepEqual(rep.Masked, []string{maskWS + "/.env", maskWS + "/app/server.key"}) {
		t.Fatalf("report = %+v", rep)
	}
	// The committed example, the non-secret file, .git and node_modules are
	// untouched.
	for _, kept := range []string{"/.env.example", "/README.md", "/.git/secret.pem", "/node_modules/.env"} {
		if slices.Contains(got, maskWS+kept) {
			t.Errorf("%s must not be masked", kept)
		}
	}
}

// TestSecretMaskOnWithNothingToHideIsTheDefaultArgv: the option is on but the
// workspace holds no secret file: the argv is the default one, and the report
// says it was asked for and is complete.
func TestSecretMaskOnWithNothingToHideIsTheDefaultArgv(t *testing.T) {
	skipUnlessPOSIXPlanner(t)
	t.Parallel()
	req := canonicalReq()
	empty := &fakeDirs{entries: map[string][]MaskDirEntry{maskWS: {file("main.go")}}}
	req.SecretMask = &SecretMaskOption{ReadDir: empty.read}
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if got, want := plan.Argv([]string{"observer", "claude"}), defaultGoldenArgv(); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv moved\n got: %#v\nwant: %#v", got, want)
	}
	if r := plan.SecretMaskReport(); !r.Enabled || !r.Complete() || len(r.Masked) != 0 {
		t.Fatalf("report = %+v, want enabled, complete, nothing masked", r)
	}
}

// TestSecretMaskIsLastAmongTheMounts: the masks come after the protective
// overlays (so no overlay shadows one) and before --chdir, whatever the
// request carries.
func TestSecretMaskIsLastAmongTheMounts(t *testing.T) {
	skipUnlessPOSIXPlanner(t)
	t.Parallel()
	req := canonicalReq()
	req.Overlays = []Overlay{
		{Path: "/home/dev/.observer/remote-secret", Kind: OverlayHideFile},
		{Path: maskWS + "/.git/config", Kind: OverlayReadOnly},
	}
	req.SecretMask = &SecretMaskOption{ReadDir: maskTree().read}
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	argv := plan.Argv([]string{"observer", "claude"})
	lastOverlay := findFlagOperand(argv, "--ro-bind-try", maskWS+"/.git/config")
	firstMask := findFlagOperand(argv, "--ro-bind", devNull)
	// the hide_file overlay of remote-secret also binds /dev/null; find the mask
	maskAt := slices.Index(argv, maskWS+"/.env")
	chdir := slices.Index(argv, "--chdir")
	if lastOverlay < 0 || firstMask < 0 || maskAt < 0 || chdir < 0 {
		t.Fatalf("missing pieces in %v", argv)
	}
	if !(lastOverlay < maskAt && maskAt < chdir) {
		t.Fatalf("mask at %d must follow the overlays (last at %d) and precede --chdir (%d)", maskAt, lastOverlay, chdir)
	}
}

// TestSecretMaskSkipsAPathAnOverlayAlreadyCovers: a second mount over a path
// an earlier overlay already hides would replace that overlay, so it is left
// to it.
func TestSecretMaskSkipsAPathAnOverlayAlreadyCovers(t *testing.T) {
	skipUnlessPOSIXPlanner(t)
	t.Parallel()
	req := canonicalReq()
	req.Overlays = []Overlay{{Path: maskWS + "/.env", Kind: OverlayHideFile}}
	req.SecretMask = &SecretMaskOption{ReadDir: maskTree().read}
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	argv := plan.Argv([]string{"observer", "claude"})
	if n := countFlagOperand(argv, "--ro-bind", devNull); n != 2 {
		t.Fatalf("%d /dev/null binds, want 2 (the overlay's .env and the mask's server.key)", n)
	}
	n := 0
	for i := range argv {
		if argv[i] == maskWS+"/.env" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf(".env appears %d times in the argv, want once", n)
	}
}

// TestSecretMaskDoesNotWalkTheObserverDir: a workspace that is a parent of
// the observer dir (a project at the home directory) must not be walked into
// it; the observer dir has its own protection.
func TestSecretMaskDoesNotWalkTheObserverDir(t *testing.T) {
	skipUnlessPOSIXPlanner(t)
	t.Parallel()
	req := canonicalReq()
	req.WorkspaceRoot = "/home/dev"
	tree := &fakeDirs{entries: map[string][]MaskDirEntry{
		"/home/dev":           {file(".env"), dir(".observer"), dir(".ssh")},
		"/home/dev/.observer": {file(".env"), file("remote-secret")},
		"/home/dev/.ssh":      {file("id_ed25519"), file("id_ed25519.pub"), file("known_hosts")},
	}}
	req.SecretMask = &SecretMaskOption{ReadDir: tree.read}
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if slices.Contains(tree.reads, "/home/dev/.observer") {
		t.Fatal("the walk entered the observer directory")
	}
	want := []string{"/home/dev/.env", "/home/dev/.ssh/id_ed25519", "/home/dev/.ssh/id_ed25519.pub"}
	if got := plan.SecretMaskReport().Masked; !reflect.DeepEqual(got, want) {
		t.Fatalf("Masked = %v, want %v", got, want)
	}
}

// TestSecretMaskPassesAPlainSpaceAsOneArgvElement: a folder or file name with
// a plain space is masked, as one argv element (bwrap is exec'd, never run
// through a shell); a tab is reported, not mounted.
func TestSecretMaskPassesAPlainSpaceAsOneArgvElement(t *testing.T) {
	skipUnlessPOSIXPlanner(t)
	t.Parallel()
	req := canonicalReq()
	tree := &fakeDirs{entries: map[string][]MaskDirEntry{
		maskWS:                  {dir("Client Work"), file("bad\tname.key")},
		maskWS + "/Client Work": {file(".env"), file("Prod Cert.pem")},
	}}
	req.SecretMask = &SecretMaskOption{ReadDir: tree.read}
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	argv := plan.Argv([]string{"observer", "claude"})
	for _, p := range []string{maskWS + "/Client Work/.env", maskWS + "/Client Work/Prod Cert.pem"} {
		if findFlagOperand(argv, "--ro-bind", devNull) < 0 || !slices.Contains(argv, p) {
			t.Errorf("%q is not masked as one argv element in %v", p, argv)
		}
	}
	for _, a := range argv {
		if strings.Contains(a, "\t") {
			t.Fatalf("a tab reached the argv: %q", a)
		}
	}
	rep := plan.SecretMaskReport()
	if rep.Complete() || gapSet(rep)[maskWS+"/bad\tname.key"] != MaskGapUnsafeName {
		t.Fatalf("report = %+v, want the tab-named key reported as unsafe_name", rep)
	}
}

// TestSecretMaskReportIsACopy: a caller cannot reach into the plan through
// the report.
func TestSecretMaskReportIsACopy(t *testing.T) {
	skipUnlessPOSIXPlanner(t)
	t.Parallel()
	req := canonicalReq()
	req.SecretMask = &SecretMaskOption{ReadDir: maskTree().read}
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	r := plan.SecretMaskReport()
	r.Masked[0] = "/tampered"
	if plan.SecretMaskReport().Masked[0] == "/tampered" {
		t.Fatal("SecretMaskReport returned the plan's own slice")
	}
}

// TestSecretMaskWithoutAReaderMasksNothingAndSaysSo: the option without its
// injected listing is not a silent no-op: the report is enabled, incomplete.
func TestSecretMaskWithoutAReaderMasksNothingAndSaysSo(t *testing.T) {
	skipUnlessPOSIXPlanner(t)
	t.Parallel()
	req := canonicalReq()
	req.SecretMask = &SecretMaskOption{}
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if got, want := plan.Argv([]string{"observer", "claude"}), defaultGoldenArgv(); !reflect.DeepEqual(got, want) {
		t.Fatalf("argv moved without a reader\n got: %#v", got)
	}
	if r := plan.SecretMaskReport(); !r.Enabled || r.Complete() {
		t.Fatalf("report = %+v, want enabled and incomplete", r)
	}
}

// TestSecretMaskArgsRefuseAHandBuiltEscape: defence in depth under
// BuildPlan's own walk: a masked path outside the workspace, or one with a
// control character, is refused rather than mounted.
func TestSecretMaskArgsRefuseAHandBuiltEscape(t *testing.T) {
	skipUnlessPOSIXPlanner(t)
	t.Parallel()
	cases := []struct {
		name string
		path string
	}{
		{"outside the workspace", "/etc/shadow"},
		{"a control character", maskWS + "/a\nb.key"},
		{"relative", "repo/.env"},
	}
	for _, tc := range cases {
		_, err := secretMaskArgs(SecretMaskReport{Enabled: true, Root: maskWS, Masked: []string{tc.path}}, nil)
		if err == nil {
			t.Errorf("%s: %q was accepted", tc.name, tc.path)
		}
	}
}
