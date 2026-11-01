//go:build !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxsbpl"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_mac_merge_test.go covers the fixes made when lane SBX-P5
// merged (audit F1 to F6 and ruling P-062 for the macOS rows) on the parts
// that run on any host: the path resolver over real symlinks, the profile
// built from it, the self-test's home rule, module_inactive on macOS, the
// automatic choice and the Apple env file's place.

// macLinkTree builds a tree under a temp root with real symlinks: tmp ->
// private/tmp (the macOS /tmp shape), link -> real (a symlinked project
// dir), and real/app/.git -> realgit inside the workspace.
func macLinkTree(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"private/tmp", "real/app/realgit/hooks", "home/.observer", "T"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "real/app/realgit/config"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"tmp": "private/tmp", "link": "real", "real/app/.git": "realgit"} {
		if err := testSymlink(t, target, filepath.Join(root, link)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	return root
}

// TestSandboxCanonicalPath: the resolver follows every link, a missing tail
// stays as written, a dangling link resolves to where a write would land,
// and a loop is refused.
func TestSandboxCanonicalPath(t *testing.T) {
	skipOnWindows(t, "the resolver serves the macOS Seatbelt driver")
	root := macLinkTree(t)
	cases := map[string]string{
		filepath.Join(root, "tmp", "x"):                     filepath.Join(root, "private", "tmp", "x"),
		filepath.Join(root, "link", "app"):                  filepath.Join(root, "real", "app"),
		filepath.Join(root, "link", "app", ".git", "hooks"): filepath.Join(root, "real", "app", "realgit", "hooks"),
		filepath.Join(root, "real", "app", "missing", "a"):  filepath.Join(root, "real", "app", "missing", "a"),
	}
	for in, want := range cases {
		if got := sandboxCanonicalPath(in); got != want {
			t.Errorf("%s -> %q, want %q", in, got, want)
		}
	}
	if err := testSymlink(t, "../nowhere/hooks", filepath.Join(root, "real", "dangling")); err != nil {
		t.Fatal(err)
	}
	if got := sandboxCanonicalPath(filepath.Join(root, "real", "dangling", "x")); got != filepath.Join(root, "nowhere", "hooks", "x") {
		t.Errorf("dangling link -> %q", got)
	}
	if err := testSymlink(t, "loop", filepath.Join(root, "loop")); err != nil {
		t.Fatal(err)
	}
	if got := sandboxCanonicalPath(filepath.Join(root, "loop", "x")); got != "" {
		t.Errorf("a link loop resolved to %q", got)
	}
	if sandboxCanonicalPath("relative/path") != "" {
		t.Error("a relative path resolved")
	}
}

// macTreeRequest is a Seatbelt request over the tree, spelled through its
// links as a user would type them.
func macTreeRequest(root string) sandboxsbpl.Request {
	ws := filepath.Join(root, "link", "app")
	return sandboxsbpl.Request{
		Home: filepath.Join(root, "home"), ObserverDir: filepath.Join(root, "home", ".observer"),
		WorkspaceRoot: ws, ObserverBin: "/usr/bin/true",
		TempDir:      filepath.Join(root, "T", "obsbx-tmp", "run1"),
		SocketParent: filepath.Join(root, "T", "obsbx"), SocketDir: filepath.Join(root, "T", "obsbx", "run1"),
		TempRoots: []string{filepath.Join(root, "T"), filepath.Join(root, "tmp")},
		Overlays: []sandbox.Overlay{
			{Path: filepath.Join(ws, ".git", "config"), Kind: sandbox.OverlayReadOnly},
			{Path: filepath.Join(ws, ".git", "hooks"), Kind: sandbox.OverlayReadOnly},
		},
		Net: sandboxsbpl.Net{Egress: sandbox.EgressInternet, ProxyPort: 8820, GatewayPort: 50123},
	}
}

// TestSeatbeltProfileFromRealSymlinks (F1): the seam's resolver turns a
// symlinked workspace and a .git that links inside it into resolved
// parameters; the hooks and config stay unwritable at their target, the
// link cannot be replaced, the shared temp root reached through tmp ->
// private/tmp is hidden at its resolved path, and the unresolved request
// is refused by name.
func TestSeatbeltProfileFromRealSymlinks(t *testing.T) {
	skipOnWindows(t, "Seatbelt is the macOS driver")
	root := macLinkTree(t)
	raw := macTreeRequest(root)
	raw.Resolve = sandboxCanonicalPath
	if _, err := sandboxsbpl.Build(raw); err == nil || !strings.Contains(err.Error(), sandboxsbpl.ReasonUnresolvedPath) {
		t.Fatalf("the unresolved request: %v", err)
	}
	req, err := sandboxsbpl.Canonicalize(macTreeRequest(root), sandboxCanonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	if req.WorkspaceRoot != filepath.Join(root, "real", "app") || req.TempRoots[1] != filepath.Join(root, "private", "tmp") {
		t.Fatalf("canonical workspace %q temp roots %q", req.WorkspaceRoot, req.TempRoots)
	}
	p, err := sandboxsbpl.Build(req)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := sandboxsbpl.Check(p.Text, p.ParamMap())
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(root, "real", "app")
	for _, c := range []struct {
		op, path string
		want     bool
	}{
		{"file-write-create", filepath.Join(ws, "realgit", "hooks", "pre-commit"), false},
		{"file-write-data", filepath.Join(ws, "realgit", "config"), false},
		{"file-write-unlink", filepath.Join(ws, ".git"), false},
		{"file-write-unlink", filepath.Join(ws, "realgit"), false},
		{"file-write-data", filepath.Join(ws, "realgit", "objects", "ab"), true},
		{"file-write-data", filepath.Join(ws, "main.go"), true},
		{"file-read-data", filepath.Join(root, "private", "tmp", "other-run", "env"), false},
		{"file-read-data", filepath.Join(root, "T", "obsbx-tmp", "run2", "x"), false},
		{"file-write-data", filepath.Join(root, "T", "obsbx-tmp", "run1", "x"), true},
	} {
		if got := sandboxsbpl.Allowed(rules, p.ParamMap(), sandboxsbpl.Query{Op: c.op, Path: c.path}); got != c.want {
			t.Errorf("%s %s: allowed %v, want %v", c.op, c.path, got, c.want)
		}
	}
}

// TestSeatbeltHomeBlinded (F4): the self-test expects an unlisted home in
// tmpfs mode, except when the workspace is the home or holds it, which the
// workspace_is_home golden supports.
func TestSeatbeltHomeBlinded(t *testing.T) {
	skipDriverOffHost(t, "Seatbelt")
	cases := []struct {
		mode, ws string
		want     bool
	}{
		{"", "/Users/dev/src/app", true},
		{sandboxsbpl.HomeModeTmpfs, "/Users/dev", false},
		{sandboxsbpl.HomeModeTmpfs, "/Users", false},
		{sandboxsbpl.HomeModeTmpfs, "/Users/devx", true},
		{sandboxsbpl.HomeModeReadonly, "/Users/dev/src/app", false},
	}
	for _, c := range cases {
		req := sandboxsbpl.Request{Home: "/Users/dev", HomeMode: c.mode, WorkspaceRoot: c.ws}
		if got := seatbeltHomeBlinded(req); got != c.want {
			t.Errorf("mode %q workspace %s: blinded %v, want %v", c.mode, c.ws, got, c.want)
		}
	}
	req := sandboxsbpl.Request{ObserverDir: "/o", SocketParent: "/s", Home: "/Users/dev", WorkspaceRoot: "/Users/dev", TempDir: "/t"}
	flags, err := seatbeltSelfTestFlags(seatbeltSelfTestArgv("/bin/observer", req)[2:])
	if err != nil || flags["--home-blinded"] != "false" {
		t.Fatalf("a workspace at the home: %v %v", flags, err)
	}
	if v := sandboxsbpl.JudgeSelfTest(sandboxsbpl.SelfTestReport{HomeListable: true, WorkspaceWritable: true, TempWritable: true}, seatbeltHomeBlinded(req)); !v.OK() {
		t.Fatalf("a workspace at the home failed its self-test: %v", v)
	}
}

// TestMacDriversModuleInactiveOnMacOS (F6): on a Mac, a listed macOS driver
// whose component is not selected reports module_inactive, never
// backend_version_untested (S2b runs after S4).
func TestMacDriversModuleInactiveOnMacOS(t *testing.T) {
	for _, id := range []string{sandboxbackend.BackendSeatbelt, sandboxbackend.BackendAppleContainer} {
		rt := macTestRuntime(t, seatbeltTestConfig(t, false, id))
		probes := rt.driverProbes(context.Background())
		for _, backend := range []string{"", id} {
			in := sandboxselect.Input{
				Request: sandboxselect.Request{Backend: backend, Tier: vocab.TierInternet, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
				Host:    sandboxbackend.HostMacOS, Enabled: []string{id}, Probes: probes,
				Tool: sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
			}
			got := sandboxselect.Select(in)
			if got.Chosen != nil || len(got.Drops) == 0 || got.Drops[0].Verdict != verdictModuleInactive {
				t.Errorf("%s (request %q): %+v, want module_inactive", id, backend, got.Drops)
			}
		}
	}
}

// TestMacRowsNeverAutoPicked (ruling P-062 for the macOS rows): the rows
// are dropped from an automatic choice by their doc verification (S4c, the
// one table; no explicit-only switch), a launch that names one gets it, a
// non-beta row later in the list wins, and a launch with only the beta rows
// available refuses naming the first as available but not chosen.
func TestMacRowsNeverAutoPicked(t *testing.T) {
	for _, id := range []string{sandboxbackend.BackendSeatbelt, sandboxbackend.BackendAppleContainer} {
		row, _ := sandboxbackend.Get(id)
		if row.ExplicitOnly {
			t.Errorf("%s carries ExplicitOnly; the verification rule is the one mechanism", id)
		}
		v, _ := row.VerificationOn(sandboxbackend.HostMacOS)
		if d, dropped := sandboxselect.AutoDrop(row, v.Kind); !dropped || d.Rule != "S4c" || d.Verdict != sandboxselect.VerdictBetaNotChosen || !strings.Contains(d.Reason, "--observer-sandbox "+id) {
			t.Errorf("%s: AutoDrop %+v", id, d)
		}
	}
	rows := map[string]dashapi.SandboxBackendAvail{
		sandboxbackend.BackendSeatbelt:       {ID: sandboxbackend.BackendSeatbelt, Available: true, Beta: true, Verification: string(vocab.VerifiedDoc)},
		sandboxbackend.BackendAppleContainer: {ID: sandboxbackend.BackendAppleContainer, Available: true, Beta: true, Verification: string(vocab.VerifiedDoc)},
		sandboxbackend.BackendOCIRunc:        {ID: sandboxbackend.BackendOCIRunc, Available: true, Verification: string(vocab.VerifiedLive)},
		sandboxbackend.BackendBwrap:          {ID: sandboxbackend.BackendBwrap, Available: false, Verdict: "unsupported_platform"},
	}
	all := func(string) bool { return true }
	mac := []string{sandboxbackend.BackendAppleContainer, sandboxbackend.BackendSeatbelt}
	p := sandboxLaunchPick(mac, rows, true, all)
	if p.chosen != "" || p.skipped == nil || p.skipped.ID != sandboxbackend.BackendAppleContainer || p.drop.Verdict != sandboxselect.VerdictBetaNotChosen {
		t.Fatalf("auto over the macOS rows: %+v", p)
	}
	if err := p.betaRefusal(mac, rows); err == nil || !strings.Contains(err.Error(), "apple-container is available but not chosen") {
		t.Fatalf("refusal %v", err)
	}
	for _, id := range mac {
		if p := sandboxLaunchPick([]string{id}, rows, false, all); p.chosen != id {
			t.Errorf("a launch naming %s got %+v", id, p)
		}
	}
	if p := sandboxLaunchPick(append(append([]string(nil), mac...), sandboxbackend.BackendOCIRunc), rows, true, all); p.chosen != sandboxbackend.BackendOCIRunc {
		t.Fatalf("the first non-beta row: %+v", p)
	}
	// The selection table agrees on a macOS host where Seatbelt probes
	// available: auto drops it at S4c, a named launch chooses it as beta.
	probe := seatbeltSelectProbe(sandboxsbpl.ProbeResult{Verdict: sandboxsbpl.Verdict{Code: sandboxsbpl.VerdictAvailable}, OSVersion: "26.0"}, nil)
	in := sandboxselect.Input{
		Request: sandboxselect.Request{Tier: vocab.TierInternet, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
		Host:    sandboxbackend.HostMacOS, Enabled: []string{sandboxbackend.BackendSeatbelt},
		Probes: map[string]sandboxselect.Probe{sandboxbackend.BackendSeatbelt: probe},
		Tool:   sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
	}
	if got := sandboxselect.Select(in); got.Chosen != nil || len(got.Drops) == 0 || got.Drops[0].Backend != sandboxbackend.BackendSeatbelt || got.Drops[0].Rule != "S4c" {
		t.Fatalf("auto on macOS: %+v", got)
	}
}

// TestAppleEnvFileIsLauncherOnly (F3): the run's env file lives in a fresh
// 0700 dir under the observer dir (hidden from every Seatbelt box, never in
// the shared temp space), is 0600, and is gone after remove.
func TestAppleEnvFileIsLauncherOnly(t *testing.T) {
	skipDriverOffHost(t, "apple container")
	obs := t.TempDir()
	p, remove, err := writeAppleEnvFile(obs, "RunAbc_123", []byte("ANTHROPIC_API_KEY=sk-test\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, obs+string(filepath.Separator)) || strings.HasPrefix(p, filepath.Clean(os.TempDir())+string(filepath.Separator)+"obsbx") {
		t.Fatalf("env file at %s", p)
	}
	fi, err := os.Stat(p)
	if err != nil || (posixModes && fi.Mode().Perm() != 0o600) {
		t.Fatalf("env file mode %v %v", fi, err)
	}
	if di, err := os.Stat(filepath.Dir(p)); err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("env dir mode %v %v", di, err)
	}
	if _, _, err := writeAppleEnvFile(obs, "RunAbc_123", nil); err == nil {
		t.Fatal("a second env file was written over the first run's dir")
	}
	remove()
	remove()
	if _, err := os.Stat(filepath.Dir(p)); !os.IsNotExist(err) {
		t.Fatalf("the env dir survived remove: %v", err)
	}
	for _, bad := range []string{"", "../x", "a/b"} {
		if _, _, err := writeAppleEnvFile(obs, bad, nil); err == nil {
			t.Errorf("run id %q accepted", bad)
		}
	}
}

// TestMacCannotRunReason: on a Mac whose macOS drivers are compiled but not
// selected (every distro's default), a machine that must sandbox is told it
// cannot, naming the opt-in; selecting one clears the reason.
func TestMacCannotRunReason(t *testing.T) {
	cfg := seatbeltTestConfig(t, false, sandboxbackend.BackendSeatbelt)
	if why := sandboxCannotRunReason(cfg, sandboxbackend.HostMacOS); !strings.Contains(why, "no sandbox backend selected") {
		t.Fatalf("unselected: %q", why)
	}
	cfg = seatbeltTestConfig(t, true, sandboxbackend.BackendSeatbelt)
	if why := sandboxCannotRunReason(cfg, sandboxbackend.HostMacOS); why != "" {
		t.Fatalf("selected: %q", why)
	}
}
