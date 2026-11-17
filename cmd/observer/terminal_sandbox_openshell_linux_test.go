//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// openShellSentinelKey is a sentinel provider key (never a real one).
const openShellSentinelKey = "sk-ant-SENTINEL-0000"

// TestOpenShellCustodyGoesThroughSandboxcred (lane O1B M4, rule W6): the
// helper's box environment goes through localCredBoxEnv, so a run with a
// credential lane hands the box the lane's sentinel in place of the key,
// and the environment rides in the env file, never on the create argv.
func TestOpenShellCustodyGoesThroughSandboxcred(t *testing.T) {
	prev := localCredBoxEnvHook
	t.Cleanup(func() { localCredBoxEnvHook = prev })
	var sawRun string
	localCredBoxEnvHook = func(h sandbox.HostArgs, env []string) []string {
		sawRun = h.RelayRun
		out := make([]string, 0, len(env))
		for _, kv := range env {
			if strings.HasPrefix(kv, "ANTHROPIC_API_KEY=") {
				kv = "ANTHROPIC_API_KEY=" + sandboxcred.SentinelPrefix + "RUN"
			}
			out = append(out, kv)
		}
		return out
	}
	h := sandbox.HostArgs{RelayRun: "RUN", SockDir: "/tmp/observer-sbx-RUN"}
	environ := []string{"ANTHROPIC_API_KEY=" + openShellSentinelKey, "TERM=xterm", "HOME=/home/dev", "OBSERVER_SANDBOX_ENV_ALLOW=ANTHROPIC_API_KEY"}
	env := openShellHelperEnv(h, openShellBoxEnv(environ))
	if sawRun != "RUN" {
		t.Fatal("the helper's environment did not go through sandboxcred's lane")
	}
	for _, kv := range env {
		if strings.Contains(kv, openShellSentinelKey) {
			t.Fatalf("the provider key reached the box: %q", kv)
		}
	}
	pf := openShellPlanFile{
		Target: sandboxopenshell.Target{Gateway: "openshell"}, Name: sandboxopenshell.SandboxName("RUN-0000-aaaa"),
		PolicyPath: "/s/runs/RUN/policy.yaml", DriverConfigJSON: `{"docker":{"mounts":[]}}`, Env: []string{"HOME=/home/dev"},
	}
	pf.Labels, _ = sandboxopenshell.RunLabels("0123456789abcdef", "RUN-0000-aaaa")
	argv, err := openShellCreateArgv(pf, pf.Env, []string{"/usr/bin/observer", "claude"})
	if err != nil {
		t.Fatal(err)
	}
	var envFlags []string
	for i, a := range argv {
		if a == "--env" {
			envFlags = append(envFlags, argv[i+1])
		}
	}
	if !slices.Equal(envFlags, []string{"HOME=/home/dev"}) {
		t.Fatalf("the create argv carries %v; only HOME may ride on it (argv is readable by every user through /proc)", envFlags)
	}
	got := openShellDecodeEnv(openShellEncodeEnv(env))
	if !slices.Contains(got, "TERM=xterm") {
		t.Fatalf("the env file lost the box environment: %q", got)
	}
}

// TestOpenShellPlanFileHoldsNoSecrets: the plan file the daemon writes
// carries paths, names and the pinned gateway, never an environment value.
func TestOpenShellPlanFileHoldsNoSecrets(t *testing.T) {
	pf := openShellPlanFile{Version: openShellPlanVersion, Env: []string{"HOME=/home/dev"}, Target: sandboxopenshell.Target{Gateway: "openshell"}}
	b, err := json.Marshal(pf)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for k := range m {
		if strings.Contains(k, "key") || strings.Contains(k, "token") || strings.Contains(k, "secret") || strings.Contains(k, "password") {
			t.Errorf("the plan file has a secret-shaped field %q", k)
		}
	}
	if env, _ := m["env"].([]any); len(env) != 1 {
		t.Errorf("the plan's env carries more than HOME: %v", m["env"])
	}
}

// TestOpenShellCopyRoundTrip (U-32 fallback 1): a single-file tool state is
// staged from the host, copied into the box, changed there, copied back to
// the copy dir and synced over the host file; a missing source starts the
// box without it and leaves no host file behind.
func TestOpenShellCopyRoundTrip(t *testing.T) {
	root := t.TempDir()
	host := filepath.Join(root, "home", ".claude.json")
	box := filepath.Join(root, "box", "home", ".claude.json")
	sock := filepath.Join(root, "sock")
	if err := os.MkdirAll(filepath.Dir(host), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sock, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(host, []byte(`{"n":0}`), 0o644); err != nil {
		t.Fatal(err)
	}
	pf := openShellPlanFile{
		CopyDir:  filepath.Join(sock, "copy"),
		CopySync: []sandboxopenshell.CopySync{{Source: host, Target: box}, {Source: filepath.Join(root, "home", "absent.json"), Target: filepath.Join(root, "box", "absent.json")}},
	}
	staged := openShellStagedNames(pf)
	present, err := openShellStage(pf, staged)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(present, []bool{true, false}) {
		t.Fatalf("present at staging %v", present)
	}
	if err := openShellCopyIn(staged[0], box, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := openShellCopyIn(staged[1], pf.CopySync[1].Target, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(box, []byte(`{"n":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := openShellCopyBack(box, staged[0]); err != nil {
		t.Fatal(err)
	}
	if err := openShellSyncBack(staged[0], host); err != nil {
		t.Fatal(err)
	}
	if err := openShellSyncBack(staged[1], pf.CopySync[1].Source); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(host)
	if string(b) != `{"n":1}` {
		t.Fatalf("host file %s", b)
	}
	if fi, _ := os.Stat(host); fi.Mode().Perm() != 0o644 {
		t.Fatalf("the sync changed the host file's mode to %v", fi.Mode().Perm())
	}
	if _, err := os.Stat(pf.CopySync[1].Source); err == nil {
		t.Fatal("a missing source was created on the host")
	}
	// A host file that became a symlink is never written through.
	link := filepath.Join(root, "home", "link.json")
	if err := os.Symlink(host, link); err != nil {
		t.Fatal(err)
	}
	if err := openShellSyncBack(staged[0], link); err == nil {
		t.Fatal("a sync wrote through a symlink")
	}
}

// TestOpenShellRunLock: the reaper sees a run as held exactly while its
// host helper holds the lock; a second helper cannot take it.
func TestOpenShellRunLock(t *testing.T) {
	dir := t.TempDir()
	if openShellRunHeld(dir) {
		t.Fatal("a run with no lock file is held")
	}
	unhold, err := openShellHoldRun(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !openShellRunHeld(dir) {
		t.Fatal("a held run reads unheld")
	}
	if _, err := openShellHoldRun(dir); err == nil {
		t.Fatal("a second helper took a held run")
	}
	unhold()
	if openShellRunHeld(dir) {
		t.Fatal("a released run reads held")
	}
}

// TestOpenShellPlaceholdersAreBound (audit finding O1B-A1): a protected
// path that does not exist yet inside a bound tree is created on the host
// by the helper, so the plan must bind it read-only without a stat; one
// case per placeholder kind, plus a placeholder outside every bound tree,
// which the helper is not asked to create.
func TestOpenShellPlaceholdersAreBound(t *testing.T) {
	cases := []struct {
		name     string
		overlay  sandbox.Overlay
		bound    bool
		wantFile bool
	}{
		{"file placeholder in the workspace's .git", sandbox.Overlay{Path: "/home/dev/src/app/.git/commondir", Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderFile}, true, true},
		{"dir placeholder in the tool state", sandbox.Overlay{Path: "/home/dev/.claude/plugins", Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderDir}, true, false},
		{"placeholder outside every bound tree", sandbox.Overlay{Path: "/home/dev/.codex/hooks.json", Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderFile}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := openShellBindFixture()
			b.overlays = append(b.overlays, tc.overlay)
			bp, err := openShellCompileInput(b)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := sandboxopenshell.Compile(bp.in)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			var mount *sandboxopenshell.Mount
			for i := range plan.Mounts {
				if plan.Mounts[i].Target == tc.overlay.Path {
					mount = &plan.Mounts[i]
				}
			}
			handed := slices.ContainsFunc(bp.placeholders, func(o sandbox.Overlay) bool { return o.Path == tc.overlay.Path })
			if handed != tc.bound {
				t.Fatalf("handed to the host helper %v, want %v", handed, tc.bound)
			}
			if !tc.bound {
				if mount != nil {
					t.Fatalf("an unbound placeholder got a mount %+v", *mount)
				}
				return
			}
			if mount == nil || !mount.ReadOnly || mount.Type != sandboxopenshell.MountTypeBind {
				t.Fatalf("the placeholder %s has mount %v, want a read-only bind", tc.overlay.Path, mount)
			}
			var file bool
			for _, bd := range bp.in.Binds {
				if bd.Source == tc.overlay.Path {
					file = bd.File
				}
			}
			if file != tc.wantFile {
				t.Fatalf("bind File %v, want %v (from the placeholder kind)", file, tc.wantFile)
			}
		})
	}
	// A placeholder that would hide rather than bind refuses the launch.
	b := openShellBindFixture()
	b.overlays = append(b.overlays, sandbox.Overlay{Path: "/home/dev/src/app/.git/info", Kind: sandbox.OverlayHideDir, Placeholder: sandbox.PlaceholderDir})
	if _, err := openShellCompileInput(b); err == nil || !strings.Contains(err.Error(), "mask mount") {
		t.Fatalf("a hiding placeholder in the workspace: %v", err)
	}
}

// TestOpenShellEveryHelperPlaceholderHasAReadOnlyMount (audit finding
// O1B-A1, end to end over the bind builder and the planner): every overlay
// compose hands sandbox.RelayHostArgv has a matching read-only bind in the
// compiled plan, and the check compose runs refuses a plan without one.
func TestOpenShellEveryHelperPlaceholderHasAReadOnlyMount(t *testing.T) {
	b := openShellBindFixture()
	b.overlays = append(b.overlays,
		sandbox.Overlay{Path: "/home/dev/src/app/.git/commondir", Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderFile},
		sandbox.Overlay{Path: "/home/dev/src/app/.git/info", Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderDir},
		sandbox.Overlay{Path: "/home/dev/src/app/.git/objects/info/alternates", Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderFile},
		sandbox.Overlay{Path: "/home/dev/.claude/settings.json", Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderFile},
		sandbox.Overlay{Path: "/home/dev/.gemini/settings.json", Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderFile},
	)
	bp, err := openShellCompileInput(b)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := sandboxopenshell.Compile(bp.in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(bp.placeholders) != 4 {
		t.Fatalf("placeholders handed to the helper %+v, want the four inside bound trees", bp.placeholders)
	}
	if err := openShellCheckPlaceholders(plan, bp.placeholders); err != nil {
		t.Fatal(err)
	}
	if _, err := sandbox.RelayHostArgv("/usr/bin/observer", sandbox.NetRequest{Egress: sandbox.EgressProxyOnly, ProxyPort: 8820, HostSocketDir: "/tmp/observer-sbx-RUN"}, bp.placeholders,
		sandbox.RelayRequest{RunID: "RUN", HostObserverDir: "/home/dev/.observer"}); err != nil {
		t.Fatalf("the host argv refuses the bound placeholders: %v", err)
	}
	// Drop one mount: the check refuses.
	var mounts []sandboxopenshell.Mount
	for _, m := range plan.Mounts {
		if m.Target != "/home/dev/src/app/.git/commondir" {
			mounts = append(mounts, m)
		}
	}
	plan.Mounts = mounts
	if err := openShellCheckPlaceholders(plan, bp.placeholders); err == nil || !strings.Contains(err.Error(), "commondir") {
		t.Fatalf("a placeholder with no read-only mount: %v", err)
	}
}

// TestOpenShellReaperSparesARunCreatedDuringTheSweep (audit finding
// O1B-A2, the audit probe's shape): while the first pass works through an
// abandoned run, a new launch plans its run and its helper creates the
// box. The label list then shows both boxes; the fresh one has a run dir
// by then, so the label pass leaves it, and only the abandoned box is
// reaped.
func TestOpenShellReaperSparesARunCreatedDuringTheSweep(t *testing.T) {
	stateDir := t.TempDir()
	gw := sandboxopenshell.Target{Gateway: "openshell"}
	old := writeOpenShellRun(t, stateDir, "run-old-00000001", gw, time.Hour)
	fresh := sandboxopenshell.SandboxName("run-new-00000002")
	f := healthyOpenShell()
	f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
		switch {
		case slices.Contains(args, "list"):
			// The new launch planned its run and created its box while the
			// first pass ran.
			writeOpenShellRun(t, stateDir, "run-new-00000002", gw, 0)
			return extrun.ExecFacts{Stdout: []byte(old.Name + "\n" + fresh + "\n"), PeakChildren: -1}, true
		case slices.Contains(args, "status"):
			return extrun.ExecFacts{Stdout: []byte(f.status), PeakChildren: -1}, true
		case slices.Contains(args, "get"):
			return extrun.ExecFacts{ExitCode: 1, Stderr: []byte(openShellNotFoundText), PeakChildren: -1}, true
		}
		return extrun.ExecFacts{PeakChildren: -1}, true
	}
	r, ex := f.runner()
	res := openShellSweep(context.Background(), r, stateDir, "0123456789abcdef", func(string) bool { return false }, time.Now)
	if slices.Contains(res.Reaped, fresh) {
		t.Fatalf("the box of a run created during the sweep was reaped: %+v", res)
	}
	for _, p := range ex.Calls() {
		if slices.Contains(p.Args, "delete") && slices.Contains(p.Args, fresh) {
			t.Fatalf("a delete was sent for the fresh box: %v", p.Args)
		}
	}
	if !slices.Contains(res.Reaped, old.Name) {
		t.Fatalf("the abandoned run was not reaped: %+v", res)
	}
}

// TestOpenShellReaperStartsWithTheDaemon (audit finding O1B-A4): the
// daemon's runtime starts the reaper when it builds the driver with
// openshell listed, with no probe and no launch first (so a CLI launch's
// or a crashed daemon's leftovers are reaped from daemon start); a runtime
// that does not list openshell stops it, and a non-daemon runtime (a CLI
// launch) never starts one.
func TestOpenShellReaperStartsWithTheDaemon(t *testing.T) {
	t.Cleanup(openShellReleaseReaper)
	running := func() (bool, string) {
		rp := processOpenShellReaper
		rp.mu.Lock()
		defer rp.mu.Unlock()
		return rp.cancel != nil, rp.dir
	}
	runtimeFor := func(daemon bool, backends ...string) (*sandboxRuntime, config.Config) {
		var full config.Config
		full.Terminal.Sandbox.Enabled = true
		full.Terminal.Sandbox.Backends = backends
		// External: this test is about the reaper; the managed gateway's
		// loop has its own tests (terminal_sandbox_openshell_gateway_test.go).
		full.Terminal.Sandbox.OpenShell.GatewayMode = config.OpenShellGatewayExternal
		return &sandboxRuntime{cfg: full.Terminal.Sandbox, observerDir: t.TempDir(), inDaemon: daemon}, full
	}
	r, full := runtimeFor(false, "bwrap", "openshell")
	newOpenShellDriver(r, full)
	if on, _ := running(); on {
		t.Fatal("a non-daemon runtime started the reaper")
	}
	r, full = runtimeFor(true, "bwrap", "openshell")
	d := newOpenShellDriver(r, full).(*openShellDriver)
	if on, dir := running(); !on || dir != d.stateDir() {
		t.Fatalf("the daemon did not start the reaper over %s at construction (running %v over %q)", d.stateDir(), on, dir)
	}
	r, full = runtimeFor(true, "bwrap")
	newOpenShellDriver(r, full)
	if on, _ := running(); on {
		t.Fatal("the reaper kept running after openshell left the backends")
	}
}

// TestOpenShellSweepWithoutAnInstallID: before any box was created there is
// no install id; a pass reads the run dirs and runs no program.
func TestOpenShellSweepWithoutAnInstallID(t *testing.T) {
	stateDir := t.TempDir()
	if id := openShellReadInstallID(stateDir); id != "" {
		t.Fatalf("an install id %q with no file", id)
	}
	r, ex := healthyOpenShell().runner()
	openShellSweep(context.Background(), r, stateDir, "", func(string) bool { return false }, time.Now)
	if n := len(ex.Calls()); n != 0 {
		t.Fatalf("%d programs ran with nothing to reap", n)
	}
	id, err := openShellInstallID(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := openShellReadInstallID(stateDir); got != id {
		t.Fatalf("read %q, minted %q", got, id)
	}
}

// TestOpenShellReaperChecksTheServer (audit finding O1B-A14): the user
// removed the run's gateway name and registered it again for another
// server. That server answers the exact not-found text, but the name no
// longer answers from the recorded server, so nothing is deleted, the box
// is never read gone and its run dir stays; the label pass does not list
// it either.
func TestOpenShellReaperChecksTheServer(t *testing.T) {
	stateDir := t.TempDir()
	gw := sandboxopenshell.Target{Gateway: "openshell"}
	pf := writeOpenShellRun(t, stateDir, "run-moved-0001", gw, time.Hour)
	if err := openShellRecordGateway(stateDir, openShellGatewayEntry{Target: gw, Server: openShellTestServer, Version: "0.1.6"}); err != nil {
		t.Fatal(err)
	}
	f := healthyOpenShell()
	moved := strings.Replace(f.status, openShellTestServer, "https://127.0.0.1:27670", 1)
	f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
		if slices.Contains(args, "status") {
			return extrun.ExecFacts{Stdout: []byte(moved), PeakChildren: -1}, true
		}
		return extrun.ExecFacts{ExitCode: 1, Stderr: []byte(openShellNotFoundText), PeakChildren: -1}, true
	}
	r, ex := f.runner()
	res := openShellSweep(context.Background(), r, stateDir, "0123456789abcdef", func(string) bool { return false }, time.Now)
	if len(res.Reaped) != 0 || !slices.Contains(res.Kept, pf.Name) || len(res.Dropped) != 0 {
		t.Fatalf("%+v: a box on a re-registered name was read gone", res)
	}
	for _, p := range ex.Calls() {
		if !slices.Contains(p.Args, "status") {
			t.Errorf("a box command ran against a name that answers from another server: %v", p.Args)
		}
	}
	if _, err := os.Stat(openShellRunDir(stateDir, "run-moved-0001")); err != nil {
		t.Fatalf("the run dir went: %v", err)
	}
	if got := openShellGateways(stateDir); len(got) != 1 {
		t.Fatalf("the recorded gateway was dropped on a server mismatch: %+v", got)
	}
}

// TestOpenShellReaperDropsEmptyGateways (audit finding O1B-A14): a recorded
// gateway is dropped once its label list comes back empty and no run dir
// names it; a non-empty list, a failed list or a run dir that names it
// keeps it.
func TestOpenShellReaperDropsEmptyGateways(t *testing.T) {
	gw := sandboxopenshell.Target{Gateway: "openshell"}
	cases := []struct {
		name   string
		list   extrun.ExecFacts
		runDir bool
		drop   bool
	}{
		{name: "empty list, no run dir", list: extrun.ExecFacts{Stdout: []byte("\n")}, drop: true},
		{name: "a box still listed", list: extrun.ExecFacts{Stdout: []byte("sbo-aaaaaaaaaaaaaaa\n")}},
		{name: "a failed list", list: extrun.ExecFacts{ExitCode: 1, Stderr: []byte("unavailable")}},
		{name: "empty list, a run dir names it", list: extrun.ExecFacts{Stdout: []byte("\n")}, runDir: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := t.TempDir()
			if err := openShellRecordGateway(stateDir, openShellGatewayEntry{Target: gw, Server: openShellTestServer, Version: "0.1.6"}); err != nil {
				t.Fatal(err)
			}
			if tc.runDir {
				writeOpenShellRun(t, stateDir, "run-young-0001", gw, 0)
			}
			f := healthyOpenShell()
			f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
				switch {
				case slices.Contains(args, "status"):
					return extrun.ExecFacts{Stdout: []byte(f.status), PeakChildren: -1}, true
				case slices.Contains(args, "list"):
					out := tc.list
					out.PeakChildren = -1
					return out, true
				}
				// The listed box's delete and get: present.
				return extrun.ExecFacts{PeakChildren: -1}, true
			}
			r, _ := f.runner()
			res := openShellSweep(context.Background(), r, stateDir, "0123456789abcdef", func(string) bool { return false }, time.Now)
			left := openShellGateways(stateDir)
			if dropped := len(left) == 0; dropped != tc.drop || (len(res.Dropped) == 1) != tc.drop {
				t.Fatalf("dropped %v (left %+v, result %+v), want %v", dropped, left, res, tc.drop)
			}
		})
	}
}

// TestOpenShellStagedFIFOIsRefused (audit finding O1B-A5): the box removes
// its copy of a file and plants a FIFO at the staged name in the copy dir
// (writable in the box). The host helper's sync, and every other read of a
// box-writable file, refuses it at once instead of blocking with no
// writer.
func TestOpenShellStagedFIFOIsRefused(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "copy-0")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	host := filepath.Join(dir, "host.json")
	if err := os.WriteFile(host, []byte(`{"n":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, read := range map[string]func() error{
		"sync back": func() error { return openShellSyncBack(fifo, host) },
		"read owned": func() error {
			_, err := openShellReadOwned(fifo, 1<<10)
			return err
		},
		"copy in": func() error { return openShellCopyIn(fifo, filepath.Join(dir, "box.json"), 0o600) },
	} {
		done := make(chan error, 1)
		go func() { done <- read() }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: a FIFO was read as a file", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s blocked on a FIFO", name)
		}
	}
	if b, _ := os.ReadFile(host); string(b) != `{"n":0}` {
		t.Fatalf("the host file changed: %s", b)
	}
}

// openShellLinks is a fake symlink resolver over a link table (a path, or
// anything under it, resolves through the link).
func openShellLinks(links map[string]string) func(string) (string, error) {
	return func(p string) (string, error) {
		for l, target := range links {
			if p == l {
				return target, nil
			}
			if strings.HasPrefix(p, l+"/") {
				return target + p[len(l):], nil
			}
		}
		return p, nil
	}
}

// TestOpenShellBindSourcesAreResolved (audit finding O1B-A6): a bind
// source reached through a symbolic link is never bound as it stands
// (Docker follows the link while the planner checks the spelling). A
// writable source, a protected path's dir and Observer's own binary refuse
// the launch with a plain reason; a read-only tool state dir and a tool bin
// dir are left out with a note. One case per shape.
func TestOpenShellBindSourcesAreResolved(t *testing.T) {
	cases := []struct {
		name    string
		link    string
		target  string
		mut     func(*openShellBindInputs)
		refuse  bool
		leftOut string
	}{
		{name: "a symlinked workspace", link: "/home/dev/src/app", target: "/data/app", refuse: true},
		{name: "a symlinked tool-state dir (GNU stow)", link: "/home/dev/.claude", target: "/home/dev/dotfiles/claude", refuse: true},
		{name: "a symlinked read-only tool state dir", link: "/home/dev/.config/tool", target: "/home/dev/dotfiles/tool", mut: func(b *openShellBindInputs) {
			b.spec.StateRO = []string{".config/tool"}
		}, leftOut: "/home/dev/.config/tool"},
		{name: "a symlinked tool bin dir", link: "/home/dev/.local/share/claude/versions/2", target: "/opt/claude/2", leftOut: "/home/dev/.local/share/claude/versions/2"},
		{name: "a symlinked observer binary", link: "/home/dev/.observer/bin/observer", target: "/opt/observer/observer", refuse: true},
		{name: "a placeholder whose dir is a link", link: "/home/dev/src/app/.git", target: "/data/app.git", mut: func(b *openShellBindInputs) {
			b.pins = nil
			b.overlays = []sandbox.Overlay{{Path: "/home/dev/src/app/.git/commondir", Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderFile}}
		}, refuse: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := openShellBindFixture()
			files := openShellFS{}
			for k, v := range map[string]fs.FileMode{
				"/home/dev/src/app": fs.ModeDir, "/home/dev/src/app/.git": fs.ModeDir, "/home/dev/src/app/.git/config": 0,
				"/home/dev/.claude": fs.ModeDir, "/home/dev/.claude.json": 0, "/home/dev/.observer/bin/observer": 0,
				"/home/dev/.local/bin": fs.ModeDir, "/home/dev/.local/share": fs.ModeDir,
				"/home/dev/.local/share/claude/versions/2": fs.ModeDir, "/usr/bin": fs.ModeDir, "/home/dev/.config/tool": fs.ModeDir,
			} {
				files[k] = v
			}
			files[tc.link] = fs.ModeSymlink
			b.lstat = files.lstat
			b.resolve = openShellLinks(map[string]string{tc.link: tc.target})
			if tc.mut != nil {
				tc.mut(&b)
			}
			bp, err := openShellCompileInput(b)
			if tc.refuse {
				if err == nil || !strings.Contains(err.Error(), "symbolic link") || !strings.Contains(err.Error(), tc.target) {
					t.Fatalf("%v, want a refusal naming the link and %s", err, tc.target)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, bd := range bp.in.Binds {
				if bd.Source == tc.leftOut {
					t.Fatalf("the link %s is bound", tc.leftOut)
				}
			}
			if !slices.ContainsFunc(bp.notes, func(n string) bool { return strings.Contains(n, tc.leftOut) && strings.Contains(n, "symbolic link") }) {
				t.Fatalf("notes %v do not name the link %s", bp.notes, tc.leftOut)
			}
			if _, err := sandboxopenshell.Compile(bp.in); err != nil {
				t.Fatalf("compile: %v", err)
			}
		})
	}
}

// TestOpenShellSyncNeverCreatesAHostFile (audit finding O1B-A7, OSH-8): the
// host has no ~/.claude.json.backup; the tool creates it in the box and the
// in-box copy-back writes it to the staged name. The helper syncs back only
// what the host had at staging, so the host still has no such file, while
// a file the host had is synced as before.
func TestOpenShellSyncNeverCreatesAHostFile(t *testing.T) {
	root := t.TempDir()
	sock := filepath.Join(root, "sock")
	if err := os.MkdirAll(filepath.Join(root, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sock, 0o700); err != nil {
		t.Fatal(err)
	}
	had := filepath.Join(root, "home", ".claude.json")
	absent := filepath.Join(root, "home", ".claude.json.backup")
	if err := os.WriteFile(had, []byte(`{"n":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pf := openShellPlanFile{
		Target: sandboxopenshell.Target{Gateway: "openshell"}, Server: openShellTestServer, Name: sandboxopenshell.SandboxName("RUN"),
		CopyDir: filepath.Join(sock, "copy"),
		CopySync: []sandboxopenshell.CopySync{
			{Source: had, Target: filepath.Join(root, "box", ".claude.json")},
			{Source: absent, Target: filepath.Join(root, "box", ".claude.json.backup")},
		},
	}
	staged := openShellStagedNames(pf)
	present, err := openShellStage(pf, staged)
	if err != nil {
		t.Fatal(err)
	}
	// The box rewrote the file the host had and created the absent one;
	// the in-box copy-back put both at their staged names.
	if err := os.WriteFile(staged[0], []byte(`{"n":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged[1], []byte(`{"box":"made"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := openShellRunner
	t.Cleanup(func() { openShellRunner = prev })
	r, _ := healthyOpenShell().runner()
	openShellRunner = func() *extrun.Runner { return r }
	openShellAfterRun(pf, staged, present, filepath.Join(root, "run"))
	if _, err := os.Stat(absent); err == nil {
		t.Fatal("the sync created a host file the host did not have")
	}
	if b, _ := os.ReadFile(had); string(b) != `{"n":1}` {
		t.Fatalf("the file the host had was not synced: %s", b)
	}
}

// The bind builder, gateway-config, host-argv and init-argv tests use
// POSIX path fixtures, which filepath reads differently off Linux, so they
// live in this Linux-only file (audit finding O1B-A8).

// TestOpenShellBindMountsFrom (decision D3): the opt-in is read from the
// user's own gateway config, never written; one case per outcome.
func TestOpenShellBindMountsFrom(t *testing.T) {
	both := "[openshell.drivers.docker]\nallow_driver_config = true\nenable_bind_mounts = true\n"
	cases := []struct {
		name   string
		body   string
		err    error
		driver string
		want   sandboxopenshell.Tri
	}{
		{"both keys on", both, nil, "docker", sandboxopenshell.TriYes},
		{"bind mounts off", "[openshell.drivers.docker]\nallow_driver_config = true\nenable_bind_mounts = false\n", nil, "docker", sandboxopenshell.TriNo},
		{"driver config absent", "[openshell.drivers.docker]\nenable_bind_mounts = true\n", nil, "docker", sandboxopenshell.TriNo},
		{"another driver's table", both, nil, "podman", sandboxopenshell.TriNo},
		{"no table at all", "[openshell.gateway]\nx = 1\n", nil, "docker", sandboxopenshell.TriNo},
		{"no file", "", fs.ErrNotExist, "docker", sandboxopenshell.TriUnknown},
		{"not toml", "[[[", nil, "docker", sandboxopenshell.TriUnknown},
		{"driver unknown", both, nil, "", sandboxopenshell.TriUnknown},
	}
	for _, tc := range cases {
		if got := openShellBindMountsFrom([]byte(tc.body), tc.err, tc.driver); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if p := openShellGatewayConfigPath(func(string) string { return "" }, "/home/dev"); p != "/home/dev/.config/openshell/gateway.toml" {
		t.Errorf("default path %s", p)
	}
	if p := openShellGatewayConfigPath(func(k string) string { return map[string]string{"XDG_CONFIG_HOME": "/x"}[k] }, "/home/dev"); p != "/x/openshell/gateway.toml" {
		t.Errorf("xdg path %s", p)
	}
}

// openShellFS is a fake lstat over a set of paths (dirs end in "/").
type openShellFS map[string]fs.FileMode

func (m openShellFS) lstat(p string) (fs.FileInfo, error) {
	mode, ok := m[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return openShellFileInfo{name: filepath.Base(p), mode: mode}, nil
}

type openShellFileInfo struct {
	name string
	mode fs.FileMode
}

func (i openShellFileInfo) Name() string       { return i.name }
func (i openShellFileInfo) Size() int64        { return 0 }
func (i openShellFileInfo) Mode() fs.FileMode  { return i.mode }
func (i openShellFileInfo) ModTime() time.Time { return time.Time{} }
func (i openShellFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i openShellFileInfo) Sys() any           { return nil }

// openShellBindFixture is a Claude Code run on the sentinel home.
func openShellBindFixture() openShellBindInputs {
	files := openShellFS{
		"/home/dev/src/app":                        fs.ModeDir,
		"/home/dev/src/app/.git":                   fs.ModeDir,
		"/home/dev/src/app/.git/config":            0,
		"/home/dev/.claude":                        fs.ModeDir,
		"/home/dev/.claude.json":                   0,
		"/home/dev/.observer/bin/observer":         0,
		"/home/dev/.local/bin":                     fs.ModeDir,
		"/home/dev/.local/share":                   fs.ModeDir,
		"/home/dev/.local/share/claude/versions/2": fs.ModeDir,
		"/usr/bin": fs.ModeDir,
	}
	return openShellBindInputs{
		home: "/home/dev", workspace: "/home/dev/src/app", sockDir: "/tmp/observer-sbx-RUN", copyDir: "/tmp/observer-sbx-RUN/copy",
		observerBin: "/home/dev/.observer/bin/observer", observerDir: "/home/dev/.observer",
		spec:        integration.SandboxSpec{StateRW: []string{".claude", ".claude.json"}},
		overlays:    []sandbox.Overlay{{Path: "/home/dev/src/app/.git/config", Kind: sandbox.OverlayReadOnly}},
		pins:        []string{"/home/dev/src/app/.git"},
		toolBinDirs: []string{"/home/dev/.local/share/claude/versions/2", "/usr/bin"},
		homeMode:    "tmpfs", tier: "proxy_only", driver: "docker", uid: 1000, gid: 1000,
		lstat: files.lstat,
	}
}

// TestOpenShellCompileInput (lane O1B M2): a Claude Code run's facts turn
// into a plan the planner compiles: the workspace and the tool state
// writable, the protected .git config and the observer binary read-only,
// the repository pin bound onto itself, ~/.claude.json copied in (not
// bound), a system bin dir and a runtime dir that holds a credential path
// left out with a note, and the socket dir read-only with its copy dir
// writable.
func TestOpenShellCompileInput(t *testing.T) {
	bp, err := openShellCompileInput(openShellBindFixture())
	if err != nil {
		t.Fatal(err)
	}
	notes := bp.notes
	plan, err := sandboxopenshell.Compile(bp.in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	mounts := map[string]sandboxopenshell.Mount{}
	for _, m := range plan.Mounts {
		mounts[m.Target] = m
	}
	want := map[string]bool{ // target -> read-only
		"/home/dev/src/app": false, "/home/dev/src/app/.git": false, "/home/dev/src/app/.git/config": true,
		"/home/dev/.claude": false, "/home/dev/.observer/bin/observer": true,
		"/home/dev/.local/bin": true, "/home/dev/.local/share/claude/versions/2": true,
		"/tmp/observer-sbx-RUN": true, "/tmp/observer-sbx-RUN/copy": false,
	}
	for target, ro := range want {
		m, ok := mounts[target]
		if !ok || m.ReadOnly != ro {
			t.Errorf("%s: mount %+v (present %v), want read-only %v", target, m, ok, ro)
		}
	}
	for _, refused := range []string{"/usr/bin", "/home/dev/.local/share", "/home/dev/.claude.json"} {
		if _, ok := mounts[refused]; ok {
			t.Errorf("%s is bound", refused)
		}
	}
	if len(plan.CopySync) != 1 || plan.CopySync[0].Target != "/home/dev/.claude.json" {
		t.Errorf("copy sync %+v", plan.CopySync)
	}
	if !plan.SharedHome {
		t.Error("a tmpfs home without the shared-home disclosure")
	}
	if len(notes) != 2 {
		t.Errorf("notes %v, want the system bin dir and the credential-holding runtime dir", notes)
	}
}

// TestOpenShellCompileInputRefusals: one case per launch the bind builder
// refuses before the planner.
func TestOpenShellCompileInputRefusals(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*openShellBindInputs)
		want string
	}{
		{"a unix socket in the tool state", func(b *openShellBindInputs) {
			files := openShellFS{"/home/dev/src/app": fs.ModeDir, "/home/dev/.claude": fs.ModeSocket}
			b.lstat = files.lstat
		}, "unix socket"},
		{"a mask overlay inside the workspace", func(b *openShellBindInputs) {
			b.overlays = append(b.overlays, sandbox.Overlay{Path: "/home/dev/src/app/secret", Kind: sandbox.OverlayHideFile})
		}, "mask mount"},
	}
	for _, tc := range cases {
		b := openShellBindFixture()
		tc.mut(&b)
		if _, err := openShellCompileInput(b); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	// A mask overlay outside every bound tree is not the box's concern.
	b := openShellBindFixture()
	b.overlays = append(b.overlays, sandbox.Overlay{Path: "/home/dev/.observer/observer.db", Kind: sandbox.OverlayHideFile})
	if _, err := openShellCompileInput(b); err != nil {
		t.Errorf("an unbound mask refused the launch: %v", err)
	}
}

// TestOpenShellMaskPathsInsideABoundTree (audit finding O1B-R1): the row
// has no mask mount, so a mask path ([terminal.sandbox].mask_paths, the
// developer's or the organization's, or a detected foreign-OS mount) inside
// a tree the plan binds refuses the launch naming the key; one outside every
// bound tree, or above one, stays allowed. The mask is compared as resolved
// too. One case per shape.
func TestOpenShellMaskPathsInsideABoundTree(t *testing.T) {
	const localKey = "[terminal.sandbox].mask_paths"
	cases := []struct {
		name    string
		cfg     []string
		foreign []string
		links   map[string]string
		want    string // "" = allowed; otherwise a word the refusal holds
		inside  string
	}{
		{name: "inside the workspace", cfg: []string{"/home/dev/src/app/secrets"}, want: localKey, inside: "/home/dev/src/app"},
		{name: "inside the tool state", cfg: []string{"/home/dev/.claude/credentials"}, want: localKey, inside: "/home/dev/.claude"},
		{name: "at the workspace itself", cfg: []string{"/home/dev/src/app"}, want: localKey, inside: "/home/dev/src/app"},
		{name: "outside every bound tree", cfg: []string{"/home/dev/.aws", "/srv/secrets"}},
		{name: "above a bound tree", cfg: []string{"/home/dev/src"}},
		{name: "a link into the workspace", cfg: []string{"/home/dev/vault/keys"}, links: map[string]string{"/home/dev/vault": "/home/dev/src/app/vault"}, want: localKey, inside: "/home/dev/src/app"},
		{name: "a foreign-OS mount inside the workspace", foreign: []string{"/home/dev/src/app/mnt"}, want: "foreign-OS mount", inside: "/home/dev/src/app"},
		// The mount table's drives (SBX-BE-24) take the same rows: a drive
		// no bind shows, or one above the workspace (a project on /mnt/d
		// under the /mnt/d mask), is allowed.
		{name: "mount-table drives outside every bound tree", foreign: []string{"/mnt/c", "/mnt/d"}},
		{name: "a mount-table drive above the workspace", foreign: []string{"/home/dev/src"}},
		{name: "a relative mask path", cfg: []string{"secrets"}, want: "not an absolute path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := openShellBindFixture()
			b.masks = openShellMasks(config.TerminalSandboxConfig{MaskPaths: tc.cfg}, tc.foreign)
			if tc.links != nil {
				b.resolve = openShellLinks(tc.links)
			}
			_, err := openShellCompileInput(b)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.inside) {
				t.Fatalf("%v, want a refusal naming %q and %q", err, tc.want, tc.inside)
			}
		})
	}
}

// TestOpenShellHostArgsRoundTrip (lane O1B M3): the wrap argv the driver
// returns is a complete sandbox-host command line (the relay and the tier
// reader see it) and the helper takes the inner launch from after the
// marker.
func TestOpenShellHostArgsRoundTrip(t *testing.T) {
	host, err := sandbox.RelayHostArgv("/usr/bin/observer", sandbox.NetRequest{Egress: sandbox.EgressProxyOnly, ProxyPort: 8820, HostSocketDir: "/tmp/observer-sbx-RUN"}, nil,
		sandbox.RelayRequest{RunID: "RUN", HostObserverDir: "/home/dev/.observer"})
	if err != nil {
		t.Fatal(err)
	}
	wrap := append([]string{"/usr/bin/observer", openShellHostVerb, "--plan", "/s/runs/RUN/plan.json", "--"}, host...)
	wrap = append(wrap, openShellInnerMarker, "/usr/bin/observer", "claude")
	plan, h, err := parseOpenShellHostArgs(wrap[2:])
	if err != nil {
		t.Fatal(err)
	}
	if plan != "/s/runs/RUN/plan.json" || h.SockDir != "/tmp/observer-sbx-RUN" || h.RelayRun != "RUN" || !slices.Equal(h.Command, []string{"/usr/bin/observer", "claude"}) {
		t.Fatalf("plan %s host %+v", plan, h)
	}
	if tier := sandboxTierOfWrap(wrap); tier != string(sandbox.EgressProxyOnly) {
		t.Fatalf("the tier reader sees %q", tier)
	}
	for _, bad := range [][]string{
		{"--plan", "/p"},
		{"--plan", "/p", "--", "/usr/bin/observer", "not-host"},
		append([]string{"--plan", "/p", "--"}, host...),
	} {
		if _, _, err := parseOpenShellHostArgs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// TestOpenShellInitArgs: the in-box init's argv round-trips through its
// parser; copies and seeds keep their order, and the env file rides as a
// path, never a value; the run's workspace rides as --cwd (live run O1B-L1:
// without it the command started in OpenShell's own /sandbox, which
// include_workdir false leaves unwritable).
func TestOpenShellInitArgs(t *testing.T) {
	pf := openShellPlanFile{
		ObserverBin: "/usr/bin/observer", SockDir: "/tmp/observer-sbx-RUN", CopyDir: "/tmp/observer-sbx-RUN/copy",
		CopySync: []sandboxopenshell.CopySync{{Source: "/home/dev/.claude.json", Target: "/home/dev/.claude.json"}},
		Seed:     []sandboxopenshell.CopySync{{Source: "/home/dev/.observer/config.toml", Target: "/home/dev/.observer/config.toml"}},
		Guest:    []string{"/usr/bin/observer", "sandbox-guest", "--"},
		Workdir:  "/home/dev/project",
	}
	staged := openShellStagedNames(pf)
	argv := append(openShellInitArgv(pf, staged, "/tmp/observer-sbx-RUN/copy/env"), "/usr/bin/observer", "claude")
	if argv[1] != openShellInitVerb {
		t.Fatalf("argv %v", argv)
	}
	a, err := parseOpenShellInitArgs(argv[2:])
	if err != nil {
		t.Fatal(err)
	}
	if a.SockDir != pf.SockDir || a.Cwd != "/home/dev/project" || a.EnvFile != "/tmp/observer-sbx-RUN/copy/env" ||
		len(a.Copies) != 1 || a.Copies[0] != [2]string{"/tmp/observer-sbx-RUN/copy/copy-0", "/home/dev/.claude.json"} ||
		len(a.Seeds) != 1 || a.Seeds[0] != [2]string{"/tmp/observer-sbx-RUN/copy/seed-0", "/home/dev/.observer/config.toml"} ||
		!slices.Equal(a.Command, []string{"/usr/bin/observer", "sandbox-guest", "--", "/usr/bin/observer", "claude"}) {
		t.Fatalf("%+v", a)
	}
	for _, bad := range [][]string{
		{"--sock-dir", "rel", "--", "x"},
		{"--sock-dir", "/d", "--copy", "/a", "--", "x"},
		{"--sock-dir", "/d", "--bogus", "v", "--", "x"},
		{"--sock-dir", "/d"},
		{"--sock-dir", "/d", "--"},
		{"--sock-dir", "/d", "--cwd", "rel", "--", "x"},
		{"--sock-dir", "/d", "--cwd"},
	} {
		if _, err := parseOpenShellInitArgs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// TestOpenShellBinDirUnderTheObserverDir (audit finding O1B-A9): a tool bin
// dir that resolves under the observer dir (a [launch.tools] path pointing
// at a file under ~/.observer/run, say) is left out with a note, never
// bound; Observer's own binary, a regular file there, still is.
func TestOpenShellBinDirUnderTheObserverDir(t *testing.T) {
	b := openShellBindFixture()
	files := openShellFS{}
	for k, v := range map[string]fs.FileMode{
		"/home/dev/src/app": fs.ModeDir, "/home/dev/.claude": fs.ModeDir,
		"/home/dev/.observer/bin/observer": 0, "/home/dev/.observer/run": fs.ModeDir,
	} {
		files[k] = v
	}
	b.lstat = files.lstat
	b.pins, b.overlays = nil, nil
	b.toolBinDirs = []string{"/home/dev/.observer/run"}
	bp, err := openShellCompileInput(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, bd := range bp.in.Binds {
		if bd.Source == "/home/dev/.observer/run" {
			t.Fatal("a dir under the observer dir is bound")
		}
	}
	if !slices.ContainsFunc(bp.notes, func(n string) bool { return strings.Contains(n, "/home/dev/.observer/run") }) {
		t.Fatalf("notes %v do not name the left-out dir", bp.notes)
	}
	if !slices.Contains(bp.in.Scope.BinPaths, "/home/dev/.observer/bin/observer") {
		t.Fatalf("Observer's binary is not a bin path: %v", bp.in.Scope.BinPaths)
	}
	if _, err := sandboxopenshell.Compile(bp.in); err != nil {
		t.Fatalf("compile: %v", err)
	}
}

// TestOpenShellDestroyKeepsAnUnclearRun (audit finding O1B-A10): Destroy
// removes a run dir only when the pinned gateway shows the box gone by the
// exact not-found text, whether or not the runtime has a logger.
func TestOpenShellDestroyKeepsAnUnclearRun(t *testing.T) {
	cases := []struct {
		name    string
		get     extrun.ExecFacts
		dirGone bool
	}{
		{name: "unclear answer, no logger", get: extrun.ExecFacts{ExitCode: 1, Stderr: []byte("permission denied")}},
		{name: "box still present, no logger", get: extrun.ExecFacts{Stdout: []byte(`{"name":"x"}`)}},
		{name: "shown gone, no logger", get: extrun.ExecFacts{ExitCode: 1, Stderr: []byte(openShellNotFoundText)}, dirGone: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := t.TempDir()
			d := &openShellDriver{r: &sandboxRuntime{observerDir: obs}}
			writeOpenShellRun(t, d.stateDir(), "run-destroy-0001", sandboxopenshell.Target{Gateway: "openshell"}, time.Hour)
			f := healthyOpenShell()
			f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
				switch {
				case slices.Contains(args, "status"):
					return extrun.ExecFacts{Stdout: []byte(f.status), PeakChildren: -1}, true
				case slices.Contains(args, "get"):
					out := tc.get
					out.PeakChildren = -1
					return out, true
				}
				return extrun.ExecFacts{PeakChildren: -1}, true
			}
			r, _ := f.runner()
			prev := openShellRunner
			t.Cleanup(func() { openShellRunner = prev })
			openShellRunner = func() *extrun.Runner { return r }
			if _, err := d.Destroy(context.Background(), termsvc.SandboxRun{ID: "run-destroy-0001"}); err != nil {
				t.Fatal(err)
			}
			_, err := os.Stat(openShellRunDir(d.stateDir(), "run-destroy-0001"))
			if gone := errors.Is(err, fs.ErrNotExist); gone != tc.dirGone {
				t.Fatalf("run dir gone %v, want %v", gone, tc.dirGone)
			}
		})
	}
}

// TestOpenShellReaperRemovesAbandonedSocketDirs (audit findings O1B-A11 and
// O1B-R2): the reaper removes an abandoned run's socket dir (the box
// environment file a killed helper left at rest there goes with it), keeps
// a held run's, and never removes a dir the plan names that is not the
// run's: one named for another run, one with the run's name outside the
// socket root, or another run's named by a plan in the wrong run dir (the
// held check reads the run dir, so that plan is skipped whole).
func TestOpenShellReaperRemovesAbandonedSocketDirs(t *testing.T) {
	cases := []struct {
		name      string
		held      bool
		sockFor   string
		elsewhere bool   // the socket dir is outside the socket root
		planRun   string // the plan's run id ("" = the run dir's name)
		removed   bool
	}{
		{name: "abandoned", sockFor: "run-sock-0001", removed: true},
		{name: "held by its helper", held: true, sockFor: "run-sock-0001"},
		{name: "a dir named for another run", sockFor: "run-other-0002"},
		{name: "the run's name outside the socket root", sockFor: "run-sock-0001", elsewhere: true},
		{name: "a plan naming another run", sockFor: "run-other-0002", planRun: "run-other-0002"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			prevRoot := openShellSockRoot
			t.Cleanup(func() { openShellSockRoot = prevRoot })
			openShellSockRoot = func() string { return root }
			stateDir := t.TempDir()
			parent := root
			if tc.elsewhere {
				parent = filepath.Join(t.TempDir(), "home")
			}
			sock := filepath.Join(parent, "observer-sbx-"+tc.sockFor)
			if err := os.MkdirAll(filepath.Join(sock, "copy"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(sock, "copy", openShellEnvFileName), []byte("TERM=xterm\x00"), 0o600); err != nil {
				t.Fatal(err)
			}
			dir := openShellRunDir(stateDir, "run-sock-0001")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			runID := tc.planRun
			if runID == "" {
				runID = "run-sock-0001"
			}
			pf := openShellPlanFile{
				Version: openShellPlanVersion, RunID: runID, Target: sandboxopenshell.Target{Gateway: "openshell"}, Server: openShellTestServer,
				GatewayVersion: "0.1.6", Name: sandboxopenshell.SandboxName(runID), SockDir: sock,
			}
			if err := openShellWriteExcl(filepath.Join(dir, "plan.json"), openShellJSON(t, pf)); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-time.Hour)
			if err := os.Chtimes(filepath.Join(dir, "plan.json"), old, old); err != nil {
				t.Fatal(err)
			}
			f := healthyOpenShell()
			f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
				if slices.Contains(args, "status") {
					return extrun.ExecFacts{Stdout: []byte(f.status), PeakChildren: -1}, true
				}
				return extrun.ExecFacts{ExitCode: 1, Stderr: []byte("unavailable"), PeakChildren: -1}, true
			}
			r, _ := f.runner()
			// The held check reads the run dir the plan sits in, never the
			// run the plan names.
			res := openShellSweep(context.Background(), r, stateDir, "", func(d string) bool { return tc.held && filepath.Base(d) == "run-sock-0001" }, time.Now)
			_, err := os.Stat(sock)
			if gone := errors.Is(err, fs.ErrNotExist); gone != tc.removed {
				t.Fatalf("socket dir removed %v, want %v (sweep %+v)", gone, tc.removed, res)
			}
			if tc.planRun != "" && (len(res.Live)+len(res.Reaped)+len(res.Kept)) != 0 {
				t.Fatalf("a plan naming another run was acted on: %+v", res)
			}
			// F-052: the abandoned run is named for its placeholder ledger.
			wantAbandoned := !tc.held && tc.planRun == ""
			if got := len(res.Abandoned) == 1 && res.Abandoned[0] == "run-sock-0001"; got != wantAbandoned || (!wantAbandoned && len(res.Abandoned) != 0) {
				t.Fatalf("abandoned %v, want the run named %v", res.Abandoned, wantAbandoned)
			}
		})
	}
}

// TestOpenShellLaunchRecordThroughTheGuestLink (live run O1B-L1, item 2)
// pins the shape the live run refused: the run's socket dir is a private
// dir (0700, this user's) holding the launch record, and the box's fixed
// guest path is the in-box init's symbolic link to it. Read through the
// link, the relay's unchanged record check refuses it ("the record's
// directory is not private": lstat sees a 0777 link, not a dir); read from
// the dir openShellBoxSocketDir resolves, it passes.
func TestOpenShellLaunchRecordThroughTheGuestLink(t *testing.T) {
	sockDir := filepath.Join(t.TempDir(), "observer-sbx-RUN")
	if err := os.Mkdir(sockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "run-0000-aaaa"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteBoxRecord(sockDir, rec); err != nil {
		t.Fatal(err)
	}
	guest := filepath.Join(t.TempDir(), ".observer-sandbox-net")
	if err := os.Symlink(sockDir, guest); err != nil {
		t.Fatal(err)
	}
	if _, present, err := sandboxrelayd.ReadBoxRecord(filepath.Join(guest, sandboxrelayd.BoxRecordName)); !present || !errors.Is(err, sandboxrelayd.ErrBadRecord) || !strings.Contains(err.Error(), "not private") {
		t.Fatalf("through the link: present %v err %v, want the private-dir refusal", present, err)
	}
	dir, ok := openShellBoxSocketDir(sockDir, guest, os.Readlink)
	if !ok || dir != sockDir {
		t.Fatalf("resolved %q %v", dir, ok)
	}
	got, present, err := sandboxrelayd.ReadBoxRecord(filepath.Join(dir, sandboxrelayd.BoxRecordName))
	if err != nil || !present || got.RunID != rec.RunID {
		t.Fatalf("from the dir: %+v %v %v", got, present, err)
	}
}

// openShellInitProbeEnv makes TestOpenShellBoxInitProbe print the relay
// client's paths as this process's inits left them.
const openShellInitProbeEnv = "OBSERVER_TEST_OPENSHELL_INIT_PROBE"

// TestOpenShellBoxInitProbe is TestOpenShellBoxInitComposed's child: it
// runs only when that test starts this binary with openShellInitProbeEnv.
func TestOpenShellBoxInitProbe(t *testing.T) {
	if os.Getenv(openShellInitProbeEnv) != "1" {
		t.Skip("runs only as TestOpenShellBoxInitComposed's child")
	}
	fmt.Printf("PROBE dir=%s record=%s spool=%s\n", boxSocketDir, boxRecordPath, relaySpoolDir)
}

// openShellInitGuestEnv names the per-test guest link path the composed
// test's child uses instead of sandbox.GuestSocketDir (F-023 V10). It is
// read here, in the test binary, by a package-level initializer, which runs
// before every init function, and only together with
// openShellInitProbeEnv; the product binary never reads it.
const openShellInitGuestEnv = "OBSERVER_TEST_OPENSHELL_INIT_GUEST"

var _ = func() bool {
	if d := os.Getenv(openShellInitGuestEnv); d != "" && os.Getenv(openShellInitProbeEnv) == "1" {
		openShellGuestLink = d
	}
	return true
}()

// TestOpenShellGuestLinkIsTheGuestDir pins, in the parent test process
// (never the composed test's child), that the guest path the in-box init
// reads is the fixed guest dir the relay and the guest helper use: the
// variable exists only for the child's per-test override (F-023 V10).
func TestOpenShellGuestLinkIsTheGuestDir(t *testing.T) {
	if os.Getenv(openShellInitProbeEnv) == "1" {
		t.Skip("the composed test's child may point it elsewhere")
	}
	if openShellGuestLink != sandbox.GuestSocketDir {
		t.Fatalf("openShellGuestLink %q, want sandbox.GuestSocketDir %q", openShellGuestLink, sandbox.GuestSocketDir)
	}
}

// TestOpenShellBoxInitComposed (review finding V1) runs this test binary
// as a child with a box's environment, so every init of the composed
// binary runs in its real order (the process_lite init, file
// terminal_sandbox_landlock_linux.go, before the openshell one), and pins
// what the relay clients read: the run's dir only with the sandbox marker
// and the guest path linked to exactly the dir named in this row's own
// variable; the shared OBSERVER_SANDBOX_SOCK_DIR never decides it in a box
// whose guard holds; and the spool stays in the box's own /tmp.
//
// The guest link lives in a per-test temp dir (openShellInitGuestEnv), not
// at the fixed host path, so the test never skips because that path
// exists and two runs on one host never collide (F-023 V10). When the
// init does not take the run's dir, the relay clients keep their default,
// sandbox.GuestSocketDir.
func TestOpenShellBoxInitComposed(t *testing.T) {
	guest := filepath.Join(t.TempDir(), "guest-net")
	sockDir := filepath.Join(t.TempDir(), "observer-sbx-RUN")
	other := filepath.Join(t.TempDir(), "observer-sbx-OTHER")
	for _, d := range []string{sockDir, other} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	def := sandbox.GuestSocketDir
	defRecord := filepath.Join(def, sandboxrelayd.BoxRecordName)
	const defSpool = "/tmp/.observer-relay-spool"
	cases := []struct {
		name   string
		link   string
		env    []string
		dir    string
		record string
	}{
		{
			"the init's link and this row's variable", sockDir,
			[]string{sandboxEnvMarker + "=1", openShellEnvSocketDir + "=" + sockDir},
			sockDir, filepath.Join(sockDir, sandboxrelayd.BoxRecordName),
		},
		{
			"the shared variable too: the openshell guard decides", sockDir,
			[]string{sandboxEnvMarker + "=1", openShellEnvSocketDir + "=" + sockDir, openShellSharedSockDirEnv + "=" + other},
			sockDir, filepath.Join(sockDir, sandboxrelayd.BoxRecordName),
		},
		{
			"the link points elsewhere", other,
			[]string{sandboxEnvMarker + "=1", openShellEnvSocketDir + "=" + sockDir},
			def, defRecord,
		},
		{
			"no sandbox marker", sockDir,
			[]string{openShellEnvSocketDir + "=" + sockDir},
			def, defRecord,
		},
		{
			"no link", "",
			[]string{sandboxEnvMarker + "=1", openShellEnvSocketDir + "=" + sockDir},
			def, defRecord,
		},
	}
	for _, tc := range cases {
		_ = os.Remove(guest)
		if tc.link != "" {
			if err := os.Symlink(tc.link, guest); err != nil {
				t.Fatal(err)
			}
		}
		var env []string
		for _, kv := range os.Environ() {
			k, _, _ := strings.Cut(kv, "=")
			if k != sandboxEnvMarker && k != openShellEnvSocketDir && k != openShellSharedSockDirEnv && k != "TMPDIR" && k != openShellInitGuestEnv {
				env = append(env, kv)
			}
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestOpenShellBoxInitProbe$", "-test.count=1", "-test.v") //nolint:gosec // G204: this test binary
		cmd.Env = append(append(env, openShellInitProbeEnv+"=1", openShellInitGuestEnv+"="+guest), tc.env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", tc.name, err, out)
		}
		want := fmt.Sprintf("PROBE dir=%s record=%s spool=%s", tc.dir, tc.record, defSpool)
		if !strings.Contains(string(out), want) {
			t.Errorf("%s: want %q in\n%s", tc.name, want, out)
		}
	}
}

// TestOpenShellEngineFirstUse (ledger row OSH-48, A9): the first probe
// records the engine's ID in the row's state dir (owner-only); the same
// ID passes after it; another ID behind the socket refuses at P8e with a
// reason naming the record to remove, and the record is never rewritten;
// removing it accepts the new engine.
func TestOpenShellEngineFirstUse(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "sandbox-openshell")
	read, save := openShellEngineRecordIO(stateDir)
	answer := openShellTestEngineID
	g := &openShellGathering{host: openShellHostFactsT{EngineRecord: read, SaveEngine: save}}
	g.out.facts.Driver = "docker"
	g.run = func(_ context.Context, _ integration.BinaryResolveSpec, args []string) extrun.Result {
		if !slices.Equal(args, sandboxopenshell.EngineInfoArgv()) {
			t.Fatalf("unexpected docker call %v", args)
		}
		return extrun.Result{Outcome: extrun.OutcomeOK, Stdout: []byte(`"` + answer + `"` + "\n")}
	}
	verdict := func() string {
		t.Helper()
		openShellEngineStep(context.Background(), g)
		v, _ := sandboxopenshell.EngineVerdict(g.out.facts.Engine)
		return v
	}
	if v := verdict(); v != "" || g.out.engineNote != "" {
		t.Fatalf("first use: %q %q", v, g.out.engineNote)
	}
	p := filepath.Join(stateDir, sandboxopenshell.EngineRecordFile)
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the record: %v %v", st, err)
	}
	if v := verdict(); v != "" {
		t.Fatalf("the same engine: %q", v)
	}
	answer = "5b1e3f0a-6c0d-4a8e-9f1a-2b3c4d5e6f70"
	if v := verdict(); v != sandboxopenshell.VerdictEngineChanged {
		t.Fatalf("another engine: %q", v)
	}
	_, reason := sandboxopenshell.EngineVerdict(g.out.facts.Engine)
	if !strings.Contains(reason, strconv.Quote(p)) {
		t.Fatalf("the reason does not name the record: %s", reason)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), openShellTestEngineID) {
		t.Fatalf("the record was rewritten: %s", b)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if v := verdict(); v != "" {
		t.Fatalf("after removing the record: %q", v)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), answer) {
		t.Fatalf("the new engine was not recorded: %s", b)
	}
	// A record that does not parse is never overwritten.
	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v := verdict(); v != sandboxopenshell.VerdictEngineRecordUnreadable {
		t.Fatalf("an unreadable record: %q", v)
	}
}

// TestOpenShellInstallIDBoundToStateDir (ledger row OSH-42): the id is
// bound to the state dir's real path. A copy of the dir mints its own id
// (so its gateway name, unit and port differ); the same dir through a
// symlink keeps its id; an install from before the binding (only the
// legacy file) adopts its id once; a copy of such an install made after
// its first use mints its own.
func TestOpenShellInstallIDBoundToStateDir(t *testing.T) {
	root := t.TempDir()
	// No unit is loaded (the legacy id's gateway is not running).
	notLoaded := func(string) (string, bool) { return "", false }
	copyDir := func(from, to string) {
		t.Helper()
		if err := os.MkdirAll(to, 0o700); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(from)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(from, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(to, e.Name()), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	a := filepath.Join(root, "a", "sandbox-openshell")
	idA, err := openShellInstallIDWith(a, notLoaded)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := openShellInstallIDWith(a, notLoaded); again != idA {
		t.Fatalf("not stable: %q %q", idA, again)
	}
	if b, err := os.ReadFile(filepath.Join(a, sandboxopenshell.LegacyInstallIDFile)); err != nil || strings.TrimSpace(string(b)) != idA {
		t.Fatalf("the legacy file for a downgrade: %v %q", err, b)
	}
	// The same dir through a symlink.
	link := filepath.Join(root, "link")
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	if got, _ := openShellInstallIDWith(link, notLoaded); got != idA {
		t.Fatalf("through a symlink: %q, want %q", got, idA)
	}
	// A copy.
	b := filepath.Join(root, "b", "sandbox-openshell")
	copyDir(a, b)
	if got := openShellReadInstallIDWith(b, notLoaded); got != "" {
		t.Fatalf("a copy reads the original's id before its first use: %q", got)
	}
	idB, err := openShellInstallIDWith(b, notLoaded)
	if err != nil || idB == idA {
		t.Fatalf("a copy shares the id: %q %v", idB, err)
	}
	if b2, err := os.ReadFile(filepath.Join(b, sandboxopenshell.LegacyInstallIDFile)); err != nil || strings.TrimSpace(string(b2)) != idB {
		t.Fatalf("the copy's legacy file still names the original (FU7-A6): %v %q", err, b2)
	}
	gA, _ := sandboxopenshell.IdentityFor(idA)
	gB, _ := sandboxopenshell.IdentityFor(idB)
	if gA.Name == gB.Name || gA.Unit == gB.Unit {
		t.Fatalf("a copy shares the gateway: %+v %+v", gA, gB)
	}
	if got, _ := openShellInstallIDWith(a, notLoaded); got != idA {
		t.Fatalf("the original's id moved: %q", got)
	}
	// An install from before the binding adopts its legacy id.
	legacyID := "0123456789abcdef"
	c := filepath.Join(root, "c", "sandbox-openshell")
	if err := os.MkdirAll(c, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c, sandboxopenshell.LegacyInstallIDFile), []byte(legacyID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := openShellReadInstallIDWith(c, notLoaded); got != legacyID {
		t.Fatalf("the read before adoption: %q", got)
	}
	if got, err := openShellInstallIDWith(c, notLoaded); err != nil || got != legacyID {
		t.Fatalf("adoption: %q %v", got, err)
	}
	d := filepath.Join(root, "d", "sandbox-openshell")
	copyDir(c, d)
	if got, _ := openShellInstallIDWith(d, notLoaded); got == legacyID {
		t.Fatal("a copy of an adopted install shares its id")
	}
}

// TestOpenShellStatBinaryFacts reads the trust rule's facts from the real
// filesystem (ledger row OSH-44): a system shell, root-owned under a
// root-owned chain, passes; a copy in a temporary dir (the user's, or a
// world-writable /tmp when the test runs as root) is refused.
func TestOpenShellStatBinaryFacts(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	f := openShellStatBinaryFacts(sandboxopenshell.Program, sh)
	if !f.Read || f.Real == "" || len(f.Dirs) == 0 || f.Dirs[len(f.Dirs)-1].Path != "/" {
		t.Fatalf("facts of %s: %+v", sh, f)
	}
	if why := sandboxopenshell.BinaryTrust(f); why != "" && f.File.UID == 0 {
		t.Fatalf("a root-owned system shell refused: %s", why)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, sandboxopenshell.GatewayProgram)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // G306: an executable test file
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(dir), 0o777); err != nil { //nolint:gosec // G302: a writable parent, the case under test
		t.Fatal(err)
	}
	if why := sandboxopenshell.BinaryTrust(openShellStatBinaryFacts(sandboxopenshell.GatewayProgram, p)); why == "" {
		t.Fatalf("a copy under %s accepted", dir)
	}
	if got := openShellStatBinaryFacts(sandboxopenshell.GatewayProgram, filepath.Join(dir, "absent")); got.Read || got.Detail == "" {
		t.Fatalf("an absent file: %+v", got)
	}
}

// TestOpenShellEngineStepSkipsPodman: row P8e is a driver capability
// (sandboxopenshell.DriverHasEngineIdentity); on the Podman driver the
// gather step runs nothing and records nothing.
func TestOpenShellEngineStepSkipsPodman(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "sandbox-openshell")
	read, save := openShellEngineRecordIO(stateDir)
	g := &openShellGathering{host: openShellHostFactsT{EngineRecord: read, SaveEngine: save}}
	g.out.facts.Driver = "podman"
	g.run = func(context.Context, integration.BinaryResolveSpec, []string) extrun.Result {
		t.Fatal("a program ran for the Podman driver")
		return extrun.Result{}
	}
	openShellEngineStep(context.Background(), g)
	if g.out.facts.Engine != (sandboxopenshell.EngineFacts{}) {
		t.Fatalf("facts recorded: %+v", g.out.facts.Engine)
	}
	if _, err := os.Stat(filepath.Join(stateDir, sandboxopenshell.EngineRecordFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a record was written: %v", err)
	}
}

// TestOpenShellLegacyAdoptionChecksTheUnit (audit finding FU7-A3): a dir
// holding only the legacy id adopts it when the id's gateway unit is not
// loaded or runs this dir's config (also through a symlinked spelling),
// and mints its own when the unit runs another dir's config (a copy made
// before the binding while the original's gateway runs). FU7-A6: a legacy
// file that does not hold an id is an error, never minted over, and the
// read-only resolver answers none for it.
func TestOpenShellLegacyAdoptionChecksTheUnit(t *testing.T) {
	legacyID := "0123456789abcdef"
	gid, _ := sandboxopenshell.IdentityFor(legacyID)
	seed := func(t *testing.T, content string) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "sandbox-openshell")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, sandboxopenshell.LegacyInstallIDFile), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	unitRuns := func(cfg string) func(string) (string, bool) {
		return func(unit string) (string, bool) {
			if unit != gid.Unit {
				t.Errorf("asked about unit %q, want %q", unit, gid.Unit)
			}
			return cfg, true
		}
	}
	t.Run("the unit runs this dir's config", func(t *testing.T) {
		dir := seed(t, legacyID+"\n")
		own := filepath.Join(dir, "gateway", "gateway.toml")
		if got := openShellReadInstallIDWith(dir, unitRuns(own)); got != legacyID {
			t.Fatalf("read: %q", got)
		}
		if got, err := openShellInstallIDWith(dir, unitRuns(own)); err != nil || got != legacyID {
			t.Fatalf("adopt: %q %v", got, err)
		}
	})
	t.Run("the unit runs this dir's config through a symlink", func(t *testing.T) {
		dir := seed(t, legacyID+"\n")
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		if got, err := openShellInstallIDWith(dir, unitRuns(filepath.Join(link, "gateway", "gateway.toml"))); err != nil || got != legacyID {
			t.Fatalf("adopt: %q %v", got, err)
		}
	})
	t.Run("the unit runs another dir's config", func(t *testing.T) {
		dir := seed(t, legacyID+"\n")
		other := unitRuns("/home/dev/.observer/sandbox-openshell/gateway/gateway.toml")
		if got := openShellReadInstallIDWith(dir, other); got != "" {
			t.Fatalf("read: %q", got)
		}
		got, err := openShellInstallIDWith(dir, other)
		if err != nil || got == legacyID || got == "" {
			t.Fatalf("a pre-binding copy adopted the running original's id: %q %v", got, err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, sandboxopenshell.LegacyInstallIDFile)); strings.TrimSpace(string(b)) != got {
			t.Fatalf("the legacy file was not rewritten: %q", b)
		}
	})
	t.Run("a legacy file that holds no id", func(t *testing.T) {
		dir := seed(t, "not an id\n")
		if got := openShellReadInstallIDWith(dir, unitRuns("")); got != "" {
			t.Fatalf("read: %q", got)
		}
		if got, err := openShellInstallIDWith(dir, func(string) (string, bool) { return "", false }); err == nil {
			t.Fatalf("minted %q over an unreadable legacy id", got)
		}
	})
}

// TestOpenShellEngineRecordRace (audit finding FU7-A7): when another probe
// writes the record between this probe's read and its write, the write's
// ErrExist reads that record back and compares it; no hint is left.
func TestOpenShellEngineRecordRace(t *testing.T) {
	for _, tc := range []struct {
		name, other, verdict string
	}{
		{"the other probe saw the same engine", openShellTestEngineID, ""},
		{"the other probe saw another engine", "5b1e3f0a-6c0d-4a8e-9f1a-2b3c4d5e6f70", sandboxopenshell.VerdictEngineChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "sandbox-openshell")
			read, save := openShellEngineRecordIO(stateDir)
			raced := func(b []byte) error {
				other, _ := json.Marshal(sandboxopenshell.EngineRecord{EngineID: tc.other, FirstSeen: 1})
				if err := save(other); err != nil {
					t.Fatal(err)
				}
				return save(b)
			}
			g := &openShellGathering{host: openShellHostFactsT{EngineRecord: read, SaveEngine: raced}}
			g.out.facts.Driver = "docker"
			g.run = func(context.Context, integration.BinaryResolveSpec, []string) extrun.Result {
				return extrun.Result{Outcome: extrun.OutcomeOK, Stdout: []byte(`"` + openShellTestEngineID + `"` + "\n")}
			}
			openShellEngineStep(context.Background(), g)
			if v, _ := sandboxopenshell.EngineVerdict(g.out.facts.Engine); v != tc.verdict || g.out.engineNote != "" {
				t.Fatalf("verdict %q note %q facts %+v", v, g.out.engineNote, g.out.facts.Engine)
			}
		})
	}
}
