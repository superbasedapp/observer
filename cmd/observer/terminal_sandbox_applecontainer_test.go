//go:build !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxapple"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_applecontainer_test.go covers the Apple container
// driver's Linux-runnable half (lane SBX-P5); the CLI calls are
// cross-compiled only (register section 13.9).

const appleTestImage = "ghcr.io/example/agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func appleTestConfig(t *testing.T, selectDriver bool, backends ...string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	cfg.Terminal.Sandbox.Enabled = true
	cfg.Terminal.Sandbox.Backends = backends
	cfg.Terminal.Sandbox.AppleContainer.Image = appleTestImage
	if selectDriver {
		cfg.Components.Add = []string{appleComponent}
	}
	return cfg
}

// countAppleProbe stands in a healthy macOS 26 Apple silicon host and counts
// the probe and the sweep.
func countAppleProbe(t *testing.T) (*atomic.Int64, *atomic.Int64) {
	t.Helper()
	var probes, sweeps atomic.Int64
	prevP, prevS := appleProbeEnvFn, appleSweepFn
	appleProbeEnvFn = func(cfg config.TerminalSandboxAppleContainerConfig) sandboxapple.ProbeEnv {
		probes.Add(1)
		return sandboxapple.ProbeEnv{
			GOOS:       "darwin",
			Arm64:      func() (bool, error) { return true, nil },
			OSVersion:  func() (string, error) { return "26.1", nil },
			Hypervisor: func() (bool, bool) { return true, true },
			LookCLI:    func() (string, error) { return "/usr/local/bin/container", nil },
			StatCLI: func(string) (sandboxapple.CLIFacts, error) {
				return sandboxapple.CLIFacts{Regular: true, OwnerOK: true, Perm: 0o755}, nil
			},
			Version: func(string) (string, error) { return "container CLI version 0.5.0", nil },
			RunHelp: func(string) (string, error) {
				return "--publish-socket <spec> --read-only-path <path> --entrypoint <cmd> --progress <type>", nil
			},
			SystemRunning: func(string) error { return nil },
			Image:         cfg.Image,
			ImagePresent:  func(string, string) (bool, error) { return true, nil },
		}
	}
	appleSweepFn = func(string, string, string) { sweeps.Add(1) }
	t.Cleanup(func() { appleProbeEnvFn, appleSweepFn = prevP, prevS })
	return &probes, &sweeps
}

func TestAppleDriverIsOptIn(t *testing.T) {
	probes, sweeps := countAppleProbe(t)
	reg, ok := sandboxDriverRegs[sandboxbackend.BackendAppleContainer]
	if !ok || reg.component != appleComponent {
		t.Fatalf("registration %+v", reg)
	}
	legacy := macTestRuntime(t, appleTestConfig(t, false, "apple-container"))
	if _, active := legacy.drivers[sandboxbackend.BackendAppleContainer]; active {
		t.Fatal("an install with no [components] block got the driver")
	}
	if p := legacy.driverProbes(context.Background())[sandboxbackend.BackendAppleContainer]; p.Verdict != verdictModuleInactive {
		t.Fatalf("an unselected driver probes as %+v", p)
	}
	unlisted := macTestRuntime(t, appleTestConfig(t, true, "bwrap"))
	if p := unlisted.drivers[sandboxbackend.BackendAppleContainer].probe(context.Background()); p.Verdict != sandboxselect.VerdictDisabledByConfig {
		t.Fatalf("an unlisted driver probes as %+v", p)
	}
	if probes.Load() != 0 || sweeps.Load() != 0 {
		t.Fatalf("probes %d sweeps %d while inactive", probes.Load(), sweeps.Load())
	}
	listed := macTestRuntime(t, appleTestConfig(t, true, "apple-container"))
	listed.inDaemon = true
	d := listed.drivers[sandboxbackend.BackendAppleContainer].(*appleDriver)
	if p := d.probe(context.Background()); p.Verdict != sandboxapple.VerdictAvailable || p.Version != "0.5.0" {
		t.Fatalf("a listed driver probes as %+v", p)
	}
	d.lastAt = d.lastAt.Add(-2 * sandboxProbeTTL)
	_ = d.probe(context.Background())
	if probes.Load() != 2 {
		t.Fatalf("probes = %d", probes.Load())
	}
	// The sweep runs once per daemon, in the background.
	for i := 0; i < 1000 && sweeps.Load() == 0; i++ {
		runtime.Gosched()
	}
	if sweeps.Load() > 1 {
		t.Fatalf("the orphan sweep ran %d times", sweeps.Load())
	}
}

func TestAppleOffMacOSRefusesByHost(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("the off-macOS half")
	}
	res := sandboxapple.Probe(appleProbeEnv(config.TerminalSandboxAppleContainerConfig{}))
	if res.Verdict.Code != sandboxapple.VerdictUnsupportedPlatform {
		t.Fatalf("off macOS: %+v", res.Verdict)
	}
}

// TestAppleIntelAndOldMacOSVerdicts: on a Mac where the row cannot run, the
// selection reports the probe's named verdict.
func TestAppleIntelAndOldMacOSVerdicts(t *testing.T) {
	for _, c := range []struct {
		res  sandboxapple.ProbeResult
		want string
	}{
		{sandboxapple.ProbeResult{Verdict: sandboxapple.Verdict{Code: sandboxapple.VerdictArchUnsupported, Reason: "Intel"}}, sandboxapple.VerdictArchUnsupported},
		{sandboxapple.ProbeResult{Verdict: sandboxapple.Verdict{Code: sandboxapple.VerdictOSTooOld, Reason: "macOS 15"}}, sandboxapple.VerdictOSTooOld},
	} {
		in := sandboxselect.Input{
			Request: sandboxselect.Request{Backend: sandboxbackend.BackendAppleContainer, Tier: vocab.TierInternet, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
			Host:    sandboxbackend.HostMacOS, Enabled: []string{sandboxbackend.BackendAppleContainer},
			Probes: map[string]sandboxselect.Probe{sandboxbackend.BackendAppleContainer: appleSelectProbe(c.res, nil)},
			Tool:   sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
		}
		got := sandboxselect.Select(in)
		if got.Chosen != nil || len(got.Drops) == 0 || got.Drops[0].Verdict != c.want {
			t.Errorf("want %s: %+v", c.want, got)
		}
	}
	// An hw_vm floor on an Intel Mac: the seatbelt row cannot meet it either.
	if sb, _ := sandboxbackend.Get(sandboxbackend.BackendSeatbelt); sb.Iso.Class.Rank() >= vocab.ClassHWVM.Rank() {
		t.Fatal("the Seatbelt row would meet an hw_vm floor")
	}
}

func TestAppleIsNeverAnAutoPick(t *testing.T) {
	p := appleSelectProbe(sandboxapple.ProbeResult{Verdict: sandboxapple.Verdict{Code: sandboxapple.VerdictAvailable}, Version: "0.5.0"}, nil)
	in := sandboxselect.Input{
		Request: sandboxselect.Request{Tier: vocab.TierInternet, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
		Host:    sandboxbackend.HostMacOS, Enabled: []string{sandboxbackend.BackendAppleContainer},
		Probes: map[string]sandboxselect.Probe{sandboxbackend.BackendAppleContainer: p},
		Tool:   sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
	}
	if got := sandboxselect.Select(in); got.Chosen != nil {
		t.Fatalf("auto picked %+v", got.Chosen)
	}
	in.Request.Backend = sandboxbackend.BackendAppleContainer
	if got := sandboxselect.Select(in); got.Chosen == nil || !got.Chosen.Beta || got.Chosen.Class != vocab.ClassHWVM {
		t.Fatalf("named explicitly: %+v", got)
	}
}

func TestApplePinsMirrorThePlanner(t *testing.T) {
	pins := appleRow().Control.Pins
	if pins.RequiredMin != sandboxapple.RequiredMin || pins.TestedLow != sandboxapple.DocLow || pins.TestedHigh != sandboxapple.DocHigh {
		t.Fatalf("pins %+v", pins)
	}
	if !appleRow().Iso.CrossesKernel || appleRow().Capture.HookPath != sandboxbackend.HookRelay {
		t.Fatal("the VM row must reach the daemon through the relay (I5)")
	}
}

func TestAppleRunEnv(t *testing.T) {
	// The box's environment is the allow-list (WINFIX2, ledger SBX-WIN-ENV-1): a provider
	// variable the launch names crosses; an unnamed one (here a base URL,
	// which Observer sets itself in the box) does not.
	env := appleRunEnv([]string{"HOME=/Users/dev", "PATH=/opt/homebrew/bin", "SSH_AUTH_SOCK=/s", envOOBAuth + "=secret", "OBSERVER_SANDBOX=0", "ANTHROPIC_BASE_URL=http://127.0.0.1:8820", "ANTHROPIC_API_KEY=k", sandboxenv.EnvAllow + "=ANTHROPIC_API_KEY"})
	for _, want := range []string{"HOME=/Users/dev", "ANTHROPIC_API_KEY=k", "OBSERVER_SANDBOX=1"} {
		if !slices.Contains(env, want) {
			t.Errorf("missing %s: %q", want, env)
		}
	}
	for _, kv := range env {
		for _, gone := range []string{"PATH=", "SSH_AUTH_SOCK=", envOOBAuth + "=", "OBSERVER_SANDBOX=0", "ANTHROPIC_BASE_URL="} {
			if strings.HasPrefix(kv, gone) {
				t.Errorf("%s survived", kv)
			}
		}
	}
}

func TestApplePlanFileHoldsNoSecrets(t *testing.T) {
	b, err := json.Marshal(applePlanFile{Version: macPlanVersion, Run: sandboxapple.RunPlan{Env: []string{"X=1"}}, Hidden: []appleHidden{{Path: "/x"}}})
	if err != nil {
		t.Fatal(err)
	}
	l := strings.ToLower(string(b))
	for _, bad := range []string{"secret", "token", "password", "credential", "apikey", "api_key"} {
		if strings.Contains(l, bad) {
			t.Errorf("plan JSON names %q: %s", bad, b)
		}
	}
	id, err := appleInstallID(t.TempDir())
	if err != nil || !sandboxapple.ValidToken(id) {
		t.Fatalf("install id %q %v", id, err)
	}
}

func TestAppleRunLive(t *testing.T) {
	live := appleRunLive(t.TempDir())
	if live("nope") {
		t.Fatal("a run with no record is live")
	}
}

// appleMountByTarget indexes a mount plan.
func appleMountByTarget(mp appleMountPlan) map[string]sandboxapple.Mount {
	got := map[string]sandboxapple.Mount{}
	for _, m := range mp.Mounts {
		got[m.Target] = m
	}
	return got
}

// appleNoFileUnderAMountSource is the D-A3 rule: no -v mount of a file whose
// parent directory is itself a mount's source (Apple container 1.6.0 then
// drops that directory mount in the guest).
func appleNoFileUnderAMountSource(t *testing.T, mp appleMountPlan) {
	t.Helper()
	sources := map[string]bool{}
	for _, m := range mp.Mounts {
		sources[m.Source] = true
	}
	for _, m := range mp.Mounts {
		if fi, err := os.Stat(m.Source); err == nil && !fi.IsDir() && sources[filepath.Dir(m.Source)] {
			t.Errorf("the file %s is mounted with -v under the mounted directory %s", m.Source, filepath.Dir(m.Source))
		}
	}
}

// TestAppleMounts: the container's mounts are the bwrap plan's inputs at
// their own paths; the protect table's read-only overlays become read-only
// paths inside the guest (a missing one through a placeholder), never a -v
// file mount under a mounted directory (D-A3); hidden ones are returned for
// the helper; the socket dir is not mounted (D-A4: the tunnel replaces it).
func TestAppleMounts(t *testing.T) {
	skipDriverOffHost(t, "apple container")
	home := t.TempDir()
	ws := filepath.Join(home, "src", "app")
	for _, d := range []string{ws, filepath.Join(home, ".claude"), filepath.Join(ws, ".git")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(ws, ".git", "config"), filepath.Join(home, ".claude", "settings.json")} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spec := integration.SandboxSpec{StateRW: []string{".claude", ".claude.json"}, StateRO: []string{".claude/settings.json"}}
	overlays := []sandbox.Overlay{
		{Path: filepath.Join(ws, ".git", "config"), Kind: sandbox.OverlayReadOnly},
		{Path: filepath.Join(ws, ".git", "hooks"), Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderDir},
		{Path: filepath.Join(ws, ".git", "commondir"), Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderFile},
		{Path: filepath.Join(home, ".claude", ".credentials.json"), Kind: sandbox.OverlayHideFile},
		{Path: "/elsewhere/not-mounted", Kind: sandbox.OverlayHideFile},
		{Path: "/elsewhere/ro", Kind: sandbox.OverlayReadOnly},
	}
	mp := appleMounts(home, ws, spec, config.TerminalSandboxConfig{}, overlays, []string{filepath.Join(ws, ".git")})
	got := appleMountByTarget(mp)
	if m := got[ws]; m.ReadOnly || m.Source != ws {
		t.Errorf("workspace %+v", m)
	}
	if m, ok := got[filepath.Join(home, ".claude")]; !ok || m.ReadOnly {
		t.Errorf("state rw %+v", m)
	}
	if _, ok := got[filepath.Join(home, ".claude.json")]; ok {
		t.Error("a missing state file was mounted")
	}
	if m, ok := got[filepath.Join(ws, ".git")]; !ok || m.ReadOnly {
		t.Errorf("the .git pin %+v", m)
	}
	for _, p := range []string{filepath.Join(ws, ".git", "config"), filepath.Join(ws, ".git", "hooks"), filepath.Join(ws, ".git", "commondir"), filepath.Join(home, ".claude", "settings.json")} {
		if _, ok := got[p]; ok {
			t.Errorf("%s is a -v mount", p)
		}
		if !slices.Contains(mp.ReadOnly, p) {
			t.Errorf("%s is not a read-only path: %q", p, mp.ReadOnly)
		}
	}
	if slices.Contains(mp.ReadOnly, "/elsewhere/ro") {
		t.Error("a read-only overlay outside every mount was planned")
	}
	if len(mp.Placeholders) != 2 {
		t.Errorf("placeholders %v", mp.Placeholders)
	}
	if _, ok := got[sandboxapple.GuestSocketDir]; ok {
		t.Error("the socket dir is mounted; a host unix socket does not connect over virtiofs (D-A4)")
	}
	if len(mp.Hidden) != 1 || mp.Hidden[0].Path != filepath.Join(home, ".claude", ".credentials.json") || mp.Hidden[0].Dir {
		t.Errorf("hidden %+v", mp.Hidden)
	}
	appleNoFileUnderAMountSource(t, mp)
	dirs := mustMacDirs(t, "run1")
	withHidden := appleWithHidden(sandboxapple.RunPlan{Mounts: mp.Mounts}, mp.Hidden, dirs)
	last := withHidden.Mounts[len(withHidden.Mounts)-1]
	if !last.ReadOnly || last.Target != mp.Hidden[0].Path || !strings.HasPrefix(last.Source, dirs.TempDir) {
		t.Errorf("hidden stand-in %+v", last)
	}
}

// TestAppleMountsPins (lane SHR-FOLLOWUPS, ledger SBX-BE-10): the launch's
// pins are mounted read-write onto themselves after the write mounts, as the
// oci path does; the read-only paths inside them are read-only paths; a pin
// outside every write mount or missing is left out; a .git gitfile pin is a
// read-only path (it can be neither renamed nor rewritten), never a -v file
// mount under the workspace (D-A3). Without the pins the .git is not a
// mount.
func TestAppleMountsPins(t *testing.T) {
	skipDriverOffHost(t, "apple container")
	home := t.TempDir()
	ws := filepath.Join(home, "src", "app")
	org := filepath.Join(home, "org")
	repo := filepath.Join(org, "team", "repo")
	wt := filepath.Join(org, "team", "wt")
	for _, d := range []string{filepath.Join(ws, ".git"), filepath.Join(repo, ".git", "hooks"), filepath.Join(home, "ro", ".git"), wt} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: /x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.TerminalSandboxConfig{ExtraRWBinds: []string{org}, ExtraROBinds: []string{filepath.Join(home, "ro")}}
	overlays := []sandbox.Overlay{{Path: filepath.Join(repo, ".git", "hooks"), Kind: sandbox.OverlayReadOnly}}
	pins := []string{filepath.Join(ws, ".git"), repo, filepath.Join(repo, ".git"), filepath.Join(home, "ro", ".git"), filepath.Join(ws, "missing"), filepath.Join(wt, ".git")}
	mp := appleMounts(home, ws, integration.SandboxSpec{}, cfg, overlays, pins)
	idx := map[string]int{}
	for i, m := range mp.Mounts {
		idx[m.Target] = i
		if slices.Contains(pins[:3], m.Target) && (m.ReadOnly || m.Source != m.Target) {
			t.Errorf("pin %s mounted as %+v", m.Target, m)
		}
	}
	for _, p := range pins[:3] {
		i, ok := idx[p]
		if !ok {
			t.Fatalf("pin %s not mounted (mounts %+v)", p, mp.Mounts)
		}
		if i < idx[org] {
			t.Errorf("pin %s mounted before its write mount", p)
		}
	}
	if !slices.Contains(mp.ReadOnly, filepath.Join(repo, ".git", "hooks")) {
		t.Errorf("the hooks overlay inside the pin is not a read-only path: %q", mp.ReadOnly)
	}
	for _, p := range pins[3:5] {
		if _, ok := idx[p]; ok {
			t.Errorf("%s mounted; it is outside every write mount or missing", p)
		}
	}
	if _, ok := idx[filepath.Join(wt, ".git")]; ok || !slices.Contains(mp.ReadOnly, filepath.Join(wt, ".git")) {
		t.Errorf("the gitfile pin: mounted=%v read-only paths %q", ok, mp.ReadOnly)
	}
	appleNoFileUnderAMountSource(t, mp)
	plain := appleMounts(home, ws, integration.SandboxSpec{}, cfg, overlays, nil)
	for _, m := range plain.Mounts {
		if m.Target == filepath.Join(ws, ".git") || m.Target == filepath.Join(repo, ".git") {
			t.Fatalf("%s is a mount without the pins", m.Target)
		}
	}
}

// TestAppleMountsPinsSkipANestedReadOnlyMount (lane SHR-FOLLOWUPS audit
// finding 1): a repository under an extra_ro_binds directory nested inside
// a write mount is not pinned, because its nearest enclosing mount is
// read-only; a repository beside it in the write mount still is.
func TestAppleMountsPinsSkipANestedReadOnlyMount(t *testing.T) {
	skipDriverOffHost(t, "apple container")
	home := t.TempDir()
	ws := filepath.Join(home, "src", "app")
	org := filepath.Join(home, "org")
	repo := filepath.Join(org, "team", "repo")
	vendor := filepath.Join(org, "vendor")
	roRepo := filepath.Join(vendor, "lib")
	for _, d := range []string{filepath.Join(ws, ".git"), filepath.Join(repo, ".git"), filepath.Join(roRepo, ".git")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.TerminalSandboxConfig{ExtraRWBinds: []string{org}, ExtraROBinds: []string{vendor}}
	pins := []string{repo, filepath.Join(repo, ".git"), roRepo, filepath.Join(roRepo, ".git")}
	got := appleMountByTarget(appleMounts(home, ws, integration.SandboxSpec{}, cfg, nil, pins))
	if m, ok := got[vendor]; !ok || !m.ReadOnly {
		t.Fatalf("the read-only bind %s is %+v", vendor, m)
	}
	for _, p := range pins[:2] {
		if m, ok := got[p]; !ok || m.ReadOnly {
			t.Errorf("pin %s mounted as %+v", p, m)
		}
	}
	for _, p := range pins[2:] {
		if m, ok := got[p]; ok {
			t.Errorf("%s mounted as %+v under the read-only mount %s", p, m, vendor)
		}
	}
}

// TestAppleComposePinsThroughTheLaunch (lane SHR-FOLLOWUPS audit findings 1
// and 2, and the 1.6.0 fixes): the launch's own compose carries the pins,
// the read-only paths and the tunnel into the plan file the helper runs; a
// repository under a read-only bind nested in the org write bind is left
// out; the in-guest check the init is told covers every planned mount and
// read-only path.
func TestAppleComposePinsThroughTheLaunch(t *testing.T) {
	skipDriverOffHost(t, "apple container")
	home := t.TempDir()
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	setTestHome(t, home)
	org := filepath.Join(t.TempDir(), "org")
	if real, err := filepath.EvalSymlinks(filepath.Dir(org)); err == nil {
		org = filepath.Join(real, "org")
	}
	repo := filepath.Join(org, "team", "repo")
	vendor := filepath.Join(org, "vendor")
	roRepo := filepath.Join(vendor, "lib")
	ws := filepath.Join(home, "src", "app")
	for _, d := range []string{filepath.Join(home, ".claude"), filepath.Join(ws, ".git", "hooks"), filepath.Join(repo, ".git", "hooks"), filepath.Join(roRepo, ".git", "hooks")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ws, ".git", "config"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := appleTestConfig(t, true, "apple-container")
	cfg.Terminal.Sandbox.ExtraRWBinds = []string{org}
	cfg.Terminal.Sandbox.ExtraROBinds = []string{vendor}
	rt := macTestRuntime(t, cfg)
	rt.orgRWBinds = []string{org}
	d, ok := rt.drivers[sandboxbackend.BackendAppleContainer].(*appleDriver)
	if !ok {
		t.Fatal("no apple container driver")
	}
	wrap, err := d.compose(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: "AbCdEfGhIjKlMnOpQrSt08", Tool: "claude-code", Dir: ws}}, "/usr/local/bin/container")
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	i := slices.Index(wrap, "--plan")
	if i < 0 {
		t.Fatalf("no plan in %q", wrap)
	}
	var plan applePlanFile
	if err := readMacPlan(wrap[i+1], &plan); err != nil {
		t.Fatal(err)
	}
	got := map[string]sandboxapple.Mount{}
	for _, m := range plan.Run.Mounts {
		got[m.Target] = m
	}
	for _, w := range []string{filepath.Join(ws, ".git"), repo, filepath.Join(repo, ".git")} {
		if m, ok := got[w]; !ok || m.ReadOnly || m.Source != w {
			t.Errorf("pin %s is %+v in the launch's plan", w, m)
		}
	}
	for _, gone := range []string{roRepo, filepath.Join(roRepo, ".git")} {
		if m, ok := got[gone]; ok && !m.ReadOnly {
			t.Errorf("%s is mounted read-write under the read-only bind %s", gone, vendor)
		}
	}
	for _, p := range []string{filepath.Join(ws, ".git", "config"), filepath.Join(ws, ".git", "hooks"), filepath.Join(ws, ".git", "commondir")} {
		if !slices.Contains(plan.Run.ReadOnlyPaths, p) {
			t.Errorf("%s is not a read-only path in the launch's plan: %q", p, plan.Run.ReadOnlyPaths)
		}
		if _, ok := got[p]; ok {
			t.Errorf("%s is a -v mount in the launch's plan", p)
		}
	}
	if _, ok := got[sandboxapple.GuestSocketDir]; ok {
		t.Error("the socket dir is mounted")
	}
	if len(plan.Run.PublishSockets) != 1 || plan.Run.PublishSockets[0].Guest != sandboxapple.GuestTunnelPath ||
		plan.Run.PublishSockets[0].Host != filepath.Join(plan.Dirs.SocketDir, sandboxapple.TunnelSocketName) {
		t.Errorf("the tunnel %+v", plan.Run.PublishSockets)
	}
	spec := appleInitSpec(appleWithHidden(plan.Run, plan.Hidden, plan.Dirs), plan.HostBin, "AbCdEfGhIjKlMnOpQrSt08")
	if !slices.Contains(spec.Mounts, ws) || !slices.Contains(spec.Mounts, filepath.Join(ws, ".git")) {
		t.Errorf("the in-guest check's mounts %q", spec.Mounts)
	}
	for _, p := range plan.Run.ReadOnlyPaths {
		if !slices.Contains(spec.ReadOnly, p) {
			t.Errorf("the in-guest check does not cover %s", p)
		}
	}
	argv, err := sandboxapple.RunArgv(func() sandboxapple.RunPlan {
		p := appleWithHidden(plan.Run, plan.Hidden, plan.Dirs)
		p.Command, _ = sandboxapple.GuestCommand(spec, plan.Guest, []string{"/usr/local/bin/observer", "claude"})
		return p
	}())
	if err != nil || !slices.Contains(argv, "--entrypoint") || !slices.Contains(argv, "--progress") {
		t.Fatalf("the launch's argv %q %v", argv, err)
	}
}

// TestAppleTunnelKinds: the relay always, the proxy only while its forward
// serves, the gateway only on a gateway tier.
func TestAppleTunnelKinds(t *testing.T) {
	dir := t.TempDir()
	if k := appleTunnelKinds(dir, false); !k["relay"] || k["proxy"] || k["gateway"] {
		t.Fatalf("no forward: %v", k)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, sandbox.ProxySocketName))
	if err != nil {
		t.Skip("no unix sockets here")
	}
	defer ln.Close()
	if k := appleTunnelKinds(dir, true); !k["proxy"] || !k["gateway"] {
		t.Fatalf("forward and gateway: %v", k)
	}
}
