//go:build !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxsbpl"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_seatbelt_test.go covers the Seatbelt driver's
// Linux-runnable half (lane SBX-P5): registration and the opt-in rule, the
// probe mapping, the floors, N6, the plan, the wrap argv, the agent's
// environment and the computed capture. The macOS half is cross-compiled
// only and is register section 13.9.

func seatbeltTestConfig(t *testing.T, selectDriver bool, backends ...string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	cfg.Terminal.Sandbox.Enabled = true
	cfg.Terminal.Sandbox.Backends = backends
	if selectDriver {
		cfg.Components.Add = []string{seatbeltComponent}
	} else {
		// The module on, its Seatbelt driver not chosen, in every edition
		// (developer and managed leave the module inactive by default).
		selectIfInactive(t, &cfg, sandboxComponent)
	}
	return cfg
}

// countSeatbeltProbe replaces the probe's facts with a healthy macOS 26
// host and counts the calls.
func countSeatbeltProbe(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	prev := seatbeltProbeEnvFn
	seatbeltProbeEnvFn = func() sandboxsbpl.ProbeEnv {
		n.Add(1)
		return sandboxsbpl.ProbeEnv{
			GOOS:      "darwin",
			OSVersion: func() (string, error) { return "26.0", nil },
			StatExec: func(string) (sandboxsbpl.ExecFacts, error) {
				return sandboxsbpl.ExecFacts{Regular: true, Perm: 0o755}, nil
			},
		}
	}
	t.Cleanup(func() { seatbeltProbeEnvFn = prev })
	return &n
}

func TestSeatbeltDriverIsOptIn(t *testing.T) {
	n := countSeatbeltProbe(t)
	reg, ok := sandboxDriverRegs[sandboxbackend.BackendSeatbelt]
	if !ok || reg.component != seatbeltComponent {
		t.Fatalf("seatbelt registration %+v", reg)
	}
	legacy := macTestRuntime(t, seatbeltTestConfig(t, false, "seatbelt"))
	if _, active := legacy.drivers[sandboxbackend.BackendSeatbelt]; active || legacy.inactiveDrivers[sandboxbackend.BackendSeatbelt] != seatbeltComponent {
		t.Fatalf("legacy drivers %v inactive %v", legacy.drivers, legacy.inactiveDrivers)
	}
	if p := legacy.driverProbes(context.Background())[sandboxbackend.BackendSeatbelt]; p.Verdict != verdictModuleInactive {
		t.Fatalf("an unselected driver probes as %+v", p)
	}
	on := macTestRuntime(t, seatbeltTestConfig(t, true, "bwrap"))
	d, ok := on.drivers[sandboxbackend.BackendSeatbelt]
	if !ok {
		t.Fatal("a block that adds the Seatbelt driver did not get it")
	}
	// Selected but not listed: nothing is read.
	if p := d.probe(context.Background()); p.Verdict != sandboxselect.VerdictDisabledByConfig {
		t.Fatalf("an unlisted driver probes as %+v", p)
	}
	if n.Load() != 0 {
		t.Fatalf("the probe read the host %d times while inactive", n.Load())
	}
	listed := macTestRuntime(t, seatbeltTestConfig(t, true, "seatbelt"))
	if p := listed.drivers[sandboxbackend.BackendSeatbelt].probe(context.Background()); p.Verdict != sandboxsbpl.VerdictAvailable || p.Version != "26.0" {
		t.Fatalf("a listed driver on a healthy host probes as %+v", p)
	}
	if n.Load() != 1 {
		t.Fatalf("probe calls = %d, want 1", n.Load())
	}
}

// TestSeatbeltOffMacOSRefusesByHost: the real (unstubbed) probe off macOS
// stops at its platform row, and the selection drops the row at S3.
func TestSeatbeltOffMacOSRefusesByHost(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this is the off-macOS half")
	}
	res := sandboxsbpl.Probe(seatbeltProbeEnv())
	if res.Verdict.Code != sandboxsbpl.VerdictUnsupportedPlatform {
		t.Fatalf("off macOS the probe says %+v", res.Verdict)
	}
	p := seatbeltSelectProbe(res, nil)
	in := sandboxselect.Input{
		Request: sandboxselect.Request{Backend: sandboxbackend.BackendSeatbelt, Tier: vocab.TierInternet, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
		Host:    sandboxHostKind(), Enabled: []string{sandboxbackend.BackendSeatbelt},
		Probes: map[string]sandboxselect.Probe{sandboxbackend.BackendSeatbelt: p},
		Tool:   sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
	}
	got := sandboxselect.Select(in)
	if got.Chosen != nil || len(got.Drops) == 0 || got.Drops[0].Verdict != sandboxselect.VerdictUnsupportedPlatform {
		t.Fatalf("selection off macOS: %+v", got)
	}
}

// TestSeatbeltIsNeverAnAutoPick: an auto request (and the guard's
// auto-upgrade) never lands on the beta row, even on a macOS host where it
// probes available.
func TestSeatbeltIsNeverAnAutoPick(t *testing.T) {
	p := seatbeltSelectProbe(sandboxsbpl.ProbeResult{Verdict: sandboxsbpl.Verdict{Code: sandboxsbpl.VerdictAvailable}, OSVersion: "26.0"}, nil)
	for _, guard := range []bool{false, true} {
		in := sandboxselect.Input{
			Request: sandboxselect.Request{Tier: vocab.TierInternet, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true, GuardEnforce: guard},
			Host:    sandboxbackend.HostMacOS, Enabled: []string{sandboxbackend.BackendSeatbelt},
			Probes: map[string]sandboxselect.Probe{sandboxbackend.BackendSeatbelt: p},
			Tool:   sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
		}
		if got := sandboxselect.Select(in); got.Chosen != nil {
			t.Fatalf("guard=%v: auto picked %+v", guard, got.Chosen)
		}
	}
	in := sandboxselect.Input{
		Request: sandboxselect.Request{Backend: sandboxbackend.BackendSeatbelt, Tier: vocab.TierInternet, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true},
		Host:    sandboxbackend.HostMacOS, Enabled: []string{sandboxbackend.BackendSeatbelt},
		Probes: map[string]sandboxselect.Probe{sandboxbackend.BackendSeatbelt: p},
		Tool:   sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
	}
	got := sandboxselect.Select(in)
	if got.Chosen == nil || !got.Chosen.Beta {
		t.Fatalf("named explicitly on macOS 26 the row is not chosen as beta: %+v", got)
	}
}

func TestSeatbeltPinsMirrorThePlanner(t *testing.T) {
	pins := seatbeltRow().Control.Pins
	if pins.RequiredMin != sandboxsbpl.SeatbeltRequiredMin || pins.TestedLow != sandboxsbpl.SeatbeltDocLow || pins.TestedHigh != sandboxsbpl.SeatbeltDocHigh {
		t.Fatalf("row pins %+v differ from the planner's", pins)
	}
}

func TestSeatbeltFloor(t *testing.T) {
	row := seatbeltRow()
	base := seatbeltTestConfig(t, true, "seatbelt").Terminal.Sandbox
	if err := macDriverFloor(row, base, ""); err != nil {
		t.Fatalf("the default config refused: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*config.TerminalSandboxConfig)
		want string
	}{
		{"not listed", func(c *config.TerminalSandboxConfig) { c.Backends = []string{"bwrap"} }, "not in [terminal.sandbox].backends"},
		{"host tier", func(c *config.TerminalSandboxConfig) { c.Egress = "host" }, "no host network tier"},
		{"container floor", func(c *config.TerminalSandboxConfig) { c.MinIsolation = "container" }, "below [terminal.sandbox].min_isolation"},
		{"org pin left none", func(c *config.TerminalSandboxConfig) { c.PinnedNoBackend = "terminal.sandbox.backends" }, "allows none"},
	}
	for _, c := range cases {
		cfg := base
		c.mut(&cfg)
		err := macDriverFloor(row, cfg, "")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	notListed := base
	notListed.Backends = []string{"bwrap"}
	if err := macDriverFloor(row, notListed, sandboxbackend.BackendSeatbelt); err != nil {
		t.Errorf("a CLI-named backend is refused by the list: %v", err)
	}
}

// TestSeatbeltNativeN6: the tools' native rows reduce to N6's facts at the
// boundary, and the outcome per tool is the table's.
func TestSeatbeltNativeN6(t *testing.T) {
	cases := map[string]sandboxsbpl.NativeOutcome{
		"codex":       sandboxsbpl.NativeDisableFlag, // on by default, its grounded flag applied (lane SBX-P3D)
		"claude-code": sandboxsbpl.NativeUnjudged,    // off by default (global setting)
		"gemini-cli":  sandboxsbpl.NativeUnjudged,    // off by default
		"goose":       sandboxsbpl.NativeKept,        // no native sandbox
		"copilot-cli": sandboxsbpl.NativeKept,        // its native sandbox is not Seatbelt-based (Linux mechanism)
	}
	for tool, want := range cases {
		dec := sandboxsbpl.DecideNative(seatbeltNative(tool))
		if dec.Outcome != want {
			t.Errorf("%s: %s (%s), want %s", tool, dec.Outcome, dec.Rule, want)
		}
	}
	if s := seatbeltNativeState("goose", sandboxsbpl.NativeDecision{Outcome: sandboxsbpl.NativeKept}); s != vocab.NativeNotApplicable {
		t.Errorf("goose state %q", s)
	}
	if s := seatbeltNativeState("codex", sandboxsbpl.NativeDecision{Outcome: sandboxsbpl.NativeDisableEnv}); s != vocab.NativeDisabledByObserver {
		t.Errorf("disable state %q", s)
	}
	if s := seatbeltNativeState("claude-code", sandboxsbpl.NativeDecision{Outcome: sandboxsbpl.NativeUnjudged}); s != "" {
		t.Errorf("an unjudged sandbox recorded %q", s)
	}
}

// TestSeatbeltComputedCapture: the run's capture is computed from the row
// (section 4.4), never read from it: full through the gateway with the
// provider block on internet, full on proxy_only, reduced unrouted.
func TestSeatbeltComputedCapture(t *testing.T) {
	row := seatbeltRow()
	in := sandboxRunCaptureFor(row, true, vocab.TierInternet, "")
	if in.Level != vocab.CaptureFull || !in.ProviderBlock {
		t.Fatalf("internet, routed: %+v", in)
	}
	if po := sandboxRunCaptureFor(row, true, vocab.TierProxyOnly, ""); po.Level != vocab.CaptureFull {
		t.Fatalf("proxy_only, routed: %+v", po)
	}
	if un := sandboxRunCaptureFor(row, false, vocab.TierInternet, ""); un.Level == vocab.CaptureFull {
		t.Fatalf("an unrouted run computes full: %+v", un)
	}
	iso := macIsolation(row, vocab.TierInternet, true, "", "")
	if iso.Verification != "" && iso.Verification != string(vocab.VerifiedDoc) {
		t.Fatalf("verification %q", iso.Verification)
	}
	if iso.Class != string(vocab.ClassProcess) || iso.Stack[0] != sandboxbackend.BackendSeatbelt {
		t.Fatalf("isolation %+v", iso)
	}
}

// TestSeatbeltWrapArgvCarriesTheRelay: the wrap argv is a complete
// sandbox-host command line, so sandbox.RelayOfWrap binds the run's capture
// health, and the helper's own parser reads it back.
func TestSeatbeltWrapArgvCarriesTheRelay(t *testing.T) {
	skipOnWindows(t, "Seatbelt is the macOS driver and takes macOS paths")
	dirs := mustMacDirs(t, "AbCdEfGhIjKlMnOpQrStUv")
	host, err := sandbox.RelayHostArgv("/opt/homebrew/bin/observer", sandbox.NetRequest{
		Egress: sandbox.EgressInternet, ProxyPort: 8820, HostSocketDir: dirs.SocketDir, ProviderBlock: true,
	}, nil, sandbox.RelayRequest{RunID: "AbCdEfGhIjKlMnOpQrStUv", HostObserverDir: "/Users/dev/.observer"})
	if err != nil {
		t.Fatal(err)
	}
	wrap := []string{"/opt/homebrew/bin/observer", seatbeltHostVerb, "--plan", "/Users/dev/.observer/sandbox-seatbelt/plans/x.json", "--"}
	wrap = append(append(wrap, host...), seatbeltInnerMarker)
	if id, dir, ok := sandbox.RelayOfWrap(wrap); !ok || id != "AbCdEfGhIjKlMnOpQrStUv" || dir != "/Users/dev/.observer" {
		t.Fatalf("RelayOfWrap = %q %q %v", id, dir, ok)
	}
	full := append(append([]string(nil), wrap...), "/opt/homebrew/bin/observer", "claude")
	plan, h, inner, err := parseMacHostArgs(seatbeltHostVerb, seatbeltInnerMarker, full[2:])
	if err != nil {
		t.Fatal(err)
	}
	if plan != "/Users/dev/.observer/sandbox-seatbelt/plans/x.json" || h.SockDir != dirs.SocketDir || !h.Gateway || !h.ProviderBlock || !reflect.DeepEqual(inner, []string{"/opt/homebrew/bin/observer", "claude"}) {
		t.Fatalf("parsed %q %+v %q", plan, h, inner)
	}
	for _, bad := range [][]string{
		{"--plan", "p"},
		{"--plan", "p", "--", "/o", "not-sandbox-host"},
		append(append([]string{"--plan", "p", "--"}, host...), "/o", "claude"),
		append(append([]string{"--plan", "p", "--"}, host...), seatbeltInnerMarker),
	} {
		if _, _, _, err := parseMacHostArgs(seatbeltHostVerb, seatbeltInnerMarker, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// TestSeatbeltRelaySocketPath: the run's directories sit in the user's own
// temp dir, the socket dir under the hidden parent, and a realistic macOS
// temp dir keeps the relay socket inside macOS's sun_path budget.
func TestSeatbeltRelaySocketPath(t *testing.T) {
	d := mustMacDirs(t, "AbCdEfGhIjKlMnOpQrStUv")
	if filepath.Dir(d.SocketDir) != d.SocketParent || filepath.Base(filepath.Dir(d.TempDir)) != "obsbx-tmp" {
		t.Fatalf("dirs %+v", d)
	}
	macTemp := "/private/var/folders/7k/abcd1234efgh5678ijkl90mnop/T"
	relay := filepath.Join(macTemp, "obsbx", "AbCdEfGhIjKlMnOpQrStUv", sandboxsbpl.RelaySocketName)
	if len(relay) > sandboxsbpl.MaxUnixSocketPath {
		t.Fatalf("a typical macOS relay socket path is %d bytes", len(relay))
	}
}

// TestSeatbeltRequestChecks: the daemon builds and checks the profile before
// the PTY child exists, so a request the profile cannot express refuses
// the launch at Attach.
func TestSeatbeltRequestChecks(t *testing.T) {
	skipOnWindows(t, "Seatbelt is the macOS driver and takes macOS paths")
	d := mustMacDirs(t, "AbCdEfGhIjKlMnOpQrStUv")
	req := sandboxsbpl.Request{
		Home: "/Users/dev", ObserverDir: "/Users/dev/.observer", WorkspaceRoot: "/Users/dev/src/app",
		ObserverBin: "/opt/homebrew/bin/observer", TempDir: d.TempDir, SocketParent: d.SocketParent, SocketDir: d.SocketDir,
		StateRW: []string{".claude"}, Net: sandboxsbpl.Net{Egress: sandbox.EgressInternet, ProxyPort: 8820},
	}
	if err := seatbeltCheckRequest(req, identityPath); err != nil {
		t.Fatalf("a plain request refused: %v", err)
	}
	if seatbeltStandInPort(3128) == 3128 {
		t.Fatal("the stand-in gateway port equals the proxy port")
	}
	bad := req
	bad.ExtraRW = []string{"/Users/dev"}
	if err := seatbeltCheckRequest(bad, identityPath); err == nil || !strings.Contains(err.Error(), "observer directory") {
		t.Fatalf("a home write bind passed: %v", err)
	}
	host := req
	host.Net.Egress = sandbox.EgressHost
	if err := seatbeltCheckRequest(host, identityPath); err == nil {
		t.Fatal("the host tier passed")
	}
}

// TestSeatbeltPlanFileHoldsNoSecrets: the plan is paths and switches only;
// the relay secrets stay in the run record.
func TestSeatbeltPlanFileHoldsNoSecrets(t *testing.T) {
	skipDriverOffHost(t, "Seatbelt")
	b, err := json.Marshal(seatbeltPlanFile{Version: macPlanVersion, NativeEnv: []string{"X=1"}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		if mm, ok := v.(map[string]any); ok {
			for k, x := range mm {
				l := strings.ToLower(k)
				for _, bad := range []string{"secret", "token", "password", "credential", "key"} {
					if strings.Contains(l, bad) {
						t.Errorf("plan field %s%s looks secret-bearing", prefix, k)
					}
				}
				walk(prefix+k+".", x)
			}
		}
	}
	walk("", m)
	dir := t.TempDir()
	p, err := writeMacPlan(dir, seatbeltDriverName, "run1", seatbeltPlanFile{Version: macPlanVersion})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeMacPlan(dir, seatbeltDriverName, "run1", seatbeltPlanFile{}); err == nil {
		t.Fatal("a plan file was written over an existing one")
	}
	var back seatbeltPlanFile
	if err := readMacPlan(p, &back); err != nil || back.Version != macPlanVersion {
		t.Fatalf("read back %+v %v", back, err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(p, link); err == nil {
		if err := readMacPlan(link, &back); err == nil {
			t.Fatal("a symlinked plan was read")
		}
	}
	if err := removeMacPlan(dir, seatbeltDriverName, "run1"); err != nil {
		t.Fatal(err)
	}
}

// TestSeatbeltAgentEnv: the agent's environment drops the host socket
// variables and any proxy or TMPDIR the host set, and carries the run's
// TMPDIR, socket dir, the marker, the gateway variables and N6's switch.
func TestSeatbeltAgentEnv(t *testing.T) {
	d := mustMacDirs(t, "AbCdEfGhIjKlMnOpQrStUv")
	host := []string{"PATH=/usr/bin", "SSH_AUTH_SOCK=/tmp/agent", "HTTPS_PROXY=http://corp:3128", "TMPDIR=/var/x/", "AGENT_SANDBOX=on", "OBSERVER_SANDBOX=0", "HOME=/Users/dev"}
	env := seatbeltAgentEnv(host, d, 50123, []string{"AGENT_SANDBOX=off"}, nil)
	has := func(kv string) bool { return slices.Contains(env, kv) }
	for _, want := range []string{"PATH=/usr/bin", "HOME=/Users/dev", "TMPDIR=" + d.TempDir + "/", sandboxsbpl.EnvSocketDir + "=" + d.SocketDir, "OBSERVER_SANDBOX=1", "HTTPS_PROXY=http://127.0.0.1:50123", "AGENT_SANDBOX=off"} {
		if !has(want) {
			t.Errorf("missing %s in %q", want, env)
		}
	}
	for _, gone := range []string{"SSH_AUTH_SOCK=/tmp/agent", "HTTPS_PROXY=http://corp:3128", "TMPDIR=/var/x/", "AGENT_SANDBOX=on", "OBSERVER_SANDBOX=0"} {
		if has(gone) {
			t.Errorf("%s survived", gone)
		}
	}
	none := seatbeltAgentEnv(host, d, 0, nil, nil)
	for _, kv := range none {
		if strings.HasPrefix(strings.ToUpper(kv), "HTTPS_PROXY=") {
			t.Errorf("a tier without a gateway carries %s", kv)
		}
	}
}

func TestSeatbeltSelfTestFlags(t *testing.T) {
	skipDriverOffHost(t, "Seatbelt")
	req := sandboxsbpl.Request{ObserverDir: "/o", SocketParent: "/s", Home: "/h", WorkspaceRoot: "/w", TempDir: "/t"}
	argv := seatbeltSelfTestArgv("/bin/observer", req)
	if argv[1] != seatbeltSelfTestVerb {
		t.Fatal(argv)
	}
	flags, err := seatbeltSelfTestFlags(argv[2:])
	if err != nil || flags["--ws"] != "/w" || flags["--home-blinded"] != "true" {
		t.Fatalf("%v %v", flags, err)
	}
	req.HomeMode = sandboxsbpl.HomeModeReadonly
	flags, _ = seatbeltSelfTestFlags(seatbeltSelfTestArgv("/bin/observer", req)[2:])
	if flags["--home-blinded"] != "false" {
		t.Fatal("readonly home reported blinded")
	}
	for _, bad := range [][]string{{"--obs"}, {"--obs", "rel"}, {"--evil", "/x"}, argv[2:4]} {
		if _, err := seatbeltSelfTestFlags(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// TestSeatbeltLifecycleIsPTYOwned: the agent is the PTY's child, so resize,
// signal and stop belong to the PTY; copy and checkpoint are not offered.
func TestSeatbeltLifecycleIsPTYOwned(t *testing.T) {
	d := &seatbeltDriver{r: macTestRuntime(t, seatbeltTestConfig(t, true, "seatbelt"))}
	ctx := context.Background()
	run := termsvc.SandboxRun{ID: "x"}
	r1, _ := d.Resize(ctx, run, 1, 1)
	r2, _ := d.Signal(ctx, run, "TERM")
	r3, _ := d.Stop(ctx, run, 0)
	r4, _ := d.Copy(ctx, termsvc.CopyRequest{})
	r5, _ := d.Checkpoint(ctx, run)
	if r1.Verdict != termsvc.VerdictPTYOwned || r2.Verdict != termsvc.VerdictPTYOwned || r3.Verdict != termsvc.VerdictPTYOwned ||
		r4.Verdict != termsvc.VerdictNotSupported || r5.Verdict != termsvc.VerdictNotSupported {
		t.Fatalf("%v %v %v %v %v", r1, r2, r3, r4, r5)
	}
}

// identityPath is the resolver of a request whose paths are already
// resolved (these fixtures name no real file).
func identityPath(p string) string { return p }

// TestMacSocketBudgetMatchesSeatbelt: the shared macOS driver file's socket
// budget and name equal the Seatbelt planner's, which refuses a longer path.
func TestMacSocketBudgetMatchesSeatbelt(t *testing.T) {
	if macRelaySocketMax != sandboxsbpl.MaxUnixSocketPath || macRelaySocketName != sandboxsbpl.RelaySocketName {
		t.Fatalf("macdriver %d %q, sandboxsbpl %d %q", macRelaySocketMax, macRelaySocketName, sandboxsbpl.MaxUnixSocketPath, sandboxsbpl.RelaySocketName)
	}
}

// TestSeatbeltComposeCarriesThePins (lane SHR-FOLLOWUPS, ledger
// SBX-BE-10): the Seatbelt launch hands the planner the same pins the bwrap
// path binds (the live workspace's .git here), so the profile write-denies
// that literal; the planner's golden (internal/sandboxsbpl pins.sb) shows
// the rule.
func TestSeatbeltComposeCarriesThePins(t *testing.T) {
	skipDriverOffHost(t, "Seatbelt")
	home := t.TempDir()
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	setTestHome(t, home)
	ws := filepath.Join(home, "src", "app")
	for _, d := range []string{filepath.Join(ws, ".git"), filepath.Join(home, ".claude")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rt := macTestRuntime(t, seatbeltTestConfig(t, true, "seatbelt"))
	d, ok := rt.drivers[sandboxbackend.BackendSeatbelt].(*seatbeltDriver)
	if !ok {
		t.Fatal("no seatbelt driver")
	}
	wrap, err := d.compose(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: "AbCdEfGhIjKlMnOpQrSt09", Tool: "claude-code", Dir: ws}})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	i := slices.Index(wrap, "--plan")
	if i < 0 {
		t.Fatalf("no plan in %q", wrap)
	}
	var plan seatbeltPlanFile
	if err := readMacPlan(wrap[i+1], &plan); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(plan.Profile.Pins, filepath.Join(ws, ".git")) {
		t.Fatalf("the profile request's pins %v lack the workspace .git", plan.Profile.Pins)
	}
	req := plan.Profile
	req.Resolve = sandboxCanonicalPath
	req.Net.GatewayPort = seatbeltStandInPort(req.Net.ProxyPort)
	prof, err := sandboxsbpl.Build(req)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range prof.Params {
		found = found || (strings.HasPrefix(x.Name, "ANCHOR") && x.Value == filepath.Join(ws, ".git"))
	}
	if !found {
		t.Fatalf("the workspace .git is not write-denied in the profile:\n%s", prof.Text)
	}
}
