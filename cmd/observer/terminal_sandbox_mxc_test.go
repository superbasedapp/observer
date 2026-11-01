//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termoob"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_mxc_test.go holds the mxc-process driver's unit tests
// (lane SBX-P6, milestones 3 and 5). Everything OS-neutral runs on any host;
// what needs a Windows build with PSEC is register WIN-1 to WIN-4.

func mxcTestConfig(t *testing.T, selectDriver bool, backends ...string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	cfg.Terminal.Sandbox.Enabled = true
	cfg.Terminal.Sandbox.Backends = backends
	if selectDriver {
		cfg.Components.Add = []string{mxcComponent}
	}
	return cfg
}

// countMXCProbes replaces the probe helper and the host OS.
func countMXCProbes(t *testing.T, osName string, answer sandboxmxc.ProbeResult) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	prevRun, prevOS := mxcProbeRunner, mxcHostOS
	mxcProbeRunner = func(context.Context, string, string, time.Duration) sandboxmxc.ProbeResult {
		n.Add(1)
		return answer
	}
	mxcHostOS = func() string { return osName }
	t.Cleanup(func() { mxcProbeRunner, mxcHostOS = prevRun, prevOS })
	return &n
}

func availableMXC() sandboxmxc.ProbeResult {
	return sandboxmxc.ProbeResult{Verdict: sandboxmxc.Verdict{Code: sandboxmxc.VerdictAvailable}, Rule: "available", Version: "1.0.1", Tier: sandboxmxc.TierBaseContainer, DenyPaths: true}
}

// TestMXCDriverIsOptIn: an install with no [components] block (every
// existing install) never gets the driver and never starts the probe
// helper; a block that adds it does.
func TestMXCDriverIsOptIn(t *testing.T) {
	n := countMXCProbes(t, "windows", availableMXC())
	legacy := ociTestRuntime(t, mxcTestConfig(t, false, "mxc-process", "bwrap"))
	if _, ok := legacy.drivers[sandboxbackend.BackendMXCProcess]; ok || legacy.inactiveDrivers[sandboxbackend.BackendMXCProcess] != mxcComponent {
		t.Fatalf("legacy drivers %v inactive %v", legacy.drivers, legacy.inactiveDrivers)
	}
	if p := legacy.driverProbes(context.Background())[sandboxbackend.BackendMXCProcess]; p.Verdict != verdictModuleInactive {
		t.Fatalf("an unselected driver probes as %+v", p)
	}
	if n.Load() != 0 {
		t.Fatal("an unselected driver started the probe helper")
	}
	on := ociTestRuntime(t, mxcTestConfig(t, true, "mxc-process"))
	if _, ok := on.drivers[sandboxbackend.BackendMXCProcess]; !ok {
		t.Fatal("a block that adds terminals.sandbox.mxc did not get the driver")
	}
}

// TestMXCDriverInertWhenNotListed: selected but not listed, nothing runs.
func TestMXCDriverInertWhenNotListed(t *testing.T) {
	n := countMXCProbes(t, "windows", availableMXC())
	rt := ociTestRuntime(t, mxcTestConfig(t, true))
	if p := rt.driverProbes(context.Background())[sandboxbackend.BackendMXCProcess]; p.Verdict != sandboxselect.VerdictDisabledByConfig {
		t.Fatalf("probe %+v", p)
	}
	if n.Load() != 0 {
		t.Fatal("the probe helper ran for a backend that is not listed")
	}
}

// TestMXCDriverOffWindows: off Windows the ladder answers its platform row
// and no helper starts.
func TestMXCDriverOffWindows(t *testing.T) {
	n := countMXCProbes(t, "linux", availableMXC())
	rt := ociTestRuntime(t, mxcTestConfig(t, true, "mxc-process"))
	if p := rt.driverProbes(context.Background())[sandboxbackend.BackendMXCProcess]; p.Verdict != sandboxmxc.VerdictUnsupportedPlatform {
		t.Fatalf("probe %+v", p)
	}
	if n.Load() != 0 {
		t.Fatal("the probe helper ran off Windows")
	}
}

// TestMXCDriverRefusalsReachTheSelection: each named refusal of the
// helper's ladder is the row's verdict, and a refused row is never chosen.
func TestMXCDriverRefusalsReachTheSelection(t *testing.T) {
	for _, code := range []string{sandboxmxc.VerdictPSECBuildTooOld, sandboxmxc.VerdictPSECUnavailable, sandboxmxc.VerdictArtifactMissing, sandboxmxc.VerdictArtifactUnverified, sandboxmxc.VerdictBackendVersionUntested} {
		countMXCProbes(t, "windows", sandboxmxc.ProbeResult{Verdict: sandboxmxc.Verdict{Code: code, Reason: "x"}})
		rt := ociTestRuntime(t, mxcTestConfig(t, true, "mxc-process"))
		p := rt.driverProbes(context.Background())[sandboxbackend.BackendMXCProcess]
		if p.Verdict != code || p.Version != sandboxmxc.Pins.RequiredMin {
			t.Errorf("%s: probe %+v", code, p)
		}
		d := rt.drivers[sandboxbackend.BackendMXCProcess].(*mxcDriver)
		if _, err := d.Create(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: t.TempDir()}); err == nil || !strings.Contains(err.Error(), code) {
			t.Errorf("%s: Create %v", code, err)
		}
	}
}

func TestMXCWrapArgvRoundTrip(t *testing.T) {
	obs := t.TempDir()
	plan := filepath.Join(obs, "p.json")
	argv := append(mxcWrapArgv("/bin/observer", plan, "run-7", obs), "/bin/observer", "claude", "--config", "/c")
	h, err := parseMXCHostArgs(argv)
	if err != nil || h.plan != plan || h.runID != "run-7" || h.observerDir != obs || strings.Join(h.inner, " ") != "/bin/observer claude --config /c" {
		t.Fatalf("parsed %+v %v", h, err)
	}
	if id, dir, ok := mxcRelayOfWrap(argv); !ok || id != "run-7" || dir != obs {
		t.Fatalf("relay of wrap %q %q %v", id, dir, ok)
	}
	for _, bad := range [][]string{
		{"/bin/observer", mxcHostVerb, "--plan", plan, "--"},
		{"/bin/observer", mxcHostVerb, "--plan", "rel", "--relay-run", "r", "--observer-dir", obs, "--"},
		{"/bin/observer", mxcHostVerb, "--plan", plan, "--relay-run", "../x", "--observer-dir", obs, "--"},
		{"/bin/observer", mxcHostVerb, "--bogus", "--"},
	} {
		if _, err := parseMXCHostArgs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// TestMXCPlanFileHoldsNoSecrets: the plan schema names no secret.
func TestMXCPlanFileHoldsNoSecrets(t *testing.T) {
	typ := reflect.TypeOf(mxcPlanFile{})
	for i := 0; i < typ.NumField(); i++ {
		n := strings.ToLower(typ.Field(i).Name + " " + typ.Field(i).Tag.Get("json"))
		for _, bad := range []string{"secret", "token", "key", "password", "credential", "auth"} {
			if strings.Contains(n, bad) {
				t.Errorf("plan field %s looks credential-bearing", typ.Field(i).Name)
			}
		}
	}
}

// TestMXCLibraryOnlyInTheHelper pins rule one of internal/sandboxmxcdll:
// only terminal_sandbox_mxc_windows.go imports the loader, and only the
// helper verbs reach Gather or HostEnv (through mxcGather), so the daemon
// never loads mxc_ffi.dll.
func TestMXCLibraryOnlyInTheHelper(t *testing.T) {
	const pkg = `"github.com/marmutapp/superbased-observer/internal/sandboxmxcdll"`
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		imports := false
		for _, im := range file.Imports {
			imports = imports || im.Path.Value == pkg
		}
		if imports && f != "terminal_sandbox_mxc_windows.go" {
			t.Errorf("%s imports the MXC loader", f)
		}
		if !imports {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			fd, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			ast.Inspect(fd, func(m ast.Node) bool {
				sel, ok := m.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "sandboxmxcdll" && (sel.Sel.Name == "Gather" || sel.Sel.Name == "HostEnv") && fd.Name.Name != "mxcGather" {
					t.Errorf("%s: %s calls sandboxmxcdll.%s", f, fd.Name.Name, sel.Sel.Name)
				}
				return true
			})
			return false
		})
	}
	// mxcGather's callers are the two helper verbs.
	src, err := os.ReadFile("terminal_sandbox_mxc_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(src), "mxcGather(") != 3 {
		t.Errorf("mxcGather must be defined once and called only by runMXCProbe and runMXCHost")
	}
}

// TestMXCBoxEnv: the box never inherits the daemon's internal variables,
// the host's proxy settings or MXC knobs, and gets the run's markers and
// the tier's network variables.
func TestMXCBoxEnv(t *testing.T) {
	base := []string{
		"PATH=C:\\bin", "OBSERVER_OOB_AUTH=secret", "OBSERVER_OOB_FD=3", envDaemonChild + "=1", "HTTPS_PROXY=http://corp:8080",
		"https_proxy=http://corp:8080", "TEMP=C:\\host-tmp", "MXC_BIN_DIR=C:\\evil", sandboxEnvMarker + "=0", "ANTHROPIC_API_KEY=k", mxcBoxDirEnv + "=C:\\forged",
		mxcProxyURLEnv + "=http://forged",
		// The allow-list (WINFIX2 R-167): the launch names the provider
		// variable; GITHUB_TOKEN is not named.
		sandboxenv.EnvAllow + "=ANTHROPIC_API_KEY", "GITHUB_TOKEN=gh-dummy",
	}
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("q", 32)))
	env := mxcBoxEnv(base, `C:\t\box`, `C:\t\box\tmp`, vocab.TierProxyOnly, 4242, tok, nil)
	got := strings.Join(env, "\n")
	for _, gone := range []string{"OBSERVER_OOB_AUTH", "OBSERVER_OOB_FD", "corp:8080", "C:\\host-tmp", "MXC_BIN_DIR", sandboxEnvMarker + "=0", "C:\\forged", "HTTPS_PROXY=", "http://forged", "GITHUB_TOKEN"} {
		if strings.Contains(got, gone) {
			t.Errorf("box env keeps %q", gone)
		}
	}
	for _, want := range []string{"PATH=C:\\bin", envDaemonChild + "=1", sandboxEnvMarker + "=1", mxcBoxDirEnv + "=C:\\t\\box", "TEMP=C:\\t\\box\\tmp", "OBSERVER_OOB_BOX=1", "NO_PROXY=127.0.0.1,localhost", "ANTHROPIC_API_KEY=k", mxcProxyURLEnv + "=" + sandboxmxc.BaseURL(4242, tok)} {
		if !strings.Contains(got, want) {
			t.Errorf("box env lacks %q", want)
		}
	}
	// The internet tier adds the gateway with the run's credentials.
	env = mxcBoxEnv(nil, `C:\b`, `C:\b\tmp`, vocab.TierInternet, 4242, tok, nil)
	if !strings.Contains(strings.Join(env, "\n"), "HTTPS_PROXY=http://observer:"+tok+"@127.0.0.1:4242") {
		t.Fatalf("internet env %v", env)
	}
	// wxc-exec itself runs with what Windows needs and nothing else.
	ex := strings.Join(mxcExecEnv(append(base, "SystemRoot=C:\\Windows", "USERPROFILE=C:\\Users\\a")), "\n")
	if strings.Contains(ex, "ANTHROPIC_API_KEY") || strings.Contains(ex, "corp:8080") || !strings.Contains(ex, "PATH=C:\\Windows") || !strings.Contains(ex, "SystemRoot=") {
		t.Fatalf("exec env %s", ex)
	}
}

func TestMXCProxyFlag(t *testing.T) {
	if f := mxcProxyFlagFor("claude"); f != "proxy" {
		t.Errorf("claude: %q", f)
	}
	if f := mxcProxyFlagFor("pi"); f != "proxy-url" {
		t.Errorf("pi: %q", f)
	}
	if f := mxcProxyFlagFor("no-such-verb"); f != "" {
		t.Errorf("unknown verb: %q", f)
	}
	got, err := mxcWithProxyFlag([]string{"obs", "claude", "--config", "c", "--", "--x"}, "proxy", "http://127.0.0.1:1/t/k")
	if err != nil || strings.Join(got, " ") != "obs claude --proxy http://127.0.0.1:1/t/k --config c -- --x" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := mxcWithProxyFlag([]string{"obs", "claude", "--proxy=http://evil"}, "proxy", "u"); err == nil {
		t.Error("an inner launch that names a proxy was accepted")
	}
	if _, err := mxcWithProxyFlag([]string{"obs", "x"}, "", "u"); err == nil {
		t.Error("a launcher without a proxy flag was accepted")
	}
}

// TestMXCRunDocument: the run's document keeps allowDaclMutation false,
// grants the box directory read-only and its temp read-write, declares no
// runtime proxy (finding L1), and travels to wxc-exec as a file, so a large
// policy is fine while an over-long inner command line is refused.
func TestMXCRunDocument(t *testing.T) {
	plan := mxcPlanFile{RunID: "r1", Workspace: `C:\w`, ReadWrite: []string{`C:\w`}, ReadOnly: []string{`C:\obs`}, Tier: "none"}
	doc, err := mxcRunDocument(plan, `C:\t\box`, `C:\t\box\tmp`, []string{`C:\obs\observer.exe`, "claude"}, []string{"A=1"}, 5000, false)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Fallback.AllowDaclMutation || doc.RuntimeConfig != nil || doc.Network.Ingress.HostLoopback != sandboxmxc.NetworkActionAllow || doc.Network.Ingress.Default != sandboxmxc.NetworkActionDeny {
		t.Fatalf("doc %+v", doc)
	}
	if !slices.Contains(doc.Filesystem.ReadonlyPaths, `C:\t\box`) || !slices.Contains(doc.Filesystem.ReadwritePaths, `C:\t\box\tmp`) || !slices.Contains(doc.Filesystem.ReadwritePaths, `C:\t\box\localappdata`) {
		t.Fatalf("fs %+v", doc.Filesystem)
	}
	// Windows needs SYSTEMROOT and LOCALAPPDATA present (MXC 1.0.1,
	// policy_validation): the host's SystemRoot (C:\Windows when the
	// environment names none) and the run's own box directory.
	if env := strings.Join(doc.Process.Env, "|"); !strings.Contains(env, `SYSTEMROOT=C:\Windows`) || !strings.Contains(env, `LOCALAPPDATA=C:\t\box\localappdata`) || doc.Process.InheritDefaultEnv {
		t.Fatalf("env %s", env)
	}
	if args := mxcExecArgs(`C:\obs\sandbox-mxc\run\r1.json`); strings.Join(args, " ") != `--config C:\obs\sandbox-mxc\run\r1.json` {
		t.Fatalf("args %v", args)
	}
	big := plan
	for i := 0; i < 2000; i++ {
		big.ReadOnly = append(big.ReadOnly, fmt.Sprintf(`C:\some\long\directory\name\%04d`, i))
	}
	if _, err := mxcRunDocument(big, `C:\t\box`, `C:\t\box\tmp`, []string{`C:\o.exe`, "claude"}, nil, 5000, false); err != nil {
		t.Fatalf("a large policy is refused although it travels as a file: %v", err)
	}
	long := []string{`C:\o.exe`, "claude", strings.Repeat("x", mxcMaxCommandLine)}
	if _, err := mxcRunDocument(plan, `C:\t\box`, `C:\t\box\tmp`, long, nil, 5000, false); err == nil {
		t.Fatal("an over-long inner command line was accepted")
	}
}

// TestMXCHelperArgvHoldsNoEnvironmentValue (finding F2): no value of the
// box's environment, provider keys and the run's token included, is on
// wxc-exec's command line or on the box process's own command line; the
// document reaches wxc-exec through an owner-only file the helper removes,
// and the token-scoped base URL reaches the inner launcher through its
// environment, inserted into its argv in memory only.
func TestMXCHelperArgvHoldsNoEnvironmentValue(t *testing.T) {
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("s", 32)))
	const key = "sk-ant-api03-not-a-real-key-0123456789"
	base := []string{"PATH=C:\\Windows\\System32", "ANTHROPIC_API_KEY=" + key, "OPENAI_API_KEY=sk-proj-another-secret-value"}
	env := mxcBoxEnv(base, `C:\t\observer-sbx-r9\`, `C:\t\observer-sbx-r9\tmp`, vocab.TierInternet, 4321, tok, nil)
	inner, err := mxcInnerLaunch([]string{`C:\obs\observer.exe`, "claude", "--model", "x"})
	if err != nil {
		t.Fatal(err)
	}
	plan := mxcPlanFile{RunID: "r9", Workspace: `C:\w`, ReadWrite: []string{`C:\w`}, Tier: "internet"}
	doc, err := mxcRunDocument(plan, `C:\t\observer-sbx-r9`, `C:\t\observer-sbx-r9\tmp`, inner, env, 4321, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	obs := t.TempDir()
	cfg, err := writeMXCConfig(obs, "r9", b)
	if err != nil {
		t.Fatal(err)
	}
	argv := append([]string{`C:\obs\mxc\wxc-exec.exe`}, mxcExecArgs(cfg.path)...)
	cmdlines := map[string]string{"wxc-exec": strings.Join(argv, " "), "box process": doc.Process.CommandLine}
	for _, kv := range env {
		_, v, _ := strings.Cut(kv, "=")
		if len(v) < 8 {
			continue
		}
		for name, line := range cmdlines {
			if strings.Contains(line, v) {
				t.Errorf("the %s command line carries the environment value of %s", name, kv)
			}
		}
	}
	for name, line := range cmdlines {
		if strings.Contains(line, tok) || strings.Contains(line, key) || strings.Contains(line, "base64") {
			t.Errorf("the %s command line carries a secret: %s", name, line)
		}
	}
	// The file holds the document, owner-only, and is removed once.
	got, err := os.ReadFile(cfg.path)
	if err != nil || string(got) != string(b) {
		t.Fatalf("config file %q %v", got, err)
	}
	if fi, err := os.Stat(cfg.path); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("config file mode %v %v", fi, err)
	}
	if _, err := writeMXCConfig(obs, "r9", b); err == nil {
		t.Fatal("a second config file for the same run was written")
	}
	cfg.remove()
	cfg.remove()
	if _, err := os.Stat(cfg.path); !os.IsNotExist(err) {
		t.Fatalf("the config file survived: %v", err)
	}
	// Inside the box the launcher puts the flag back, in memory.
	if got := mxcBoxArgv(inner, sandboxmxc.BaseURL(4321, tok)); strings.Join(got, " ") != `C:\obs\observer.exe claude --proxy `+sandboxmxc.BaseURL(4321, tok)+` --model x` {
		t.Fatalf("box argv %v", got)
	}
	for _, same := range [][]string{mxcBoxArgv(inner, ""), mxcBoxArgv([]string{"obs", "hook", "claude-code"}, "u"), mxcBoxArgv([]string{"obs", "claude", "--proxy=x"}, "u")} {
		if strings.Contains(strings.Join(same, " "), "--proxy u") {
			t.Fatalf("argv rewritten: %v", same)
		}
	}
	if _, err := mxcInnerLaunch([]string{"obs", "claude", "--proxy", "http://evil"}); err == nil {
		t.Fatal("an inner launch naming its own proxy was accepted")
	}
}

// TestMXCConfigFileRemovedAtFirstConnection: the box's first connection to
// the run's port removes the config file (wxc-exec has read it by then).
func TestMXCConfigFileRemovedAtFirstConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int64
	wrapped := mxcOnFirstAccept(ln, func() { n.Add(1) })
	defer func() { _ = wrapped.Close() }()
	go func() {
		for {
			c, err := wrapped.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for n.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n.Load() != 1 {
		t.Fatalf("first-accept hook ran %d times", n.Load())
	}
}

// fakeProfileSID derives a stand-in SID from a profile name.
func fakeProfileSID(name string) (string, error) { return "S-1-15-2-" + name, nil }

// hostIdentity is the host helper's answer for run id: the SID it read
// from the box process's token.
func hostIdentity(id, sid string) *sandboxmxc.BoxIdentity {
	return &sandboxmxc.BoxIdentity{V: sandboxmxc.BoxIdentityVersion, RunID: id, ContainerID: sandboxmxc.ContainerName(id), SID: sid}
}

// TestMXCBoxDetection (finding F1): only Observer's own container, the one
// the run's host helper read from that run's box process, for the run the
// box directory names, with the driver selected, is an Observer box; a
// foreign AppContainer is not.
func TestMXCBoxDetection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), mxcBoxDirPrefix+"run-7")
	own := mxcBoxFacts{
		AppContainer: true, TokenSID: "S-1-15-2-observer-run-7", BoxDir: dir, RecordRunID: "run-7",
		Identity: hostIdentity("run-7", "S-1-15-2-observer-run-7"), NameSID: fakeProfileSID,
		DriverSelected: func() bool { return true },
	}
	if id := mxcBoxRunID(own); id != "run-7" {
		t.Fatalf("our own box: %q", id)
	}
	// A faulted record: the directory still names the run, the profile
	// still matches, so gate events still block.
	norec := own
	norec.RecordRunID = ""
	if id := mxcBoxRunID(norec); id != "run-7" {
		t.Fatalf("our own box with a missing record: %q", id)
	}
	for name, mut := range map[string]func(*mxcBoxFacts){
		"a foreign AppContainer token":     func(f *mxcBoxFacts) { f.TokenSID = "S-1-15-2-1-2-3-4-5-6-7" },
		"a foreign container with our dir": func(f *mxcBoxFacts) { f.TokenSID = "S-1-15-2-vendor-sandbox" },
		"no AppContainer token":            func(f *mxcBoxFacts) { f.AppContainer = false },
		"no box directory":                 func(f *mxcBoxFacts) { f.BoxDir = "" },
		"a relative box directory":         func(f *mxcBoxFacts) { f.BoxDir = "observer-sbx-run-7" },
		"another run's record":             func(f *mxcBoxFacts) { f.RecordRunID = "run-8" },
		"a directory naming no run":        func(f *mxcBoxFacts) { f.RecordRunID, f.BoxDir = "", t.TempDir() },
		"a bad run id":                     func(f *mxcBoxFacts) { f.RecordRunID = "../x" },
		"the driver not selected":          func(f *mxcBoxFacts) { f.DriverSelected = func() bool { return false } },
		"no selection check":               func(f *mxcBoxFacts) { f.DriverSelected = nil },
		"no identity answer":               func(f *mxcBoxFacts) { f.Identity, f.IdentityErr = nil, fmt.Errorf("no") },
		"another run's identity answer":    func(f *mxcBoxFacts) { f.Identity = hostIdentity("run-8", "S-1-15-2-observer-run-7") },
	} {
		f := own
		mut(&f)
		if id := mxcBoxRunID(f); id != "" {
			t.Errorf("%s: recognised as box %q", name, id)
		}
	}
	// Off Windows nothing registers a detection, so nothing is marked.
	if runtime.GOOS != "windows" {
		ensureBoxDetected()
		if boxInsideByToken || boxArgvRewrite != nil {
			t.Fatal("a box was detected off Windows")
		}
		if got := boxArgs([]string{"obs", "claude"}); strings.Join(got, " ") != "obs claude" {
			t.Fatalf("argv rewritten off Windows: %v", got)
		}
	}
}

// TestMXCPlaceholders (finding F3): the helper creates a missing protected
// path before the box exists and removes it afterwards when untouched; a
// path outside the writable roots is refused.
func TestMXCPlaceholders(t *testing.T) {
	ws := t.TempDir()
	plan := mxcPlanFile{
		ReadWrite:        []string{ws},
		PlaceholderDirs:  []string{filepath.Join(ws, ".git")},
		PlaceholderFiles: []string{filepath.Join(ws, ".mcp.json")},
	}
	created, err := mxcCreatePlaceholders(plan)
	if err != nil || len(created) != 2 {
		t.Fatalf("created %v %v", created, err)
	}
	if fi, err := os.Stat(filepath.Join(ws, ".git")); err != nil || !fi.IsDir() {
		t.Fatalf(".git placeholder %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(ws, ".mcp.json")); err != nil || string(b) != "{}\n" {
		t.Fatalf(".mcp.json placeholder %q %v", b, err)
	}
	mxcRemovePlaceholders(created)
	for _, p := range []string{".git", ".mcp.json"} {
		if _, err := os.Lstat(filepath.Join(ws, p)); !os.IsNotExist(err) {
			t.Errorf("%s placeholder left behind: %v", p, err)
		}
	}
	// A placeholder the host filled meanwhile stays.
	created, err = mxcCreatePlaceholders(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".git", "config"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mxcRemovePlaceholders(created)
	if _, err := os.Stat(filepath.Join(ws, ".git", "config")); err != nil {
		t.Fatal("a placeholder the host filled was removed")
	}
	bad := mxcPlanFile{ReadWrite: []string{ws}, PlaceholderDirs: []string{filepath.Join(t.TempDir(), "x")}}
	if _, err := mxcCreatePlaceholders(bad); err == nil {
		t.Fatal("a placeholder outside the writable roots was created")
	}
}

// TestSandboxLaunchPickNeverAutoPicksBeta (ruling P-062): a launch that
// names no backend never takes a beta row; one that names it does; with
// bwrap enabled and available the legacy path stays the fallback, and
// otherwise the refusal names the beta row as available but not chosen.
func TestSandboxLaunchPickNeverAutoPicksBeta(t *testing.T) {
	rows := map[string]dashapi.SandboxBackendAvail{
		sandboxbackend.BackendMXCProcess: {ID: sandboxbackend.BackendMXCProcess, Available: true, Beta: true},
		// A live-verified row: automatic selection may take it (P-067).
		sandboxbackend.BackendOCIRunc: {ID: sandboxbackend.BackendOCIRunc, Available: true, Beta: false, Verification: "live"},
		sandboxbackend.BackendBwrap:   {ID: sandboxbackend.BackendBwrap, Available: false, Verdict: "unsupported_platform"},
	}
	all := func(string) bool { return true }
	only := []string{sandboxbackend.BackendMXCProcess}
	p := sandboxLaunchPick(only, rows, true, all)
	if p.chosen != "" || p.skipped == nil || p.drop.Verdict != sandboxselect.VerdictBetaNotChosen {
		t.Fatalf("auto pick %+v", p)
	}
	err := p.betaRefusal(only, rows)
	if err == nil || !strings.Contains(err.Error(), "mxc-process is available but not chosen") || !strings.Contains(err.Error(), "--observer-sandbox mxc-process") {
		t.Fatalf("refusal %v", err)
	}
	if p := sandboxLaunchPick(only, rows, false, all); p.chosen != sandboxbackend.BackendMXCProcess {
		t.Fatalf("a launch that names the beta row did not get it: %+v", p)
	}
	// A non-beta row later in the list wins over the beta row.
	both := []string{sandboxbackend.BackendMXCProcess, sandboxbackend.BackendOCIRunc}
	if p := sandboxLaunchPick(both, rows, true, all); p.chosen != sandboxbackend.BackendOCIRunc {
		t.Fatalf("first non-beta row: %+v", p)
	}
	// bwrap enabled and available stays the fallback (the legacy path).
	rows[sandboxbackend.BackendBwrap] = dashapi.SandboxBackendAvail{ID: sandboxbackend.BackendBwrap, Available: true, Beta: true}
	withBwrap := []string{sandboxbackend.BackendMXCProcess, sandboxbackend.BackendBwrap}
	p = sandboxLaunchPick(withBwrap, rows, true, all)
	if err := p.betaRefusal(withBwrap, rows); err != nil {
		t.Fatalf("bwrap fallback refused: %v", err)
	}
	// An unusable row (no active driver) is never chosen.
	if p := sandboxLaunchPick(both, rows, true, func(id string) bool { return id != sandboxbackend.BackendOCIRunc }); p.chosen != "" {
		t.Fatalf("an unusable row was chosen: %+v", p)
	}
}

func startMXCPort(t *testing.T, p *mxcPort) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx, ln) }()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestMXCPortTiers is milestone 3's shared-port proof over real HTTP (the
// unit half of register WIN-2): a none token opens no proxy, a proxy_only
// token no gateway, a wrong token nothing, and the proxy stream reaches
// the model proxy with the token prefix stripped.
func TestMXCPortTiers(t *testing.T) {
	var upstreamPath atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath.Store(r.URL.RequestURI() + " auth=" + r.Header.Get("Proxy-Authorization"))
		_, _ = io.WriteString(w, "model")
	}))
	defer upstream.Close()
	var gatewayHits atomic.Int64
	gw := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gatewayHits.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("the run's credentials reached the gateway's handler")
		}
		w.WriteHeader(http.StatusTeapot)
	})
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("t", 32)))
	other, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("o", 32)))
	for _, tier := range sandboxmxc.Tiers() {
		port := startMXCPort(t, &mxcPort{Token: tok, Tier: tier, ProxyAddr: strings.TrimPrefix(upstream.URL, "http://"), Gateway: gw})
		base := fmt.Sprintf("http://127.0.0.1:%d", port)
		resp, err := http.Post(base+"/t/"+tok+"/v1/messages?x=1", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		wantProxy := tier != vocab.TierNone
		if (resp.StatusCode == http.StatusOK) != wantProxy {
			t.Errorf("%s: proxy status %d %s", tier, resp.StatusCode, body)
		}
		if wantProxy && (string(body) != "model" || upstreamPath.Load() != "/v1/messages?x=1 auth=") {
			t.Errorf("%s: proxy reached %v", tier, upstreamPath.Load())
		}
		// Another run's token opens nothing.
		resp, err = http.Post(base+"/t/"+other+"/v1/messages", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: another run's token got %d", tier, resp.StatusCode)
		}
		// The gateway through the run's credentials.
		before := gatewayHits.Load()
		status := mxcConnect(t, port, "example.com:443", tok)
		wantGW := tier == vocab.TierInternet
		if wantGW && (status != http.StatusTeapot || gatewayHits.Load() != before+1) {
			t.Errorf("%s: gateway status %d", tier, status)
		}
		if !wantGW && (status != http.StatusForbidden || gatewayHits.Load() != before) {
			t.Errorf("%s: gateway opened on a tier without it (%d)", tier, status)
		}
		if s := mxcConnect(t, port, "example.com:443", other); s != http.StatusProxyAuthRequired {
			t.Errorf("%s: gateway with another token: %d", tier, s)
		}
	}
}

// mxcConnect sends a CONNECT with the run's Basic credentials and returns
// the status.
func mxcConnect(t *testing.T, port int, target, tok string) int {
	t.Helper()
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	cred := base64.StdEncoding.EncodeToString([]byte(sandboxmxc.ProxyUser + ":" + tok))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, cred)
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestMXCProviderHostBlockOnThePort: section 7.3 on the shared port's
// gateway: a provider host and a literal IP are refused when the run
// claims full capture.
func TestMXCProviderHostBlockOnThePort(t *testing.T) {
	gw, err := mxcGatewayFor(mxcPlanFile{ProviderBlock: true}, vocab.TierInternet)
	if err != nil || gw == nil || gw.Providers == nil {
		t.Fatalf("gateway %v %v", gw, err)
	}
	gw.Resolve = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.9")}, nil }
	gw.LocalAddrs = func() ([]net.IP, error) { return nil, nil }
	gw.Dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("no network in a test")
	}
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("p", 32)))
	port := startMXCPort(t, &mxcPort{Token: tok, Tier: vocab.TierInternet, Gateway: gw})
	if s := mxcConnect(t, port, "api.anthropic.com:443", tok); s != http.StatusForbidden {
		t.Errorf("provider host: %d", s)
	}
	if s := mxcConnect(t, port, "203.0.113.9:443", tok); s != http.StatusForbidden {
		t.Errorf("literal IP: %d", s)
	}
	if gw.Providers.Refused() != 2 {
		t.Errorf("refusals counted %d", gw.Providers.Refused())
	}
	// No gateway below the internet tier; no block without full capture.
	if g, _ := mxcGatewayFor(mxcPlanFile{}, vocab.TierProxyOnly); g != nil {
		t.Error("a gateway on proxy_only")
	}
	if g, _ := mxcGatewayFor(mxcPlanFile{}, vocab.TierInternet); g == nil || g.Providers != nil {
		t.Error("a provider block without the plan asking")
	}
}

// TestMXCHelperRechecksHooksMidRun (A10; RERUN2 D3): the MXC helper's
// forwarder, served through ServeConn on the run's port as the Windows
// helper does, re-reads the hook registration on its own timer: once the
// stub probe's Disabled set changes, a run_health report reaches the
// daemon and the run's terminal_run row is lowered with hooks_drifted.
// Before the fix the helper read the baseline once and never again, so
// the row stayed capture_degraded 0.
func TestMXCHelperRechecksHooksMidRun(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC transport")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.Config{}
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	iso := termrun.Isolation{
		Class: "process", Stack: []string{"mxc-process"}, EgressTier: "internet", CaptureLevel: "full",
		CaptureRule: "C6", CaptureOrigin: "sandboxed", Verification: "live", KeyCustody: "host_bound",
	}
	runID, err := recordSandboxCLIRun(ctx, cfg, "claude-code", t.TempDir(), iso)
	if err != nil || runID == "" {
		t.Fatalf("record: %q %v", runID, err)
	}
	database, closeDB, err := openDBForConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	st := store.New(database)

	obs := shortTempDir(t)
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "run-mxc-hooks", TerminalRunID: runID, Tool: "claude-code", WorkspaceDir: obs, Roots: []string{obs}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	ep, err := sandboxRelayEndpoint(obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(ep), 0o700); err != nil {
		t.Fatal(err)
	}
	dln, err := localipc.DefaultTransport().Listen(ep)
	if err != nil {
		t.Fatal(err)
	}
	lower := func(ctx context.Context, id string, h store.TerminalRunCaptureHealth) error {
		_, err := st.LowerTerminalRunCapture(ctx, id, h, resealRunEvidence)
		return err
	}
	d := &sandboxrelayd.Daemon{
		ObserverDir: obs, Rules: relayRules, Peer: sandboxrelayd.PeerSameUser,
		OnHealth: relayOnHealth(lower, nil),
	}
	go func() { _ = d.Serve(ctx, dln) }()

	var mu sync.Mutex
	disabled := map[string]bool{}
	probe := func() (sandboxrelayd.HookRegistration, error) {
		mu.Lock()
		defer mu.Unlock()
		reg := sandboxrelayd.HookRegistration{Events: []string{"PreToolUse", "PostToolUse"}}
		if disabled["project"] {
			reg.Events = []string{"PostToolUse"}
		}
		return reg, nil
	}
	fw := mxcHelperForwarder(ctx, rec, obs, probe, 40*time.Millisecond)
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("h", 32)))
	_ = startMXCPort(t, &mxcPort{Token: tok, Tier: vocab.TierNone, Relay: fw.ServeConn})

	time.Sleep(150 * time.Millisecond)
	if fw.HooksDrifted() {
		t.Fatal("an unchanged registration drifted")
	}
	mu.Lock()
	disabled["project"] = true // the agent switched its project hooks off
	mu.Unlock()
	deadline := time.Now().Add(10 * time.Second)
	for {
		h, ok, err := st.LoadTerminalRunCaptureHealth(ctx, runID)
		if err == nil && ok && strings.Contains(h.Causes, "hooks_drifted") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the row was not lowered with hooks_drifted: %+v %v %v (helper drifted %v)", h, ok, err, fw.HooksDrifted())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestMXCRelayThroughThePortAndThePipe is the relay path of the P6
// acceptance (in-box client -> the helper's loopback port with the token ->
// the daemon over the owner-only local IPC endpoint), with the real relay
// daemon and forwarder: a request lands, and a link without the token, or
// with another run's box secret, is refused.
func TestMXCRelayThroughThePortAndThePipe(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC transport")
	}
	obs := shortTempDir(t)
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "run-mxc", Tool: "claude-code", WorkspaceDir: obs, Roots: []string{obs}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	ep, err := sandboxRelayEndpoint(obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(ep), 0o700); err != nil {
		t.Fatal(err)
	}
	dln, err := localipc.DefaultTransport().Listen(ep)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ran atomic.Int64
	d := &sandboxrelayd.Daemon{
		ObserverDir: obs, Rules: relayRules, Peer: sandboxrelayd.PeerSameUser,
		Exec: func(_ context.Context, run sandboxrelayd.RunRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			ran.Add(1)
			return sandboxrelay.HookResponse{Stdout: []byte("ran " + run.RunID + " " + string(req.Stdin))}, nil
		},
	}
	go func() { _ = d.Serve(ctx, dln) }()
	fw := &sandboxrelayd.Forwarder{Run: rec, DialDaemon: dialSandboxRelay(obs), Rules: relayRules}
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("r", 32)))
	port := startMXCPort(t, &mxcPort{Token: tok, Tier: vocab.TierNone, Relay: fw.ServeConn})

	box := shortTempDir(t)
	if err := sandboxrelayd.WriteBoxRecord(box, rec); err != nil {
		t.Fatal(err)
	}
	if err := writeMXCLoopback(box, mxcLoopback{V: 1, Port: port, Token: tok}); err != nil {
		t.Fatal(err)
	}
	br, ok, err := sandboxrelayd.ReadBoxRecord(filepath.Join(box, sandboxrelayd.BoxRecordName))
	if !ok || err != nil {
		t.Fatalf("box record %v %v", ok, err)
	}
	rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
	defer rcancel()
	resp, err := mxcBoxRoundTrip(rctx, box, br, sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PreToolUse"}, Stdin: []byte("payload")})
	if err != nil || string(resp.Stdout) != "ran run-mxc payload" {
		t.Fatalf("round trip %q %v", resp.Stdout, err)
	}
	// Another run's box secret is refused by the forwarder; the daemon
	// never runs it.
	forged := br
	forged.BoxSecret = append([]byte(nil), br.BoxSecret...)
	forged.BoxSecret[0] ^= 0xff
	if _, err := mxcBoxRoundTrip(rctx, box, forged, sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PreToolUse"}}); err == nil {
		t.Fatal("a forged box secret was relayed")
	}
	// A stream without the token never reaches the forwarder.
	lb, _ := readMXCLoopback(box)
	lb.Token, _ = sandboxmxc.EncodeToken([]byte(strings.Repeat("x", 32)))
	if _, err := dialMXCUpgrade(rctx, lb, "relay", sandboxmxc.UpgradeRelay); err == nil {
		t.Fatal("a relay stream opened with another token")
	}
	if ran.Load() != 1 {
		t.Fatalf("the executor ran %d times", ran.Load())
	}
}

// shortTempDir is a short directory (unix socket paths are short).
func shortTempDir(t *testing.T) string {
	t.Helper()
	base := ""
	if runtime.GOOS != "windows" {
		base = "/tmp"
	}
	d, err := os.MkdirTemp(base, "mxc")
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(d, 0o700)
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// TestMXCOOBTransport is the Windows OOB transport (section 5.6) end to
// end over the local IPC endpoint: the helper's Hello carries the daemon's
// own token, a box-announced session is forwarded only as discovered, and
// box lifecycle frames are dropped.
func TestMXCOOBTransport(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC transport")
	}
	obs := shortTempDir(t)
	const runID = "run-oob"
	if err := processMXCOOB.open(obs, runID); err != nil {
		t.Fatal(err)
	}
	src, ok := mxcOOBSource(mxcWrapArgv("/bin/observer", filepath.Join(obs, "p.json"), runID, obs))
	if !ok {
		t.Fatal("no OOB source for the run's wrap argv")
	}
	defer func() { _ = src.Close() }()
	// The launcher's reader is already accepting when the helper dials (it
	// reads at once); on Windows a named-pipe client waits until the server
	// accepts (go-winio keeps the first instance busy), so start the accept
	// first here too (Windows 11 Pro rerun 2026-10-25, D5 group 8).
	if r, ok := src.(*mxcOOBReader); ok {
		go r.once.Do(r.accept)
	}
	daemonToken, _ := termoob.NewSessionToken()
	ep, _ := mxcOOBEndpoint(obs, runID)
	c, err := localipc.DefaultTransport().Dial(context.Background(), ep, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	up := newMXCOOBUplink(c, termoob.Hello{AuthToken: daemonToken, CorrelationToken: "corr", Tool: "claude-code"}, 1)
	if up == nil {
		t.Fatal("no uplink")
	}
	// A box stream: Hello with the port token, a lifecycle frame (dropped)
	// and a session announce (forwarded lowered).
	portToken, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("b", 32)))
	pr, pw := io.Pipe()
	go func() {
		enc := termoob.NewEncoder(pw)
		_ = enc.WriteHello(termoob.Hello{AuthToken: portToken})
		_ = enc.WriteLifecycle(termoob.Lifecycle{Phase: termoob.PhaseToolExecEnd, At: 2})
		_ = enc.WriteSession(termoob.Session{SessionID: "sess-1"})
		_ = pw.Close()
	}()
	mxcForwardBoxOOB(pr, portToken, up)
	up.end(7, 3)

	dec := termoob.NewDecoder(src, daemonToken)
	var got []string
	for {
		f, err := dec.Read()
		if err != nil {
			break
		}
		switch f.Type {
		case termoob.TypeHello:
			got = append(got, "hello:"+f.Hello.CorrelationToken)
		case termoob.TypeLifecycle:
			got = append(got, "life:"+string(f.Lifecycle.Phase))
		case termoob.TypeSession:
			got = append(got, "session:"+f.Session.SessionID+":"+f.Session.Source)
		}
	}
	want := "hello:corr life:launcher_started session:sess-1:discovered life:tool_exec_end"
	if strings.Join(got, " ") != want {
		t.Fatalf("frames\n got %s\nwant %s", strings.Join(got, " "), want)
	}
	// A wrong box token poisons the box stream: nothing is forwarded.
	if _, ok := mxcOOBSource(mxcWrapArgv("/bin/observer", "/p", runID, obs)); ok {
		t.Fatal("the run's OOB endpoint was handed out twice")
	}
}

// TestMXCInnerEnvNoProxy: the box reaches its own port directly.
func TestMXCInnerEnvNoProxy(t *testing.T) {
	env := strings.Join(mxcInnerEnv(vocab.TierNone, 1, "t"), " ")
	if strings.Contains(env, "HTTPS_PROXY") || !strings.Contains(env, "NO_PROXY=127.0.0.1") {
		t.Fatalf("none tier env %s", env)
	}
}

// TestMXCRegistryRowMatchesThePlanner keeps the row's pins, tiers and
// relay transport equal to the planner's.
func TestMXCRegistryRowMatchesThePlanner(t *testing.T) {
	row := mxcRow()
	if row.Control.Pins.RequiredMin != sandboxmxc.Pins.RequiredMin || row.Control.Pins.TestedLow != sandboxmxc.Pins.TestedLow || row.Control.Pins.TestedHigh != sandboxmxc.Pins.TestedHigh {
		t.Errorf("pins %+v vs %+v", row.Control.Pins, sandboxmxc.Pins)
	}
	if len(row.Net.Egress) != len(sandboxmxc.Tiers()) {
		t.Errorf("tiers %v vs %v", row.Net.Egress, sandboxmxc.Tiers())
	}
	for _, tr := range sandboxmxc.Tiers() {
		if !row.OffersTier(tr) {
			t.Errorf("row lacks %s", tr)
		}
	}
	if row.Capture.Relay != sandboxbackend.RelaySingleLoopbackPortToken || row.Term.Transport != sandboxbackend.TransportExecUnderHostConPTY || row.Iso.HostMutation {
		t.Errorf("row %+v", row)
	}
	if v, ok := row.VerificationOn(sandboxbackend.HostWindows); !ok || !v.Kind.IsBeta() || v.RegisterRef == "" {
		t.Errorf("verification %+v", v)
	}
}

// mxcAdversarialCases is section 13.12 for the Windows family: each case
// is either a unit test here (passing) or a register entry of section
// 13.10 with what the live run must prove.
var mxcAdversarialCases = []struct{ id, unit, register string }{
	{"A1", "TestMXCProviderHostBlockOnThePort", "WIN-2: a direct provider request and a literal-IP request fail from inside a live box, and a proxied turn lands an api_turns row"},
	{"A2", "", "WIN-1: kill the daemon mid-run: the helper's kill-on-close job leaves no container; native resume is offered"},
	{"A3", "", "WIN-1: sleep and network flaps on a live run; gate events block while the daemon is unreachable"},
	{"A4", "", "WIN-1: an update apply with a live run defers (deferred_live_sandbox)"},
	{"A5", "TestMXCRelayThroughThePortAndThePipe", "the relay's fuzz targets cover the frames; the port adds only token routing (sandboxmxc TestPortRouting)"},
	{"A6", "TestMXCRelayThroughThePortAndThePipe", "WIN-2: a reattached run's relay works and a link without the token is refused, on a live box"},
	{"A7", "", "WIN-1: browser reconnect, daemon restart, host sleep and a dead agent on a live box end honestly with native resume"},
	{"A8", "", "not applicable: a local row with no stored endpoint credential"},
	{"A9", "", "not applicable: no engine socket on this row"},
	{"A10", "TestMXCHelperRechecksHooksMidRun", "WIN-3: the agent edits its hook config mid-run: hooks_drifted within one interval"},
	{"A11", "", "not applicable: the row takes no snapshot or warm image"},
	{"A12", "TestMXCDriverRefusalsReachTheSelection", "a replaced or below-minimum MXC file is refused before load (sandboxmxcdll TestGatherStops); the signed manifest of section 12.3 is the release job's"},
	{"A13", "", "covered by the shared posture comparison (SBX-GOV-5), no row-specific case"},
}

// TestMXCAdversarialCasesAccountedFor: every 13.12 case has a passing unit
// test or a register entry, never a silent skip.
func TestMXCAdversarialCasesAccountedFor(t *testing.T) {
	src, err := os.ReadFile("terminal_sandbox_mxc_test.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range mxcAdversarialCases {
		seen[c.id] = true
		if c.unit == "" && c.register == "" {
			t.Errorf("%s has neither a test nor a register entry", c.id)
		}
		if c.unit != "" && !strings.Contains(string(src), "func "+c.unit+"(") {
			t.Errorf("%s names a missing test %s", c.id, c.unit)
		}
	}
	for i := 1; i <= 13; i++ {
		if !seen[fmt.Sprintf("A%d", i)] {
			t.Errorf("A%d is not accounted for", i)
		}
	}
	_ = json.Valid
}

// TestMXCPlanFileRoundTrip: the plan the daemon writes is the plan the
// helper reads; a link, a wrong version or a bad tier is refused.
func TestMXCPlanFileRoundTrip(t *testing.T) {
	obs := t.TempDir()
	plan := mxcPlanFile{Version: mxcPlanVersion, RunID: "run-p", ObserverDir: obs, Tier: "proxy_only", ProxyPort: 8820, Workspace: obs, ReadWrite: []string{obs}}
	p, err := writeMXCPlan(obs, plan)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readMXCPlan(p)
	if err != nil || got.RunID != "run-p" || got.ProxyPort != 8820 {
		t.Fatalf("read %+v %v", got, err)
	}
	if _, err := writeMXCPlan(obs, plan); err == nil {
		t.Fatal("a second plan for the same run was written")
	}
	link := filepath.Join(obs, "link.json")
	if err := os.Symlink(p, link); err == nil {
		if _, err := readMXCPlan(link); err == nil {
			t.Fatal("a linked plan was read")
		}
	}
	for _, bad := range []mxcPlanFile{{Version: 99, RunID: "r", Tier: "none"}, {Version: mxcPlanVersion, RunID: "r", Tier: "sideways"}} {
		b, _ := json.Marshal(bad)
		bp := filepath.Join(obs, fmt.Sprintf("bad-%d-%s.json", bad.Version, bad.Tier))
		if err := os.WriteFile(bp, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readMXCPlan(bp); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if err := removeMXCPlan(obs, "run-p"); err != nil {
		t.Fatal(err)
	}
}

func TestMXCHelloFromEnv(t *testing.T) {
	env := map[string]string{envOOBAuth: "a", envOOBCorr: "c", envOOBTool: "claude-code"}
	h, ok := mxcHelloFromEnv(func(k string) string { return env[k] })
	if !ok || h.AuthToken != "a" || h.CorrelationToken != "c" || h.Tool != "claude-code" {
		t.Fatalf("hello %+v %v", h, ok)
	}
	if _, ok := mxcHelloFromEnv(func(string) string { return "" }); ok {
		t.Fatal("a helper with no daemon token authenticated a channel")
	}
}

// TestMXCPlanGrants: the plan grants the workspace and the tool's state
// read-write, the observer binary read-only, never the observer directory,
// and refuses a sensitive extra write grant.
func TestMXCPlanGrants(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	countMXCProbes(t, "windows", availableMXC())
	home := t.TempDir()
	setTestHome(t, home)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	onboardTestClaude(t, home)
	ws := filepath.Join(home, "proj")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := mxcTestConfig(t, true, "mxc-process")
	rt := ociTestRuntime(t, cfg)
	d := rt.drivers[sandboxbackend.BackendMXCProcess].(*mxcDriver)
	plan, err := d.plan(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: "run-g", Tool: "claude-code", Dir: ws}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(plan.ReadWrite, ws) || !slices.Contains(plan.ReadWrite, filepath.Join(home, ".claude")) {
		t.Fatalf("rw %v", plan.ReadWrite)
	}
	for _, p := range append(append([]string(nil), plan.ReadWrite...), plan.ReadOnly...) {
		if p == rt.observerDir || strings.HasPrefix(rt.observerDir, p+string(filepath.Separator)) {
			t.Errorf("grant %s shows the observer directory", p)
		}
	}
	if plan.Tier != "internet" || plan.ProxyPort == 0 {
		t.Fatalf("plan %+v", plan)
	}
	// B5 (Windows 11 Pro live run): the workspace is not a repository, so
	// no .git is made or pinned there (the box must not see a .git the host
	// lacks); the plan lists it as absent, for the after-run report.
	gitDir := filepath.Join(ws, ".git")
	for _, l := range [][]string{plan.PlaceholderDirs, plan.PlaceholderFiles, plan.ReadOnly, plan.Denied} {
		for _, p := range l {
			if p == gitDir || strings.HasPrefix(p, gitDir+string(filepath.Separator)) {
				t.Fatalf("non-repository workspace: %s is made or pinned (placeholders %v %v, ro %v, denied %v)", p, plan.PlaceholderDirs, plan.PlaceholderFiles, plan.ReadOnly, plan.Denied)
			}
		}
	}
	if !slices.Equal(plan.AbsentGitDirs, []string{gitDir}) {
		t.Fatalf("absent .git dirs %v, want [%s]", plan.AbsentGitDirs, gitDir)
	}
	created, err := mxcCreatePlaceholders(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(gitDir); !os.IsNotExist(err) {
		t.Fatalf("the helper made a .git the host lacks: %v", err)
	}
	mxcRemovePlaceholders(created)
	if got := mxcAbsentGitNotice(mxcAbsentGitCreated(plan)); got != "" {
		t.Fatalf("a notice with no .git made: %q", got)
	}
	if err := os.Mkdir(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := mxcAbsentGitNotice(mxcAbsentGitCreated(plan)); !strings.Contains(got, gitDir) || !strings.Contains(got, "check them before you run git here") {
		t.Fatalf("the run-made .git is not named: %q", got)
	}
	if err := os.Remove(gitDir); err != nil {
		t.Fatal(err)
	}
	// A repository without hooks gets .git/hooks; its config is read-only.
	repo := filepath.Join(home, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rplan, err := d.plan(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: "run-r", Tool: "claude-code", Dir: repo}})
	if err != nil {
		t.Fatal(err)
	}
	if hooks := filepath.Join(repo, ".git", "hooks"); !slices.Contains(rplan.PlaceholderDirs, hooks) || !slices.Contains(rplan.ReadOnly, hooks) || !slices.Contains(rplan.ReadOnly, filepath.Join(repo, ".git", "config")) {
		t.Fatalf("repository without hooks: placeholders %v, ro %v", rplan.PlaceholderDirs, rplan.ReadOnly)
	}
	if len(rplan.AbsentGitDirs) != 0 {
		t.Fatalf("a repository's .git listed as absent: %v", rplan.AbsentGitDirs)
	}
	// A workspace holding the observer directory is refused.
	if _, err := d.plan(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: "run-h", Tool: "claude-code", Dir: filepath.Dir(rt.observerDir)}}); err == nil {
		t.Fatal("a workspace that shows the observer directory was planned")
	}
	// A sensitive extra write grant is refused.
	rt.cfg.ExtraRWBinds = []string{home}
	if _, err := d.plan(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: "run-s", Tool: "claude-code", Dir: ws}}); err == nil {
		t.Fatal("the home directory was granted writable")
	}
}

// TestMXCStageLastRow (finding L3): the version stage is judged through the
// version row alone, so a library that loaded and answered its version is
// reported as such, not as a missing probe answer.
func TestMXCStageLastRow(t *testing.T) {
	for stage, want := range map[string]string{"version": "version", "request": "request_probe", "create": "", "echo": "", "": ""} {
		if got := mxcStageLastRow(stage); got != want {
			t.Errorf("%q: %q, want %q", stage, got, want)
		}
	}
	f := sandboxmxc.HostFacts{Windows: true, Active: true, Build: 26200, UBR: 9711, LibraryVersion: "1.0.1"}
	for _, bf := range sandboxmxc.ManifestX64.Files {
		f.Files = append(f.Files, sandboxmxc.FileFact{Name: bf.Name, Present: true, SHA256: bf.SHA256, SignatureChecked: true, Signed: true})
	}
	if r := sandboxmxc.ProbeThrough(f, sandboxmxc.ManifestX64, mxcStageLastRow("version")); !r.Verdict.OK() || r.Version != "1.0.1" {
		t.Fatalf("version stage of the laptop's facts: %+v", r)
	}
}

// TestMXCBoxEnvCarriesItsTier (P-094 residual, lane SHR-FOLLOWUPS): the MXC
// row's wrap runs no host helper, so its box env sets the tier variable from
// the plan's tier beside the marker, and an inherited one never survives.
func TestMXCBoxEnvCarriesItsTier(t *testing.T) {
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("q", 32)))
	env := mxcBoxEnv([]string{sandbox.EnvEgress + "=internet"}, `C:\b`, `C:\b\tmp`, vocab.TierNone, 4242, tok, nil)
	var tiers []string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, sandbox.EnvEgress+"="); ok {
			tiers = append(tiers, v)
		}
	}
	if len(tiers) != 1 || tiers[0] != "none" {
		t.Fatalf("box env tier values %q, want exactly [none]", tiers)
	}
}

// TestSandboxMXCPlanProviderDirectRefuseAll (lane w6-governance audit follow-up 7,
// DEC-9): the driver itself carries the organization's posture into the
// run's network plan. An unrouted internet run computes a capped capture
// (rule C3, transcripts_only) and gets no provider block under
// capture_rule; under refuse_all the same run's plan turns the block on,
// with the proxy's upstream hosts.
func TestSandboxMXCPlanProviderDirectRefuseAll(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	countMXCProbes(t, "windows", availableMXC())
	home := t.TempDir()
	setTestHome(t, home)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	onboardTestClaude(t, home)
	ws := filepath.Join(home, "proj")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	rt := ociTestRuntime(t, mxcTestConfig(t, true, "mxc-process"))
	rt.providerHosts = []string{"openrouter.ai"}
	d := rt.drivers[sandboxbackend.BackendMXCProcess].(*mxcDriver)
	created := termsvc.CreateResult{Run: termsvc.SandboxRun{ID: "run-pd", Tool: "claude-code", Dir: ws}}
	if c := sandboxRunCaptureFor(mxcRow(), created.ProxyRouted, vocab.TierInternet, ""); c.Level == vocab.CaptureFull {
		t.Fatalf("the run is not capped: %+v", c)
	}
	plan, err := d.plan(created)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ProviderBlock {
		t.Fatal("capture_rule blocked provider hosts on an unrouted run")
	}
	rt.cfg.ProviderDirectInForce = string(vocab.ProviderDirectRefuseAll)
	plan, err = d.plan(created)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ProviderBlock || !slices.Contains(plan.ProviderHosts, "openrouter.ai") {
		t.Fatalf("refuse_all did not reach the plan: block %v hosts %v", plan.ProviderBlock, plan.ProviderHosts)
	}
}
