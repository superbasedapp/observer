//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// gwFake is a scripted systemd user manager, openshell-gateway and
// openshell CLI for the managed gateway's lifecycle (lane O2 M3).
type gwFake struct {
	mu      sync.Mutex
	unit    string // the unit's state as is-active prints it
	version string // openshell-gateway --version and openshell --version
	listen  map[int]bool
	port    int
	failRun bool
	healthy bool
	// dies: the unit exits (failed) right after its launch.
	dies bool
	// keepFailed: a stop leaves a failed unit failed (systemctl stop does
	// not clear failed; reset-failed does).
	keepFailed bool
	// stopLeavesFailed: a stop leaves the unit failed (a gateway that
	// exits non-zero on SIGTERM); reset-failed clears it.
	stopLeavesFailed bool
	plans            []extrun.Plan
	genCerts         int
	// config is the --config the running unit was started with;
	// foreignConfig, when set, is what `systemctl show` answers instead (a
	// unit of the same name run from another state dir, ledger row OSH-42).
	config, foreignConfig string
	// showFails: `systemctl show` itself fails (audit finding FU7-A11).
	showFails bool
}

func newGWFake() *gwFake {
	return &gwFake{unit: "inactive", version: "0.1.6", listen: map[int]bool{}, healthy: true}
}

func (f *gwFake) facts(p extrun.Plan) extrun.ExecFacts {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plans = append(f.plans, p)
	ok := func(s string) extrun.ExecFacts { return extrun.ExecFacts{Stdout: []byte(s), PeakChildren: -1} }
	prog := filepath.Base(p.Path)
	args := p.Args
	switch {
	case prog == "systemctl" && slices.Contains(args, "is-system-running"):
		return ok("running\n")
	case prog == "systemctl" && slices.Contains(args, "is-active"):
		code := 3
		if f.unit == "active" {
			code = 0
		}
		return extrun.ExecFacts{Stdout: []byte(f.unit + "\n"), ExitCode: code, PeakChildren: -1}
	case prog == "systemctl" && slices.Contains(args, "stop"):
		switch {
		case f.stopLeavesFailed:
			f.unit = "failed"
		case !(f.keepFailed && f.unit == "failed"):
			f.unit = "inactive"
		}
		delete(f.listen, f.port)
		return ok("")
	case prog == "systemctl" && slices.Contains(args, "show"):
		if f.showFails {
			return extrun.ExecFacts{ExitCode: 1, Stderr: []byte("Failed to connect to bus\n"), PeakChildren: -1}
		}
		cfg := f.config
		if f.foreignConfig != "" {
			cfg = f.foreignConfig
		}
		if f.unit != "active" || cfg == "" {
			return ok("\n")
		}
		return ok("{ path=/usr/bin/openshell-gateway ; argv[]=/usr/bin/openshell-gateway --config " + cfg + " --db-url sqlite:/x/openshell.db ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n")
	case prog == "systemctl" && slices.Contains(args, "reset-failed"):
		if f.unit == "failed" && !f.keepFailed {
			f.unit = "inactive"
		}
		return ok("")
	case prog == "systemctl":
		return ok("")
	case prog == "systemd-run":
		if f.failRun {
			return extrun.ExecFacts{ExitCode: 1, Stderr: []byte("Failed to connect to bus"), PeakChildren: -1}
		}
		f.unit = "active"
		if f.dies {
			f.unit = "failed"
		}
		for i, a := range args {
			switch a {
			case "--port":
				f.port = atoiTest(args[i+1])
			case "--config":
				f.config = args[i+1]
			}
		}
		if !f.dies {
			f.listen[f.port] = true
		}
		return ok("")
	case prog == "openshell-gateway" && slices.Equal(args, []string{"--version"}):
		return ok("openshell-gateway " + f.version + "\n")
	case prog == "openshell-gateway" && len(args) > 0 && args[0] == "generate-certs":
		f.genCerts++
		dir := args[2]
		for _, rel := range sandboxopenshell.PKIFiles {
			pth := filepath.Join(dir, rel)
			_ = os.MkdirAll(filepath.Dir(pth), 0o700)
			_ = os.WriteFile(pth, []byte("SENTINEL-PEM "+rel), 0o600)
		}
		return ok("")
	case prog == "openshell-gateway":
		return ok("") // config preflight
	case prog == "docker":
		return openShellFakeImageInspect(args) // image inspect of a runtime image
	case prog == "openshell" && slices.Equal(args, []string{"--version"}):
		return ok("openshell " + f.version + "\n")
	case prog == "openshell" && slices.Contains(args, "add"):
		return ok("")
	case prog == "openshell" && slices.Contains(args, "status"):
		name := ""
		for i, a := range args {
			if a == "-g" {
				name = args[i+1]
			}
		}
		if f.unit != "active" || !f.healthy {
			return extrun.ExecFacts{ExitCode: 1, Stderr: []byte("connection refused"), PeakChildren: -1}
		}
		return ok(`{"gateway":"` + name + `","server":"` + sandboxopenshell.ServerFor(f.port) + `","status":"connected","version":"` + f.version + `","authentication":{"status":"authenticated"}}`)
	}
	return extrun.ExecFacts{ExitCode: 2, Stderr: []byte("unscripted"), PeakChildren: -1}
}

func atoiTest(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// calls returns the base names and argv of the programs started.
func (f *gwFake) progs(name string) [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]string
	for _, p := range f.plans {
		if filepath.Base(p.Path) == name {
			out = append(out, p.Args)
		}
	}
	return out
}

func (f *gwFake) reset() { f.mu.Lock(); f.plans = nil; f.mu.Unlock() }

// gwHarness is an executor over the fake with a memory keystore.
type gwHarness struct {
	t        *testing.T
	fake     *gwFake
	stateDir string
	runtime  string
	ks       *keystore.MemStore
	exec     *openShellGatewayExec
}

func newGWHarness(t *testing.T) *gwHarness {
	t.Helper()
	oldWait, oldPoll := openShellGatewayStartWait, openShellGatewayPoll
	openShellGatewayStartWait, openShellGatewayPoll = 2*time.Second, time.Millisecond
	t.Cleanup(func() { openShellGatewayStartWait, openShellGatewayPoll = oldWait, oldPoll })
	h := &gwHarness{t: t, fake: newGWFake(), stateDir: filepath.Join(t.TempDir(), "sandbox-openshell"), ks: &keystore.MemStore{}}
	h.runtime = filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(h.runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	ex := &extruntest.Executor{Facts: h.fake.facts}
	files := extruntest.Files{}
	for _, b := range []string{"openshell", "openshell-gateway", "systemd-run", "systemctl", "docker"} {
		files["/usr/bin/"+b] = extruntest.File{}
	}
	r := extruntest.NewRunner("linux", files, ex, nil)
	r.Resolve = func(s integration.BinaryResolveSpec) toolresolve.Resolution {
		return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: "/usr/bin/" + s.Names.Unix[0]}
	}
	host := openShellGatewayHostT{
		RuntimeDir: func() string { return h.runtime },
		StateFS:    func(string) (sandboxopenshell.Tri, string) { return sandboxopenshell.TriYes, "ext4" },
		RuntimeFS:  func(string) (sandboxopenshell.Tri, string) { return sandboxopenshell.TriYes, "" },
		PortFree: func(p int) bool {
			h.fake.mu.Lock()
			defer h.fake.mu.Unlock()
			return !h.fake.listen[p]
		},
		Lock:         func(string) (func(), error) { return func() {}, nil },
		Rand:         bytes.NewReader(bytes.Repeat([]byte{5}, 4*sandboxopenshell.KEKBytes)),
		DockerAccess: func(openShellUnitEngine) (sandboxopenshell.Tri, string) { return sandboxopenshell.TriYes, "" },
		DockerHost:   func() string { return "" },
	}
	h.exec = &openShellGatewayExec{stateDir: h.stateDir, runner: r, host: host, store: openShellCustody{s: h.ks}, backend: "keychain", log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return h
}

func (h *gwHarness) ensure(wanted bool) openShellManaged {
	h.t.Helper()
	return h.exec.ensure(context.Background(), wanted)
}

// TestOpenShellGatewayFirstStart: a first start generates the PKI in the
// runtime dir, takes it into the keystore, writes the config and the
// record, pins the custody, writes the key-encryption key only into the
// RAM dir's owner-only env file the unit reads, registers the private
// gateway and settles ready.
func TestOpenShellGatewayFirstStart(t *testing.T) {
	h := newGWHarness(t)
	m := h.ensure(true)
	if !m.decision.Ready() || m.decision.Rule != "G23" {
		t.Fatalf("decision %+v", m.decision)
	}
	if h.fake.genCerts != 1 {
		t.Fatalf("generate-certs ran %d times", h.fake.genCerts)
	}
	id := m.id
	for _, n := range sandboxopenshell.CustodyRecordNames(id) {
		if _, err := h.ks.Get(n); err != nil {
			t.Fatalf("custody record %s: %v", n, err)
		}
	}
	if m.record == nil || m.record.Version != "0.1.6" || m.record.Server != sandboxopenshell.ServerFor(m.record.Port) {
		t.Fatalf("record %+v", m.record)
	}
	if m.record.Port < sandboxopenshell.GatewayPortBase || m.record.Port >= sandboxopenshell.GatewayPortBase+sandboxopenshell.GatewayPortRange {
		t.Fatalf("port %d outside the managed block", m.record.Port)
	}
	runs := h.fake.progs("systemd-run")
	if len(runs) != 1 {
		t.Fatalf("systemd-run ran %d times", len(runs))
	}
	kek, _ := h.ks.Get(sandboxopenshell.CustodyRecordNames(id)[1])
	for _, a := range runs[0] {
		if strings.Contains(a, kek) {
			t.Fatalf("the key-encryption key is on the systemd-run argv: %q", a)
		}
	}
	// The key-encryption key is in no program's environment or argv: it
	// reaches the unit only through the RAM dir's owner-only env file
	// (audit finding O2-A6).
	for _, p := range h.fake.plans {
		if filepath.Base(p.Path) == "systemd-run" || filepath.Base(p.Path) == "systemctl" {
			for _, kv := range append(slices.Clone(p.Env), p.Args...) {
				if strings.Contains(kv, kek) {
					t.Fatalf("%s carries the key-encryption key", filepath.Base(p.Path))
				}
			}
		}
	}
	if !slices.Contains(runs[0], "--property=EnvironmentFile="+m.layout.EnvFile) {
		t.Fatal("the unit does not read the RAM dir's env file")
	}
	envb, err := os.ReadFile(m.layout.EnvFile)
	if err != nil || string(envb) != sandboxopenshell.GatewayKEKEnv+"="+kek+"\n" {
		t.Fatalf("env file: %v", err)
	}
	if fi, _ := os.Stat(m.layout.EnvFile); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("the env file must be owner-only")
	}
	if b, err := os.ReadFile(m.layout.CustodyPath); err != nil || strings.TrimSpace(string(b)) != sandboxopenshell.CustodyKeychain {
		t.Fatalf("custody pin: %q %v", b, err)
	}
	// Every openshell CLI call about the private gateway runs with its
	// private registry, never the user's own.
	for _, p := range h.fake.plans {
		if filepath.Base(p.Path) == "openshell" && !slices.Equal(p.Args, []string{"--version"}) {
			if !slices.Contains(p.Env, "XDG_CONFIG_HOME="+m.layout.CLIConfigHome) {
				t.Fatalf("openshell %v ran without the private registry: %v", p.Args, p.Env)
			}
		}
	}
	cfg, err := os.ReadFile(m.layout.ConfigPath)
	if err != nil || !strings.Contains(string(cfg), "enable_bind_mounts = true") || strings.Contains(string(cfg), kek) {
		t.Fatalf("config: %v", err)
	}
	if fi, err := os.Stat(m.layout.ConfigPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v", err)
	}
	// The state dir holds no key at rest: only the config, the record,
	// the lock and the recorded gateways.
	_ = filepath.WalkDir(h.stateDir, func(p string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte("SENTINEL-PEM")) || bytes.Contains(b, []byte(kek)) {
				t.Fatalf("%s holds key material at rest", p)
			}
		}
		return nil
	})
	if b, err := os.ReadFile(filepath.Join(m.layout.TLSDir, "ca.key")); err != nil || string(b) != "SENTINEL-PEM ca.key" {
		t.Fatalf("the runtime PKI: %v", err)
	}
	if got := openShellGateways(h.stateDir); len(got) != 1 || got[0].Target != m.target() {
		t.Fatalf("recorded gateways %+v", got)
	}

	// A second pass adopts the running gateway: no new start.
	h.fake.reset()
	if m2 := h.ensure(true); !m2.decision.Ready() || len(h.fake.progs("systemd-run")) != 0 {
		t.Fatalf("the second pass restarted: %+v", m2.decision)
	}
}

// TestOpenShellGatewayRestoreAfterReboot: the unit and the RAM dir are
// gone (a reboot); the next start restores the held PKI, never
// regenerates it, and keeps the recorded port.
func TestOpenShellGatewayRestoreAfterReboot(t *testing.T) {
	h := newGWHarness(t)
	m := h.ensure(true)
	port := m.record.Port
	h.fake.mu.Lock()
	h.fake.unit, h.fake.listen = "inactive", map[int]bool{}
	h.fake.mu.Unlock()
	if err := os.RemoveAll(m.layout.RuntimeDir); err != nil {
		t.Fatal(err)
	}
	m2 := h.ensure(true)
	if !m2.decision.Ready() || h.fake.genCerts != 1 || m2.record.Port != port {
		t.Fatalf("after a reboot: %+v gen %d port %d->%d", m2.decision, h.fake.genCerts, port, m2.record.Port)
	}
	if b, _ := os.ReadFile(filepath.Join(m2.layout.TLSDir, "client", "tls.key")); string(b) != "SENTINEL-PEM client/tls.key" {
		t.Fatalf("restored key %q", b)
	}
	if fi, err := os.Stat(filepath.Join(m2.layout.TLSDir, "client", "tls.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("a restored key must be owner-only")
	}
}

// writeLiveRun plants a fresh run dir pinned to the managed gateway (too
// young for the reaper's grace, so it counts as live).
func writeLiveRun(t *testing.T, stateDir string, m openShellManaged) {
	t.Helper()
	dir := openShellRunDir(stateDir, "run-0000-live")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pf := openShellPlanFile{Version: openShellPlanVersion, RunID: "run-0000-live", Target: m.target(), Server: m.record.Server, GatewayVersion: "0.1.6", Name: sandboxopenshell.SandboxName("run-0000-live")}
	b, _ := json.Marshal(pf)
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestOpenShellGatewayUpgrade: an upgraded package waits for a live run
// and restarts the gateway once the run ends (never under it).
func TestOpenShellGatewayUpgrade(t *testing.T) {
	h := newGWHarness(t)
	m := h.ensure(true)
	// Pretend the running gateway is an older one.
	rec := *m.record
	rec.Version = "0.1.5"
	b, _ := json.Marshal(rec)
	if err := os.WriteFile(m.layout.RecordPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	writeLiveRun(t, h.stateDir, m)
	h.fake.reset()
	w := h.ensure(true)
	if w.decision.Action != sandboxopenshell.GatewayWait || w.decision.Verdict != sandboxopenshell.VerdictGatewayUpgradePending {
		t.Fatalf("with a live run: %+v", w.decision)
	}
	if len(h.fake.progs("systemd-run")) != 0 || len(h.fake.progs("systemctl")) == 0 {
		t.Fatal("the gateway was touched under a live run")
	}
	for _, a := range h.fake.progs("systemctl") {
		if slices.Contains(a, "stop") {
			t.Fatal("stopped under a live run")
		}
	}
	if err := os.RemoveAll(openShellRunDir(h.stateDir, "run-0000-live")); err != nil {
		t.Fatal(err)
	}
	h.fake.reset()
	u := h.ensure(true)
	if !u.decision.Ready() || u.record.Version != "0.1.6" {
		t.Fatalf("after the run ended: %+v %+v", u.decision, u.record)
	}
	stops, starts := 0, len(h.fake.progs("systemd-run"))
	for _, a := range h.fake.progs("systemctl") {
		if slices.Contains(a, "stop") {
			stops++
		}
	}
	if stops != 1 || starts != 1 || h.fake.genCerts != 1 {
		t.Fatalf("upgrade: %d stops, %d starts, %d generations", stops, starts, h.fake.genCerts)
	}
}

// TestOpenShellGatewayNotWanted: with managed mode no longer wanted the
// gateway is stopped once idle (its RAM dir removed, its keys kept), and
// with nothing recorded no program runs at all.
func TestOpenShellGatewayNotWanted(t *testing.T) {
	h := newGWHarness(t)
	m := h.ensure(true)
	writeLiveRun(t, h.stateDir, m)
	h.fake.reset()
	if d := h.ensure(false).decision; d.Action != sandboxopenshell.GatewayWait {
		t.Fatalf("with a live run: %+v", d)
	}
	_ = os.RemoveAll(openShellRunDir(h.stateDir, "run-0000-live"))
	if d := h.ensure(false).decision; d.Action != sandboxopenshell.GatewayNone || d.Rule != "G3" {
		t.Fatalf("idle: %+v", d)
	}
	if _, err := os.Stat(m.layout.RuntimeDir); !os.IsNotExist(err) {
		t.Fatalf("the RAM dir is still there: %v", err)
	}
	if _, err := h.ks.Get(sandboxopenshell.CustodyRecordNames(m.id)[0]); err != nil {
		t.Fatal("a stop must keep the keys")
	}

	fresh := newGWHarness(t)
	if d := fresh.ensure(false).decision; d.Action != sandboxopenshell.GatewayNone {
		t.Fatalf("nothing recorded: %+v", d)
	}
	if n := len(fresh.fake.plans); n != 0 {
		t.Fatalf("%d programs ran with nothing wanted or recorded", n)
	}
	if openShellReadInstallID(fresh.stateDir) != "" {
		t.Fatal("a not-wanted pass minted an install id")
	}
}

// TestOpenShellGatewayRefusals: a refused host starts nothing.
func TestOpenShellGatewayRefusals(t *testing.T) {
	cases := []struct {
		name    string
		mod     func(h *gwHarness)
		verdict string
	}{
		{"fail-closed keystore", func(h *gwHarness) { h.exec.backend = keystore.FailClosed().Backend() }, sandboxopenshell.VerdictGatewayCustodyUnavailable},
		{"the user manager cannot reach docker", func(h *gwHarness) {
			h.exec.host.DockerAccess = func(openShellUnitEngine) (sandboxopenshell.Tri, string) {
				return sandboxopenshell.TriNo, "no docker group"
			}
		}, sandboxopenshell.VerdictGatewayNoDockerAccess},
		{"foreign state dir", func(h *gwHarness) {
			h.exec.host.StateFS = func(string) (sandboxopenshell.Tri, string) { return sandboxopenshell.TriNo, "9p" }
		}, sandboxopenshell.VerdictGatewayStateForeignFS},
		{"runtime dir not RAM", func(h *gwHarness) {
			h.exec.host.RuntimeFS = func(string) (sandboxopenshell.Tri, string) { return sandboxopenshell.TriNo, "ext4" }
		}, sandboxopenshell.VerdictGatewayRuntimeDirUnsafe},
		{"no runtime dir", func(h *gwHarness) { h.exec.host.RuntimeDir = func() string { return "" } }, sandboxopenshell.VerdictGatewayRuntimeDirUnsafe},
		{"untested pair", func(h *gwHarness) {
			h.exec.runner.Resolve = func(s integration.BinaryResolveSpec) toolresolve.Resolution {
				return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: "/usr/bin/" + s.Names.Unix[0]}
			}
			h.fake.version = "0.1.5"
		}, sandboxopenshell.VerdictGatewayBinaryUntested},
		{"systemd-run fails", func(h *gwHarness) { h.fake.failRun = true }, sandboxopenshell.VerdictGatewayStartFailed},
		// Ledger row OSH-44: openshell-gateway found only in a dir the
		// user can write is never started (it would receive the KEK).
		{"gateway binary in a user-writable fallback dir", func(h *gwHarness) {
			h.exec.runner.Resolve = func(s integration.BinaryResolveSpec) toolresolve.Resolution {
				if s.Names.Unix[0] == sandboxopenshell.GatewayProgram {
					return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: "/home/dev/.cache/tool/bin/" + s.Names.Unix[0]}
				}
				return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: "/usr/bin/" + s.Names.Unix[0]}
			}
		}, sandboxopenshell.VerdictBinaryUntrusted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newGWHarness(t)
			tc.mod(h)
			m := h.ensure(true)
			if m.decision.Verdict != tc.verdict || m.decision.Ready() {
				t.Fatalf("decision %+v, want %s", m.decision, tc.verdict)
			}
			if tc.verdict != sandboxopenshell.VerdictGatewayStartFailed && len(h.fake.progs("systemd-run")) != 0 {
				t.Fatal("a refused host started the unit")
			}
		})
	}
}

// TestOpenShellManagedProbe: in managed mode the probe ladder runs the
// lifecycle pass, pins the run to the private gateway (name, server and
// private registry), reads the bind-mount opt-in from the private config
// and passes P4m; an answer from another server is refused.
func TestOpenShellManagedProbe(t *testing.T) {
	h := newGWHarness(t)
	f := healthyOpenShell()
	var managed openShellManaged
	f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
		if prog == "openshell" && slices.Contains(args, "status") {
			return extrun.ExecFacts{Stdout: []byte(`{"gateway":"` + managed.id.Name + `","server":"` + managed.record.Server + `","status":"connected","version":"0.1.6","authentication":{"status":"authenticated"}}`), PeakChildren: -1}, true
		}
		return extrun.ExecFacts{}, false
	}
	r, ex := f.runner()
	hf := healthyHost()
	hf.BindMounts = func(string) sandboxopenshell.Tri { return sandboxopenshell.TriNo } // the user's own config: never read in managed mode
	hf.Managed = func(ctx context.Context) openShellManaged {
		managed = h.exec.ensure(ctx, true)
		return managed
	}
	got := openShellGather(context.Background(), config.TerminalSandboxOpenShellConfig{}, sandboxbackend.HostLinux, r, hf)
	if !got.res.Available() {
		t.Fatalf("managed probe: %+v", got.res)
	}
	if got.pin.Target != managed.target() || got.pin.Server != managed.record.Server {
		t.Fatalf("pin %+v, want the private gateway %+v", got.pin, managed.target())
	}
	if !strings.Contains(got.managedHint, "gateway_mode managed") {
		t.Fatalf("hint %q", got.managedHint)
	}
	// The D3 probe reads the private config, which Observer wrote with
	// the export (lane OC items 2 and 3).
	if g := got.ocsfGateway(); g.Mode != sandboxopenshell.GatewayManaged || g.ManagedConfigPath != managed.layout.ConfigPath {
		t.Fatalf("ocsf gateway %+v", g)
	}
	if st, why := sandboxopenshell.ClassifyOCSFExport(openShellOCSFExport(openShellOCSFSource(got.ocsfGateway()).path(got.ocsfGateway())), sandboxopenshell.OCSFReceiverEndpoint()); st != sandboxopenshell.OCSFExportPresent {
		t.Fatalf("managed export %s: %s", st, why)
	}
	for _, c := range ex.Calls() {
		if filepath.Base(c.Path) == "openshell" && (slices.Contains(c.Args, "status") || slices.Contains(c.Args, "info")) &&
			!slices.Contains(c.Env, "XDG_CONFIG_HOME="+managed.layout.CLIConfigHome) {
			t.Fatalf("%v ran against the user's registry", c.Args)
		}
	}
	// Another server answering under the name is refused at P4m.
	f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
		if prog == "openshell" && slices.Contains(args, "status") {
			return extrun.ExecFacts{Stdout: []byte(`{"gateway":"` + managed.id.Name + `","server":"https://127.0.0.1:17670","status":"connected","version":"0.1.6","authentication":{"status":"authenticated"}}`), PeakChildren: -1}, true
		}
		return extrun.ExecFacts{}, false
	}
	r2, _ := f.runner()
	if got := openShellGather(context.Background(), config.TerminalSandboxOpenShellConfig{}, sandboxbackend.HostLinux, r2, hf); got.res.Rule != "P4m" {
		t.Fatalf("another server: %+v", got.res)
	}
}

// TestOpenShellCLIEnvFor: the interactive create about a managed target
// runs with its private registry, and never inherits the user's own
// registry location or active gateway.
func TestOpenShellCLIEnvFor(t *testing.T) {
	environ := []string{"HOME=/home/dev", "XDG_CONFIG_HOME=/home/dev/.config", "OPENSHELL_GATEWAY=mine", "TERM=xterm"}
	tg := sandboxopenshell.Target{Gateway: "observer-0123456789ab", ConfigHome: "/run/user/1000/observer-openshell-0123456789ab/cli"}
	env := openShellCLIEnvFor(environ, tg)
	if !slices.Contains(env, "XDG_CONFIG_HOME="+tg.ConfigHome) || slices.Contains(env, "XDG_CONFIG_HOME=/home/dev/.config") || slices.Contains(env, "OPENSHELL_GATEWAY=mine") {
		t.Fatalf("env %v", env)
	}
	if ext := openShellCLIEnvFor(environ, sandboxopenshell.Target{Gateway: "openshell"}); !slices.Contains(ext, "XDG_CONFIG_HOME=/home/dev/.config") {
		t.Fatalf("external keeps the user's registry: %v", ext)
	}
}

// TestOpenShellGatewayProcessDeclaration: every program the managed
// lifecycle starts is declared by the component's catalog row.
func TestOpenShellGatewayProcessDeclaration(t *testing.T) {
	h := newGWHarness(t)
	_ = h.ensure(true)
	_ = h.ensure(false)
	c, ok := components.Get(openShellComponentID)
	if !ok {
		t.Fatal("no catalog row")
	}
	for _, p := range h.fake.plans {
		if p.Component != openShellComponentID {
			t.Fatalf("%s ran under component %q", p.Path, p.Component)
		}
		if !extrun.DeclaresProcess(c.Surface.Processes, p.Path) {
			t.Errorf("%s is not declared in Surface.Processes", filepath.Base(p.Path))
		}
	}
}

// TestOpenShellGatewayReconcileOptIn: with managed mode not wanted and no
// gateway ever recorded, the daemon starts no reconcile loop (the row's
// opt-in rule: nothing runs while it is not chosen).
func TestOpenShellGatewayReconcileOptIn(t *testing.T) {
	dir := t.TempDir()
	openShellGatewayReconcile(dir, false, nil)
	lp := processOpenShellGatewayLoop
	lp.mu.Lock()
	running := lp.cancel != nil
	lp.mu.Unlock()
	if running {
		t.Fatal("a loop started with nothing wanted or recorded")
	}
	if openShellGatewayRecorded(dir) {
		t.Fatal("recorded with no record")
	}
}

// TestOpenShellParseMountinfo reads the mountinfo shapes the state dir
// check meets: WSL2's DrvFs, a FUSE mount, an escaped mount point and a
// local root (lane O2 M4).
func TestOpenShellParseMountinfo(t *testing.T) {
	cases := []struct {
		line           string
		mp, typ, src   string
		ok             bool
		stateTri       sandboxopenshell.Tri
		stateNameMatch string
	}{
		{`84 63 0:59 / /mnt/c rw,noatime - 9p drvfs rw,dirsync,aname=drvfs;path=C:\;uid=1000`, "/mnt/c", "9p", "drvfs", true, sandboxopenshell.TriNo, "DrvFs"},
		{`90 29 0:61 / /home/dev/remote rw,nosuid - fuse.sshfs dev@host:/srv rw,user_id=1000`, "/home/dev/remote", "fuse.sshfs", "dev@host:/srv", true, sandboxopenshell.TriNo, "FUSE"},
		{`91 29 0:62 / /home/dev/my\040dir rw - ext4 /dev/sda2 rw`, "/home/dev/my dir", "ext4", "/dev/sda2", true, sandboxopenshell.TriUnknown, ""},
		{`22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw`, "/", "ext4", "/dev/sda1", true, sandboxopenshell.TriUnknown, ""},
		{`garbage`, "", "", "", false, sandboxopenshell.TriUnknown, ""},
	}
	for _, tc := range cases {
		mp, typ, src, ok := openShellParseMountinfo(tc.line)
		if mp != tc.mp || typ != tc.typ || src != tc.src || ok != tc.ok {
			t.Errorf("%q: %q %q %q %v", tc.line, mp, typ, src, ok)
		}
		if tc.stateNameMatch != "" {
			tri, name := sandboxopenshell.GatewayStateFS(sandboxopenshell.FSFacts{MountType: typ, MountSource: src})
			if tri != tc.stateTri || !strings.Contains(name, tc.stateNameMatch) {
				t.Errorf("%q: %q %q", tc.line, tri, name)
			}
		}
	}
	// The real host: the test's own temp dir is on some filesystem the
	// facts reader can read without error.
	if f := openShellFSFacts(t.TempDir()); f.Magic == 0 {
		t.Fatal("statfs read nothing for a temp dir")
	}
}

// TestOpenShellGatewayRefusedBeforeCreating: a foreign state dir or an
// unusable runtime dir refuses before anything is created (no install id,
// no gateway dir, no keystore opened, no program run; audit finding
// O2-A11).
func TestOpenShellGatewayRefusedBeforeCreating(t *testing.T) {
	for _, mod := range []func(h *gwHarness){
		func(h *gwHarness) {
			h.exec.host.StateFS = func(string) (sandboxopenshell.Tri, string) { return sandboxopenshell.TriNo, "nfs4" }
		},
		func(h *gwHarness) {
			h.exec.host.RuntimeFS = func(string) (sandboxopenshell.Tri, string) { return sandboxopenshell.TriNo, "ext4" }
		},
	} {
		h := newGWHarness(t)
		h.exec.store = openShellCustody{}
		opened := false
		h.exec.openKeystore = func(string, string) (keystore.Store, string) { opened = true; return &keystore.MemStore{}, "" }
		mod(h)
		if d := h.ensure(true).decision; d.Action != sandboxopenshell.GatewayRefuse {
			t.Fatalf("decision %+v", d)
		}
		if opened || len(h.fake.plans) != 0 || openShellReadInstallID(h.stateDir) != "" || openShellGatewayRecorded(h.stateDir) {
			t.Fatalf("created or ran something before refusing: opened %v, %d programs", opened, len(h.fake.plans))
		}
	}
}

// TestOpenShellGatewayStillStartingKeepsTheUnit: a launched gateway that
// has not answered yet while its unit runs (a first start pulling its
// images over a slow link) is still starting: the unit is never stopped,
// the RAM dir stays, the probe says it is starting, and a later pass
// finishes the start once it answers (audit finding O2-V1).
func TestOpenShellGatewayStillStartingKeepsTheUnit(t *testing.T) {
	h := newGWHarness(t)
	openShellGatewayStartWait, openShellGatewayFinishWait = 20*time.Millisecond, 5*time.Millisecond
	h.fake.healthy = false
	m := h.ensure(true)
	if m.decision.Verdict != sandboxopenshell.VerdictGatewayStarting || m.decision.Rule != "G14b" || !strings.Contains(m.decision.Reason, "s ago") {
		t.Fatalf("decision %+v", m.decision)
	}
	for _, a := range h.fake.progs("systemctl") {
		if slices.Contains(a, "stop") {
			t.Fatal("a start still under way was stopped")
		}
	}
	if _, err := os.Stat(m.layout.TLSDir); err != nil {
		t.Fatal("the RAM dir of a start under way was removed")
	}
	if m.record == nil || !m.record.Starting || m.record.StartedAt == 0 {
		t.Fatalf("no provisional record: %+v", m.record)
	}
	h.fake.mu.Lock()
	h.fake.healthy = true
	h.fake.mu.Unlock()
	done := h.ensure(true)
	if !done.decision.Ready() || done.record == nil || done.record.Starting {
		t.Fatalf("the start did not finish: %+v %+v", done.decision, done.record)
	}
	if n := len(h.fake.progs("systemd-run")); n != 1 {
		t.Fatalf("relaunched %d times", n)
	}
}

// TestOpenShellGatewayStartOverBudget: a start still not answering after
// its budget is stopped and cleaned up, with the failure said plainly
// (row G14c).
func TestOpenShellGatewayStartOverBudget(t *testing.T) {
	h := newGWHarness(t)
	openShellGatewayStartWait, openShellGatewayFinishWait = 10*time.Millisecond, 5*time.Millisecond
	h.fake.healthy = false
	m := h.ensure(true)
	rec := *m.record
	rec.StartedAt -= int64(openShellFirstStartBudget/time.Second) + 10
	if err := openShellWriteRecord(m.layout, &rec); err != nil {
		t.Fatal(err)
	}
	over := h.ensure(true)
	if over.decision.Rule != "G14c" || over.decision.Verdict != sandboxopenshell.VerdictGatewayStartFailed {
		t.Fatalf("decision %+v", over.decision)
	}
	h.fake.mu.Lock()
	unit := h.fake.unit
	h.fake.mu.Unlock()
	if unit != "inactive" {
		t.Fatalf("the unit is %s", unit)
	}
	if _, err := os.Stat(m.layout.RuntimeDir); !os.IsNotExist(err) {
		t.Fatal("the RAM dir is still there after an overrun start")
	}
}

// TestOpenShellGatewayUnitDiesDuringStart: a unit that stops before the
// gateway answers is a real failure: it is stopped and cleaned up, the
// gateway stays recorded for the not-wanted path (audit finding O2-A3),
// and a unit left failed is refused, not restarted every pass (row G14a,
// audit finding O2-V6).
func TestOpenShellGatewayUnitDiesDuringStart(t *testing.T) {
	h := newGWHarness(t)
	h.fake.dies, h.fake.keepFailed = true, true
	m := h.ensure(true)
	if m.decision.Verdict != sandboxopenshell.VerdictGatewayStartFailed || !strings.Contains(m.decision.Reason, "journalctl") {
		t.Fatalf("decision %+v", m.decision)
	}
	if _, err := os.Stat(m.layout.RuntimeDir); !os.IsNotExist(err) {
		t.Fatal("the RAM dir (PKI copy and env file) is still there")
	}
	if !openShellGatewayRecorded(h.stateDir) {
		t.Fatal("a failed start must still count as recorded for the not-wanted path")
	}
	h.fake.reset()
	again := h.ensure(true)
	if again.decision.Rule != "G14a" || again.decision.Verdict != sandboxopenshell.VerdictGatewayStartFailed || !strings.Contains(again.decision.Reason, "reset-failed") {
		t.Fatalf("a failed unit: %+v", again.decision)
	}
	if len(h.fake.progs("systemd-run")) != 0 {
		t.Fatal("a failed unit was started again")
	}
}

// TestOpenShellGatewayRAMDirRemovedWhenNotRunning: a RAM dir left behind
// by a crash (the PKI copy and the KEK env file) goes on the next pass
// that finds no gateway running, wanted or not (audit finding O2-V4).
func TestOpenShellGatewayRAMDirRemovedWhenNotRunning(t *testing.T) {
	for _, wanted := range []bool{false, true} {
		h := newGWHarness(t)
		m := h.ensure(true)
		h.fake.mu.Lock()
		h.fake.unit, h.fake.listen = "inactive", map[int]bool{} // a crash
		h.fake.mu.Unlock()
		stale := filepath.Join(m.layout.RuntimeDir, "stale-marker")
		if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = h.ensure(wanted)
		if _, err := os.Stat(stale); !os.IsNotExist(err) {
			t.Fatalf("wanted %v: the crashed gateway's RAM dir was kept", wanted)
		}
	}
}

// TestOpenShellGatewayCustodyPinRules: the pin is written only after a
// save that happened, a key set found with no pin is pinned where it is,
// and a locked keychain refuses (and is probed again) rather than moving
// to the file store (audit finding O2-V3).
func TestOpenShellGatewayCustodyPinRules(t *testing.T) {
	t.Run("no pin before a save that never happened", func(t *testing.T) {
		h := newGWHarness(t)
		h.exec.store = openShellCustody{s: keystore.FailClosed()}
		m := h.ensure(true)
		if m.decision.Ready() {
			t.Fatal("a failing store started")
		}
		if _, err := os.Stat(m.layout.CustodyPath); !os.IsNotExist(err) {
			t.Fatal("a pin was written for a save that never happened")
		}
	})
	t.Run("a set found with no pin is pinned where it is", func(t *testing.T) {
		h := newGWHarness(t)
		m := h.ensure(true)
		if err := os.Remove(m.layout.CustodyPath); err != nil {
			t.Fatal(err)
		}
		_ = h.ensure(true)
		if b, err := os.ReadFile(m.layout.CustodyPath); err != nil || strings.TrimSpace(string(b)) != sandboxopenshell.CustodyKeychain {
			t.Fatalf("not re-pinned: %q %v", b, err)
		}
		// A later file-only session is now refused, not handed a new PKI.
		h.fake.mu.Lock()
		h.fake.unit, h.fake.listen = "inactive", map[int]bool{}
		h.fake.mu.Unlock()
		h.exec.store, h.exec.backend = openShellCustody{s: &keystore.MemStore{}}, "file"
		h.exec.openKeystore = func(string, string) (keystore.Store, string) {
			return &keystore.MemStore{}, keystore.ReasonKeychainUnavailable
		}
		if d := h.ensure(true).decision; d.Verdict != sandboxopenshell.VerdictGatewayCustodyChanged || h.fake.genCerts != 1 {
			t.Fatalf("decision %+v, generations %d", d, h.fake.genCerts)
		}
	})
	t.Run("a locked keychain refuses and is probed again", func(t *testing.T) {
		h := newGWHarness(t)
		h.exec.store = openShellCustody{}
		forgot := 0
		h.exec.forgetKeystore = func(string) { forgot++ }
		h.exec.openKeystore = func(string, string) (keystore.Store, string) {
			return &keystore.MemStore{}, keystore.ReasonProbeTimeout
		}
		d := h.ensure(true).decision
		if d.Verdict != sandboxopenshell.VerdictGatewayCustodyUnavailable || !strings.Contains(d.Reason, "did not answer") {
			t.Fatalf("decision %+v", d)
		}
		if forgot == 0 || h.fake.genCerts != 0 || len(h.fake.progs("systemd-run")) != 0 {
			t.Fatalf("forgot %d, generations %d", forgot, h.fake.genCerts)
		}
	})
	t.Run("an install pinned to owner_file never waits on the keychain", func(t *testing.T) {
		// Lane OC, audit finding O2-W1 (b): the keys are in the file
		// store; a keychain that would time out is never asked.
		h := newGWHarness(t)
		h.exec.backend = "file"
		m := h.ensure(true)
		if b, err := os.ReadFile(m.layout.CustodyPath); err != nil || strings.TrimSpace(string(b)) != sandboxopenshell.CustodyOwnerFile {
			t.Fatalf("pin %q %v", b, err)
		}
		h.fake.mu.Lock()
		h.fake.unit, h.fake.listen = "inactive", map[int]bool{}
		h.fake.mu.Unlock()
		h.exec.store, h.exec.backend, h.exec.reason = openShellCustody{}, "", ""
		var asked []string
		h.exec.openKeystore = func(_, pinned string) (keystore.Store, string) {
			asked = append(asked, pinned)
			if pinned == sandboxopenshell.CustodyOwnerFile {
				return fileBackedMem{h.ks}, openShellReasonPinnedOwnerFile
			}
			return &keystore.MemStore{}, keystore.ReasonProbeTimeout
		}
		if d := h.ensure(true).decision; !d.Ready() || h.fake.genCerts != 1 {
			t.Fatalf("decision %+v, generations %d", d, h.fake.genCerts)
		}
		if len(asked) != 1 || asked[0] != sandboxopenshell.CustodyOwnerFile {
			t.Fatalf("opened with pins %q", asked)
		}
	})
}

// fileBackedMem is a memory keystore that reports the file backend.
type fileBackedMem struct{ *keystore.MemStore }

func (fileBackedMem) Backend() string { return "file" }

// TestOpenShellGatewayNotWantedWithAnAbandonedRun: an unheld run older
// than the grace still pins the gateway: not wanted, it waits instead of
// stopping (audit finding O2-A4).
func TestOpenShellGatewayNotWantedWithAnAbandonedRun(t *testing.T) {
	h := newGWHarness(t)
	m := h.ensure(true)
	writeLiveRun(t, h.stateDir, m)
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(filepath.Join(openShellRunDir(h.stateDir, "run-0000-live"), "plan.json"), old, old); err != nil {
		t.Fatal(err)
	}
	h.fake.reset()
	if d := h.ensure(false).decision; d.Rule != "G2" || d.Action != sandboxopenshell.GatewayWait {
		t.Fatalf("with an abandoned run recorded: %+v", d)
	}
	for _, a := range h.fake.progs("systemctl") {
		if slices.Contains(a, "stop") {
			t.Fatal("stopped with an abandoned run recorded")
		}
	}
}

// TestOpenShellGatewayCustodyChange: keys saved in the keychain are never
// regenerated when a later session's keystore offers the owner file store
// (audit finding O2-A5).
func TestOpenShellGatewayCustodyChange(t *testing.T) {
	h := newGWHarness(t)
	_ = h.ensure(true)
	h.fake.mu.Lock()
	h.fake.unit, h.fake.listen = "inactive", map[int]bool{}
	h.fake.mu.Unlock()
	h.exec.store, h.exec.backend = openShellCustody{s: &keystore.MemStore{}}, "file"
	m := h.ensure(true)
	if m.decision.Verdict != sandboxopenshell.VerdictGatewayCustodyChanged || h.fake.genCerts != 1 {
		t.Fatalf("decision %+v, generations %d", m.decision, h.fake.genCerts)
	}
	if !strings.Contains(m.decision.Reason, openShellGatewayKeystoreService) {
		t.Fatalf("the reason must name the service to clear: %q", m.decision.Reason)
	}
}

// TestOpenShellManagedHintAndNote: the probe hint and the run's posture
// note say which custody is in force, and that owner_file is unencrypted
// (audit findings O2-A1, O2-A13).
func TestOpenShellManagedHintAndNote(t *testing.T) {
	keys := "/home/dev/.observer/sandbox-openshell/gateway/keys"
	own := openShellManagedHint(openShellManaged{custody: sandboxopenshell.CustodyOwnerFile, layout: sandboxopenshell.GatewayLayout{KeysDir: keys}})
	for _, want := range []string{"custody=owner_file", "unencrypted", "CA key", keys, "no stronger than your own OpenShell install"} {
		if !strings.Contains(own, want) {
			t.Fatalf("owner_file hint lacks %q: %s", want, own)
		}
	}
	if kc := openShellManagedHint(openShellManaged{custody: sandboxopenshell.CustodyKeychain}); !strings.Contains(kc, "custody=keychain") || strings.Contains(kc, "unencrypted") {
		t.Fatalf("keychain hint %q", kc)
	}
	p := openShellProbe{managedCustody: sandboxopenshell.CustodyOwnerFile}
	p.facts.GatewayMode = sandboxopenshell.GatewayManaged
	if n := openShellModeNote(p); n != "gateway_mode=managed custody=owner_file telemetry=off" {
		t.Fatalf("managed note %q", n)
	}
	p.facts.GatewayMode = sandboxopenshell.GatewayExternal
	if n := openShellModeNote(p); n != "gateway_mode=external telemetry=unknown" {
		t.Fatalf("external note %q", n)
	}
}

// TestOpenShellStateDirMask: a configured state dir is a mask a bound
// tree may not cover (audit finding O2-A11); the default one adds none.
func TestOpenShellStateDirMask(t *testing.T) {
	var cfg config.TerminalSandboxConfig
	for _, m := range openShellMasks(cfg, nil) {
		if strings.Contains(m.key, "state_dir") {
			t.Fatal("the default state dir added a mask")
		}
	}
	cfg.OpenShell.StateDir = "/srv/osh-state"
	found := false
	for _, m := range openShellMasks(cfg, nil) {
		found = found || (strings.Contains(m.key, "state_dir") && m.path == "/srv/osh-state")
	}
	if !found {
		t.Fatal("a configured state dir is not a mask")
	}
}

// TestOpenShellDockerAccessRows is one case per row of the docker access
// table (audit findings O2-A8, O2-V2, O2-W3 and O2-W4).
func TestOpenShellDockerAccessRows(t *testing.T) {
	const rootless = "unix:///run/user/1000/docker.sock"
	base := openShellDockerFacts{SockFound: true, SockUID: 0, SockGID: 998, SockMode: 0o660, UID: 1000, ManagerGroups: []int{1000, 998}}
	cases := []struct {
		name string
		mod  func(f *openShellDockerFacts)
		tri  sandboxopenshell.Tri
		why  string
	}{
		{"D1 DOCKER_CONTEXT", func(f *openShellDockerFacts) { f.EnvContext = "rootless" }, sandboxopenshell.TriNo, "DOCKER_CONTEXT"},
		{"D1 DOCKER_CONTEXT=default passes", func(f *openShellDockerFacts) { f.EnvContext = "default" }, sandboxopenshell.TriYes, ""},
		{"D2 docker context use", func(f *openShellDockerFacts) { f.ConfigContext = "desktop-linux" }, sandboxopenshell.TriNo, "docker context use"},
		{"D2 the default context passes", func(f *openShellDockerFacts) { f.ConfigContext = "default" }, sandboxopenshell.TriYes, ""},
		{"D3 a tcp DOCKER_HOST", func(f *openShellDockerFacts) { f.DockerHost = "tcp://192.0.2.10:2375" }, sandboxopenshell.TriNo, `"tcp" engine`},
		{"D3 an ssh DOCKER_HOST", func(f *openShellDockerFacts) { f.DockerHost = "ssh://dev@example.com" }, sandboxopenshell.TriNo, "not a local unix socket"},
		{"D3 a relative unix path", func(f *openShellDockerFacts) { f.DockerHost = "unix://run/docker.sock" }, sandboxopenshell.TriNo, ""},
		{"a local unix DOCKER_HOST passes", func(f *openShellDockerFacts) { f.DockerHost, f.UnitDockerHost = rootless, rootless }, sandboxopenshell.TriYes, ""},
		{"D4 socket not read", func(f *openShellDockerFacts) { f.SockFound = false }, sandboxopenshell.TriUnknown, ""},
		{"D5 the user owns the socket (rootless)", func(f *openShellDockerFacts) { f.SockUID, f.SockMode, f.ManagerGroups = 1000, 0o600, nil }, sandboxopenshell.TriYes, ""},
		{"D6 a 0666 socket", func(f *openShellDockerFacts) { f.SockMode, f.ManagerGroups = 0o666, []int{1000} }, sandboxopenshell.TriYes, ""},
		{"D7 no user manager found", func(f *openShellDockerFacts) { f.ManagerGroups = nil }, sandboxopenshell.TriUnknown, ""},
		{"D8 the manager holds the group", func(*openShellDockerFacts) {}, sandboxopenshell.TriYes, ""},
		{"D9 the manager lacks the group", func(f *openShellDockerFacts) { f.ManagerGroups = []int{1000} }, sandboxopenshell.TriNo, "cannot open"},
		{"D9 the group may not write", func(f *openShellDockerFacts) { f.SockMode = 0o640 }, sandboxopenshell.TriNo, ""},
		// Lane OC, audit finding O2-W3: DOCKER_HOST wins over a context (the
		// docker CLI's own rule), a value with no scheme is never echoed,
		// and an ACL entry can admit the user manager.
		{"D1 DOCKER_CONTEXT with a local DOCKER_HOST passes", func(f *openShellDockerFacts) {
			f.EnvContext, f.DockerHost, f.UnitDockerHost = "rootless", rootless, rootless
		}, sandboxopenshell.TriYes, ""},
		{"D2 docker context use with a local DOCKER_HOST passes", func(f *openShellDockerFacts) {
			f.ConfigContext, f.DockerHost, f.UnitDockerHost = "desktop-linux", rootless, rootless
		}, sandboxopenshell.TriYes, ""},
		{"D3 an address with no scheme is not echoed", func(f *openShellDockerFacts) { f.DockerHost = "10.0.0.5:2375" }, sandboxopenshell.TriNo, "an address with no scheme"},
		{"D3 an odd scheme is not echoed", func(f *openShellDockerFacts) { f.DockerHost = "10.0.0.5://x" }, sandboxopenshell.TriNo, "unrecognised scheme"},
		// Lane OC, audit finding O2-W4: the launch's engine must be the
		// unit's (from its one owner).
		{"D3a the launch drives another engine than the unit", func(f *openShellDockerFacts) { f.DockerHost = rootless }, sandboxopenshell.TriNo, "another engine socket"},
		{"D3a the default socket spelled out is the same engine", func(f *openShellDockerFacts) { f.DockerHost = "unix:///var/run/docker.sock" }, sandboxopenshell.TriYes, ""},
		{"D3a the unit's engine without DOCKER_HOST here", func(f *openShellDockerFacts) { f.UnitDockerHost = rootless }, sandboxopenshell.TriNo, "another engine socket"},
		// Lane OC fix round 1, audit finding OC-A6: two paths of one socket
		// (a /var/run symlink) are the same engine; the refusal names the
		// owner that chose the unit's engine.
		{"D3a two paths of the same socket file pass", func(f *openShellDockerFacts) {
			f.DockerHost, f.SameEngineFile = "unix:///run/docker.sock", true
		}, sandboxopenshell.TriYes, ""},
		{"D3a the daemon's engine is named", func(f *openShellDockerFacts) {
			f.DockerHost, f.UnitOwner = rootless, openShellEngineOwnerDaemon
		}, sandboxopenshell.TriNo, "restart the daemon with this one"},
		{"D3a the running gateway's engine is named", func(f *openShellDockerFacts) {
			f.DockerHost, f.UnitOwner = rootless, openShellEngineOwnerGateway
		}, sandboxopenshell.TriNo, "no daemon runs for this state dir"},
		{"D8 is not judged from the mode when an ACL is set", func(f *openShellDockerFacts) {
			f.SockACL = []openShellACLEntry{{Tag: openShellACLGroupObj, Perm: 6}, {Tag: openShellACLMask, Perm: 4}}
		}, sandboxopenshell.TriNo, "no ACL entry"},
		{"D8a a named user entry admits", func(f *openShellDockerFacts) {
			f.ManagerGroups = []int{1000}
			f.SockACL = []openShellACLEntry{{Tag: openShellACLUser, Perm: 6, ID: 1000}, {Tag: openShellACLGroupObj, Perm: 6}, {Tag: openShellACLMask, Perm: 6}}
		}, sandboxopenshell.TriYes, ""},
		{"D8a a named group entry admits", func(f *openShellDockerFacts) {
			f.ManagerGroups = []int{1000, 1500}
			f.SockACL = []openShellACLEntry{{Tag: openShellACLGroupObj, Perm: 6}, {Tag: openShellACLGroup, Perm: 6, ID: 1500}, {Tag: openShellACLMask, Perm: 7}}
		}, sandboxopenshell.TriYes, ""},
		{"D8a a named user entry that denies decides alone", func(f *openShellDockerFacts) {
			f.SockACL = []openShellACLEntry{{Tag: openShellACLUser, Perm: 4, ID: 1000}, {Tag: openShellACLGroupObj, Perm: 6}, {Tag: openShellACLMask, Perm: 6}}
		}, sandboxopenshell.TriNo, ""},
		{"D8b an ACL that could not be read", func(f *openShellDockerFacts) { f.SockACLUnread, f.ManagerGroups = true, []int{1000} }, sandboxopenshell.TriUnknown, ""},
	}
	ids := map[string]bool{}
	for _, tc := range cases {
		id, _, _ := strings.Cut(tc.name, " ")
		ids[id] = true
		f := base
		tc.mod(&f)
		tri, why := openShellDockerAccessFrom(f)
		if tri != tc.tri || !strings.Contains(why, tc.why) {
			t.Errorf("%s: %q %q", tc.name, tri, why)
		}
		if strings.Contains(why, "192.0.2.10") || strings.Contains(why, "example.com") || strings.Contains(why, "10.0.0.5") || strings.Contains(why, "/run/user/") {
			t.Errorf("%s: the reason names a host address: %q", tc.name, why)
		}
	}
	for _, r := range openShellDockerRows {
		if id, _, _ := strings.Cut(r.id, " "); !ids[id] {
			t.Errorf("row %s has no case", r.id)
		}
	}
	if h, ok := openShellDockerHostPath("unix:///var/run/docker.sock"); !ok || h != openShellDockerSocket {
		t.Fatal("the default socket path")
	}
}

// TestOpenShellGatewayOCSFExport (lane OC item 2): Observer writes its own
// managed gateway's OCSF export pointed at the daemon's loopback receiver,
// and the D3 reader finds it present; rendered without it, the config has
// no export table and another digest, so an idle gateway restarts with the
// change (G18) and a gateway a run holds keeps running (G23).
func TestOpenShellGatewayOCSFExport(t *testing.T) {
	h := newGWHarness(t)
	m := h.ensure(true)
	if !m.decision.Ready() {
		t.Fatalf("decision %+v", m.decision)
	}
	with, err := os.ReadFile(m.layout.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(with), "[openshell.gateway.otlp.ocsf]\nenabled = true\nendpoint = \""+sandboxopenshell.OCSFReceiverEndpoint()+"\"") {
		t.Fatalf("no export in the managed config:\n%s", with)
	}
	if !sandboxopenshell.LoopbackOTLP(openShellGatewayOCSFEndpoint()) {
		t.Fatalf("endpoint %q is not loopback", openShellGatewayOCSFEndpoint())
	}
	if st, why := sandboxopenshell.ClassifyOCSFExport(openShellOCSFExport(m.layout.ConfigPath), sandboxopenshell.OCSFReceiverEndpoint()); st != sandboxopenshell.OCSFExportPresent {
		t.Fatalf("the D3 reader says %s: %s", st, why)
	}
	digestWith := m.record.ConfigDigest

	old := openShellGatewayOCSFEndpoint
	t.Cleanup(func() { openShellGatewayOCSFEndpoint = old })
	openShellGatewayOCSFEndpoint = func() string { return "" }
	without, err := openShellRenderGatewayConfig(m.id, m.id.Name, m.record.Version)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(without, "otlp") {
		t.Fatalf("an export without an endpoint:\n%s", without)
	}
	if sandboxopenshell.GatewayConfigDigest(without, "") == digestWith {
		t.Fatal("the export is not part of the config digest")
	}
	// A run holds the gateway: the config change waits (G23, no stop).
	writeLiveRun(t, h.stateDir, m)
	h.fake.reset()
	if d := h.ensure(true).decision; !d.Ready() || d.Rule != "G23" || len(h.fake.progs("systemd-run")) != 0 {
		t.Fatalf("with a live run: %+v", d)
	}
	// Idle: restarted with the new config (G18), now without the export.
	_ = os.RemoveAll(openShellRunDir(h.stateDir, "run-0000-live"))
	h.fake.reset()
	u := h.ensure(true)
	if !u.decision.Ready() || len(h.fake.progs("systemd-run")) != 1 || u.record.ConfigDigest == digestWith {
		t.Fatalf("idle restart: %+v %+v", u.decision, u.record)
	}
	if b, _ := os.ReadFile(u.layout.ConfigPath); strings.Contains(string(b), "otlp") {
		t.Fatalf("restarted config still exports:\n%s", b)
	}
}

// TestOpenShellGatewayOwnStopResetsFailed (lane OC, audit finding O2-W2
// (b)): a stop Observer makes that leaves the unit failed is reset, so the
// next wanted pass starts the gateway instead of refusing at G14a.
func TestOpenShellGatewayOwnStopResetsFailed(t *testing.T) {
	h := newGWHarness(t)
	if m := h.ensure(true); !m.decision.Ready() {
		t.Fatalf("first start %+v", m.decision)
	}
	h.fake.stopLeavesFailed = true
	h.fake.reset()
	if d := h.ensure(false).decision; d.Rule != "G3" {
		t.Fatalf("not wanted: %+v", d)
	}
	stops, resets := -1, -1
	for i, a := range h.fake.progs("systemctl") {
		switch {
		case slices.Contains(a, "stop") && stops < 0:
			stops = i
		case slices.Contains(a, "reset-failed") && resets < 0:
			resets = i
		}
	}
	if stops < 0 || resets < stops {
		t.Fatalf("no reset-failed after the stop: %v", h.fake.progs("systemctl"))
	}
	h.fake.stopLeavesFailed = false
	if m := h.ensure(true); !m.decision.Ready() {
		t.Fatalf("after Observer's own stop: %+v", m.decision)
	}
}

// TestOpenShellGatewayFailedUnitRetries (lane OC, audit finding O2-W2
// (a)): a unit that failed on its own is started again after a wait, a
// bounded number of times with a doubling wait, and only then does G14a
// hold for the user; a reset by the user starts a fresh episode.
func TestOpenShellGatewayFailedUnitRetries(t *testing.T) {
	h := newGWHarness(t)
	now := time.Now()
	old := openShellGatewayNow
	t.Cleanup(func() { openShellGatewayNow = old })
	openShellGatewayNow = func() time.Time { return now }
	m := h.ensure(true)
	if !m.decision.Ready() {
		t.Fatalf("first start %+v", m.decision)
	}
	runs := func() int { return len(h.fake.progs("systemd-run")) }
	crash := func() {
		h.fake.mu.Lock()
		h.fake.unit, h.fake.listen = "failed", map[int]bool{}
		h.fake.mu.Unlock()
	}
	// A transient failure: retried after a minute, and it comes back.
	crash()
	if d := h.ensure(true).decision; d.Rule != "G14a" || !strings.Contains(d.Reason, "automatic retry 1 of 3") || runs() != 1 {
		t.Fatalf("seen failed: %+v (%d starts)", d, runs())
	}
	now = now.Add(61 * time.Second)
	if d := h.ensure(true).decision; !d.Ready() || runs() != 2 {
		t.Fatalf("retry: %+v (%d starts)", d, runs())
	}
	// Audit finding OC-A7: the episode ends only once the unit stayed
	// active for openShellFailedHealthy, not at its first active pass.
	if st, ok := openShellReadFailedRetries(m.layout); !ok || st.Retries != 1 || st.ActiveSince == 0 {
		t.Fatalf("the episode ended at the first active pass: %+v %v", st, ok)
	}
	now = now.Add(openShellFailedHealthy)
	if d := h.ensure(true).decision; !d.Ready() || runs() != 2 {
		t.Fatalf("healthy: %+v (%d starts)", d, runs())
	}
	if _, err := os.Stat(openShellFailedRetriesPath(m.layout)); !os.IsNotExist(err) {
		t.Fatalf("the episode did not end after the unit stayed healthy: %v", err)
	}
	// A unit that keeps failing: three retries with 1, 2 and 4 minute
	// waits, then G14a holds.
	h.fake.dies, h.fake.keepFailed = true, true
	crash()
	if d := h.ensure(true).decision; d.Rule != "G14a" {
		t.Fatalf("crash loop seen: %+v", d)
	}
	for i, wait := range []time.Duration{60 * time.Second, 120 * time.Second, 240 * time.Second} {
		now = now.Add(wait - time.Second)
		if d := h.ensure(true).decision; d.Rule != "G14a" || runs() != 2+i {
			t.Fatalf("retry %d early: %+v (%d starts)", i+1, d, runs())
		}
		now = now.Add(time.Second)
		if d := h.ensure(true).decision; d.Verdict != sandboxopenshell.VerdictGatewayStartFailed || runs() != 3+i {
			t.Fatalf("retry %d: %+v (%d starts)", i+1, d, runs())
		}
	}
	now = now.Add(time.Hour)
	if d := h.ensure(true).decision; d.Rule != "G14a" || !strings.Contains(d.Reason, "after 3 automatic retries") || runs() != 5 {
		t.Fatalf("retries spent: %+v (%d starts)", d, runs())
	}
	// The user fixed it and ran reset-failed: started again.
	h.fake.mu.Lock()
	h.fake.unit, h.fake.dies, h.fake.keepFailed = "inactive", false, false
	h.fake.mu.Unlock()
	if d := h.ensure(true).decision; !d.Ready() || runs() != 6 {
		t.Fatalf("after reset-failed: %+v (%d starts)", d, runs())
	}
}

// TestOpenShellGatewayCrashLoopAfterAnswerIsBounded is audit finding
// OC-A7: a gateway that answers after a retry and then crash-loops (seen
// activating while systemd restarts it, then failed again) does not get
// fresh retries: the episode's count goes on, and after the third retry
// G14a holds.
func TestOpenShellGatewayCrashLoopAfterAnswerIsBounded(t *testing.T) {
	h := newGWHarness(t)
	now := time.Now()
	old := openShellGatewayNow
	t.Cleanup(func() { openShellGatewayNow = old })
	openShellGatewayNow = func() time.Time { return now }
	if m := h.ensure(true); !m.decision.Ready() {
		t.Fatalf("first start %+v", m.decision)
	}
	runs := func() int { return len(h.fake.progs("systemd-run")) }
	set := func(state string) {
		h.fake.mu.Lock()
		h.fake.unit, h.fake.listen = state, map[int]bool{}
		h.fake.mu.Unlock()
	}
	for i, wait := range []time.Duration{60 * time.Second, 120 * time.Second, 240 * time.Second} {
		set("failed")
		if d := h.ensure(true).decision; d.Rule != "G14a" || !strings.Contains(d.Reason, "automatic retry "+strconv.Itoa(i+1)+" of 3") {
			t.Fatalf("failure %d: %+v", i+1, d)
		}
		now = now.Add(wait)
		if d := h.ensure(true).decision; !d.Ready() || runs() != 2+i {
			t.Fatalf("retry %d: %+v (%d starts)", i+1, d, runs())
		}
		// It answered, then crashed: systemd restarts it.
		now = now.Add(time.Minute)
		set("activating")
		h.ensure(true)
	}
	set("failed")
	now = now.Add(time.Hour)
	if d := h.ensure(true).decision; d.Rule != "G14a" || !strings.Contains(d.Reason, "after 3 automatic retries") || runs() != 4 {
		t.Fatalf("a crash loop after answering got more retries: %+v (%d starts)", d, runs())
	}
}

// TestOpenShellGatewayDockerHostOwner (lane OC, audit finding O2-W4): the
// unit's DOCKER_HOST and the config digest come from one owner, never the
// probing process: a CLI launch whose environment differs neither
// restarts the daemon's idle gateway nor changes what it is given; the
// daemon's own value does restart it (through the digest).
func TestOpenShellGatewayDockerHostOwner(t *testing.T) {
	const rootless = "unix:///run/user/1000/docker.sock"
	h := newGWHarness(t)
	caller, daemon := rootless, false
	var accessArg []string
	h.exec.host.DockerHost = func() string { return caller }
	var owners []string
	h.exec.host.DockerAccess = func(unit openShellUnitEngine) (sandboxopenshell.Tri, string) {
		accessArg, owners = append(accessArg, unit.DockerHost), append(owners, unit.Owner)
		return sandboxopenshell.TriYes, ""
	}
	h.exec.daemon = func() bool { return daemon }
	setenv := func() []string {
		var out []string
		for _, a := range h.fake.progs("systemd-run") {
			for _, s := range a {
				if strings.HasPrefix(s, "--setenv=DOCKER_HOST=") {
					out = append(out, s)
				}
			}
		}
		return out
	}
	// The first start (nothing recorded) takes the starter's value and
	// records it.
	m := h.ensure(true)
	if !m.decision.Ready() || m.record.DockerHost != rootless || len(setenv()) != 1 {
		t.Fatalf("first start: %+v %+v %v", m.decision, m.record, setenv())
	}
	// A CLI launch without DOCKER_HOST: the recorded value, no restart.
	caller = ""
	h.fake.reset()
	accessArg = nil
	if m2 := h.ensure(true); !m2.decision.Ready() || len(h.fake.progs("systemd-run")) != 0 {
		t.Fatalf("a CLI with another DOCKER_HOST restarted: %+v", m2.decision)
	}
	if len(accessArg) == 0 || accessArg[0] != rootless {
		t.Fatalf("docker access judged %q, want the unit's %q", accessArg, rootless)
	}
	// The daemon (the owner) without DOCKER_HOST: restarted with its own.
	daemon = true
	h.fake.reset()
	m3 := h.ensure(true)
	if !m3.decision.Ready() || len(h.fake.progs("systemd-run")) != 1 || m3.record.DockerHost != "" || len(setenv()) != 0 {
		t.Fatalf("the daemon's value: %+v %+v", m3.decision, m3.record)
	}
	// A CLI launch with DOCKER_HOST again: no restart back.
	daemon, caller = false, rootless
	h.fake.reset()
	if m4 := h.ensure(true); !m4.decision.Ready() || len(h.fake.progs("systemd-run")) != 0 {
		t.Fatalf("the CLI restarted it back: %+v", m4.decision)
	}
	if owners[len(owners)-1] != openShellEngineOwnerGateway {
		t.Fatalf("a CLI launch beside a running gateway: owner %q", owners[len(owners)-1])
	}
	// Audit finding OC-A6: with no daemon, once the gateway stopped and no
	// run is recorded on it, the recorded value is not kept for good: the
	// next CLI launch's engine is taken and recorded.
	h.fake.mu.Lock()
	h.fake.unit = "inactive"
	h.fake.mu.Unlock()
	caller = ""
	h.fake.reset()
	owners = nil
	m5 := h.ensure(true)
	if !m5.decision.Ready() || len(h.fake.progs("systemd-run")) != 1 || m5.record.DockerHost != "" || len(setenv()) != 0 || len(owners) == 0 || owners[0] != openShellEngineOwnerLaunch {
		t.Fatalf("a stopped gateway with no run: %+v %+v owners %v", m5.decision, m5.record, owners)
	}
}

// openShellTestACL encodes a POSIX access ACL value.
func openShellTestACL(es ...openShellACLEntry) []byte {
	b := []byte{2, 0, 0, 0}
	for _, e := range es {
		b = append(b, byte(e.Tag), byte(e.Tag>>8), byte(e.Perm), byte(e.Perm>>8), byte(e.ID), byte(e.ID>>8), byte(e.ID>>16), byte(e.ID>>24))
	}
	return b
}

// TestOpenShellSameEngineFile (audit finding OC-A6): a symlinked path and
// its target are one socket file; two files are not; a path that cannot be
// stat'ed is not shown the same (the paths then compare as strings).
func TestOpenShellSameEngineFile(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.sock"), filepath.Join(dir, "b.sock")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "run")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if !openShellSameEngineFile(a, filepath.Join(link, "a.sock")) {
		t.Fatal("a path through a symlinked dir is not its target")
	}
	if openShellSameEngineFile(a, b) || openShellSameEngineFile(a, filepath.Join(dir, "none.sock")) {
		t.Fatal("different or missing files shown the same")
	}
}

// TestOpenShellParseACL: the xattr value decodes; a bad length or version
// does not; a plain file has no ACL (read without privilege).
func TestOpenShellParseACL(t *testing.T) {
	want := []openShellACLEntry{{Tag: 0x01, Perm: 6, ID: 0xFFFFFFFF}, {Tag: openShellACLUser, Perm: 6, ID: 1000}, {Tag: openShellACLMask, Perm: 6, ID: 0xFFFFFFFF}}
	got, err := openShellParseACL(openShellTestACL(want...))
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := openShellParseACL([]byte{2, 0, 0, 0, 1}); err == nil {
		t.Fatal("a bad length decoded")
	}
	if _, err := openShellParseACL([]byte{1, 0, 0, 0}); err == nil {
		t.Fatal("a bad version decoded")
	}
	p := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if acl, unread := openShellSocketACL(p); acl != nil || unread {
		t.Fatalf("a plain file: %+v %v", acl, unread)
	}
}

// TestOpenShellGatewayNamespaceMoveWaitsForRecordedRuns (finding
// OC2-A5): a gateway started before it had its own sandbox namespace
// (its boxes in the driver default) is never restarted onto the new
// namespace while a run is recorded on it, even an abandoned one, since
// the restarted gateway's list and reconcile would no longer see that
// box; once no run is recorded it moves, and its record keeps the label.
func TestOpenShellGatewayNamespaceMoveWaitsForRecordedRuns(t *testing.T) {
	h := newGWHarness(t)
	m := h.ensure(true)
	if m.record.SandboxLabel != m.id.Name {
		t.Fatalf("a first start's label: %q", m.record.SandboxLabel)
	}
	// Pretend the running gateway is one from before the namespace.
	old, err := openShellRenderGatewayConfig(m.id, sandboxopenshell.DefaultSandboxLabel, m.record.Version)
	if err != nil || strings.Contains(old, "sandbox_label") {
		t.Fatalf("the pre-namespace config: %v\n%s", err, old)
	}
	rec := *m.record
	rec.SandboxLabel, rec.ConfigDigest = "", sandboxopenshell.GatewayConfigDigest(old, rec.DockerHost)
	b, _ := json.Marshal(rec)
	if err := os.WriteFile(m.layout.RecordPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	writeLiveRun(t, h.stateDir, m)
	aged := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(filepath.Join(openShellRunDir(h.stateDir, "run-0000-live"), "plan.json"), aged, aged); err != nil {
		t.Fatal(err)
	}
	h.fake.reset()
	w := h.ensure(true)
	if !w.decision.Ready() || w.decision.Rule == "G18" {
		t.Fatalf("with a run recorded under the old namespace: %+v", w.decision)
	}
	if len(h.fake.progs("systemd-run")) != 0 {
		t.Fatal("restarted onto a new namespace with a run recorded")
	}
	for _, a := range h.fake.progs("systemctl") {
		if slices.Contains(a, "stop") {
			t.Fatal("stopped with a run recorded")
		}
	}
	if err := os.RemoveAll(openShellRunDir(h.stateDir, "run-0000-live")); err != nil {
		t.Fatal(err)
	}
	h.fake.reset()
	u := h.ensure(true)
	if !u.decision.Ready() || u.record.SandboxLabel != m.id.Name {
		t.Fatalf("after the run ended: %+v %+v", u.decision, u.record)
	}
	if len(h.fake.progs("systemd-run")) != 1 {
		t.Fatalf("the namespace move: %d starts", len(h.fake.progs("systemd-run")))
	}
	cfg, err := os.ReadFile(m.layout.ConfigPath)
	if err != nil || !strings.Contains(string(cfg), `sandbox_label = "`+m.id.Name+`"`) {
		t.Fatalf("the moved config: %v\n%s", err, cfg)
	}
	// A gateway that moved keeps its label while a run is recorded.
	writeLiveRun(t, h.stateDir, u)
	h.fake.reset()
	if k := h.ensure(true); !k.decision.Ready() || len(h.fake.progs("systemd-run")) != 0 {
		t.Fatalf("a moved gateway with a run: %+v", k.decision)
	}
}

// TestOpenShellGatewayFirstOC2RecordKeepsItsNamespace (finding OC2-V1): a
// record written by the first build that set the namespace has no label
// field although its gateway runs under its own name; with a run recorded
// it is matched by its digest and never restarted into the driver default.
func TestOpenShellGatewayFirstOC2RecordKeepsItsNamespace(t *testing.T) {
	h := newGWHarness(t)
	m := h.ensure(true)
	rec := *m.record
	rec.SandboxLabel = "" // the first OC2 build wrote no label field
	b, _ := json.Marshal(rec)
	if err := os.WriteFile(m.layout.RecordPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	writeLiveRun(t, h.stateDir, m)
	aged := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(filepath.Join(openShellRunDir(h.stateDir, "run-0000-live"), "plan.json"), aged, aged); err != nil {
		t.Fatal(err)
	}
	h.fake.reset()
	if d := h.ensure(true).decision; !d.Ready() || len(h.fake.progs("systemd-run")) != 0 {
		t.Fatalf("a first-OC2 record with a run recorded was restarted: %+v", d)
	}
	for _, a := range h.fake.progs("systemctl") {
		if slices.Contains(a, "stop") {
			t.Fatal("stopped with a run recorded")
		}
	}
	cfg, err := os.ReadFile(m.layout.ConfigPath)
	if err != nil || !strings.Contains(string(cfg), `sandbox_label = "`+m.id.Name+`"`) {
		t.Fatalf("the config left its own namespace: %v\n%s", err, cfg)
	}
}

// TestOpenShellGatewayConfigPinsImages (ledger row OSH-48, lane FU7): the
// private config names both runtime images by their pinned digest
// references, the start waits for the supervisor image under that
// reference, and a gateway started before the pins (its config names no
// image) keeps running while a run holds it, then restarts onto the pins
// once idle, in its own namespace.
func TestOpenShellGatewayConfigPinsImages(t *testing.T) {
	h := newGWHarness(t)
	m := h.ensure(true)
	pinned, ok := sandboxopenshell.PinnedRuntimeImages(sandboxopenshell.Version{Major: 0, Minor: 1, Patch: 6})
	if !ok {
		t.Fatal("v0.1.6 has no pinned images")
	}
	cfg, err := os.ReadFile(m.layout.ConfigPath)
	if err != nil || !strings.Contains(string(cfg), `supervisor_image = "`+pinned.Supervisor+`"`) || !strings.Contains(string(cfg), `sandbox_runtime_image = "`+pinned.Sandbox+`"`) {
		t.Fatalf("the private config does not pin the images: %v\n%s", err, cfg)
	}
	waited := false
	for _, a := range h.fake.progs("docker") {
		if slices.Contains(a, pinned.Supervisor) {
			waited = true
		}
	}
	if !waited {
		t.Fatalf("the start did not wait for %s: %v", pinned.Supervisor, h.fake.progs("docker"))
	}

	// A gateway from before the pins.
	old, err := openShellRenderGatewayConfig(m.id, m.id.Name, "")
	if err != nil || strings.Contains(old, "supervisor_image") {
		t.Fatalf("the pre-pin config: %v\n%s", err, old)
	}
	rec := *m.record
	rec.ConfigDigest = sandboxopenshell.GatewayConfigDigest(old, rec.DockerHost)
	b, _ := json.Marshal(rec)
	if err := os.WriteFile(m.layout.RecordPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.layout.ConfigPath, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	writeLiveRun(t, h.stateDir, m)
	h.fake.reset()
	if d := h.ensure(true).decision; !d.Ready() || len(h.fake.progs("systemd-run")) != 0 {
		t.Fatalf("a pre-pin gateway holding a live run was restarted: %+v", d)
	}
	if err := os.RemoveAll(openShellRunDir(h.stateDir, "run-0000-live")); err != nil {
		t.Fatal(err)
	}
	h.fake.reset()
	u := h.ensure(true)
	if !u.decision.Ready() || len(h.fake.progs("systemd-run")) != 1 || u.record.SandboxLabel != m.id.Name {
		t.Fatalf("the idle pre-pin gateway: %+v %d starts, label %q", u.decision, len(h.fake.progs("systemd-run")), u.record.SandboxLabel)
	}
	cfg, err = os.ReadFile(m.layout.ConfigPath)
	if err != nil || !strings.Contains(string(cfg), pinned.Supervisor) || !strings.Contains(string(cfg), `sandbox_label = "`+m.id.Name+`"`) {
		t.Fatalf("the restarted config: %v\n%s", err, cfg)
	}
}

// TestOpenShellGatewayNeverStopsAForeignUnit (ledger row OSH-42): before a
// stop or restart the unit's --config must be this layout's. A unit of
// this install's name started from another state dir's config (a copied
// ~/.observer from before the install-id binding) is never stopped: the
// restart is refused with gateway_unit_foreign, naming both configs.
func TestOpenShellGatewayNeverStopsAForeignUnit(t *testing.T) {
	h := newGWHarness(t)
	m := h.ensure(true)
	if h.fake.config != m.layout.ConfigPath {
		t.Fatalf("the unit's config %q, the layout's %q", h.fake.config, m.layout.ConfigPath)
	}
	// This layout's own unit restarts on a config change.
	old := openShellGatewayOCSFEndpoint
	t.Cleanup(func() { openShellGatewayOCSFEndpoint = old })
	openShellGatewayOCSFEndpoint = func() string { return "" }
	h.fake.reset()
	if d := h.ensure(true).decision; !d.Ready() || len(h.fake.progs("systemd-run")) != 1 {
		t.Fatalf("own unit: %+v", d)
	}
	// Another state dir's unit of the same name is never stopped.
	h.fake.foreignConfig = "/home/dev/.observer-copy/sandbox-openshell/gateway/gateway.toml"
	openShellGatewayOCSFEndpoint = old
	h.fake.reset()
	d := h.ensure(true).decision
	if d.Verdict != sandboxopenshell.VerdictGatewayUnitForeign || !strings.Contains(d.Reason, h.fake.foreignConfig) || !strings.Contains(d.Reason, m.layout.ConfigPath) {
		t.Fatalf("a foreign unit: %+v", d)
	}
	for _, a := range h.fake.progs("systemctl") {
		if slices.Contains(a, "stop") {
			t.Fatal("a foreign unit was stopped")
		}
	}
	if len(h.fake.progs("systemd-run")) != 0 {
		t.Fatal("a foreign unit was restarted")
	}

	// FU7-A11: a `systemctl show` that fails refuses the stop (nothing is
	// stopped), and a unit that is not loaded passes the check.
	h.fake.foreignConfig = ""
	h.fake.showFails = true
	h.fake.reset()
	if err := h.exec.stopUnit(context.Background(), m.id, m.layout, true); err == nil || !strings.Contains(err.Error(), "could not read") {
		t.Fatalf("a failed show: %v", err)
	}
	for _, a := range h.fake.progs("systemctl") {
		if slices.Contains(a, "stop") {
			t.Fatal("stopped although its start command could not be read")
		}
	}
	h.fake.showFails = false
	h.fake.unit = "inactive"
	if err := h.exec.unitIsThisLayouts(context.Background(), m.id, m.layout); err != nil {
		t.Fatalf("a unit that is not loaded: %v", err)
	}
}
