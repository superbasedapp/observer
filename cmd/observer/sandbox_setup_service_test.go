//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/defaultworkspace"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
)

// setupRig is one sandbox setup service over fake I/O: a real temp config
// written through the real [terminal.sandbox] writer, a real install ledger
// over a temp database, and counted probe, version and spawn seams.
type setupRig struct {
	svc      *sandboxSetupService
	cfgPath  string
	ledger   *toolInstallLedger
	st       *store.Store
	programs map[string]string
	live     map[string]int
	liveErr  error
	// probe is what the fake driver probe answers (zero: available).
	probe sandboxselect.Probe
	// socket is the engine socket the passive fact finds ("" none).
	socket string
	floors sandboxselect.Floors

	mu        sync.Mutex
	probes    int
	versions  int
	spawned   [][]string
	labels    []string
	compAdds  []string
	compRems  []string
	connected []string
	// connectedFields are the credential fields each connect received.
	connectedFields []map[string]string
}

func newSetupRig(t *testing.T, cfgText string) *setupRig {
	t.Helper()
	setTestHome(t, t.TempDir())
	r := &setupRig{programs: map[string]string{}, live: map[string]int{}}
	r.cfgPath = filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(r.cfgPath, []byte(cfgText), 0o600); err != nil {
		t.Fatal(err)
	}
	r.ledger, r.st, _, _ = newTestLedger(t, npmCodexPlan)
	h := sandboxSetupHost{
		loadConfig:    func() (config.Config, error) { return config.Load(config.LoadOptions{GlobalPath: r.cfgPath}) },
		hostKind:      func() sandboxbackend.HostKind { return sandboxbackend.HostLinux },
		goos:          "linux",
		arch:          "amd64",
		readOSRelease: func() string { return "ID=ubuntu\nID_LIKE=debian\n" },
		snapshot: func(c config.Config) componentstate.Snapshot {
			return componentstate.ResolveGoverned(c.Components, nil, componentstate.Governed{})
		},
		floors:           func(context.Context, config.Config) (sandboxselect.Floors, error) { return r.floors, nil },
		resolveProgram:   func(name string) string { return r.programs[name] },
		contentPresent:   func(config.Config, string) bool { return false },
		hostedCredential: func(string) bool { return false },
		hostedConsent:    func(string) bool { return false },
		hostedAccount:    func(string) (bool, bool) { return false, false },
		liveRuns:         func(_ context.Context, b string) (int, error) { return r.live[b], r.liveErr },
		records:          func(ctx context.Context) ([]store.ToolInstallRow, error) { return r.ledger.SandboxRecords(ctx) },
		engineSocket:     func(config.Config) string { return r.socket },
		statFile:         sandboxSetupStatFile,
		fileDigest:       sandboxSetupFileSHA256,
		probeRow: func(context.Context, string, config.Config) (sandboxselect.Probe, bool) {
			r.mu.Lock()
			r.probes++
			r.mu.Unlock()
			if r.probe.Verdict != "" {
				return r.probe, true
			}
			return sandboxselect.Probe{Compiled: true, Verdict: sandboxselect.VerdictAvailable}, true
		},
		runVersion: func(context.Context, string) (string, error) {
			r.mu.Lock()
			r.versions++
			r.mu.Unlock()
			return "bubblewrap 0.9.0", nil
		},
	}
	o := sandboxSetupOptions{ConfigPath: r.cfgPath, Surface: "dashboard", Spawn: func(_ context.Context, argv []string, label string) (string, int, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.spawned = append(r.spawned, argv)
		r.labels = append(r.labels, label)
		return "h-" + string(rune('0'+len(r.spawned))), -1, nil
	}}
	r.svc = newSandboxSetupService(o, r.ledger, h)
	r.svc.run = sandboxSetupRunIO{
		writeConfig: sandboxSetupConfigWriter(r.cfgPath),
		componentAdd: func(_ context.Context, c, principal string) error {
			r.compAdds = append(r.compAdds, c+"|"+principal)
			return nil
		},
		componentRemove: func(_ context.Context, c, principal string) error {
			r.compRems = append(r.compRems, c+"|"+principal)
			return nil
		},
		download: func(context.Context, sandboxDownloadRequest) (sandboxDownloadResult, error) {
			return sandboxDownloadResult{}, errors.New("no download in tests")
		},
		contentFetch:  func(context.Context, config.Config, []string) error { return nil },
		contentImport: func(config.Config, string) error { return nil },
		hostedConnect: func(_ context.Context, provider string, fields map[string]string) error {
			r.connected = append(r.connected, provider)
			r.connectedFields = append(r.connectedFields, fields)
			return nil
		},
		observerBin: func() string { return "/opt/observer" },
		goos:        "linux",
		fileSHA256:  func(string) (string, error) { return "", os.ErrNotExist },
		removeFile:  func(string) error { return nil },
	}
	return r
}

const setupBaseConfig = "[terminal.launch]\nallow_install = true\n[terminal.sandbox]\nenabled = true\nbackends = [\"bwrap\"]\n"

func (r *setupRig) plan(t *testing.T, backend string) dashapi.SandboxSetupPlan {
	t.Helper()
	p, err := r.svc.Plan(context.Background(), backend)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func stepOf(t *testing.T, p dashapi.SandboxSetupPlan, prereq string) dashapi.SandboxSetupStep {
	t.Helper()
	for _, s := range p.Steps {
		if s.Prereq == prereq {
			return s
		}
	}
	t.Fatalf("plan %s has no step %s: %+v", p.Backend, prereq, p.Steps)
	return dashapi.SandboxSetupStep{}
}

func setupCodeOf(err error) (int, string) {
	var e *sandboxSetupError
	if errors.As(err, &e) {
		return e.status, e.code
	}
	return 0, ""
}

// TestSandboxSetupPassiveStartsNoProcess: Plan and Summary read passive facts
// only: no driver probe, no version run and no exec; Check runs one probe.
func TestSandboxSetupPassiveStartsNoProcess(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, setupBaseConfig)
	r.programs["bwrap"] = "/usr/bin/bwrap"
	old := sandboxSetupExecOutput
	sandboxSetupExecOutput = func(context.Context, string, ...string) (string, error) {
		t.Error("the passive path executed a program")
		return "", errors.New("no exec")
	}
	t.Cleanup(func() { sandboxSetupExecOutput = old })
	ctx := context.Background()
	if _, err := r.svc.Summary(ctx); err != nil {
		t.Fatal(err)
	}
	p := r.plan(t, sandboxbackend.BackendBwrap)
	if r.probes != 0 || r.versions != 0 || len(r.spawned) != 0 {
		t.Fatalf("passive path: probes %d versions %d spawns %d", r.probes, r.versions, len(r.spawned))
	}
	if p.Checked || stepOf(t, p, "bwrap").State != string(sandboxsetup.StateDone) {
		t.Fatalf("passive plan = %+v", p)
	}
	c, err := r.svc.Check(ctx, sandboxbackend.BackendBwrap)
	if err != nil {
		t.Fatal(err)
	}
	if r.probes != 1 || r.versions != 1 || !c.Checked || !c.Ready {
		t.Fatalf("check: probes %d versions %d plan %+v", r.probes, r.versions, c)
	}
}

// TestSandboxSetupGates: one row per gate, in the plan's order.
func TestSandboxSetupGates(t *testing.T) {
	requireComponents(t, sandboxComponent)
	cases := []struct {
		name    string
		cfg     string
		backend string
		prep    func(r *setupRig)
		req     func(p dashapi.SandboxSetupPlan) dashapi.SandboxSetupRunRequest
		status  int
		code    string
	}{
		{
			"unknown backend", setupBaseConfig, "no-such-row", nil,
			func(dashapi.SandboxSetupPlan) dashapi.SandboxSetupRunRequest {
				return dashapi.SandboxSetupRunRequest{Step: "x"}
			},
			http.StatusNotFound, dashapi.SandboxSetupCodeUnknownStep,
		},
		{
			"kill switch off", "[terminal.launch]\nallow_install = false\n[terminal.sandbox]\nenabled = true\n", "bwrap", nil,
			func(p dashapi.SandboxSetupPlan) dashapi.SandboxSetupRunRequest {
				return dashapi.SandboxSetupRunRequest{Step: "bwrap", Fingerprint: p.Fingerprint}
			}, http.StatusForbidden, dashapi.SandboxSetupCodeInstallDisabled,
		},
		{
			"org floor refuses", setupBaseConfig, "bwrap", func(r *setupRig) { r.floors.AllowedBackends = []string{"oci-runc"} },
			func(p dashapi.SandboxSetupPlan) dashapi.SandboxSetupRunRequest {
				return dashapi.SandboxSetupRunRequest{Step: "bwrap", Fingerprint: p.Fingerprint}
			}, http.StatusForbidden, dashapi.SandboxSetupCodeNotAllowedByOrg,
		},
		{
			"stale fingerprint", setupBaseConfig, "bwrap", nil,
			func(dashapi.SandboxSetupPlan) dashapi.SandboxSetupRunRequest {
				return dashapi.SandboxSetupRunRequest{Step: "bwrap", Fingerprint: "stale"}
			}, http.StatusConflict, dashapi.SandboxSetupCodePlanChanged,
		},
		{
			"unknown step", setupBaseConfig, "bwrap", nil,
			func(p dashapi.SandboxSetupPlan) dashapi.SandboxSetupRunRequest {
				return dashapi.SandboxSetupRunRequest{Step: "nope", Fingerprint: p.Fingerprint}
			}, http.StatusBadRequest, dashapi.SandboxSetupCodeUnknownStep,
		},
		{
			"unknown action", setupBaseConfig, "bwrap", nil,
			func(p dashapi.SandboxSetupPlan) dashapi.SandboxSetupRunRequest {
				return dashapi.SandboxSetupRunRequest{Step: "bwrap", Action: "purge", Fingerprint: p.Fingerprint}
			}, http.StatusBadRequest, dashapi.SandboxSetupCodeUnknownStep,
		},
		{
			"elevation off", setupBaseConfig, "bwrap", nil,
			func(p dashapi.SandboxSetupPlan) dashapi.SandboxSetupRunRequest {
				return dashapi.SandboxSetupRunRequest{Step: "bwrap", Fingerprint: p.Fingerprint}
			}, http.StatusForbidden, dashapi.SandboxSetupCodeElevationDisabled,
		},
		{
			"done step", setupBaseConfig, "bwrap", func(r *setupRig) { r.programs["bwrap"] = "/usr/bin/bwrap" },
			func(p dashapi.SandboxSetupPlan) dashapi.SandboxSetupRunRequest {
				return dashapi.SandboxSetupRunRequest{Step: "bwrap", Fingerprint: p.Fingerprint}
			}, http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable,
		},
		{
			"undo with live runs", setupBaseConfig, "bwrap", func(r *setupRig) { r.live["bwrap"] = 2 },
			func(p dashapi.SandboxSetupPlan) dashapi.SandboxSetupRunRequest {
				return dashapi.SandboxSetupRunRequest{Step: "enable", Action: "undo", Fingerprint: p.Fingerprint}
			}, http.StatusConflict, dashapi.SandboxSetupCodeLiveRuns,
		},
		{
			"update of a package step", setupBaseConfig, "bwrap", nil,
			func(p dashapi.SandboxSetupPlan) dashapi.SandboxSetupRunRequest {
				return dashapi.SandboxSetupRunRequest{Step: "bwrap", Action: "update", Fingerprint: p.Fingerprint}
			}, http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newSetupRig(t, tc.cfg)
			if tc.prep != nil {
				tc.prep(r)
			}
			var p dashapi.SandboxSetupPlan
			if tc.backend == "bwrap" {
				p = r.plan(t, tc.backend)
			}
			_, err := r.svc.Run(context.Background(), tc.backend, tc.req(p), "dashboard")
			status, code := setupCodeOf(err)
			if status != tc.status || code != tc.code {
				t.Fatalf("= %d %s (%v), want %d %s", status, code, err, tc.status, tc.code)
			}
			if code == dashapi.SandboxSetupCodePlanChanged {
				var e *sandboxSetupError
				// A fingerprint that is not the passive plan's runs the
				// active check once (D-1), so the fresh plan is the checked
				// one.
				if errors.As(err, &e); e.plan == nil || !e.plan.Checked || r.probes != 1 {
					t.Fatalf("plan_changed without the fresh checked plan: %+v (probes %d)", e.plan, r.probes)
				}
			}
			if len(r.spawned) != 0 {
				t.Fatalf("a refused run spawned %v", r.spawned)
			}
		})
	}
}

// TestSandboxSetupRunsAnElevatedPackageStep: with the key on, the bwrap step
// runs the derived apt argv under sudo in a setup terminal and records it.
func TestSandboxSetupRunsAnElevatedPackageStep(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, setupBaseConfig+"[terminal.sandbox.setup]\nallow_elevated = true\n")
	p := r.plan(t, "bwrap")
	st := stepOf(t, p, "bwrap")
	if !st.CanRun || st.Class != string(sandboxsetup.ClassElevated) {
		t.Fatalf("bwrap step = %+v", st)
	}
	started, err := r.svc.Run(context.Background(), "bwrap", dashapi.SandboxSetupRunRequest{Step: "bwrap", Fingerprint: p.Fingerprint}, "dashboard")
	if err != nil {
		t.Fatal(err)
	}
	pm, _ := toolinstall.PackageManagerByName("apt")
	_, want, _ := toolinstall.InstallArgvFor(pm, []string{"bubblewrap"})
	if len(r.spawned) != 1 || !reflect.DeepEqual(r.spawned[0], want) || want[0] != "sudo" {
		t.Fatalf("spawned %v, want %v", r.spawned, want)
	}
	if r.labels[0] != "sandbox-setup:bwrap:bwrap" || started.Kind != dashapi.SandboxSetupStartedTerminal || started.Handle == "" {
		t.Fatalf("label %q started %+v", r.labels[0], started)
	}
	rows, _ := r.ledger.SandboxRecords(context.Background())
	if len(rows) != 1 || rows[0].Channel != "apt" || !rows[0].Elevated || rows[0].Backend != "bwrap" {
		t.Fatalf("record = %+v", rows)
	}
}

// TestSandboxSetupEnableAppendsToTheEnd: the enable step appends the row to
// the END of backends (ruling R4) and turns the sandbox on.
func TestSandboxSetupEnableAppendsToTheEnd(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, "[terminal.launch]\nallow_install = true\n[terminal.sandbox]\nenabled = false\nbackends = [\"bwrap\"]\n")
	p := r.plan(t, sandboxbackend.BackendProcessLite)
	if !stepOf(t, p, "enable").CanRun {
		t.Fatalf("enable step = %+v", stepOf(t, p, "enable"))
	}
	started, err := r.svc.Run(context.Background(), sandboxbackend.BackendProcessLite, dashapi.SandboxSetupRunRequest{Step: "enable", Fingerprint: p.Fingerprint}, "dashboard")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(config.LoadOptions{GlobalPath: r.cfgPath})
	if !cfg.Terminal.Sandbox.Enabled || !reflect.DeepEqual(cfg.Terminal.Sandbox.Backends, []string{"bwrap", "process_lite"}) {
		t.Fatalf("sandbox = enabled %v backends %v", cfg.Terminal.Sandbox.Enabled, cfg.Terminal.Sandbox.Backends)
	}
	if started.Kind != dashapi.SandboxSetupStartedDone || started.Plan == nil {
		t.Fatalf("started = %+v", started)
	}
	// Undo removes it again; the sandbox stays on.
	p = *started.Plan
	if _, err := r.svc.Run(context.Background(), sandboxbackend.BackendProcessLite, dashapi.SandboxSetupRunRequest{Step: "enable", Action: "undo", Fingerprint: p.Fingerprint}, "dashboard"); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load(config.LoadOptions{GlobalPath: r.cfgPath})
	if !cfg.Terminal.Sandbox.Enabled || !reflect.DeepEqual(cfg.Terminal.Sandbox.Backends, []string{"bwrap"}) {
		t.Fatalf("after undo = enabled %v backends %v", cfg.Terminal.Sandbox.Enabled, cfg.Terminal.Sandbox.Backends)
	}
}

// TestSandboxSetupComponentStep: the component step goes through
// componentsvc as the surface and is recorded per backend.
func TestSandboxSetupComponentStep(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, setupBaseConfig)
	p := r.plan(t, sandboxbackend.BackendProcessLite)
	st := stepOf(t, p, sandboxsetup.PrereqComponent)
	if !st.CanRun || st.Channel != string(sandboxsetup.ChComponent) {
		t.Fatalf("component step = %+v", st)
	}
	if _, err := r.svc.Run(context.Background(), sandboxbackend.BackendProcessLite, dashapi.SandboxSetupRunRequest{Step: sandboxsetup.PrereqComponent, Fingerprint: p.Fingerprint}, "dashboard"); err != nil {
		t.Fatal(err)
	}
	comp, _ := sandboxSetupComponentFor(sandboxbackend.BackendProcessLite)
	if len(r.compAdds) != 1 || r.compAdds[0] != comp+"|dashboard" {
		t.Fatalf("component adds = %v", r.compAdds)
	}
	rows, _ := r.ledger.SandboxRecords(context.Background())
	if len(rows) != 1 || rows[0].Tool != "component:process_lite" {
		t.Fatalf("records = %+v", rows)
	}
}

// TestSandboxSetupConfigKeyStepAndUndo: a disclosed config key is written
// with its previous value recorded, and the undo restores it.
func TestSandboxSetupConfigKeyStepAndUndo(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, setupBaseConfig)
	ctx := context.Background()
	p := r.plan(t, sandboxbackend.BackendOCIRunsc)
	st := stepOf(t, p, "oci-allow-rootful")
	if !st.CanRun {
		t.Fatalf("allow_rootful step = %+v", st)
	}
	started, err := r.svc.Run(ctx, sandboxbackend.BackendOCIRunsc, dashapi.SandboxSetupRunRequest{Step: "oci-allow-rootful", Fingerprint: p.Fingerprint}, "dashboard")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(config.LoadOptions{GlobalPath: r.cfgPath})
	if !cfg.Terminal.Sandbox.OCI.AllowRootful {
		t.Fatal("allow_rootful was not written")
	}
	after := stepOf(t, *started.Plan, "oci-allow-rootful")
	if after.State != string(sandboxsetup.StateDone) || !after.CanUndo {
		t.Fatalf("after = %+v", after)
	}
	if _, err := r.svc.Run(ctx, sandboxbackend.BackendOCIRunsc, dashapi.SandboxSetupRunRequest{Step: "oci-allow-rootful", Action: "undo", Fingerprint: started.Plan.Fingerprint}, "dashboard"); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load(config.LoadOptions{GlobalPath: r.cfgPath})
	if cfg.Terminal.Sandbox.OCI.AllowRootful {
		t.Fatal("undo did not restore allow_rootful")
	}
}

// TestSandboxSetupPackageUndoAndSharedKeep: the undo of a package step runs
// the derived uninstall; with another set-up row using the prerequisite the
// undo is refused at click time.
func TestSandboxSetupPackageUndoAndSharedKeep(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, setupBaseConfig+"[terminal.sandbox.setup]\nallow_elevated = true\n")
	ctx := context.Background()
	p := r.plan(t, "bwrap")
	if _, err := r.svc.Run(ctx, "bwrap", dashapi.SandboxSetupRunRequest{Step: "bwrap", Fingerprint: p.Fingerprint}, "dashboard"); err != nil {
		t.Fatal(err)
	}
	r.programs["bwrap"] = "/usr/bin/bwrap"
	r.ledger.observeExit("h-1", 0)
	p = r.plan(t, "bwrap")
	if st := stepOf(t, p, "bwrap"); !st.CanUndo || st.Record == nil || st.Record.Status != string(toolinstall.StatusInstalled) {
		t.Fatalf("bwrap step after install = %+v", st)
	}
	// A second row listed that also sets up bwrap keeps it.
	if err := os.WriteFile(r.cfgPath, []byte(strings.Replace(setupBaseConfig, `["bwrap"]`, `["bwrap", "cloud-hypervisor"]`, 1)+"[terminal.sandbox.setup]\nallow_elevated = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kept := r.plan(t, "bwrap")
	if st := stepOf(t, kept, "bwrap"); st.CanUndo || !strings.Contains(st.Reason, "Kept") {
		t.Fatalf("shared bwrap step = %+v", st)
	}
	_, err := r.svc.Run(ctx, "bwrap", dashapi.SandboxSetupRunRequest{Step: "bwrap", Action: "undo", Fingerprint: kept.Fingerprint}, "dashboard")
	if _, code := setupCodeOf(err); code != dashapi.SandboxSetupCodeStepNotRunnable {
		t.Fatalf("undo of a shared prerequisite = %v", err)
	}
	// Alone again, the undo runs the derived uninstall.
	if err := os.WriteFile(r.cfgPath, []byte(setupBaseConfig+"[terminal.sandbox.setup]\nallow_elevated = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p = r.plan(t, "bwrap")
	if _, err := r.svc.Run(ctx, "bwrap", dashapi.SandboxSetupRunRequest{Step: "bwrap", Action: "undo", Fingerprint: p.Fingerprint}, "dashboard"); err != nil {
		t.Fatal(err)
	}
	pm, _ := toolinstall.PackageManagerByName("apt")
	_, install, _ := toolinstall.InstallArgvFor(pm, []string{"bubblewrap"})
	want, _ := toolinstall.PlanUninstall("apt", install)
	if len(r.spawned) != 2 || !reflect.DeepEqual(r.spawned[1], want.Argv) {
		t.Fatalf("uninstall spawned %v, want %v", r.spawned, want.Argv)
	}
}

// runCtxFor builds a handler context over a plan step (for the channels a
// planner cannot reach in a test: a grounded pin, a hosted row).
func runCtxFor(r *setupRig, backend string, step sandboxsetup.Step, req dashapi.SandboxSetupRunRequest) runCtx {
	row, _ := sandboxbackend.Get(backend)
	return runCtx{s: r.svc, si: sandboxSetupInput{in: sandboxsetup.PlanInput{Row: row}}, step: step, req: req, surface: "dashboard"}
}

// TestSandboxSetupPinnedDownloadOp: a pinned download runs as an op, writes
// the placed path into its config key and records the digest.
func TestSandboxSetupPinnedDownloadOp(t *testing.T) {
	r := newSetupRig(t, setupBaseConfig)
	placed := filepath.Join(t.TempDir(), "cloud-hypervisor")
	r.svc.run.download = func(_ context.Context, req sandboxDownloadRequest) (sandboxDownloadResult, error) {
		if req.Pin != "cloud-hypervisor" || req.Managed {
			return sandboxDownloadResult{}, errors.New("unexpected request")
		}
		req.Progress(10, 10)
		return sandboxDownloadResult{Path: placed, SHA256: "deadbeef", Source: sandboxsetup.SourceVendorRelease, Version: "v54", Bytes: 10}, nil
	}
	step := sandboxsetup.Step{
		Prereq: "cloud-hypervisor", Label: "Cloud Hypervisor", Channel: sandboxsetup.ChPinned, Class: sandboxsetup.ClassAuto,
		Consent: &sandboxsetup.Consent{Pin: "cloud-hypervisor", Version: "v54", SHA256: "deadbeef", Bytes: 10, Source: sandboxsetup.SourceVendorRelease},
	}
	started, err := runPinned(context.Background(), runCtxFor(r, sandboxbackend.BackendCloudHypervisor, step, dashapi.SandboxSetupRunRequest{}))
	if err != nil || started.Kind != dashapi.SandboxSetupStartedOp {
		t.Fatalf("started %+v %v", started, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var op dashapi.SandboxSetupOp
	for time.Now().Before(deadline) {
		op, _ = r.svc.Op(context.Background(), started.OpID)
		if op.Status != string(toolinstall.StatusInstalling) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if op.Status != string(toolinstall.StatusInstalled) || op.Done != 10 {
		t.Fatalf("op = %+v", op)
	}
	cfg, _ := config.Load(config.LoadOptions{GlobalPath: r.cfgPath})
	if cfg.Terminal.Sandbox.VM.CloudHypervisorPath != placed {
		t.Fatalf("cloud_hypervisor_path = %q", cfg.Terminal.Sandbox.VM.CloudHypervisorPath)
	}
	rows, _ := r.ledger.SandboxRecords(context.Background())
	if len(rows) != 1 || rows[0].Digest != "deadbeef" || rows[0].PlacedPath != placed {
		t.Fatalf("record = %+v", rows)
	}
}

// TestSandboxSetupConsentEcho: a pinned download needs the shown consent.
func TestSandboxSetupConsentEcho(t *testing.T) {
	step := sandboxsetup.Step{Label: "x", Consent: &sandboxsetup.Consent{Pin: "p", SHA256: "AB", Bytes: 5}}
	cases := []struct {
		name string
		c    *dashapi.SandboxSetupConsent
		ok   bool
	}{
		{"missing", nil, false},
		{"other pin", &dashapi.SandboxSetupConsent{Pin: "q", SHA256: "ab", Bytes: 5}, false},
		{"other size", &dashapi.SandboxSetupConsent{Pin: "p", SHA256: "ab", Bytes: 6}, false},
		{"other digest", &dashapi.SandboxSetupConsent{Pin: "p", SHA256: "cd", Bytes: 5}, false},
		{"echoed", &dashapi.SandboxSetupConsent{Pin: "p", SHA256: "ab", Bytes: 5}, true},
	}
	for _, tc := range cases {
		err := gateConsent(step, dashapi.SandboxSetupRunRequest{Consent: tc.c})
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if err != nil {
			if status, code := setupCodeOf(err); status != http.StatusPreconditionFailed || code != dashapi.SandboxSetupCodeConsentRequired {
				t.Errorf("%s: = %d %s", tc.name, status, code)
			}
		}
	}
}

// TestSandboxSetupTerminalChannels: oci_pull, hosted consent and the
// org-shell sign-in run Observer's own verbs in a setup terminal; a guide
// step is refused; hosted_connect stores the key without a terminal.
func TestSandboxSetupTerminalChannels(t *testing.T) {
	r := newSetupRig(t, setupBaseConfig)
	ctx := context.Background()
	// A host-absolute folder, so the consent row runs on Windows too.
	work, _ := filepath.Abs(filepath.FromSlash("/work"))
	cases := []struct {
		h    setupHandler
		step sandboxsetup.Step
		req  dashapi.SandboxSetupRunRequest
		want []string
	}{
		{runOCIPull, sandboxsetup.Step{Prereq: "oci-image", Package: "oci", Channel: sandboxsetup.ChOCIPull}, dashapi.SandboxSetupRunRequest{}, []string{"/opt/observer", "sandbox", "oci", "pull"}},
		{runHostedConsent, sandboxsetup.Step{Prereq: "hosted-consent", Channel: sandboxsetup.ChConsent}, dashapi.SandboxSetupRunRequest{FromFile: work}, []string{"/opt/observer", "sandbox", "hosted", "consent", "modal", "--workspace", work}},
		{runOrgShellLogin, sandboxsetup.Step{Prereq: "orgshell-login", Channel: sandboxsetup.ChOrgShell}, dashapi.SandboxSetupRunRequest{}, []string{"/opt/observer", "sandbox", "org-shell", "login"}},
	}
	for i, tc := range cases {
		if _, err := tc.h(ctx, runCtxFor(r, sandboxbackend.BackendModal, tc.step, tc.req)); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(r.spawned[i], tc.want) {
			t.Errorf("spawned %v, want %v", r.spawned[i], tc.want)
		}
	}
	if _, err := refuseNotRunnable(ctx, runCtxFor(r, "bwrap", sandboxsetup.Step{Label: "x"}, dashapi.SandboxSetupRunRequest{})); err == nil {
		t.Fatal("a guide step ran")
	}
	if _, err := runOCIPull(ctx, runCtxFor(r, "apple-container", sandboxsetup.Step{Package: "apple-container", Channel: sandboxsetup.ChOCIPull}, dashapi.SandboxSetupRunRequest{})); err == nil {
		t.Fatal("an engine with no pull verb ran")
	}
	if _, err := runHostedConnect(ctx, runCtxFor(r, sandboxbackend.BackendModal, sandboxsetup.Step{Channel: sandboxsetup.ChHostedKey}, dashapi.SandboxSetupRunRequest{Key: "k-1"})); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.connected, []string{"modal"}) || len(r.spawned) != len(cases) {
		t.Fatalf("connected %v spawned %v", r.connected, r.spawned)
	}
}

// TestSandboxSetupHostedConsentNeedsProject: a consent run without a folder
// falls back to the default workspace when it is set up (review finding 6,
// 2026-11-12); otherwise it is refused before any terminal opens, naming the
// fix (the setup terminal starts in the home directory, which is never
// uploaded). A relative folder is always refused.
func TestSandboxSetupHostedConsentNeedsProject(t *testing.T) {
	// Host-absolute spellings, so the table runs on Windows too.
	defDir, _ := filepath.Abs(filepath.FromSlash("/home/dev/observer-workspace"))
	work, _ := filepath.Abs(filepath.FromSlash("/work"))
	ready := defaultworkspace.Status{Resolved: defaultworkspace.Resolved{Dir: defDir, Builtin: true}, Exists: true, Ready: true}
	notReady := defaultworkspace.Status{Resolved: defaultworkspace.Resolved{Dir: defDir, Builtin: true}, Problem: "Observer has not finished setting this folder up."}
	step := sandboxsetup.Step{Prereq: "hosted-consent", Channel: sandboxsetup.ChConsent}
	for _, tc := range []struct {
		name      string
		ws        string
		def       *defaultworkspace.Status
		wantWS    string
		wantInErr string
	}{
		{"no folder, default workspace ready", "", &ready, defDir, ""},
		{"blank folder, default workspace ready", "  ", &ready, defDir, ""},
		{"picked folder wins over the default", work, &ready, work, ""},
		{"no folder, default workspace not ready", "", &notReady, "", "default workspace is not ready"},
		{"no folder, no default workspace", "", nil, "", "--from-file"},
		{"relative folder", "relative/dir", &ready, "", "absolute"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newSetupRig(t, setupBaseConfig)
			if tc.def != nil {
				def := *tc.def
				r.svc.run.defaultWorkspace = func(config.Config) defaultworkspace.Status { return def }
			}
			_, err := runHostedConsent(context.Background(), runCtxFor(r, sandboxbackend.BackendModal, step, dashapi.SandboxSetupRunRequest{FromFile: tc.ws}))
			if tc.wantWS == "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantInErr) {
					t.Fatalf("err = %v, want a refusal naming %q", err, tc.wantInErr)
				}
				if len(r.spawned) != 0 {
					t.Fatalf("a refused consent spawned %v", r.spawned)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"/opt/observer", "sandbox", "hosted", "consent", "modal", "--workspace", tc.wantWS}
			if len(r.spawned) != 1 || !reflect.DeepEqual(r.spawned[0], want) {
				t.Fatalf("spawned %v, want %v", r.spawned, want)
			}
		})
	}
}

// TestSandboxSetupDispatchCoversEveryChannel: every Channel has a run
// handler (none only refuses).
func TestSandboxSetupDispatchCoversEveryChannel(t *testing.T) {
	for _, ch := range []sandboxsetup.Channel{
		sandboxsetup.ChComponent, sandboxsetup.ChEnable, sandboxsetup.ChConfig, sandboxsetup.ChPM, sandboxsetup.ChPinned,
		sandboxsetup.ChContent, sandboxsetup.ChOCIPull, sandboxsetup.ChCommand, sandboxsetup.ChHostedKey,
		sandboxsetup.ChConsent, sandboxsetup.ChOrgShell, sandboxsetup.ChNone,
	} {
		if runHandlers[ch] == nil {
			t.Errorf("no run handler for %s", ch)
		}
	}
}

// TestSandboxSetupElevateArgv: elevation is sudo on Linux, WSL and macOS
// (an argv toolinstall built under sudo is kept), the RunAs wrapper on
// Windows.
func TestSandboxSetupElevateArgv(t *testing.T) {
	cases := []struct {
		goos string
		in   []string
		want []string
	}{
		{"linux", []string{"runsc", "install"}, []string{"sudo", "--", "runsc", "install"}},
		{"darwin", []string{"installer", "-pkg", "/x.pkg"}, []string{"sudo", "--", "installer", "-pkg", "/x.pkg"}},
		{"linux", []string{"sudo", "apt-get", "install", "-y", "bubblewrap"}, []string{"sudo", "apt-get", "install", "-y", "bubblewrap"}},
	}
	for _, tc := range cases {
		if got := elevateArgv(tc.in, tc.goos); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %v = %v, want %v", tc.goos, tc.in, got, tc.want)
		}
	}
	win := elevateArgv([]string{"dism.exe", "/online", "it's"}, "windows")
	if win[0] != "powershell.exe" || !strings.Contains(win[4], "Start-Process -FilePath 'dism.exe' -Verb RunAs -Wait") || !strings.Contains(win[4], "'it''s'") {
		t.Fatalf("windows = %v", win)
	}
}

// TestSandboxSetupInUseBy: a shared prerequisite names the other listed
// rows that set it up.
func TestSandboxSetupInUseBy(t *testing.T) {
	bw, _ := sandboxbackend.Get("bwrap")
	cases := []struct {
		listed []string
		want   map[string][]string
	}{
		{[]string{"bwrap"}, nil},
		{[]string{"bwrap", "cloud-hypervisor"}, map[string][]string{"bwrap": {"cloud-hypervisor"}}},
		{[]string{"cloud-hypervisor", "oci-runc"}, map[string][]string{"bwrap": {"cloud-hypervisor"}}},
	}
	for _, tc := range cases {
		if got := sandboxSetupInUseBy(bw, tc.listed); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v = %v, want %v", tc.listed, got, tc.want)
		}
	}
}

// TestSandboxSetupInUseByIgnoresTheMasterSwitch: the gathered input names
// the other listed rows sharing a prerequisite whether or not
// [terminal.sandbox].enabled is on, since the switch turns a listed row
// back on (P-254). One case per row.
func TestSandboxSetupInUseByIgnoresTheMasterSwitch(t *testing.T) {
	bw, _ := sandboxbackend.Get("bwrap")
	cases := []struct {
		name string
		cfg  string
		want map[string][]string
	}{
		{"sandbox on, two rows listed", "[terminal.sandbox]\nenabled = true\nbackends = [\"bwrap\", \"cloud-hypervisor\"]\n", map[string][]string{"bwrap": {"cloud-hypervisor"}}},
		{"sandbox off, two rows listed", "[terminal.sandbox]\nenabled = false\nbackends = [\"bwrap\", \"cloud-hypervisor\"]\n", map[string][]string{"bwrap": {"cloud-hypervisor"}}},
		{"sandbox off, the row alone", "[terminal.sandbox]\nenabled = false\nbackends = [\"bwrap\"]\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newSetupRig(t, "[terminal.launch]\nallow_install = true\n"+tc.cfg)
			si, err := gatherSandboxSetupInput(context.Background(), r.svc.host, bw)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(si.in.InUseBy, tc.want) {
				t.Fatalf("InUseBy = %v, want %v", si.in.InUseBy, tc.want)
			}
		})
	}
}

// TestSandboxSetupRecordNames: the generic steps are recorded per backend;
// another row's generic record never maps onto this row.
func TestSandboxSetupRecordNames(t *testing.T) {
	if sandboxRecordName("component", "bwrap") != "component:bwrap" || sandboxRecordName("bwrap", "x") != "bwrap" {
		t.Fatal("record names")
	}
	rows := []store.ToolInstallRow{
		{ID: 3, Tool: "component:cloud-hypervisor", Status: "installed"},
		{ID: 2, Tool: "component:bwrap", Status: "installed"},
		{ID: 1, Tool: "bwrap", Status: "installed", Channel: "apt"},
	}
	got := sandboxSetupRecords(rows, "bwrap")
	if len(got) != 2 || got["component"].ID != 2 || got["bwrap"].ID != 1 {
		t.Fatalf("records = %+v", got)
	}
}

// TestSandboxSetupFactRules: one case per passive fact rule.
func TestSandboxSetupFactRules(t *testing.T) {
	r := newSetupRig(t, setupBaseConfig)
	h := r.svc.host
	h.resolveProgram = func(n string) string {
		if n == "docker" {
			return "/usr/bin/docker"
		}
		return ""
	}
	h.contentPresent = func(_ config.Config, k string) bool { return k == "sandbox.rootfs" }
	h.hostedCredential = func(string) bool { return true }
	h.hostedConsent = func(string) bool { return false }
	cfg := config.Default()
	cfg.Terminal.Sandbox.OCI.AllowRootful = true
	cases := []struct {
		prereq  string
		present bool
		has     bool
	}{
		{"container-engine", true, true}, // podman|docker: docker resolves
		{"bwrap", false, true},
		{"vm-image-set", false, true}, // the guest binary is missing
		{"oci-allow-rootful", true, true},
		{"hosted-key", true, true},
		{"hosted-consent", false, true},
		{"hosted-account", false, false}, // unknown unless a credential reads it
		{"userns", false, false},         // no passive fact: the probe judges it
	}
	for _, tc := range cases {
		f, ok := passiveFacts(h, cfg, sandboxbackend.Capability{ID: "e2b", Setup: []string{tc.prereq}}, nil)[tc.prereq]
		if ok != tc.has || f.Present != tc.present {
			t.Errorf("%s: fact %+v ok %v, want present %v ok %v", tc.prereq, f, ok, tc.present, tc.has)
		}
	}
}

// TestSandboxSetupCheckConfigCopy: the active check's config lists the row,
// selects its component and turns the sandbox on, never touching the input.
func TestSandboxSetupCheckConfigCopy(t *testing.T) {
	cfg := config.Default()
	cfg.Terminal.Sandbox.Backends = []string{"bwrap"}
	cfg.Components.Remove = []string{"terminals.sandbox", "terminals.sandbox.vm", "other"}
	out := sandboxSetupCheckConfig(cfg, "cloud-hypervisor", "terminals.sandbox.vm")
	if !out.Terminal.Sandbox.Enabled || !reflect.DeepEqual(out.Terminal.Sandbox.Backends, []string{"bwrap", "cloud-hypervisor"}) {
		t.Fatalf("sandbox = %+v", out.Terminal.Sandbox.Backends)
	}
	if !slices.Contains(out.Components.Add, "terminals.sandbox.vm") || !reflect.DeepEqual(out.Components.Remove, []string{"other"}) {
		t.Fatalf("components = %+v", out.Components)
	}
	if cfg.Terminal.Sandbox.Enabled || len(cfg.Terminal.Sandbox.Backends) != 1 || len(cfg.Components.Remove) != 3 || len(cfg.Components.Add) != 0 {
		t.Fatalf("the input was changed: %+v %+v", cfg.Terminal.Sandbox.Backends, cfg.Components)
	}
}

// TestSandboxSetupNilLedgerAndSpawn: the seam `observer doctor` builds (no
// ledger, no runner) plans and refuses, never panics; refusals carry Code().
func TestSandboxSetupNilLedgerAndSpawn(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, setupBaseConfig+"[terminal.sandbox.setup]\nallow_elevated = true\n")
	r.svc.ledger = nil
	r.svc.host.records = func(ctx context.Context) ([]store.ToolInstallRow, error) {
		var l *toolInstallLedger
		return l.SandboxRecords(ctx)
	}
	r.svc.o.Spawn = nil
	ctx := context.Background()
	if _, err := r.svc.Summary(ctx); err != nil {
		t.Fatal(err)
	}
	p := r.plan(t, "bwrap")
	_, err := r.svc.Run(ctx, "bwrap", dashapi.SandboxSetupRunRequest{Step: "bwrap", Fingerprint: p.Fingerprint}, "cli")
	var coded interface{ Code() string }
	if !errors.As(err, &coded) || coded.Code() != dashapi.SandboxSetupCodeTerminalUnavailable {
		t.Fatalf("run with no runner = %v", err)
	}
	// newSandboxSetup itself takes a nil Ledger and Spawn and "" config.
	if s := newSandboxSetup(sandboxSetupOptions{Surface: "cli"}); s == nil {
		t.Fatal("newSandboxSetup returned nil")
	}
}

// TestSandboxSetupCLIForegroundRun: on the CLI the runner returns the
// child's exit code with no handle; Run returns done with the fresh plan
// and the record settles from that exit code.
func TestSandboxSetupCLIForegroundRun(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, setupBaseConfig+"[terminal.sandbox.setup]\nallow_elevated = true\n")
	r.svc.o.Spawn = func(_ context.Context, argv []string, _ string) (string, int, error) {
		r.spawned = append(r.spawned, argv)
		r.programs["bwrap"] = "/usr/bin/bwrap"
		return "", 0, nil
	}
	p := r.plan(t, "bwrap")
	started, err := r.svc.Run(context.Background(), "bwrap", dashapi.SandboxSetupRunRequest{Step: "bwrap", Fingerprint: p.Fingerprint}, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if started.Kind != dashapi.SandboxSetupStartedDone || started.Handle != "" || started.Plan == nil {
		t.Fatalf("started = %+v", started)
	}
	if st := stepOf(t, *started.Plan, "bwrap"); st.State != string(sandboxsetup.StateDone) || st.Record == nil || st.Record.Status != string(toolinstall.StatusInstalled) {
		t.Fatalf("bwrap after the foreground run = %+v", st)
	}
}
