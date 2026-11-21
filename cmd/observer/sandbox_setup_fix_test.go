//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
)

// The live-check fix round (2026-11-07): one test per defect row.

// setupOCIConfig selects the oci driver's module; oci-runc is not listed yet.
const setupOCIConfig = setupBaseConfig + "[components]\nadd = [\"terminals.sandbox.oci\"]\n"

// ociRigAfterInstall is an oci-runc rig whose engine is installed and whose
// probe stops at the image (the step only the active check can see).
func ociRigAfterInstall(t *testing.T) *setupRig {
	t.Helper()
	r := newSetupRig(t, setupOCIConfig)
	r.programs["podman"] = "/usr/bin/podman"
	r.socket = "/run/user/1000/podman/podman.sock"
	r.probe = sandboxselect.Probe{Compiled: true, Verdict: "image_missing", Reason: "the image is not present"}
	return r
}

// TestSandboxSetupRunAfterCheck (D-1, F8): a step only the active check can
// judge runs from the checked plan's fingerprint; the run probes again (the
// click's one probe) and gates on what it finds now. A stale fingerprint is
// still refused, with the checked plan; a passive fingerprint never probes.
func TestSandboxSetupRunAfterCheck(t *testing.T) {
	r := ociRigAfterInstall(t)
	ctx := context.Background()
	passive := r.plan(t, sandboxbackend.BackendOCIRunc)
	if st := stepOf(t, passive, "oci-image"); st.State != string(sandboxsetup.StateUnknown) || st.CanRun {
		t.Fatalf("passive image step = %+v", st)
	}
	checked, err := r.svc.Check(ctx, sandboxbackend.BackendOCIRunc)
	if err != nil {
		t.Fatal(err)
	}
	if st := stepOf(t, checked, "oci-image"); !st.CanRun || st.Class != string(sandboxsetup.ClassTerminal) {
		t.Fatalf("checked image step = %+v", st)
	}
	started, err := r.svc.Run(ctx, sandboxbackend.BackendOCIRunc, dashapi.SandboxSetupRunRequest{Step: "oci-image", Fingerprint: checked.Fingerprint}, "dashboard")
	if err != nil {
		t.Fatalf("run after a check = %v", err)
	}
	if started.Kind != dashapi.SandboxSetupStartedTerminal || len(r.spawned) != 1 || !reflect.DeepEqual(r.spawned[0], []string{"/opt/observer", "sandbox", "oci", "pull"}) {
		t.Fatalf("started %+v spawned %v", started, r.spawned)
	}
	if r.probes != 2 {
		t.Fatalf("probes = %d, want 2 (the check and the run's own)", r.probes)
	}

	// Stale: plan_changed with the checked plan.
	_, err = r.svc.Run(ctx, sandboxbackend.BackendOCIRunc, dashapi.SandboxSetupRunRequest{Step: "oci-image", Fingerprint: "stale"}, "dashboard")
	var e *sandboxSetupError
	if !errors.As(err, &e) || e.code != dashapi.SandboxSetupCodePlanChanged || e.plan == nil || !e.plan.Checked {
		t.Fatalf("stale = %v (plan %+v)", err, e)
	}

	// A passive fingerprint runs without a probe.
	before := r.probes
	passive = r.plan(t, sandboxbackend.BackendOCIRunc)
	if _, err := r.svc.Run(ctx, sandboxbackend.BackendOCIRunc, dashapi.SandboxSetupRunRequest{Step: sandboxsetup.PrereqEnable, Fingerprint: passive.Fingerprint}, "dashboard"); err != nil {
		t.Fatal(err)
	}
	if r.probes != before {
		t.Fatalf("a passive-fingerprint run probed (%d -> %d)", before, r.probes)
	}
}

// TestSandboxSetupCLIRunChecksAnUnknownStep (D-1, F8): `run --step` on a
// step only the check can judge checks first, then runs it.
func TestSandboxSetupCLIRunChecksAnUnknownStep(t *testing.T) {
	r := ociRigAfterInstall(t)
	var foreground [][]string
	deps := sandboxSetupCmdDeps{
		open: func(_ context.Context, _ string, spawn sandboxSetupSpawnFunc) (dashapi.SandboxSetup, func(), error) {
			r.svc.o.Spawn = spawn
			return r.svc, func() {}, nil
		},
		foreground: func(_ context.Context, argv []string, _ sandboxSetupStdio) (int, error) {
			foreground = append(foreground, argv)
			return 0, nil
		},
		isTTY: func(io.Reader) bool { return false },
		sleep: func(context.Context, time.Duration) error { return nil },
	}
	cmd := newSandboxSetupCmdWith(deps)
	var out, errb bytes.Buffer
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs([]string{"run", sandboxbackend.BackendOCIRunc, "--step", "oci-image", "--yes"})
	err := cmd.ExecuteContext(context.Background())
	var ee exitErr
	if err != nil && (!errors.As(err, &ee) || int(ee) != 0) {
		t.Fatalf("run = %v\nout: %s\nerr: %s", err, out.String(), errb.String())
	}
	if len(foreground) != 1 || !reflect.DeepEqual(foreground[0], []string{"/opt/observer", "sandbox", "oci", "pull"}) {
		t.Fatalf("foreground = %v\nout: %s\nerr: %s", foreground, out.String(), errb.String())
	}
	if strings.Contains(out.String(), "not checked yet") {
		t.Fatalf("the CLI still says not checked yet:\n%s", out.String())
	}
}

// TestSandboxSetupSummaryUnconfirmed (D-2, D-L5-1, F13): a row set up as far
// as the passive facts show reads unconfirmed in the summary, never "next: a
// step Observer does not do"; doctor reads it OK.
func TestSandboxSetupSummaryUnconfirmed(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, setupBaseConfig)
	r.programs["bwrap"] = "/usr/bin/bwrap"
	sums, err := r.svc.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var bw dashapi.SandboxSetupSummary
	for _, s := range sums {
		if s.Backend == sandboxbackend.BackendBwrap {
			bw = s
		}
	}
	if bw.Ready || !bw.Unconfirmed || bw.Next != "" {
		t.Fatalf("bwrap summary = %+v", bw)
	}
	if r.probes != 0 {
		t.Fatalf("the summary probed (%d)", r.probes)
	}
	checks := sandboxSetupDoctorChecks(context.Background(), r.svc, sandboxbackend.HostLinux)
	for _, c := range checks {
		if c.Name == "sandbox.setup.bwrap" && (c.Status != diag.StatusOK || !strings.Contains(c.Message, "is set up")) {
			t.Errorf("doctor row = %+v", c)
		}
	}
}

// TestSandboxSetupDefaultBackendUndo (D-7): undoing Enable on the default
// backend with nothing else listed is refused with a sentence, and the file
// is not touched.
func TestSandboxSetupDefaultBackendUndo(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, setupBaseConfig)
	p := r.plan(t, sandboxbackend.BackendBwrap)
	if st := stepOf(t, p, sandboxsetup.PrereqEnable); st.CanUndo {
		t.Fatalf("enable step offers undo: %+v", st)
	}
	before, _ := os.ReadFile(r.cfgPath)
	_, err := r.svc.Run(context.Background(), sandboxbackend.BackendBwrap, dashapi.SandboxSetupRunRequest{Step: sandboxsetup.PrereqEnable, Action: "undo", Fingerprint: p.Fingerprint}, "dashboard")
	status, code := setupCodeOf(err)
	if status != http.StatusConflict || code != dashapi.SandboxSetupCodeStepNotRunnable || !strings.Contains(err.Error(), "default backend") {
		t.Fatalf("undo = %d %s %v", status, code, err)
	}
	after, _ := os.ReadFile(r.cfgPath)
	if !bytes.Equal(before, after) {
		t.Fatal("the refused undo changed the config")
	}
}

// TestSandboxSetupEnableRecords (D-8): the enable step writes its record like
// the component step, and its undo marks it undone.
func TestSandboxSetupEnableRecords(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, setupBaseConfig)
	ctx := context.Background()
	p := r.plan(t, sandboxbackend.BackendProcessLite)
	started, err := r.svc.Run(ctx, sandboxbackend.BackendProcessLite, dashapi.SandboxSetupRunRequest{Step: sandboxsetup.PrereqEnable, Fingerprint: p.Fingerprint}, "dashboard")
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := r.ledger.SandboxRecords(ctx)
	if len(rows) != 1 || rows[0].Tool != "enable:process_lite" || rows[0].Channel != string(sandboxsetup.ChEnable) || rows[0].Status != string(toolinstall.StatusInstalled) {
		t.Fatalf("records = %+v", rows)
	}
	if st := stepOf(t, *started.Plan, sandboxsetup.PrereqEnable); st.Record == nil {
		t.Fatalf("enable step has no record: %+v", st)
	}
	p = *started.Plan
	if _, err := r.svc.Run(ctx, sandboxbackend.BackendProcessLite, dashapi.SandboxSetupRunRequest{Step: sandboxsetup.PrereqEnable, Action: "undo", Fingerprint: p.Fingerprint}, "dashboard"); err != nil {
		t.Fatal(err)
	}
	rows, _ = r.ledger.SandboxRecords(ctx)
	if len(rows) == 0 || rows[0].Status != string(toolinstall.StatusUninstalled) {
		t.Fatalf("after undo records = %+v", rows)
	}
}

// TestSandboxSetupLiveRunsUnknownFailsClosed (F9): when the live-run count
// cannot be learned (a CLI whose daemon did not answer), undo is refused.
func TestSandboxSetupLiveRunsUnknownFailsClosed(t *testing.T) {
	requireComponents(t, sandboxComponent)
	r := newSetupRig(t, "[terminal.launch]\nallow_install = true\n[terminal.sandbox]\nenabled = true\nbackends = [\"bwrap\", \"process_lite\"]\n")
	r.liveErr = errors.New("the daemon at 127.0.0.1:8081 did not answer")
	p := r.plan(t, sandboxbackend.BackendProcessLite)
	if st := stepOf(t, p, sandboxsetup.PrereqEnable); st.CanUndo {
		t.Fatalf("enable step offers undo with the live runs unknown: %+v", st)
	}
	_, err := r.svc.Run(context.Background(), sandboxbackend.BackendProcessLite, dashapi.SandboxSetupRunRequest{Step: sandboxsetup.PrereqEnable, Action: "undo", Fingerprint: p.Fingerprint}, "cli")
	if _, code := setupCodeOf(err); code != dashapi.SandboxSetupCodeLiveRuns {
		t.Fatalf("undo = %v", err)
	}
	cfg, _ := config.Load(config.LoadOptions{GlobalPath: r.cfgPath})
	if !slices.Contains(cfg.Terminal.Sandbox.Backends, sandboxbackend.BackendProcessLite) {
		t.Fatal("the refused undo removed the row")
	}
}

// TestSandboxSetupLiveRunsFromTheDaemon (F9): outside the daemon, the count
// is the running daemon's answer; no daemon is nothing live; a daemon that
// does not answer is an error.
func TestSandboxSetupLiveRunsFromTheDaemon(t *testing.T) {
	old := newDaemonLiveRunsClient
	t.Cleanup(func() { newDaemonLiveRunsClient = old })
	cases := []struct {
		name string
		rep  daemonLiveRunsReport
		err  error
		want int
		bad  bool
	}{
		{"no daemon", daemonLiveRunsReport{}, nil, 0, false},
		{"one live", daemonLiveRunsReport{Answered: true, Runs: []dashapi.LiveSandboxRun{{Backend: "bwrap"}, {Backend: "oci-runc"}}}, nil, 1, false},
		{"no answer", daemonLiveRunsReport{}, errors.New("timeout"), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newDaemonLiveRunsClient = func(string) daemonLiveRunsClient {
				return daemonLiveRunsClient{query: func(context.Context) (daemonLiveRunsReport, error) { return tc.rep, tc.err }}
			}
			n, err := sandboxSetupLiveRunsFor("")(context.Background(), "bwrap")
			if n != tc.want || (err != nil) != tc.bad {
				t.Fatalf("= %d %v, want %d (error %v)", n, err, tc.want, tc.bad)
			}
		})
	}
}

// TestSandboxSetupPlacedFileFacts (F4, F6): the configured path the download
// step writes is the program's fact, and a placed file whose sha256 changed
// reads missing so Repair runs.
func TestSandboxSetupPlacedFileFacts(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "cloud-hypervisor")
	if err := os.WriteFile(bin, []byte("pinned bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	sum, _ := sandboxSetupFileSHA256(bin)
	r := newSetupRig(t, setupBaseConfig+"[terminal.sandbox.vm]\ncloud_hypervisor_path = \""+filepath.ToSlash(bin)+"\"\n")
	ctx := context.Background()
	id, err := r.ledger.BeginSandboxOp(ctx, sandboxInstallRecord{Name: "cloud-hypervisor", Backend: sandboxbackend.BackendCloudHypervisor, Channel: string(sandboxsetup.ChPinned), Argv: []string{"pinned_download", "cloud-hypervisor", "v54.0"}, Display: "download"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ledger.FinishSandboxOp(ctx, id, sandboxOpOutcome{Digest: sum, PlacedPath: filepath.ToSlash(bin)}, func() string { return bin }); err != nil {
		t.Fatal(err)
	}
	st := stepOf(t, r.plan(t, sandboxbackend.BackendCloudHypervisor), "cloud-hypervisor")
	if st.State != string(sandboxsetup.StateDone) {
		t.Fatalf("placed file = %s %q", st.State, st.Reason)
	}
	if err := os.WriteFile(bin, []byte("pinned bytes, changed"), 0o700); err != nil {
		t.Fatal(err)
	}
	st = stepOf(t, r.plan(t, sandboxbackend.BackendCloudHypervisor), "cloud-hypervisor")
	if st.State != string(sandboxsetup.StateMissing) || !strings.Contains(st.Reason, "sha256 no longer matches") {
		t.Fatalf("changed file = %s %q", st.State, st.Reason)
	}
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	st = stepOf(t, r.plan(t, sandboxbackend.BackendCloudHypervisor), "cloud-hypervisor")
	if st.State != string(sandboxsetup.StateMissing) || !strings.Contains(st.Reason, "is not on this machine") {
		t.Fatalf("removed file = %s %q", st.State, st.Reason)
	}
}

// TestSandboxSetupProbeDirsHoldLibexec (F3): the passive resolve looks where
// packages put helpers off PATH (virtiofsd in /usr/libexec).
func TestSandboxSetupProbeDirsHoldLibexec(t *testing.T) {
	for _, want := range []string{"/usr/libexec", "/usr/lib/qemu", "/usr/sbin"} {
		if !slices.ContainsFunc(passiveProbeDirs, func(d integration.ProbeDir) bool { return d.Rel == want && d.OS == integration.ProbeUnix }) {
			t.Errorf("passive probe dirs lack %s", want)
		}
	}
}

// TestSandboxSetupEngineSocketStep (F7, F14): oci-runc has a step that
// starts the engine's socket (a terminal step, as the user), done once a
// socket exists, and the docker group guide.
func TestSandboxSetupEngineSocketStep(t *testing.T) {
	r := newSetupRig(t, setupOCIConfig)
	r.programs["podman"] = "/usr/bin/podman"
	p := r.plan(t, sandboxbackend.BackendOCIRunc)
	st := stepOf(t, p, "engine-socket")
	if st.State != string(sandboxsetup.StateMissing) || !st.CanRun || st.Class != string(sandboxsetup.ClassTerminal) {
		t.Fatalf("engine socket step = %+v", st)
	}
	if _, err := r.svc.Run(context.Background(), sandboxbackend.BackendOCIRunc, dashapi.SandboxSetupRunRequest{Step: "engine-socket", Fingerprint: p.Fingerprint}, "dashboard"); err != nil {
		t.Fatal(err)
	}
	if len(r.spawned) != 1 || !reflect.DeepEqual(r.spawned[0], []string{"systemctl", "--user", "enable", "--now", "podman.socket"}) {
		t.Fatalf("spawned %v", r.spawned)
	}
	// The step's terminal is still running (in flight); a machine whose
	// socket listens reads the step done.
	r2 := newSetupRig(t, setupOCIConfig)
	r2.programs["podman"] = "/usr/bin/podman"
	r2.socket = "/run/user/1000/podman/podman.sock"
	if st := stepOf(t, r2.plan(t, sandboxbackend.BackendOCIRunc), "engine-socket"); st.State != string(sandboxsetup.StateDone) {
		t.Fatalf("with a socket = %+v", st)
	}
	if st := stepOf(t, p, "docker-group"); st.Class != string(sandboxsetup.ClassNever) || st.Disclosure == "" {
		t.Fatalf("docker group step = %+v", st)
	}
}
