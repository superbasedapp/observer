//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// fakeSetupCodedErr is a seam error carrying a closed code.
type fakeSetupCodedErr struct{ code string }

func (e fakeSetupCodedErr) Error() string { return "refused: " + e.code }
func (e fakeSetupCodedErr) Code() string  { return e.code }

// fakeSandboxSetup is a stateful dashapi.SandboxSetup: a successful Run
// marks the step done and moves the fingerprint, the way the real seam's
// fresh plan would.
type fakeSandboxSetup struct {
	mu      sync.Mutex
	backend string
	label   string
	blocked string
	beta    string
	steps   []dashapi.SandboxSetupStep
	// argv is the argv a step spawns through the injected runner (nil: the
	// step completes in-process).
	argv map[string][]string
	// runErr is returned by Run for a step.
	runErr map[string]error
	// planChangedOnce answers the next Run with plan_changed (and moves the
	// fingerprint) once.
	planChangedOnce bool
	// opSeq, when set, makes Run answer kind op and Op walk the sequence.
	opSeq []dashapi.SandboxSetupOp
	opIdx int
	sums  []dashapi.SandboxSetupSummary
	gen   int

	spawn  sandboxSetupSpawnFunc
	runs   []dashapi.SandboxSetupRunRequest
	checks int
}

func (f *fakeSandboxSetup) planLocked(checked bool) dashapi.SandboxSetupPlan {
	p := dashapi.SandboxSetupPlan{
		Backend: f.backend, Label: f.label, Blocked: f.blocked, Beta: f.beta, Checked: checked,
		Fingerprint: fmt.Sprintf("fp-%d", f.gen), Next: -1,
	}
	p.Steps = append([]dashapi.SandboxSetupStep(nil), f.steps...)
	for i, st := range p.Steps {
		if !sandboxSetupStepDone(st) {
			p.Next = i
			break
		}
	}
	p.Ready = p.Next < 0 && p.Blocked == ""
	return p
}

func (f *fakeSandboxSetup) Summary(context.Context) ([]dashapi.SandboxSetupSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sums != nil {
		return f.sums, nil
	}
	p := f.planLocked(false)
	s := dashapi.SandboxSetupSummary{Backend: p.Backend, Label: p.Label, Ready: p.Ready, Blocked: p.Blocked}
	if p.Next >= 0 {
		s.Next = p.Steps[p.Next].Label
	}
	return []dashapi.SandboxSetupSummary{s}, nil
}

func (f *fakeSandboxSetup) Plan(_ context.Context, backend string) (dashapi.SandboxSetupPlan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if backend != f.backend {
		return dashapi.SandboxSetupPlan{}, fakeSetupCodedErr{dashapi.SandboxSetupCodeUnknownStep}
	}
	return f.planLocked(false), nil
}

func (f *fakeSandboxSetup) Check(_ context.Context, backend string) (dashapi.SandboxSetupPlan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	return f.planLocked(true), nil
}

func (f *fakeSandboxSetup) Run(ctx context.Context, backend string, req dashapi.SandboxSetupRunRequest, surface string) (dashapi.SandboxSetupStarted, error) {
	f.mu.Lock()
	f.runs = append(f.runs, req)
	if surface != "cli" {
		f.mu.Unlock()
		return dashapi.SandboxSetupStarted{}, errors.New("surface " + surface)
	}
	if f.planChangedOnce || req.Fingerprint != fmt.Sprintf("fp-%d", f.gen) {
		f.planChangedOnce = false
		f.gen++
		f.mu.Unlock()
		return dashapi.SandboxSetupStarted{}, fakeSetupCodedErr{dashapi.SandboxSetupCodePlanChanged}
	}
	if err := f.runErr[req.Step]; err != nil {
		f.mu.Unlock()
		return dashapi.SandboxSetupStarted{}, err
	}
	idx := -1
	for i, st := range f.steps {
		if st.Prereq == req.Step {
			idx = i
		}
	}
	argv := f.argv[req.Step]
	spawn := f.spawn
	f.mu.Unlock()
	exit := 0
	if argv != nil {
		_, code, err := spawn(ctx, argv, "Installing "+req.Step)
		if err != nil {
			return dashapi.SandboxSetupStarted{}, err
		}
		exit = code
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gen++
	if exit != 0 {
		code := exit
		f.steps[idx].Record = &dashapi.ToolInstallRecord{ID: int64(len(f.runs)), Tool: req.Step, Status: "install_failed", ExitCode: &code}
		return dashapi.SandboxSetupStarted{Kind: dashapi.SandboxSetupStartedDone}, nil
	}
	if req.Action == dashapi.SandboxSetupActionUndo {
		f.steps[idx].State = "missing"
	} else {
		f.steps[idx].State = "done"
		f.steps[idx].CanRun = false
	}
	f.steps[idx].Record = &dashapi.ToolInstallRecord{ID: int64(len(f.runs)), Tool: req.Step, Status: "installed", SubjectKind: "sandbox", Backend: backend}
	if f.opSeq != nil {
		return dashapi.SandboxSetupStarted{Kind: dashapi.SandboxSetupStartedOp, OpID: "op-1"}, nil
	}
	if argv != nil {
		return dashapi.SandboxSetupStarted{Kind: dashapi.SandboxSetupStartedTerminal}, nil
	}
	p := f.planLocked(false)
	return dashapi.SandboxSetupStarted{Kind: dashapi.SandboxSetupStartedDone, Plan: &p}, nil
}

func (f *fakeSandboxSetup) Op(_ context.Context, id string) (dashapi.SandboxSetupOp, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id != "op-1" || f.opIdx >= len(f.opSeq) {
		return dashapi.SandboxSetupOp{}, false
	}
	op := f.opSeq[f.opIdx]
	f.opIdx++
	return op, true
}

// newFakeSetup is a backend with two runnable terminal steps.
func newFakeSetup() *fakeSandboxSetup {
	return &fakeSandboxSetup{
		backend: sandboxbackend.BackendBwrap,
		label:   "Bubblewrap",
		steps: []dashapi.SandboxSetupStep{
			{Prereq: "component", Kind: "component", Label: "Sandboxes module", State: "done", Class: "auto", Channel: "component_select"},
			{Prereq: "bwrap", Kind: "program", Label: "bubblewrap program", State: "missing", Class: "elevated", Channel: "pm", Display: "sudo apt-get install -y bubblewrap", CanRun: true},
			{Prereq: "enable", Kind: "enable", Label: "Turn the backend on", State: "missing", Class: "terminal", Channel: "terminal_cmd", Display: "observer enables bwrap", CanRun: true},
		},
		argv: map[string][]string{
			"bwrap":  {"sudo", "apt-get", "install", "-y", "bubblewrap"},
			"enable": {"true"},
		},
	}
}

// setupRun is one command invocation's result.
type setupRun struct {
	out, err   string
	code       int
	foreground [][]string
}

// runSetupCmd runs `observer sandbox setup <args>` over the fake, with a
// fake foreground runner answering exits[argv[0]].
func runSetupCmd(t *testing.T, f *fakeSandboxSetup, tty bool, stdin string, exits map[string]int, args ...string) setupRun {
	t.Helper()
	var res setupRun
	deps := sandboxSetupCmdDeps{
		open: func(_ context.Context, _ string, spawn sandboxSetupSpawnFunc) (dashapi.SandboxSetup, func(), error) {
			if f == nil {
				return nil, nil, nil
			}
			f.spawn = spawn
			return f, func() {}, nil
		},
		foreground: func(_ context.Context, argv []string, _ sandboxSetupStdio) (int, error) {
			res.foreground = append(res.foreground, argv)
			return exits[argv[0]], nil
		},
		isTTY: func(io.Reader) bool { return tty },
		sleep: func(context.Context, time.Duration) error { return nil },
	}
	cmd := newSandboxSetupCmdWith(deps)
	var out, errb bytes.Buffer
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	var ee exitErr
	switch {
	case errors.As(err, &ee):
		res.code = int(ee)
	case err != nil:
		res.code = -1
		t.Logf("non-exit error: %v", err)
	}
	res.out, res.err = out.String(), errb.String()
	return res
}

func TestSandboxSetupCmdStatusSummaryHumanAndJSON(t *testing.T) {
	f := newFakeSetup()
	f.sums = []dashapi.SandboxSetupSummary{
		{Backend: "bwrap", Label: "Bubblewrap", Next: "bubblewrap program"},
		{Backend: "cloud-hypervisor", Label: "Cloud Hypervisor microVM", Ready: true},
		{Backend: "openshell", Label: "OpenShell", Blocked: "runs on native Linux only"},
	}
	r := runSetupCmd(t, f, true, "", nil, "status")
	if r.code != 0 {
		t.Fatalf("code %d: %s", r.code, r.err)
	}
	for _, want := range []string{"next: bubblewrap program", "ready", "blocked", "runs on native Linux only"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("status output lacks %q:\n%s", want, r.out)
		}
	}
	r = runSetupCmd(t, f, true, "", nil, "status", "--json")
	want, _ := json.MarshalIndent(map[string]any{"backends": f.sums}, "", "  ")
	if strings.TrimSpace(r.out) != string(want) {
		t.Errorf("status --json:\n%s\nwant:\n%s", r.out, want)
	}
}

// TestSandboxSetupCmdStatusBeta: a beta row reads "(beta)" after its label
// with its sentence under it, in the summary and in one backend's plan, and
// --json carries the sentence through the wire (operator ruling P-256).
func TestSandboxSetupCmdStatusBeta(t *testing.T) {
	const sentence = "Setup on Windows 11 Pro is beta: it has not been checked on a live host yet."
	f := newFakeSetup()
	f.sums = []dashapi.SandboxSetupSummary{
		{Backend: "hcs", Label: "Hyper-V isolated containers (HCS)", Blocked: "not in this release", Beta: sentence},
		{Backend: "bwrap", Label: "Bubblewrap", Next: "bubblewrap program"},
	}
	r := runSetupCmd(t, f, true, "", nil, "status")
	if r.code != 0 {
		t.Fatalf("code %d: %s", r.code, r.err)
	}
	if !strings.Contains(r.out, "hcs (Hyper-V isolated containers (HCS)) (beta)") || !strings.Contains(r.out, "\n  "+sentence+"\n") {
		t.Errorf("status lacks the beta label or sentence:\n%s", r.out)
	}
	if strings.Contains(r.out, "Bubblewrap) (beta)") {
		t.Errorf("a non-beta row reads beta:\n%s", r.out)
	}
	r = runSetupCmd(t, f, true, "", nil, "status", "--json")
	var sums struct {
		Backends []dashapi.SandboxSetupSummary `json:"backends"`
	}
	if err := json.Unmarshal([]byte(r.out), &sums); err != nil || len(sums.Backends) != 2 || sums.Backends[0].Beta != sentence || sums.Backends[1].Beta != "" {
		t.Errorf("status --json beta: %v %+v", err, sums)
	}

	f = newFakeSetup()
	f.beta = sentence
	r = runSetupCmd(t, f, true, "", nil, "status", f.backend)
	if r.code != 0 {
		t.Fatalf("plan code %d: %s", r.code, r.err)
	}
	lines := strings.Split(r.out, "\n")
	if len(lines) < 2 || !strings.Contains(lines[0], " (beta): ") || lines[1] != "  "+sentence {
		t.Errorf("plan head lacks the beta label or sentence:\n%s", r.out)
	}
	r = runSetupCmd(t, f, true, "", nil, "status", f.backend, "--json")
	var plan dashapi.SandboxSetupPlan
	if err := json.Unmarshal([]byte(r.out), &plan); err != nil || plan.Beta != sentence {
		t.Errorf("plan --json beta = %q (%v)", plan.Beta, err)
	}
}

func TestSandboxSetupCmdStatusPlanJSONEqualsDashapi(t *testing.T) {
	f := newFakeSetup()
	r := runSetupCmd(t, f, true, "", nil, "status", "bwrap", "--json")
	if r.code != 0 {
		t.Fatalf("code %d: %s", r.code, r.err)
	}
	f.mu.Lock()
	plan := f.planLocked(false)
	f.mu.Unlock()
	want, _ := json.MarshalIndent(plan, "", "  ")
	if strings.TrimSpace(r.out) != string(want) {
		t.Errorf("status <backend> --json:\n%s\nwant:\n%s", r.out, want)
	}
	var got dashapi.SandboxSetupPlan
	if err := json.Unmarshal([]byte(r.out), &got); err != nil || got.Fingerprint != plan.Fingerprint {
		t.Errorf("JSON does not decode into dashapi.SandboxSetupPlan: %v", err)
	}
	// Human form names the next command.
	r = runSetupCmd(t, f, true, "", nil, "status", "bwrap")
	if !strings.Contains(r.out, "Next: observer sandbox setup run bwrap --step bwrap") {
		t.Errorf("plan text lacks the next command:\n%s", r.out)
	}
}

func TestSandboxSetupCmdCheckRunsActiveCheckOnce(t *testing.T) {
	f := newFakeSetup()
	r := runSetupCmd(t, f, true, "", nil, "check", "bwrap", "--json")
	if r.code != 0 || f.checks != 1 {
		t.Fatalf("code %d checks %d: %s", r.code, f.checks, r.err)
	}
	var got dashapi.SandboxSetupPlan
	if err := json.Unmarshal([]byte(r.out), &got); err != nil || !got.Checked {
		t.Errorf("check --json: checked=%v err=%v", got.Checked, err)
	}
	if len(f.runs) != 0 {
		t.Errorf("check ran a step: %+v", f.runs)
	}
}

func TestSandboxSetupCmdRunAsksBeforeEachStep(t *testing.T) {
	f := newFakeSetup()
	r := runSetupCmd(t, f, true, "y\ny\n", nil, "run", "bwrap")
	if r.code != 0 {
		t.Fatalf("code %d: %s\n%s", r.code, r.err, r.out)
	}
	if n := strings.Count(r.out, "Run this step? [y/N]"); n != 2 {
		t.Errorf("asked %d times, want 2 (one per runnable step):\n%s", n, r.out)
	}
	if len(f.runs) != 2 || f.runs[0].Step != "bwrap" || f.runs[1].Step != "enable" {
		t.Errorf("runs %+v", f.runs)
	}
	for _, req := range f.runs {
		if req.Action != dashapi.SandboxSetupActionRun || req.Fingerprint == "" {
			t.Errorf("request %+v", req)
		}
	}
	if len(r.foreground) != 2 {
		t.Errorf("foreground runs %v", r.foreground)
	}
	if !strings.Contains(r.out, "asks for your password itself") {
		t.Errorf("elevated step lacks the password note:\n%s", r.out)
	}
	if !strings.Contains(r.out, "is set up and ready") {
		t.Errorf("no closing line:\n%s", r.out)
	}
}

func TestSandboxSetupCmdRunDeclinedStepRunsNothing(t *testing.T) {
	f := newFakeSetup()
	r := runSetupCmd(t, f, true, "n\nn\n", nil, "run", "bwrap")
	if r.code != 0 || len(f.runs) != 0 || len(r.foreground) != 0 {
		t.Fatalf("code %d runs %+v fg %v", r.code, f.runs, r.foreground)
	}
	if !strings.Contains(r.out, "Skipped: bubblewrap program") || !strings.Contains(r.out, "still needs") {
		t.Errorf("output:\n%s", r.out)
	}
}

func TestSandboxSetupCmdNonTTYRefusesWithoutYes(t *testing.T) {
	f := newFakeSetup()
	r := runSetupCmd(t, f, false, "y\ny\n", nil, "run", "bwrap")
	if r.code != sandboxSetupExitUsage {
		t.Fatalf("code %d, want 2", r.code)
	}
	if len(f.runs) != 0 || len(r.foreground) != 0 {
		t.Errorf("ran without a terminal: %+v", f.runs)
	}
	if !strings.Contains(r.err, "--yes") {
		t.Errorf("refusal does not name --yes: %s", r.err)
	}
	// --yes answers each question (still one per step).
	f = newFakeSetup()
	r = runSetupCmd(t, f, false, "", nil, "run", "bwrap", "--yes")
	if r.code != 0 || len(f.runs) != 2 {
		t.Fatalf("--yes: code %d runs %d: %s", r.code, len(f.runs), r.err)
	}
	if n := strings.Count(r.out, "yes (--yes)"); n != 2 {
		t.Errorf("--yes answered %d questions, want 2", n)
	}
}

func TestSandboxSetupCmdDownloadConsentLine(t *testing.T) {
	f := newFakeSetup()
	consent := &dashapi.SandboxSetupConsent{Pin: "cloud-hypervisor-v54-linux-amd64", Version: "54.0", SHA256: "0123456789abcdef0123", Bytes: 4_200_000, Source: "vendor_release"}
	f.steps = []dashapi.SandboxSetupStep{
		{Prereq: "cloud-hypervisor", Label: "Cloud Hypervisor binary", State: "missing", Class: "auto", Channel: "pinned_download", CanRun: true, Consent: consent},
	}
	f.argv = nil
	dir := t.TempDir()
	file := filepath.Join(dir, "ch")
	r := runSetupCmd(t, f, true, "y\n", nil, "run", "bwrap", "--step", "cloud-hypervisor", "--from-file", file)
	if r.code != 0 {
		t.Fatalf("code %d: %s", r.code, r.err)
	}
	if !strings.Contains(r.out, "Download: v54.0, about 4 MB, sha256 0123456789ab, from vendor_release") {
		t.Errorf("no consent line:\n%s", r.out)
	}
	if len(f.runs) != 1 || f.runs[0].Consent == nil || *f.runs[0].Consent != *consent {
		t.Fatalf("the run does not echo the shown consent: %+v", f.runs)
	}
	if f.runs[0].FromFile != file {
		t.Errorf("from_file %q, want %q", f.runs[0].FromFile, file)
	}
}

func TestSandboxSetupCmdFromFileOnlyOnDownloadSteps(t *testing.T) {
	f := newFakeSetup()
	r := runSetupCmd(t, f, true, "y\n", nil, "run", "bwrap", "--step", "bwrap", "--from-file", "/tmp/x")
	if r.code != 0 || len(f.runs) != 1 || f.runs[0].FromFile != "" {
		t.Fatalf("code %d runs %+v", r.code, f.runs)
	}
}

func TestSandboxSetupCmdGuideStepPrintsAndRunsNothing(t *testing.T) {
	f := newFakeSetup()
	f.steps[1] = dashapi.SandboxSetupStep{Prereq: "bwrap", Label: "bubblewrap program", State: "missing", Class: "guide", Channel: "none", Display: "sudo apt-get install -y bubblewrap", Docs: "sandboxed-terminals.md#bwrap"}
	r := runSetupCmd(t, f, true, "", nil, "run", "bwrap", "--step", "bwrap")
	if r.code != 0 {
		t.Fatalf("code %d: %s", r.code, r.err)
	}
	if !strings.Contains(r.out, "run it yourself") || !strings.Contains(r.out, "    sudo apt-get install -y bubblewrap") {
		t.Errorf("guide output:\n%s", r.out)
	}
	if len(f.runs) != 0 || len(r.foreground) != 0 || strings.Contains(r.out, "[y/N]") {
		t.Errorf("a guide step asked or ran: runs %+v", f.runs)
	}
}

func TestSandboxSetupCmdNeverStepPrintsAndRunsNothing(t *testing.T) {
	f := newFakeSetup()
	f.steps[1] = dashapi.SandboxSetupStep{Prereq: "userns", Label: "unprivileged user namespaces", State: "blocked", Class: "never", Channel: "none", Reason: "AppArmor restricts unprivileged user namespaces on this host", Docs: "sandboxed-terminals.md#userns"}
	r := runSetupCmd(t, f, true, "", nil, "run", "bwrap", "--step", "userns")
	if r.code != sandboxSetupExitBlocked {
		t.Fatalf("code %d, want 3", r.code)
	}
	for _, want := range []string{"AppArmor restricts", "Docs: sandboxed-terminals.md#userns"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("never output lacks %q:\n%s", want, r.out)
		}
	}
	if len(f.runs) != 0 || len(r.foreground) != 0 {
		t.Errorf("a never step ran: %+v", f.runs)
	}
	// The walk shows it, runs what it can, and exits 3.
	f.steps[2].CanRun = true
	r = runSetupCmd(t, f, true, "y\n", nil, "run", "bwrap")
	if r.code != sandboxSetupExitBlocked || len(f.runs) != 1 || f.runs[0].Step != "enable" {
		t.Errorf("walk: code %d runs %+v", r.code, f.runs)
	}
}

func TestSandboxSetupCmdPlanChangedReasks(t *testing.T) {
	f := newFakeSetup()
	f.planChangedOnce = true
	r := runSetupCmd(t, f, true, "y\ny\n", nil, "run", "bwrap", "--step", "bwrap")
	if r.code != 0 {
		t.Fatalf("code %d: %s\n%s", r.code, r.err, r.out)
	}
	if n := strings.Count(r.out, "Run this step? [y/N]"); n != 2 {
		t.Errorf("asked %d times, want 2 (once more after plan_changed):\n%s", n, r.out)
	}
	if len(f.runs) != 2 || f.runs[0].Fingerprint == f.runs[1].Fingerprint {
		t.Errorf("the second run does not name the fresh plan: %+v", f.runs)
	}
	if !strings.Contains(r.out, "The plan changed") {
		t.Errorf("no plan-changed note:\n%s", r.out)
	}
}

func TestSandboxSetupCmdExitCodes(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakeSandboxSetup) *fakeSandboxSetup
		exits map[string]int
		args  []string
		want  int
	}{
		{"done", nil, nil, []string{"run", "bwrap", "--step", "component"}, 0},
		{"step failed", nil, map[string]int{"sudo": 7}, []string{"run", "bwrap", "--step", "bwrap"}, sandboxSetupExitFailed},
		{"walk stops at a failed step", nil, map[string]int{"sudo": 7}, []string{"run", "bwrap"}, sandboxSetupExitFailed},
		{"unknown backend", nil, nil, []string{"run", "no-such-row"}, sandboxSetupExitUsage},
		{"unknown step", nil, nil, []string{"run", "bwrap", "--step", "nope"}, sandboxSetupExitUsage},
		{"undo without --step", nil, nil, []string{"undo", "bwrap"}, sandboxSetupExitUsage},
		{"too many args", nil, nil, []string{"check", "bwrap", "extra"}, sandboxSetupExitUsage},
		{"bad flag", nil, nil, []string{"status", "--nope"}, sandboxSetupExitUsage},
		{"blocked plan", func(f *fakeSandboxSetup) *fakeSandboxSetup {
			f.blocked = "OpenShell does not run under WSL2"
			return f
		}, nil, []string{"run", "bwrap"}, sandboxSetupExitBlocked},
		{"not in build", func(*fakeSandboxSetup) *fakeSandboxSetup { return nil }, nil, []string{"status"}, sandboxSetupExitBlocked},
		{"kill switch", func(f *fakeSandboxSetup) *fakeSandboxSetup {
			f.runErr = map[string]error{"bwrap": fakeSetupCodedErr{dashapi.SandboxSetupCodeInstallDisabled}}
			return f
		}, nil, []string{"run", "bwrap", "--step", "bwrap"}, sandboxSetupExitRefused},
		{"elevation switch", func(f *fakeSandboxSetup) *fakeSandboxSetup {
			f.runErr = map[string]error{"bwrap": fakeSetupCodedErr{dashapi.SandboxSetupCodeElevationDisabled}}
			return f
		}, nil, []string{"run", "bwrap", "--step", "bwrap"}, sandboxSetupExitRefused},
		{"live runs", func(f *fakeSandboxSetup) *fakeSandboxSetup {
			f.runErr = map[string]error{"bwrap": fmt.Errorf("refused (%s): 2 live runs", dashapi.SandboxSetupCodeLiveRuns)}
			return f
		}, nil, []string{"update", "bwrap", "--step", "bwrap", "--yes"}, sandboxSetupExitRefused},
		{"org refuses", func(f *fakeSandboxSetup) *fakeSandboxSetup {
			for i := range f.steps {
				f.steps[i].State, f.steps[i].CanRun = "not_allowed", false
			}
			return f
		}, nil, []string{"run", "bwrap"}, sandboxSetupExitRefused},
		{"undo with nothing to undo", nil, nil, []string{"undo", "bwrap", "--step", "bwrap", "--yes"}, sandboxSetupExitFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSetup()
			if tc.setup != nil {
				f = tc.setup(f)
			}
			r := runSetupCmd(t, f, true, "y\ny\ny\n", tc.exits, tc.args...)
			if r.code != tc.want {
				t.Errorf("code %d, want %d\nout:\n%s\nerr:\n%s", r.code, tc.want, r.out, r.err)
			}
		})
	}
}

func TestSandboxSetupCmdUndoUpdateRepairSendTheirAction(t *testing.T) {
	for _, action := range []string{dashapi.SandboxSetupActionUndo, dashapi.SandboxSetupActionUpdate, dashapi.SandboxSetupActionRepair} {
		t.Run(action, func(t *testing.T) {
			f := newFakeSetup()
			f.steps[1].State, f.steps[1].CanUndo, f.steps[1].CanRun = "done", true, false
			r := runSetupCmd(t, f, true, "y\n", nil, action, "bwrap", "--step", "bwrap")
			if r.code != 0 {
				t.Fatalf("code %d: %s", r.code, r.err)
			}
			if len(f.runs) != 1 || f.runs[0].Action != action || f.runs[0].Step != "bwrap" {
				t.Errorf("runs %+v", f.runs)
			}
			if !strings.Contains(r.out, "[y/N]") {
				t.Errorf("%s did not ask:\n%s", action, r.out)
			}
		})
	}
}

func TestSandboxSetupCmdOpIsPolledToItsEnd(t *testing.T) {
	f := newFakeSetup()
	f.argv = nil
	f.opSeq = []dashapi.SandboxSetupOp{
		{ID: "op-1", Status: "installing", Done: 1, Total: 4_000_000},
		{ID: "op-1", Status: "installed", Done: 4_000_000, Total: 4_000_000},
	}
	r := runSetupCmd(t, f, true, "y\n", nil, "run", "bwrap", "--step", "bwrap")
	if r.code != 0 || f.opIdx != 2 {
		t.Fatalf("code %d polls %d: %s", r.code, f.opIdx, r.err)
	}
	f = newFakeSetup()
	f.argv = nil
	f.opSeq = []dashapi.SandboxSetupOp{{ID: "op-1", Status: "install_failed", Error: "sha256 mismatch"}}
	r = runSetupCmd(t, f, true, "y\n", nil, "run", "bwrap", "--step", "bwrap")
	if r.code != sandboxSetupExitFailed || !strings.Contains(r.err, "sha256 mismatch") {
		t.Fatalf("failed op: code %d err %s", r.code, r.err)
	}
}

func TestSandboxSetupCmdRecordsJSON(t *testing.T) {
	f := newFakeSetup()
	rec := &dashapi.ToolInstallRecord{ID: 4, Tool: "bwrap", SubjectKind: "sandbox", Backend: "bwrap", Status: "installed", Channel: "pm"}
	f.steps[1].Record = rec
	f.steps[2].Record = rec // the same record twice is listed once
	r := runSetupCmd(t, f, true, "", nil, "records", "--json")
	if r.code != 0 {
		t.Fatalf("code %d: %s", r.code, r.err)
	}
	want, _ := json.MarshalIndent(map[string]any{"records": []dashapi.ToolInstallRecord{*rec}}, "", "  ")
	if strings.TrimSpace(r.out) != string(want) {
		t.Errorf("records --json:\n%s\nwant:\n%s", r.out, want)
	}
	r = runSetupCmd(t, newFakeSetup(), true, "", nil, "records", "--json")
	if strings.TrimSpace(r.out) != "{\n  \"records\": []\n}" {
		t.Errorf("empty records --json: %s", r.out)
	}
}

func TestSandboxSetupCmdCodeExitTableCoversEveryCode(t *testing.T) {
	for _, code := range dashapi.SandboxSetupCodes() {
		if _, ok := sandboxSetupCodeExits[code]; !ok {
			t.Errorf("no exit for seam code %q", code)
		}
	}
	if len(sandboxSetupCodeExits) != len(dashapi.SandboxSetupCodes()) {
		t.Errorf("exit table has codes the seam does not: %v", sandboxSetupCodeExits)
	}
}

func TestSandboxSetupCmdErrCode(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{dashapi.ErrSandboxSetupNotInBuild, dashapi.SandboxSetupCodeNotInBuild},
		{fmt.Errorf("wrap: %w", fakeSetupCodedErr{dashapi.SandboxSetupCodeConsentRequired}), dashapi.SandboxSetupCodeConsentRequired},
		{errors.New("409 plan_changed"), dashapi.SandboxSetupCodePlanChanged},
		{errors.New("not_plan_changed_x"), ""},
		{errors.New("disk full"), ""},
	}
	for _, tc := range cases {
		if got := sandboxSetupErrCode(tc.err); got != tc.want {
			t.Errorf("sandboxSetupErrCode(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestSandboxSetupCmdNotRunnableTableRows(t *testing.T) {
	cases := []struct {
		st   dashapi.SandboxSetupStep
		row  string
		exit int
	}{
		{dashapi.SandboxSetupStep{State: "done"}, "done", 0},
		{dashapi.SandboxSetupStep{State: "not_applicable"}, "done", 0},
		{dashapi.SandboxSetupStep{State: "not_allowed", Class: "terminal"}, "not_allowed", sandboxSetupExitRefused},
		{dashapi.SandboxSetupStep{State: "blocked", Class: "guide"}, "never", sandboxSetupExitBlocked},
		{dashapi.SandboxSetupStep{State: "missing", Class: "never"}, "never", sandboxSetupExitBlocked},
		{dashapi.SandboxSetupStep{State: "in_flight", Class: "terminal"}, "in_flight", 0},
		{dashapi.SandboxSetupStep{State: "missing", Class: "guide"}, "guide", 0},
		{dashapi.SandboxSetupStep{State: "unknown", Class: "terminal"}, "unknown", 0},
		{dashapi.SandboxSetupStep{State: "missing", Class: "terminal"}, "other", sandboxSetupExitFailed},
	}
	for _, tc := range cases {
		for _, row := range sandboxSetupNotRunnable {
			if row.match(tc.st) {
				if row.name != tc.row || row.exit != tc.exit {
					t.Errorf("%+v matched %s (exit %d), want %s (exit %d)", tc.st, row.name, row.exit, tc.row, tc.exit)
				}
				break
			}
		}
	}
}

func TestSandboxSetupCmdIsWiredUnderSandbox(t *testing.T) {
	root := newSandboxCmd()
	setup, _, err := root.Find([]string{"setup"})
	if err != nil || setup.Name() != "setup" {
		t.Fatalf("observer sandbox setup not registered: %v", err)
	}
	for _, verb := range []string{"status", "check", "run", "undo", "update", "repair", "records"} {
		if c, _, err := setup.Find([]string{verb}); err != nil || c.Name() != verb {
			t.Errorf("observer sandbox setup %s missing", verb)
		}
	}
	for _, code := range []string{"0  done", "1  a step failed", "2  usage", "3  blocked", "4  refused"} {
		if !strings.Contains(setup.Long, code) {
			t.Errorf("Long text does not document exit %q", code)
		}
	}
}

func TestSandboxSetupCmdForegroundRunsInHomeAndReturnsExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	var out bytes.Buffer
	code, err := sandboxSetupForeground(context.Background(), []string{"sh", "-c", "pwd; exit 3"}, sandboxSetupStdio{In: strings.NewReader(""), Out: &out, Err: io.Discard})
	if err != nil || code != 3 {
		t.Fatalf("code %d err %v", code, err)
	}
	want, _ := filepath.EvalSymlinks(home)
	got, _ := filepath.EvalSymlinks(strings.TrimSpace(out.String()))
	if got != want {
		t.Errorf("ran in %q, want the home directory %q (D-050)", got, want)
	}
	if _, err := sandboxSetupForeground(context.Background(), nil, sandboxSetupStdio{}); err == nil {
		t.Error("empty argv ran")
	}
}

func TestSandboxSetupCmdDoctorRows(t *testing.T) {
	f := newFakeSetup()
	f.sums = []dashapi.SandboxSetupSummary{
		{Backend: sandboxbackend.BackendBwrap, Label: "Bubblewrap", Next: "bubblewrap program"},
		{Backend: sandboxbackend.BackendCloudHypervisor, Label: "Cloud Hypervisor microVM", Ready: true},
		{Backend: sandboxbackend.BackendSeatbelt, Label: "macOS Seatbelt", Next: "x"},
	}
	checks := sandboxSetupDoctorChecks(context.Background(), f, sandboxbackend.HostLinux)
	byName := map[string]diag.Check{}
	for _, c := range checks {
		byName[c.Name] = c
	}
	if len(checks) != 2 {
		t.Fatalf("checks %+v", checks)
	}
	ready := byName["sandbox.setup.cloud-hypervisor"]
	if ready.Status != diag.StatusOK {
		t.Errorf("ready row: %+v", ready)
	}
	next := byName["sandbox.setup.bwrap"]
	if next.Status != diag.StatusWarn || !strings.Contains(next.Message, "next step bubblewrap program") {
		t.Errorf("next-step row: %+v", next)
	}
	if len(next.Details) == 0 || next.Details[0] != "run: observer sandbox setup run bwrap --step bwrap" {
		t.Errorf("next-step row lacks the exact command: %+v", next.Details)
	}
	if _, ok := byName["sandbox.setup.seatbelt"]; ok {
		t.Error("a row that does not run on this host has a doctor row")
	}
	if f.checks != 0 || len(f.runs) != 0 {
		t.Error("doctor ran the active check or a step")
	}
	// A guide next step names the guide command.
	f.steps[1].Class, f.steps[1].CanRun = "guide", false
	checks = sandboxSetupDoctorChecks(context.Background(), f, sandboxbackend.HostLinux)
	for _, c := range checks {
		if c.Name == "sandbox.setup.bwrap" && (len(c.Details) == 0 || c.Details[0] != "run: sudo apt-get install -y bubblewrap") {
			t.Errorf("guide row: %+v", c)
		}
	}
	// Not in this build: nothing.
	if got := sandboxSetupDoctorChecks(context.Background(), notInBuildSetup{}, sandboxbackend.HostLinux); len(got) != 0 {
		t.Errorf("not-in-build seam added rows: %+v", got)
	}
	if got := sandboxSetupDoctorChecks(context.Background(), nil, sandboxbackend.HostLinux); len(got) != 0 {
		t.Errorf("nil seam added rows: %+v", got)
	}
}

// notInBuildSetup is a seam that answers dashapi.ErrSandboxSetupNotInBuild
// from every method, the shape a build without the setup body has. It
// replaces the core lane's stub type, which lane daemon's real seam
// retired.
type notInBuildSetup struct{}

func (notInBuildSetup) Summary(context.Context) ([]dashapi.SandboxSetupSummary, error) {
	return nil, dashapi.ErrSandboxSetupNotInBuild
}

func (notInBuildSetup) Plan(context.Context, string) (dashapi.SandboxSetupPlan, error) {
	return dashapi.SandboxSetupPlan{}, dashapi.ErrSandboxSetupNotInBuild
}

func (notInBuildSetup) Check(context.Context, string) (dashapi.SandboxSetupPlan, error) {
	return dashapi.SandboxSetupPlan{}, dashapi.ErrSandboxSetupNotInBuild
}

func (notInBuildSetup) Run(context.Context, string, dashapi.SandboxSetupRunRequest, string) (dashapi.SandboxSetupStarted, error) {
	return dashapi.SandboxSetupStarted{}, dashapi.ErrSandboxSetupNotInBuild
}

func (notInBuildSetup) Op(context.Context, string) (dashapi.SandboxSetupOp, bool) {
	return dashapi.SandboxSetupOp{}, false
}
