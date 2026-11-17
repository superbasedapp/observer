//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_setup.go is the cmd-side seam of sandbox setup (sandbox
// installation lifecycle plan section 3.6): dashapi.SandboxSetup over the
// pure planner internal/sandboxsetup. The facts are sandbox_setup_facts.go's
// (passive) and sandbox_setup_check.go's (the active check, on a click
// only); the runner is sandbox_setup_run.go's. The dashboard routes
// (internal/intelligence/dashboard/sandbox_setup.go) and `observer sandbox
// setup` call this one seam.

// sandboxSetupOptions is what newSandboxSetup is built from.
type sandboxSetupOptions struct {
	ConfigPath string
	// Surface is "dashboard" or "cli".
	Surface string
	// Spawn runs one setup argv. Dashboard: CreateSetup, returning the PTY
	// handle at once (exit tracked by the ledger, exitCode -1). CLI: runs in
	// the foreground on the person's terminal and returns its exit code with
	// handle "".
	Spawn func(ctx context.Context, argv []string, label string) (handle string, exitCode int, err error)
	// Ledger is the install ledger: a *toolInstallLedger, or a
	// dashapi.ToolInstallLedger holding one (the terminal surfaces' value),
	// so the daemon's wiring names no terminals type; anything else (nil
	// included) leaves setup without records, and a step that records
	// refuses.
	Ledger any
	Logger *slog.Logger
	Now    func() time.Time
}

// sandboxSetupNow is the clock of the live-run age reads.
var sandboxSetupNow = time.Now

// newSandboxSetup builds the sandbox setup seam. A nil Ledger (no database:
// plans show no records and a step that records refuses), a nil Spawn (no
// runner, as `observer doctor` builds it: a terminal step answers
// terminal_unavailable) and a ConfigPath of "" (the default config path)
// are all valid.
func newSandboxSetup(o sandboxSetupOptions) dashapi.SandboxSetup {
	ledger, _ := o.Ledger.(*toolInstallLedger)
	return newSandboxSetupService(o, ledger, productionSandboxSetupHost(o.ConfigPath, ledger))
}

// sandboxSetupService implements dashapi.SandboxSetup.
type sandboxSetupService struct {
	o      sandboxSetupOptions
	ledger *toolInstallLedger
	host   sandboxSetupHost
	ops    *sandboxSetupOps
	// run holds the runner's injected I/O (sandbox_setup_run.go).
	run sandboxSetupRunIO
	// mu serialises Run, so two clicks cannot both act on one plan.
	mu sync.Mutex
}

// newSandboxSetupService builds the service over explicit seams (tests).
func newSandboxSetupService(o sandboxSetupOptions, ledger *toolInstallLedger, h sandboxSetupHost) *sandboxSetupService {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Surface == "" {
		o.Surface = "dashboard"
	}
	run := productionSandboxSetupRunIO(o.ConfigPath)
	run.applyLive = sandboxLiveApplyFor(o.Surface, o.ConfigPath)
	run.refreshProbe = sandboxProbeRefreshFor(o.Surface, o.ConfigPath)
	s := &sandboxSetupService{o: o, ledger: ledger, host: h, ops: newSandboxSetupOps(), run: run}
	ledger.setOnSandboxSettled(s.recordSettled)
	return s
}

// recordSettled runs once a sandbox setup record settles in this process
// (the ledger's one hook, any status, a terminal step, a foreground run or
// an in-process op): the daemon's sandbox probe reads the host again, and
// the outcome is logged.
func (s *sandboxSetupService) recordSettled(backend string) {
	outcome := ""
	if s.run.refreshProbe != nil {
		ctx, cancel := context.WithTimeout(context.Background(), liveRunsDaemonTimeout)
		defer cancel()
		outcome = s.run.refreshProbe(ctx, backend)
	}
	s.o.Logger.Info("sandbox setup: probe refresh", "backend", backend, "surface", s.o.Surface, "outcome", outcome)
}

// sandboxSetupError is a refusal with its HTTP status and closed code (the
// dashboard handler reads it through an interface, so it names no type
// here); FreshPlan is set on plan_changed.
type sandboxSetupError struct {
	status int
	code   string
	msg    string
	plan   *dashapi.SandboxSetupPlan
}

// Error implements error.
func (e *sandboxSetupError) Error() string { return e.msg }

// SandboxSetupCode is the closed error code (dashapi.SandboxSetupCodes).
func (e *sandboxSetupError) SandboxSetupCode() string { return e.code }

// HTTPStatus is the status the route answers.
func (e *sandboxSetupError) HTTPStatus() int { return e.status }

// Code is the closed error code, under the name the CLI reads with
// errors.As (interface{ Code() string }).
func (e *sandboxSetupError) Code() string { return e.code }

// FreshPlan is the plan a plan_changed refusal carries (nil otherwise).
func (e *sandboxSetupError) FreshPlan() *dashapi.SandboxSetupPlan { return e.plan }

// setupErr builds a refusal.
func setupErr(status int, code, format string, args ...any) error {
	return &sandboxSetupError{status: status, code: code, msg: fmt.Sprintf(format, args...)}
}

// errSetupUnknownBackend refuses a backend this host does not offer.
func errSetupUnknownBackend(id string) error {
	return setupErr(http.StatusNotFound, dashapi.SandboxSetupCodeUnknownStep, "unknown sandbox backend %q (not an offered row on this host)", id)
}

// rowFor is backend's registry row, if it is offered.
func rowFor(backend string) (sandboxbackend.Capability, error) {
	row, ok := sandboxbackend.Get(backend)
	if !ok || !row.Offered() {
		return sandboxbackend.Capability{}, errSetupUnknownBackend(backend)
	}
	return row, nil
}

// sandboxSetupNotInBuild is the Blocked text of a row whose driver this
// build does not carry.
func sandboxSetupNotInBuild(row sandboxbackend.Capability) string {
	return "The " + row.Label + " driver is not in this build of Observer, so it cannot be set up here."
}

// buildPlan runs the planner over in and applies the one gate the planner
// cannot see: the row's driver is not in this build.
func buildPlan(in sandboxsetup.PlanInput, inBuild bool) sandboxsetup.Plan {
	p := sandboxsetup.Build(in)
	if !inBuild && p.Blocked == "" {
		p.Blocked = sandboxSetupNotInBuild(in.Row)
		p.Steps, p.Next, p.Ready = nil, -1, false
		p.Fingerprint = sandboxsetup.Fingerprint(nil)
	}
	return p
}

// plan gathers row's passive input and plans it.
func (s *sandboxSetupService) plan(ctx context.Context, backend string, active bool) (sandboxSetupInput, sandboxsetup.Plan, error) {
	row, err := rowFor(backend)
	if err != nil {
		return sandboxSetupInput{}, sandboxsetup.Plan{}, err
	}
	si, err := gatherSandboxSetupInput(ctx, s.host, row)
	if err != nil {
		return sandboxSetupInput{}, sandboxsetup.Plan{}, fmt.Errorf("sandboxSetup.plan: %w", err)
	}
	if active && si.inBuild {
		si.in = activeCheck(ctx, s.host, si)
	}
	return si, buildPlan(si.in, si.inBuild), nil
}

// Summary implements dashapi.SandboxSetup: one row per offered backend that
// runs on this host, from passive facts.
func (s *sandboxSetupService) Summary(ctx context.Context) ([]dashapi.SandboxSetupSummary, error) {
	host := s.host.hostKind()
	out := []dashapi.SandboxSetupSummary{}
	for _, row := range sandboxbackend.Offered() {
		if !row.RunsOn(host) {
			continue
		}
		_, p, err := s.plan(ctx, row.ID, false)
		if err != nil {
			return nil, err
		}
		sum := dashapi.SandboxSetupSummary{Backend: p.Backend, Label: p.Label, Ready: p.Ready, Unconfirmed: p.Unconfirmed, Blocked: p.Blocked, Beta: p.Beta}
		if p.Blocked == "" && p.Next >= 0 && p.Next < len(p.Steps) {
			sum.Next = p.Steps[p.Next].Label
		}
		out = append(out, sum)
	}
	return out, nil
}

// Plan implements dashapi.SandboxSetup (passive facts: no exec, no dial).
func (s *sandboxSetupService) Plan(ctx context.Context, backend string) (dashapi.SandboxSetupPlan, error) {
	si, p, err := s.plan(ctx, backend, false)
	if err != nil {
		return dashapi.SandboxSetupPlan{}, err
	}
	return s.wire(ctx, si, p, false), nil
}

// Check implements dashapi.SandboxSetup: the active check (the person's
// click), then the plan with checked set.
func (s *sandboxSetupService) Check(ctx context.Context, backend string) (dashapi.SandboxSetupPlan, error) {
	si, p, err := s.plan(ctx, backend, true)
	if err != nil {
		return dashapi.SandboxSetupPlan{}, err
	}
	s.o.Logger.Info("sandbox setup: active check", "backend", backend, "surface", s.o.Surface, "ready", p.Ready, "checked", si.inBuild)
	// A check may have found the host changed: this process's next probe
	// reads it again (the check's own probe is ephemeral and never cached).
	dropSandboxProbeCache()
	return s.wire(ctx, si, p, si.inBuild), nil
}

// Op implements dashapi.SandboxSetup.
func (s *sandboxSetupService) Op(_ context.Context, id string) (dashapi.SandboxSetupOp, bool) {
	return s.ops.get(id)
}

// wire renders a plan for the wire, with each step's record as the tool
// routes render one.
func (s *sandboxSetupService) wire(ctx context.Context, _ sandboxSetupInput, p sandboxsetup.Plan, checked bool) dashapi.SandboxSetupPlan {
	out := dashapi.SandboxSetupPlan{
		Backend: p.Backend, Label: p.Label, Next: p.Next, Ready: p.Ready, Unconfirmed: p.Unconfirmed, Blocked: p.Blocked, Beta: p.Beta,
		Checked: checked, Fingerprint: p.Fingerprint, Steps: make([]dashapi.SandboxSetupStep, 0, len(p.Steps)),
	}
	var rows map[int64]store.ToolInstallRow
	if s.ledger != nil {
		if rs, err := s.host.records(ctx); err == nil {
			rows = make(map[int64]store.ToolInstallRow, len(rs))
			for _, r := range rs {
				rows[r.ID] = r
			}
		}
	}
	for _, st := range p.Steps {
		w := dashapi.SandboxSetupStep{
			Prereq: st.Prereq, Kind: string(st.Kind), Label: st.Label, State: string(st.State),
			Class: string(st.Class), Channel: string(st.Channel), Display: st.Display, DisplayIsCommand: st.DisplayIsCommand,
			Reason: st.Reason, Disclosure: st.Disclosure, After: st.After, Docs: st.Docs, CanRun: st.CanRun, CanUndo: st.CanUndo,
			UndoRefused: st.UndoRefused,
		}
		if extra := sandboxSetupStepExtras[st.Kind]; extra != nil {
			extra(p.Backend, &w)
		}
		if st.Record != nil {
			if row, ok := rows[st.Record.ID]; ok && s.ledger != nil {
				rec := s.ledger.SandboxRecordWire(row)
				w.Record = &rec
			}
		}
		if c := st.Consent; c != nil {
			w.Consent = &dashapi.SandboxSetupConsent{Pin: c.Pin, Version: c.Version, SHA256: c.SHA256, Bytes: c.Bytes, Source: c.Source, URL: c.URL}
		}
		out.Steps = append(out.Steps, w)
	}
	return out
}

// sandboxSetupStepExtras adds, per step kind, what a surface needs beyond the
// plan to carry a step out. One row per kind that has extras (dispatch on the
// step's kind, never on a backend id); a kind absent here adds nothing.
var sandboxSetupStepExtras = map[sandboxsetup.Kind]func(backend string, w *dashapi.SandboxSetupStep){
	sandboxsetup.KindCredential: hostedCredentialStepExtras,
}

// hostedCredentialStepExtras names the credential fields a credential step
// asks for (the provider's own variable names, never a value) and its CLI
// form, `observer sandbox hosted connect <provider>`, which reads the same
// fields from stdin and stores them through the same keystore path. A
// provider whose calls carry a token minted per run has no stored credential
// and gets neither.
func hostedCredentialStepExtras(backend string, w *dashapi.SandboxSetupStep) {
	v, ok := sandboxremote.VendorFor(backend)
	if !ok || v.MintedCredential || len(v.EnvCredential) == 0 {
		return
	}
	w.Fields = append([]string(nil), v.EnvCredential...)
	w.Command = "observer sandbox hosted connect " + backend
}

// ---- in-process operations (pinned downloads) ------------------------------

// sandboxSetupOps is the in-process operation table: one owner of the ops a
// run started, read by Op.
type sandboxSetupOps struct {
	mu  sync.Mutex
	ops map[string]*dashapi.SandboxSetupOp
}

func newSandboxSetupOps() *sandboxSetupOps {
	return &sandboxSetupOps{ops: map[string]*dashapi.SandboxSetupOp{}}
}

// start registers a new op in status installing and returns its id.
func (o *sandboxSetupOps) start(status string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	o.mu.Lock()
	o.ops[id] = &dashapi.SandboxSetupOp{ID: id, Status: status}
	o.mu.Unlock()
	return id
}

// progress records bytes done and total.
func (o *sandboxSetupOps) progress(id string, done, total int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if op := o.ops[id]; op != nil {
		op.Done, op.Total = done, total
	}
}

// finish records the op's final status and error.
func (o *sandboxSetupOps) finish(id, status string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if op := o.ops[id]; op != nil {
		op.Status = status
		if err != nil {
			op.Error = err.Error()
		}
	}
}

// get returns a copy of op id.
func (o *sandboxSetupOps) get(id string) (dashapi.SandboxSetupOp, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	op := o.ops[id]
	if op == nil {
		return dashapi.SandboxSetupOp{}, false
	}
	return *op, true
}

// errSandboxSetupNoLedger is a step that must be recorded in a process with
// no install ledger (no database).
var errSandboxSetupNoLedger = errors.New("sandbox setup: this process has no install record (no database), so the step is not run")

// Compile-time checks.
var (
	_ dashapi.SandboxSetup            = (*sandboxSetupService)(nil)
	_ dashapi.SandboxSetupLiveApplier = (*sandboxSetupService)(nil)
)
