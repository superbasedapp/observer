//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/defaultworkspace"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandbox_setup_run.go is the runner of sandbox setup (plan section 3.5):
// gates in the plan's order, then ONE dispatch table keyed by the step's
// Channel (never by a backend id). Every argv is server-derived (the
// planner's derived pm argv or the remedy's compile-time constant); a run
// request carries only the backend, the step, the action, the plan
// fingerprint, the download consent echo, a local path and, for
// hosted_connect only, a typed key or typed credential fields that are never
// logged.

// sandboxSetupRunIO is the runner's injected I/O. The production value is
// productionSandboxSetupRunIO; tests replace any field.
type sandboxSetupRunIO struct {
	// writeConfig is the [terminal.sandbox] writer: the config write lock
	// the dashboard's save pipeline takes (config.WriteLock), a structural
	// patch, and the file's backup (config.PatchFile).
	writeConfig func(ctx context.Context, apply func(*config.Config) error) error
	// componentAdd and componentRemove apply one component change through
	// componentsvc (Preview then Apply), as principal.
	componentAdd    func(ctx context.Context, component, principal string) error
	componentRemove func(ctx context.Context, component, principal string) error
	// download fetches or verifies and places one pinned file (lane
	// download's body).
	download func(ctx context.Context, req sandboxDownloadRequest) (sandboxDownloadResult, error)
	// contentFetch fetches content kinds; contentImport imports them from a
	// directory the person names.
	contentFetch  func(ctx context.Context, cfg config.Config, kinds []string) error
	contentImport func(cfg config.Config, dir string) error
	// hostedConnect stores typed credential fields for provider in the
	// keychain (a "" name is the one key of a provider with one field).
	hostedConnect func(ctx context.Context, provider string, fields map[string]string) error
	// observerBin is this binary's path (the CLI verbs a setup terminal
	// runs).
	observerBin func() string
	goos        string
	// fileSHA256 and removeFile act on a file Observer placed.
	fileSHA256 func(path string) (string, error)
	removeFile func(path string) error
	// audit writes one metadata-only audit row.
	audit func(ctx context.Context, detail string)
	// applyLive makes a [terminal.sandbox] write take effect in the running
	// daemon (sandbox_live_apply.go) and returns the outcome; nil applies
	// nothing.
	applyLive func(ctx context.Context, backend string) string
	// refreshProbe makes the running daemon's sandbox probe read the host
	// again after a setup record settled (sandboxProbeRefreshFor); nil
	// refreshes nothing.
	refreshProbe func(ctx context.Context, backend string) string
	// defaultWorkspace reports the default workspace for cfg
	// (defaultworkspace.Inspect): its folder, whether Observer finished
	// setting it up, and what keeps it from being used. A consent step run
	// with no folder falls back to it; nil means there is none.
	defaultWorkspace func(cfg config.Config) defaultworkspace.Status
}

// productionSandboxSetupRunIO wires the real I/O for configPath.
func productionSandboxSetupRunIO(configPath string) sandboxSetupRunIO {
	return sandboxSetupRunIO{
		writeConfig: sandboxSetupConfigWriter(configPath),
		componentAdd: func(ctx context.Context, component, principal string) error {
			return sandboxSetupComponentChange(ctx, configPath, componentsvc.Change{Add: []string{component}}, principal)
		},
		componentRemove: func(ctx context.Context, component, principal string) error {
			return sandboxSetupComponentChange(ctx, configPath, componentsvc.Change{Remove: []string{component}}, principal)
		},
		download: sandboxSetupDownload,
		contentFetch: func(ctx context.Context, cfg config.Config, kinds []string) error {
			env := sandboxContentEnvFor(cfg, configPath)
			// The person's click on this step is the opt-in for these kinds,
			// before the row is enabled (the daemon's own first-use fetch
			// waits for the driver to be active).
			env.active = func(k content.Kind) bool { return slices.Contains(kinds, string(k)) }
			var errs []error
			for _, k := range kinds {
				if _, err := env.fetch(ctx, content.Kind(k)); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		},
		contentImport: func(cfg config.Config, dir string) error {
			env := sandboxContentEnvFor(cfg, configPath)
			_, err := sandboxContentImport(env.store, env.trust.VendorKeys, dir)
			return err
		},
		hostedConnect: func(ctx context.Context, provider string, fields map[string]string) error {
			return hostedConnectStore(ctx, configPath, provider, fields)
		},
		observerBin: func() string {
			p, err := os.Executable()
			if err != nil {
				return "observer"
			}
			return p
		},
		goos:       sandboxSetupGOOS(),
		fileSHA256: sandboxSetupFileSHA256,
		removeFile: os.Remove,
		defaultWorkspace: func(cfg config.Config) defaultworkspace.Status {
			return defaultworkspace.Inspect(defaultWorkspaceEnv(cfg), cfg.Workspace.DefaultDir)
		},
	}
}

// sandboxSetupExecOutput runs a fixed argv and returns its output (the
// active check's version read).
var sandboxSetupExecOutput = func(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output() //nolint:gosec // G204: a resolved program path with a constant argv
	return string(out), err
}

// sandboxSetupConfigWriter is the [terminal.sandbox] writer of setup: the
// same lock the dashboard's config save pipeline holds (config.WriteLock is
// its configWriteMu), the config validated, then a structural patch through
// config.PatchFile (which keeps the previous file as its backup), exactly as
// sandboxRememberSignIn writes [terminal.sandbox]. Never a second writer of
// another shape.
func sandboxSetupConfigWriter(configPath string) func(ctx context.Context, apply func(*config.Config) error) error {
	return func(_ context.Context, apply func(*config.Config) error) error {
		path, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			return err
		}
		mu := config.WriteLock()
		mu.Lock()
		defer mu.Unlock()
		cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
		if err != nil {
			return err
		}
		next := cfg
		if err := apply(&next); err != nil {
			return err
		}
		if err := config.Validate(next); err != nil {
			return err
		}
		patches, err := config.StructuralPatches(cfg, next)
		if err != nil {
			return err
		}
		if len(patches) == 0 {
			return nil
		}
		_, err = config.PatchFile(path, next, patches)
		return err
	}
}

// sandboxSetupComponentChange is componentsvc's Preview then Apply bound to
// that preview's fingerprint.
func sandboxSetupComponentChange(ctx context.Context, configPath string, ch componentsvc.Change, principal string) error {
	svc, err := newComponentsService(configPath, nil)
	if err != nil {
		return err
	}
	p, err := svc.Preview(ctx, ch)
	if err != nil {
		return err
	}
	if len(p.ManagedRefused) > 0 {
		return setupErr(http.StatusForbidden, dashapi.SandboxSetupCodeNotAllowedByOrg, "your organization sets this machine's components: %s", strings.Join(p.ManagedRefused, "; "))
	}
	_, err = svc.Apply(ctx, ch, componentsvc.ApplyOptions{ExpectFingerprint: p.Fingerprint, Principal: principal})
	return err
}

// sandboxSetupFileSHA256 hashes a placed file.
func sandboxSetupFileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a file Observer placed and recorded
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sandboxPinConfigKeys maps a pinned download's pin id to the config key the
// runner writes the placed path into.
var sandboxPinConfigKeys = map[string]string{
	"cloud-hypervisor": "terminal.sandbox.vm.cloud_hypervisor_path",
}

// sandboxConfigKeySetters are the disclosed config keys a config_key step
// may write, each with how to set it and read its previous value. A key
// absent here is never written.
var sandboxConfigKeySetters = map[string]struct {
	get func(c *config.Config) string
	set func(c *config.Config, v string)
}{
	"terminal.sandbox.oci.allow_rootful": {
		get: func(c *config.Config) string { return fmt.Sprint(c.Terminal.Sandbox.OCI.AllowRootful) },
		set: func(c *config.Config, v string) { c.Terminal.Sandbox.OCI.AllowRootful = v == "true" },
	},
	"terminal.sandbox.vm.cloud_hypervisor_path": {
		get: func(c *config.Config) string { return c.Terminal.Sandbox.VM.CloudHypervisorPath },
		set: func(c *config.Config, v string) { c.Terminal.Sandbox.VM.CloudHypervisorPath = v },
	},
}

// sandboxPullArgv is the argv of an oci_pull step per engine (the step's
// Package): the existing pull seam run in a setup terminal so the person
// sees the engine's output. An engine absent here has no pull verb in
// Observer and its step is not runnable.
var sandboxPullArgv = map[string][]string{
	"oci": {"sandbox", "oci", "pull"},
}

// runCtx is one run's state, shared by the handlers.
type runCtx struct {
	s       *sandboxSetupService
	si      sandboxSetupInput
	plan    sandboxsetup.Plan
	step    sandboxsetup.Step
	req     dashapi.SandboxSetupRunRequest
	surface string
}

// label is the setup terminal's label (one PTY per step).
func (rc runCtx) label() string {
	return "sandbox-setup:" + rc.si.in.Row.ID + ":" + rc.step.Prereq
}

// recordName is the step's record name.
func (rc runCtx) recordName() string { return sandboxRecordName(rc.step.Prereq, rc.si.in.Row.ID) }

// setupHandler carries out one step.
type setupHandler func(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error)

// runHandlers is THE dispatch table of a run (and a repair or update): one
// handler per Channel.
var runHandlers map[sandboxsetup.Channel]setupHandler

// undoHandlers is the dispatch table of an undo.
var undoHandlers map[sandboxsetup.Channel]setupHandler

func init() {
	runHandlers = map[sandboxsetup.Channel]setupHandler{
		sandboxsetup.ChComponent: runComponent,
		sandboxsetup.ChEnable:    runEnable,
		sandboxsetup.ChConfig:    runConfigKey,
		sandboxsetup.ChPM:        runTerminal,
		sandboxsetup.ChCommand:   runTerminal,
		sandboxsetup.ChPinned:    runPinned,
		sandboxsetup.ChContent:   runContent,
		sandboxsetup.ChOCIPull:   runOCIPull,
		sandboxsetup.ChConsent:   runHostedConsent,
		sandboxsetup.ChOrgShell:  runOrgShellLogin,
		sandboxsetup.ChHostedKey: runHostedConnect,
		sandboxsetup.ChNone:      refuseNotRunnable,
	}
	undoHandlers = map[sandboxsetup.Channel]setupHandler{
		sandboxsetup.ChComponent: undoComponent,
		sandboxsetup.ChEnable:    undoEnable,
		sandboxsetup.ChConfig:    undoConfigKey,
		sandboxsetup.ChPM:        undoPackage,
		sandboxsetup.ChPinned:    undoPinned,
	}
}

// Run implements dashapi.SandboxSetup.
func (s *sandboxSetupService) Run(ctx context.Context, backend string, req dashapi.SandboxSetupRunRequest, surface string) (dashapi.SandboxSetupStarted, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if surface == "" {
		surface = s.o.Surface
	}
	si, p, checked, err := s.planForRun(ctx, backend, req)
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	step, err := s.gate(ctx, si, p, checked, req)
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	rc := runCtx{s: s, si: si, plan: p, step: step, req: req, surface: surface}
	table, ch := runHandlers, step.Channel
	if req.Action == dashapi.SandboxSetupActionUndo {
		table, ch = undoHandlers, undoChannel(step)
	}
	h := table[ch]
	if h == nil {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%s: Observer has no %s for this step; %s", step.Label, req.Action, step.Display)
	}
	started, err := h(ctx, rc)
	s.o.Logger.Info("sandbox setup: step", "backend", backend, "step", step.Prereq, "action", req.Action,
		"channel", step.Channel, "class", step.Class, "surface", surface, "kind", started.Kind, "ok", err == nil)
	if s.run.audit != nil {
		s.run.audit(ctx, fmt.Sprintf("backend=%s step=%s action=%s channel=%s class=%s ok=%v", backend, step.Prereq, req.Action, step.Channel, step.Class, err == nil))
	}
	return started, err
}

// planForRun is the plan a run is gated against: the passive plan, unless
// the request names another fingerprint. A plan shown after "Check this
// machine" carries facts only the active check sees (a service, an image,
// a kernel rung), so the passive plan can never match it; the click on one
// step of one named row is then the opt-in for one probe of that row
// (ruling R1, ledger SBXSETUP-3): the active check runs again and the run is
// gated against what it finds now. A request matching neither is still
// refused as plan_changed, with the checked plan. The probe runs only when
// the gates before the fingerprint would let the run through.
func (s *sandboxSetupService) planForRun(ctx context.Context, backend string, req dashapi.SandboxSetupRunRequest) (sandboxSetupInput, sandboxsetup.Plan, bool, error) {
	si, p, err := s.plan(ctx, backend, false)
	if err != nil || req.Fingerprint == "" || req.Fingerprint == p.Fingerprint || !si.inBuild {
		return si, p, false, err
	}
	if s.preGate(si, p, req) != nil {
		return si, p, false, nil
	}
	si, p, err = s.plan(ctx, backend, true)
	s.o.Logger.Info("sandbox setup: active check for a run", "backend", backend, "step", req.Step, "surface", s.o.Surface, "matched", err == nil && req.Fingerprint == p.Fingerprint)
	return si, p, true, err
}

// preGate is the run gates that come before the fingerprint (the action, the
// module, the kill switch, the organization, a row that cannot run here).
func (s *sandboxSetupService) preGate(si sandboxSetupInput, p sandboxsetup.Plan, req dashapi.SandboxSetupRunRequest) error {
	action := req.Action
	if action == "" {
		action = dashapi.SandboxSetupActionRun
	}
	if !slices.Contains([]string{dashapi.SandboxSetupActionRun, dashapi.SandboxSetupActionUndo, dashapi.SandboxSetupActionUpdate, dashapi.SandboxSetupActionRepair}, action) {
		return setupErr(http.StatusBadRequest, dashapi.SandboxSetupCodeUnknownStep, "unknown action %q (run, undo, update or repair)", req.Action)
	}
	if !sandboxModuleActive(s.host.snapshot(si.cfg)) {
		return setupErr(http.StatusNotFound, dashapi.SandboxSetupCodeNotInBuild, "the sandbox module (%s) is not selected on this machine", sandboxComponent)
	}
	if !si.in.AllowInstall {
		return setupErr(http.StatusForbidden, dashapi.SandboxSetupCodeInstallDisabled, "guided installs are turned off on this machine ([terminal.launch].allow_install)")
	}
	if !si.in.OrgAllowed {
		return setupErr(http.StatusForbidden, dashapi.SandboxSetupCodeNotAllowedByOrg, "your organization does not allow %s on this machine (allowed_backends)", si.in.Row.ID)
	}
	if p.Blocked != "" {
		return setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%s", p.Blocked)
	}
	return nil
}

// gate applies the runner's gates in the plan's order and returns the step.
// checked says p follows an active check (the fresh plan a plan_changed
// refusal carries is then the checked one).
func (s *sandboxSetupService) gate(ctx context.Context, si sandboxSetupInput, p sandboxsetup.Plan, checked bool, req dashapi.SandboxSetupRunRequest) (sandboxsetup.Step, error) {
	action := req.Action
	if action == "" {
		action = dashapi.SandboxSetupActionRun
	}
	if err := s.preGate(si, p, req); err != nil {
		return sandboxsetup.Step{}, err
	}
	if req.Fingerprint != p.Fingerprint {
		fresh := s.wire(ctx, si, p, checked)
		return sandboxsetup.Step{}, &sandboxSetupError{
			status: http.StatusConflict, code: dashapi.SandboxSetupCodePlanChanged,
			msg: "the setup plan changed since it was shown; review the fresh plan and try again", plan: &fresh,
		}
	}
	idx := slices.IndexFunc(p.Steps, func(st sandboxsetup.Step) bool { return st.Prereq == req.Step })
	if idx < 0 {
		return sandboxsetup.Step{}, setupErr(http.StatusBadRequest, dashapi.SandboxSetupCodeUnknownStep, "unknown step %q for %s", req.Step, si.in.Row.ID)
	}
	step := p.Steps[idx]
	switch action {
	case dashapi.SandboxSetupActionUndo:
		return step, gateUndo(si, step)
	case dashapi.SandboxSetupActionUpdate:
		if err := gateLiveRuns(si); err != nil {
			return step, err
		}
		if step.Channel != sandboxsetup.ChPinned || step.Record == nil {
			return step, setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%s: an update of this step is yours to run: %s", step.Label, step.Display)
		}
		return step, gateConsent(step, req)
	}
	if !step.CanRun {
		if elevationWouldRun(si.in, step.Prereq) {
			return step, setupErr(http.StatusForbidden, dashapi.SandboxSetupCodeElevationDisabled, "%s needs your password; turn on [terminal.sandbox.setup].allow_elevated in Settings to run it in a setup terminal, or run it yourself: %s", step.Label, step.Display)
		}
		return step, setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%s is %s and cannot be run here (%s)", step.Label, step.State, strings.TrimSpace(step.Reason+" "+step.Display))
	}
	// The second guard of the elevation switch: whatever the planner said,
	// an elevated step never runs with the key off.
	if step.Class == sandboxsetup.ClassElevated && !si.in.AllowElevated {
		return step, setupErr(http.StatusForbidden, dashapi.SandboxSetupCodeElevationDisabled, "elevated steps are off ([terminal.sandbox.setup].allow_elevated)")
	}
	if step.Class != sandboxsetup.ClassElevated && len(step.Argv) > 0 && step.Argv[0] == "sudo" {
		return step, setupErr(http.StatusForbidden, dashapi.SandboxSetupCodeElevationDisabled, "%s would need elevation but is not an elevated step", step.Label)
	}
	if step.Channel == sandboxsetup.ChPinned {
		return step, gateConsent(step, req)
	}
	return step, nil
}

// elevationWouldRun reports whether the step would be runnable with the
// elevation key on (so a refusal names the key, not a dead end).
func elevationWouldRun(in sandboxsetup.PlanInput, prereq string) bool {
	if in.AllowElevated {
		return false
	}
	in.AllowElevated = true
	for _, st := range sandboxsetup.Build(in).Steps {
		if st.Prereq == prereq {
			return st.CanRun && st.Class == sandboxsetup.ClassElevated
		}
	}
	return false
}

// gateLiveRuns refuses while a live run uses the row, or while no one could
// say whether one does (a CLI whose daemon did not answer: fail closed).
func gateLiveRuns(si sandboxSetupInput) error {
	if si.in.LiveRunsUnknown {
		return setupErr(http.StatusConflict, dashapi.SandboxSetupCodeLiveRuns, "Observer could not ask the running daemon whether a sandboxed run uses %s, so it does not change it from here; try again when the daemon answers, or use the dashboard", si.in.Row.ID)
	}
	if si.in.LiveRuns > 0 {
		return setupErr(http.StatusConflict, dashapi.SandboxSetupCodeLiveRuns, "%s live sandboxed run(s) use %s; end them or wait for them to finish first", fmt.Sprint(si.in.LiveRuns), si.in.Row.ID)
	}
	return nil
}

// gateUndo applies the undo gates: live runs, a shared prerequisite another
// set-up row uses (read again now, never from the plan shown), CanUndo.
func gateUndo(si sandboxSetupInput, step sandboxsetup.Step) error {
	if err := gateLiveRuns(si); err != nil {
		return err
	}
	if others := si.in.InUseBy[step.Prereq]; len(others) > 0 && step.Kind != sandboxsetup.KindComponent && step.Kind != sandboxsetup.KindEnable {
		return setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%s is kept: also used by %s", step.Label, strings.Join(others, ", "))
	}
	if !step.CanUndo {
		if step.UndoNote != "" {
			return setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%s: %s", step.Label, step.UndoNote)
		}
		return setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%s cannot be undone by Observer (only what Observer did is undone)", step.Label)
	}
	return nil
}

// gateConsent requires the request to echo the consent shown (pin, sha256,
// bytes), and a step whose only source is a file the person names (a
// managed node with no org mirror) to name one: it never reaches a fetch.
func gateConsent(step sandboxsetup.Step, req dashapi.SandboxSetupRunRequest) error {
	c, got := step.Consent, req.Consent
	if c == nil || got == nil || got.Pin != c.Pin || !strings.EqualFold(got.SHA256, c.SHA256) || got.Bytes != c.Bytes {
		return setupErr(http.StatusPreconditionFailed, dashapi.SandboxSetupCodeConsentRequired, "%s downloads a file: confirm the version, size and sha256 shown before it runs", step.Label)
	}
	if c.Source == sandboxsetup.SourceFromFile && strings.TrimSpace(req.FromFile) == "" {
		return setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%s: %v", step.Label, errSandboxDownloadManaged)
	}
	return nil
}

// undoChannel is the handler key of an undo: a record a package channel
// installed is undone through its derived uninstall, whatever class the
// step reads as now.
func undoChannel(step sandboxsetup.Step) sandboxsetup.Channel {
	if step.Kind == sandboxsetup.KindComponent {
		return sandboxsetup.ChComponent
	}
	if step.Kind == sandboxsetup.KindEnable {
		return sandboxsetup.ChEnable
	}
	if step.Record != nil {
		if toolinstall.HasDefinedUninstall(step.Record.Channel) {
			return sandboxsetup.ChPM
		}
		return sandboxsetup.Channel(step.Record.Channel)
	}
	return step.Channel
}

// applied makes a [terminal.sandbox] write take effect in the running daemon
// and returns the done answer with the fresh plan and the apply's note.
func (rc runCtx) applied(ctx context.Context) (dashapi.SandboxSetupStarted, error) {
	outcome := ""
	if rc.s.run.applyLive != nil {
		outcome = rc.s.run.applyLive(ctx, rc.si.in.Row.ID)
	}
	rc.s.o.Logger.Info("sandbox setup: live apply", "backend", rc.si.in.Row.ID, "surface", rc.surface, "outcome", outcome)
	started, err := rc.fresh(ctx)
	if err == nil {
		started.Note = sandboxLiveApplyNotes[outcome]
	}
	return started, err
}

// fresh is the done answer with the fresh plan.
func (rc runCtx) fresh(ctx context.Context) (dashapi.SandboxSetupStarted, error) {
	si, p, err := rc.s.plan(ctx, rc.si.in.Row.ID, false)
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	w := rc.s.wire(ctx, si, p, false)
	return dashapi.SandboxSetupStarted{Kind: dashapi.SandboxSetupStartedDone, Plan: &w}, nil
}

// verifyFor is the step's settle check: the prerequisite's own Detect read
// again passively after the run ("" = not detected yet).
func (rc runCtx) verifyFor() func() string {
	h, row, id := rc.s.host, rc.si.in.Row, rc.step.Prereq
	return func() string {
		cfg, err := h.loadConfig()
		if err != nil {
			return ""
		}
		f, ok := passiveFacts(h, cfg, sandboxbackend.Capability{ID: row.ID, Setup: []string{id}}, nil)[id]
		if !ok || !f.Present {
			return ""
		}
		if f.Path != "" {
			return f.Path
		}
		return "detected"
	}
}

// sandboxSettleCtx is what the settle rules read about one setup terminal
// step that exited.
type sandboxSettleCtx struct {
	// exitOK: the step exited 0.
	exitOK bool
	// passive is the prerequisite's own passive fact read again; hasPassive
	// false means only the active check can see it (Apple container's service
	// and image, an oci row's image).
	passive    sandboxsetup.Fact
	hasPassive bool
	// checkDone runs the row's active check once and reports whether the
	// step reads done.
	checkDone func() bool
}

// sandboxSettleRule is one row of the ordered settle table: the first row
// that hits answers where the prerequisite resolved ("": not found).
type sandboxSettleRule struct {
	name  string
	match func(c sandboxSettleCtx) (found string, hit bool)
}

// sandboxSettleRules decide a terminal step's settle, top-down:
//
//   - passive_fact: a prerequisite with a passive fact is judged by it, as
//     before (installed when present, else installed_not_found), whatever
//     the exit;
//   - exit_failed: a failed step runs no check (install_failed follows from
//     the exit);
//   - checked_done: a step only the active check can see that exited 0
//     settles installed when that check reads it done (the click that ran
//     the step is the opt-in for this one probe of the row, ruling R1);
//   - checked_not_done: otherwise installed_not_found.
var sandboxSettleRules = []sandboxSettleRule{
	{"passive_fact", func(c sandboxSettleCtx) (string, bool) {
		if !c.hasPassive {
			return "", false
		}
		switch {
		case !c.passive.Present:
			return "", true
		case c.passive.Path != "":
			return c.passive.Path, true
		}
		return "detected", true
	}},
	{"exit_failed", func(c sandboxSettleCtx) (string, bool) { return "", !c.exitOK }},
	{"checked_done", func(c sandboxSettleCtx) (string, bool) {
		return "checked", c.checkDone != nil && c.checkDone()
	}},
	{"checked_not_done", func(sandboxSettleCtx) (string, bool) { return "", true }},
}

// sandboxSettleDecision walks sandboxSettleRules for c and returns the answer
// and the row that decided it.
func sandboxSettleDecision(c sandboxSettleCtx) (string, string) {
	for _, r := range sandboxSettleRules {
		if found, hit := r.match(c); hit {
			return found, r.name
		}
	}
	return "", ""
}

// settleCheck is a setup terminal step's settle check (sandboxSettleRules):
// its own passive fact read again, or the row's active check after an exit 0
// when only that check can see the step.
func (rc runCtx) settleCheck() func(exitOK bool) string {
	s, h, backend, id := rc.s, rc.s.host, rc.si.in.Row.ID, rc.step.Prereq
	return func(exitOK bool) string {
		c := sandboxSettleCtx{exitOK: exitOK, checkDone: func() bool { return s.checkStepDone(context.Background(), backend, id) }}
		if cfg, err := h.loadConfig(); err == nil {
			c.passive, c.hasPassive = passiveFacts(h, cfg, sandboxbackend.Capability{ID: backend, Setup: []string{id}}, nil)[id]
		}
		found, rule := sandboxSettleDecision(c)
		s.o.Logger.Info("sandbox setup: settle check", "backend", backend, "step", id, "rule", rule, "found", found != "")
		return found
	}
}

// checkStepDone runs backend's active check once and reports whether its
// step prereq reads done. The step's own record is left out: it is still in
// flight while its exit settles.
func (s *sandboxSetupService) checkStepDone(ctx context.Context, backend, prereq string) bool {
	ctx, cancel := context.WithTimeout(ctx, sandboxSetupProbeTimeout+5*time.Second)
	defer cancel()
	row, err := rowFor(backend)
	if err != nil {
		return false
	}
	si, err := gatherSandboxSetupInput(ctx, s.host, row)
	if err != nil || !si.inBuild {
		return false
	}
	delete(si.in.Records, prereq)
	p := buildPlan(activeCheck(ctx, s.host, si), si.inBuild)
	done := false
	for _, st := range p.Steps {
		if st.Prereq == prereq {
			done = st.State == sandboxsetup.StateDone
		}
	}
	s.o.Logger.Info("sandbox setup: active check after a step", "backend", backend, "step", prereq, "surface", s.o.Surface, "done", done)
	return done
}

// recordDone records an in-process step that finished at once.
func (rc runCtx) recordDone(ctx context.Context, channel string, argv []string, display string, verify func() string) error {
	l := rc.s.ledger
	if l == nil {
		return nil
	}
	id, err := l.BeginSandboxOp(ctx, sandboxInstallRecord{Name: rc.recordName(), Backend: rc.si.in.Row.ID, Channel: channel, Argv: argv, Display: display})
	if err != nil {
		return err
	}
	_, err = l.FinishSandboxOp(ctx, id, sandboxOpOutcome{}, verify)
	return err
}

// ---- run handlers -----------------------------------------------------------

func refuseNotRunnable(_ context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	return dashapi.SandboxSetupStarted{}, setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%s is a step for you to follow: %s", rc.step.Label, rc.step.Display)
}

// runComponent selects the row's component through componentsvc.
func runComponent(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	comp := rc.si.in.ComponentID
	if comp == "" {
		return refuseNotRunnable(ctx, rc)
	}
	if err := rc.s.run.componentAdd(ctx, comp, rc.surface); err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	snapshot, load := rc.s.host.snapshot, rc.s.host.loadConfig
	verify := func() string {
		cfg, err := load()
		if err == nil && sandboxSetupComponentSelected(snapshot(cfg), rc.si.in.Row.ID, comp) {
			return comp
		}
		return ""
	}
	if err := rc.recordDone(ctx, string(sandboxsetup.ChComponent), []string{"components", "add", comp}, "observer components add "+comp, verify); err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	return rc.fresh(ctx)
}

// runEnable turns the sandbox on and appends the row to the END of
// [terminal.sandbox].backends (ruling R4), so an existing preference never
// changes.
func runEnable(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	id := rc.si.in.Row.ID
	err := rc.s.run.writeConfig(ctx, func(c *config.Config) error {
		listed := sandboxSetupListed(c.Terminal.Sandbox)
		if !slices.Contains(listed, id) {
			listed = append(listed, id)
		}
		c.Terminal.Sandbox.Backends = listed
		c.Terminal.Sandbox.Enabled = true
		return nil
	})
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	load := rc.s.host.loadConfig
	verify := func() string {
		cfg, err := load()
		if err == nil && cfg.Terminal.Sandbox.Enabled && slices.Contains(sandboxSetupListed(cfg.Terminal.Sandbox), id) {
			return id
		}
		return ""
	}
	if err := rc.recordDone(ctx, string(sandboxsetup.ChEnable), []string{"sandbox_enable", id}, "add "+id+" to [terminal.sandbox].backends and turn the sandbox on", verify); err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	return rc.applied(ctx)
}

// runConfigKey writes one disclosed key, recording its previous value.
func runConfigKey(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	key := rc.step.Package
	if _, ok := sandboxConfigKeySetters[key]; !ok {
		return refuseNotRunnable(ctx, rc)
	}
	prev, err := writeConfigKey(ctx, rc.s.run.writeConfig, key, "true")
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	if err := rc.recordDone(ctx, string(sandboxsetup.ChConfig), []string{"config_key", key, "true", "previous=" + prev}, "set "+key+" = true", rc.verifyFor()); err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	return rc.fresh(ctx)
}

// writeConfigKey sets key to value through the writer and returns its
// previous value.
func writeConfigKey(ctx context.Context, write func(context.Context, func(*config.Config) error) error, key, value string) (string, error) {
	setter, ok := sandboxConfigKeySetters[key]
	if !ok {
		return "", fmt.Errorf("sandbox setup: %s is not a key setup writes", key)
	}
	prev := ""
	err := write(ctx, func(c *config.Config) error {
		prev = setter.get(c)
		setter.set(c, value)
		return nil
	})
	return prev, err
}

// elevateArgv wraps an elevated step's argv: on Linux, WSL and macOS under
// sudo (an argv toolinstall already built under sudo is kept as it is, so
// its uninstall reads back), on Windows in the fixed Start-Process -Verb
// RunAs shape so Windows shows its own consent.
func elevateArgv(argv []string, goos string) []string {
	if len(argv) == 0 {
		return nil
	}
	if goos == "windows" {
		args := make([]string, 0, len(argv)-1)
		for _, a := range argv[1:] {
			args = append(args, psSingleQuote(a))
		}
		list := "@()"
		if len(args) > 0 {
			list = "@(" + strings.Join(args, ",") + ")"
		}
		script := strings.Join([]string{
			"$ErrorActionPreference = 'Stop'",
			"$p = Start-Process -FilePath " + psSingleQuote(argv[0]) + " -Verb RunAs -Wait -PassThru -ArgumentList " + list,
			"exit $p.ExitCode",
		}, "\n")
		return []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script}
	}
	if argv[0] == "sudo" {
		return append([]string(nil), argv...)
	}
	return append([]string{"sudo", "--"}, argv...)
}

// psSingleQuote quotes s as a PowerShell single-quoted string.
func psSingleQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// runTerminal runs a pm or terminal_cmd step's server-derived argv in a
// setup terminal (elevated only when the class says so) and records it.
func runTerminal(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	argv := append([]string(nil), rc.step.Argv...)
	if len(argv) == 0 {
		return refuseNotRunnable(ctx, rc)
	}
	elevated := rc.step.Class == sandboxsetup.ClassElevated
	if elevated {
		argv = elevateArgv(argv, rc.s.run.goos)
	}
	channel := string(rc.step.Channel)
	if rc.step.Channel == sandboxsetup.ChPM {
		// The record's channel is the package manager's, so PlanUninstall
		// derives the same channel's remove argv.
		if ch := pmChannelFor(rc.step.Argv, rc.step.Package); ch != "" {
			channel = ch
		}
	}
	rec := sandboxInstallRecord{Name: rc.recordName(), Backend: rc.si.in.Row.ID, Channel: channel, Argv: argv, Display: toolinstall.DisplayArgv(argv), Elevated: elevated}
	return rc.spawnRecorded(ctx, rec, argv)
}

// spawnRecorded spawns argv through Spawn and records it (a PTY handle is
// tracked by the ledger; a foreground run is settled with its exit code).
func (rc runCtx) spawnRecorded(ctx context.Context, rec sandboxInstallRecord, argv []string) (dashapi.SandboxSetupStarted, error) {
	if rc.s.o.Spawn == nil {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusServiceUnavailable, dashapi.SandboxSetupCodeTerminalUnavailable, "no setup terminal is available here: %s", errTerminalUnavailableText)
	}
	if rc.s.ledger == nil {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusServiceUnavailable, dashapi.SandboxSetupCodeTerminalUnavailable, "%v", errSandboxSetupNoLedger)
	}
	handle, code, err := rc.s.o.Spawn(ctx, argv, rc.label())
	if err != nil {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusServiceUnavailable, dashapi.SandboxSetupCodeTerminalUnavailable, "the setup terminal did not start: %v", err)
	}
	if handle == "" {
		if _, err := rc.s.ledger.SettleSandboxForeground(ctx, rec, code, rc.settleCheck()); err != nil {
			return dashapi.SandboxSetupStarted{}, err
		}
		return rc.fresh(ctx)
	}
	if _, err := rc.s.ledger.RecordSandboxInstall(ctx, rec, handle, rc.settleCheck()); err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	return dashapi.SandboxSetupStarted{Kind: dashapi.SandboxSetupStartedTerminal, Handle: handle, Label: rc.step.Label}, nil
}

// errTerminalUnavailableText names why no setup terminal runs.
const errTerminalUnavailableText = "the dashboard terminal is off ([handoff].allow_dashboard_launch) or this platform has no PTY; run the command yourself"

// runPinned downloads (or verifies a local file) and places one pinned file
// as an in-process op, then writes the placed path into its config key.
func runPinned(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	l := rc.s.ledger
	if l == nil {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusServiceUnavailable, dashapi.SandboxSetupCodeTerminalUnavailable, "%v", errSandboxSetupNoLedger)
	}
	c := rc.step.Consent
	source := c.Source
	if rc.req.FromFile != "" {
		if !filepath.IsAbs(rc.req.FromFile) {
			return dashapi.SandboxSetupStarted{}, setupErr(http.StatusBadRequest, dashapi.SandboxSetupCodeStepNotRunnable, "from_file must be an absolute path")
		}
		source = "from_file"
	}
	recID, err := l.BeginSandboxOp(ctx, sandboxInstallRecord{
		Name: rc.recordName(), Backend: rc.si.in.Row.ID, Channel: string(sandboxsetup.ChPinned),
		Argv: []string{"pinned_download", c.Pin, c.Version}, Display: "download " + c.Pin + " " + c.Version, Source: source,
	})
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	opID := rc.s.ops.start(string(toolinstall.StatusInstalling))
	key := sandboxPinConfigKeys[c.Pin]
	write, download, verify := rc.s.run.writeConfig, rc.s.run.download, rc.verifyFor()
	ops, managed, logger := rc.s.ops, rc.si.in.Managed, rc.s.o.Logger
	go func() {
		bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
		defer cancel()
		res, derr := download(bctx, sandboxDownloadRequest{
			Pin: c.Pin, FromFile: rc.req.FromFile, Managed: managed,
			Progress: func(done, total int64) { ops.progress(opID, done, total) },
		})
		if derr == nil && key != "" {
			_, derr = writeConfigKey(bctx, write, key, res.Path)
		}
		out := sandboxOpOutcome{Err: derr, Digest: res.SHA256, PlacedPath: res.Path}
		st, ferr := l.FinishSandboxOp(bctx, recID, out, func() string {
			if res.Path != "" {
				return res.Path
			}
			return verify()
		})
		if ferr != nil {
			logger.Warn("sandbox setup: settling a download failed", "pin", c.Pin, "err", ferr)
			st = toolinstall.StatusInstallFailed
		}
		ops.finish(opID, string(st), derr)
	}()
	return dashapi.SandboxSetupStarted{Kind: dashapi.SandboxSetupStartedOp, OpID: opID, Label: rc.step.Label}, nil
}

// runContent fetches the step's content kinds, or imports them from the
// directory the person named (from_file).
func runContent(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	kinds := strings.Split(rc.step.Package, ",")
	var err error
	if dir := strings.TrimSpace(rc.req.FromFile); dir != "" {
		if !filepath.IsAbs(dir) {
			return dashapi.SandboxSetupStarted{}, setupErr(http.StatusBadRequest, dashapi.SandboxSetupCodeStepNotRunnable, "the import directory must be an absolute path")
		}
		err = rc.s.run.contentImport(rc.si.cfg, dir)
	} else {
		err = rc.s.run.contentFetch(ctx, rc.si.cfg, kinds)
	}
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	if err := rc.recordDone(ctx, string(sandboxsetup.ChContent), append([]string{"content"}, kinds...), "sandbox content "+strings.Join(kinds, ", "), rc.verifyFor()); err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	return rc.fresh(ctx)
}

// runOCIPull runs the engine's existing pull verb in a setup terminal.
func runOCIPull(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	tail, ok := sandboxPullArgv[rc.step.Package]
	if !ok {
		return refuseNotRunnable(ctx, rc)
	}
	argv := append([]string{rc.s.run.observerBin()}, tail...)
	rec := sandboxInstallRecord{Name: rc.recordName(), Backend: rc.si.in.Row.ID, Channel: string(sandboxsetup.ChOCIPull), Argv: argv, Display: toolinstall.DisplayArgv(argv)}
	return rc.spawnRecorded(ctx, rec, argv)
}

// runHostedConsent runs the provider's consent screen in a setup terminal,
// where the person reads what leaves the machine and answers (the existing
// `observer sandbox hosted consent` verb). from_file names the workspace the
// consent is for. With none, the run falls back to the default workspace
// when Observer has finished setting it up (review finding 6, 2026-11-12),
// so `observer sandbox setup run <backend> --step <consent>` works with no
// flag; otherwise it is refused naming the fix, because a setup terminal
// starts in the home directory, which is never uploaded, so a consent
// without a project could only fail (upload_scope_home; seen live on
// 2026-11-12).
func runHostedConsent(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	ws := strings.TrimSpace(rc.req.FromFile)
	if ws == "" {
		var st defaultworkspace.Status
		if rc.s.run.defaultWorkspace != nil {
			st = rc.s.run.defaultWorkspace(rc.si.cfg)
		}
		if !st.Ready || st.Dir == "" {
			why := ""
			if st.Problem != "" {
				why = " (" + strings.TrimSuffix(st.Problem, ".") + ")"
			}
			return dashapi.SandboxSetupStarted{}, setupErr(http.StatusBadRequest, dashapi.SandboxSetupCodeStepNotRunnable,
				"the default workspace is not ready%s: set it up in Terminals > Settings > Default workspace (or restart Observer), or pick the folder the consent is for (--from-file <folder>)", why)
		}
		ws = st.Dir
	}
	if !filepath.IsAbs(ws) {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusBadRequest, dashapi.SandboxSetupCodeStepNotRunnable, "the workspace must be an absolute path")
	}
	argv := []string{rc.s.run.observerBin(), "sandbox", "hosted", "consent", rc.si.in.Row.ID, "--workspace", ws}
	rec := sandboxInstallRecord{Name: rc.recordName(), Backend: rc.si.in.Row.ID, Channel: string(sandboxsetup.ChConsent), Argv: argv, Display: toolinstall.DisplayArgv(argv)}
	return rc.spawnRecorded(ctx, rec, argv)
}

// runOrgShellLogin runs the org-shell device sign-in in a setup terminal
// (the existing `observer sandbox org-shell login` verb shows its code).
func runOrgShellLogin(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	argv := []string{rc.s.run.observerBin(), "sandbox", "org-shell", "login"}
	rec := sandboxInstallRecord{Name: rc.recordName(), Backend: rc.si.in.Row.ID, Channel: string(sandboxsetup.ChOrgShell), Argv: argv, Display: toolinstall.DisplayArgv(argv)}
	return rc.spawnRecorded(ctx, rec, argv)
}

// runHostedConnect stores the typed credential in the keychain: the one key
// (Key) of a provider that needs one, or each named field (Fields) of a
// provider that needs several, through the same store the Hosted sandboxes
// panel and `observer sandbox hosted connect` use. A value is never logged,
// never echoed and never recorded; a refusal names a field, never a value.
func runHostedConnect(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	fields := make(map[string]string, len(rc.req.Fields)+1)
	for k, v := range rc.req.Fields {
		if k == "" {
			return dashapi.SandboxSetupStarted{}, setupErr(http.StatusBadRequest, dashapi.SandboxSetupCodeStepNotRunnable, "a credential field has no name")
		}
		fields[k] = v
	}
	if rc.req.Key != "" {
		fields[""] = rc.req.Key
	}
	typed := false
	for _, v := range fields {
		typed = typed || strings.TrimSpace(v) != ""
	}
	if !typed {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusBadRequest, dashapi.SandboxSetupCodeStepNotRunnable, "type the provider's API key to store it")
	}
	if err := rc.s.run.hostedConnect(ctx, rc.si.in.Row.ID, fields); err != nil {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusBadRequest, dashapi.SandboxSetupCodeStepNotRunnable, "%v", err)
	}
	return rc.fresh(ctx)
}

// ---- undo handlers ----------------------------------------------------------

// recordRow is the step's record id and name, or an error when none.
func (rc runCtx) recordID() (int64, error) {
	if rc.step.Record == nil {
		return 0, setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%s has no record of what Observer did", rc.step.Label)
	}
	return rc.step.Record.ID, nil
}

// undoComponent removes the row's component (its data is kept).
func undoComponent(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	id, err := rc.recordID()
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	uerr := rc.s.run.componentRemove(ctx, rc.si.in.ComponentID, rc.surface)
	if rc.s.ledger != nil {
		if merr := rc.s.ledger.MarkSandboxUndone(ctx, rc.recordName(), id, "observer components remove "+rc.si.in.ComponentID, uerr); merr != nil && uerr == nil {
			uerr = merr
		}
	}
	if uerr != nil {
		return dashapi.SandboxSetupStarted{}, uerr
	}
	return rc.fresh(ctx)
}

// undoEnable removes the row from backends (the sandbox stays on).
func undoEnable(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	id := rc.si.in.Row.ID
	err := rc.s.run.writeConfig(ctx, func(c *config.Config) error {
		var keep []string
		for _, b := range sandboxSetupListed(c.Terminal.Sandbox) {
			if b != id {
				keep = append(keep, b)
			}
		}
		c.Terminal.Sandbox.Backends = keep
		return nil
	})
	// The enable step's record is marked undone; an enable done before that
	// step recorded has none to mark.
	if rec := rc.step.Record; rec != nil && rc.s.ledger != nil {
		if merr := rc.s.ledger.MarkSandboxUndone(ctx, rc.recordName(), rec.ID, "remove "+id+" from [terminal.sandbox].backends", err); merr != nil && err == nil {
			err = merr
		}
	}
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	return rc.applied(ctx)
}

// undoConfigKey restores a key's previous value from the record.
func undoConfigKey(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	recID, err := rc.recordID()
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	row, err := rc.s.recordRow(ctx, rc.recordName(), recID)
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	key, prev, ok := configKeyRecord(row.Argv)
	if !ok {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "the record of %s does not say what to restore", rc.step.Label)
	}
	_, uerr := writeConfigKey(ctx, rc.s.run.writeConfig, key, prev)
	if merr := rc.s.ledger.MarkSandboxUndone(ctx, rc.recordName(), recID, "restore "+key, uerr); merr != nil && uerr == nil {
		uerr = merr
	}
	if uerr != nil {
		return dashapi.SandboxSetupStarted{}, uerr
	}
	return rc.fresh(ctx)
}

// configKeyRecord reads a config_key record's argv: ["config_key", key,
// value, "previous=<v>"].
func configKeyRecord(argv []string) (key, prev string, ok bool) {
	if len(argv) < 4 || argv[0] != "config_key" || !strings.HasPrefix(argv[3], "previous=") {
		return "", "", false
	}
	return argv[1], strings.TrimPrefix(argv[3], "previous="), true
}

// recordRow loads the step's record (it must still be the latest).
func (s *sandboxSetupService) recordRow(ctx context.Context, name string, id int64) (store.ToolInstallRow, error) {
	if s.ledger == nil {
		return store.ToolInstallRow{}, errSandboxSetupNoLedger
	}
	return s.ledger.latestSandbox(ctx, name, id)
}

// undoPackage runs the derived uninstall of a package step in a setup
// terminal (remove, never purge; under sudo when the install was).
func undoPackage(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	recID, err := rc.recordID()
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	if rc.s.ledger == nil {
		return dashapi.SandboxSetupStarted{}, errSandboxSetupNoLedger
	}
	if rc.s.o.Spawn == nil {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusServiceUnavailable, dashapi.SandboxSetupCodeTerminalUnavailable, "no setup terminal is available here: %s", errTerminalUnavailableText)
	}
	code := 0
	started, err := rc.s.ledger.UninstallSandbox(ctx, rc.recordName(), recID, func(argv []string) (string, error) {
		h, c, err := rc.s.o.Spawn(ctx, argv, rc.label()+":undo")
		code = c
		return h, err
	})
	if err != nil {
		if errors.Is(err, dashapi.ErrToolInstallStale) || errors.Is(err, dashapi.ErrToolUninstallUnsupported) {
			return dashapi.SandboxSetupStarted{}, setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%v", err)
		}
		return dashapi.SandboxSetupStarted{}, err
	}
	if started.Handle == "" {
		if err := rc.s.ledger.SettleSandboxUninstall(ctx, rc.recordName(), recID, code); err != nil {
			return dashapi.SandboxSetupStarted{}, err
		}
		return rc.fresh(ctx)
	}
	return dashapi.SandboxSetupStarted{Kind: dashapi.SandboxSetupStartedTerminal, Handle: started.Handle, Label: rc.step.Label}, nil
}

// undoPinned deletes the file Observer placed after re-checking its digest,
// then clears its config key. A file whose digest no longer matches is not
// Observer's to delete: the undo refuses and says so.
func undoPinned(ctx context.Context, rc runCtx) (dashapi.SandboxSetupStarted, error) {
	recID, err := rc.recordID()
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	row, err := rc.s.recordRow(ctx, rc.recordName(), recID)
	if err != nil {
		return dashapi.SandboxSetupStarted{}, err
	}
	if row.PlacedPath == "" || row.Digest == "" {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "the record of %s names no placed file", rc.step.Label)
	}
	sum, err := rc.s.run.fileSHA256(row.PlacedPath)
	if err == nil && !strings.EqualFold(sum, row.Digest) {
		return dashapi.SandboxSetupStarted{}, setupErr(http.StatusConflict, dashapi.SandboxSetupCodeStepNotRunnable, "%s changed since Observer placed it (its sha256 differs), so Observer leaves it alone", row.PlacedPath)
	}
	var uerr error
	if err == nil {
		uerr = rc.s.run.removeFile(row.PlacedPath)
	}
	if key := sandboxPinConfigKeys[pinOfRecord(row.Argv)]; key != "" && uerr == nil {
		_, uerr = writeConfigKey(ctx, rc.s.run.writeConfig, key, "")
	}
	if merr := rc.s.ledger.MarkSandboxUndone(ctx, rc.recordName(), recID, "remove "+row.PlacedPath, uerr); merr != nil && uerr == nil {
		uerr = merr
	}
	if uerr != nil {
		return dashapi.SandboxSetupStarted{}, uerr
	}
	return rc.fresh(ctx)
}

// pinOfRecord is the pin id a pinned_download record's argv names.
func pinOfRecord(argv []string) string {
	if len(argv) >= 2 && argv[0] == string(sandboxsetup.ChPinned) {
		return argv[1]
	}
	return ""
}

// sandboxPMChannels are the package-manager channels a pm step's argv can
// come from (toolinstall's host package-manager table).
var sandboxPMChannels = []string{"apt", "dnf", "pacman", "zypper", "apk", "brew"}

// pmChannelFor is the package-manager channel whose InstallArgvFor of pkg
// is exactly argv ("" when none is), so the record's channel is the one
// toolinstall.PlanUninstall reads back.
func pmChannelFor(argv []string, pkg string) string {
	for _, name := range sandboxPMChannels {
		pm, ok := toolinstall.PackageManagerByName(name)
		if !ok {
			continue
		}
		if ch, got, ok := toolinstall.InstallArgvFor(pm, []string{pkg}); ok && slices.Equal(got, argv) {
			return ch
		}
	}
	return ""
}

// sandboxSetupGOOS is the build's GOOS (a function so the runner's I/O
// struct stays the one place it is read).
func sandboxSetupGOOS() string { return runtime.GOOS }
