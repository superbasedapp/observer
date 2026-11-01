//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// terminal_sandbox_mxc.go is the mxc-process driver's daemon side (sandbox
// plan v2 sections 4.6, 5.2, 5.6, 11.3 and 13 P6; lane SBX-P6): Microsoft
// Execution Containers' ProcessContainer on native Windows 11. The pure
// decisions are internal/sandboxmxc's; the C ABI is internal/sandboxmxcdll,
// which only the helper verbs in terminal_sandbox_mxc_windows.go import,
// so the daemon never loads mxc_ffi.dll (TestMXCLibraryOnlyInTheHelper).
// The driver registers itself from init; terminal_sandbox_mxc_omit.go is
// its twin in a build without it.
//
// What runs where: the daemon's runtime probes through a short-lived
// `observer sandbox-mxc-probe` process (only when the driver is selected,
// the sandbox is on and "mxc-process" is listed), prepares the workspace
// with the shared step, writes the run record and a per-run plan file, and
// listens for the run's OOB stream; the PTY child (inside the terminal's
// own ConPTY) is `observer sandbox-mxc-host --plan <file> ... -- observer
// <verb> ...`, which verifies and loads the MXC files, validates the run's
// config document with MXC's own probe, serves the run's one loopback port
// (relay, model proxy, egress gateway, box OOB), hops the relay to the
// daemon over the owner-only named pipe, and runs `wxc-exec --config
// <file>` (an owner-only file removed once read, never the document on a
// command line: finding F2) as a console client of the same ConPTY.

// The driver's ids, helper verbs and flags.
const (
	mxcComponent = "terminals.sandbox.mxc"
	mxcHostVerb  = "sandbox-mxc-host"
	mxcProbeVerb = "sandbox-mxc-probe"
	// mxcPlanVersion is the plan file's schema version (2: the protected
	// placeholders, finding F3).
	mxcPlanVersion = 2
	// mxcBoxDirEnv names the run's box directory (the launch record and
	// the loopback record) in the box's environment. A box that changes it
	// can only point its own hooks at a record it cannot sign for: the
	// round trip fails and gate events block.
	mxcBoxDirEnv = "OBSERVER_SANDBOX_BOX_DIR"
	// mxcFlagPlan, mxcFlagRelayRun and mxcFlagObserverDir are the host
	// verb's flags before its "--".
	mxcFlagPlan        = "--plan"
	mxcFlagRelayRun    = "--relay-run"
	mxcFlagObserverDir = "--observer-dir"
	// mxcDefaultProbeTimeout bounds the probe helper when the config says
	// nothing (at least 4 s for the first run of a new binary, JSP-2).
	mxcDefaultProbeTimeout = 30 * time.Second
	// mxcOOBAcceptWait is how long the daemon waits for the helper to open
	// the run's OOB stream.
	mxcOOBAcceptWait = 2 * time.Minute
)

func init() {
	registerSandboxDriver(sandboxDriverReg{
		backend: sandboxbackend.BackendMXCProcess, component: mxcComponent,
		build: newMXCDriver,
		// The daemon serves the capture relay on Windows only while this
		// driver is selected (the relay stays Linux-only otherwise).
		relayOS: "windows",
		// The box writes to the handles wxc-exec inherits (RERUN2 D1).
		cliConsoleHost: true,
	})
	sandboxHelperFuncs[mxcHostVerb] = runMXCHost
	sandboxHelperFuncs[mxcProbeVerb] = runMXCProbe
	sandboxWrapRelays = append(sandboxWrapRelays, mxcRelayOfWrap)
	sandboxOOBSources = append(sandboxOOBSources, mxcOOBSource)
}

// mxcRow is the registry row.
func mxcRow() sandboxbackend.Capability {
	row, _ := sandboxbackend.Get(sandboxbackend.BackendMXCProcess)
	return row
}

// mxcProbeRunner runs the probe helper and returns its answer (a variable
// so a test can count calls and feed answers).
var mxcProbeRunner = runMXCProbeHelper

// mxcHostOS is the operating system the driver judges (a test seam).
var mxcHostOS = func() string { return runtime.GOOS }

// mxcDriver is the mxc-process lifecycle service over one runtime.
type mxcDriver struct {
	r   *sandboxRuntime
	cfg config.TerminalSandboxMXCConfig

	mu     sync.Mutex
	last   sandboxmxc.ProbeResult
	lastAt time.Time
}

// newMXCDriver builds the driver. Nothing is probed until a dialog or a
// launch asks.
func newMXCDriver(r *sandboxRuntime, full config.Config) sandboxDriver {
	return &mxcDriver{r: r, cfg: full.Terminal.Sandbox.MXC}
}

// listed reports whether mxc-process is among the enabled backends (or the
// CLI named it).
func (d *mxcDriver) listed() bool {
	return slices.Contains(sandboxEnabledBackends(d.r.cfg), sandboxbackend.BackendMXCProcess) || d.r.forceBackend == sandboxbackend.BackendMXCProcess
}

// probe is the selection input. Nothing is started while mxc-process is
// not listed, and off Windows the ladder stops at its platform row without
// starting anything.
func (d *mxcDriver) probe(ctx context.Context) sandboxselect.Probe {
	if !d.listed() {
		return sandboxselect.Probe{Compiled: true, Verdict: sandboxselect.VerdictDisabledByConfig, Reason: "mxc-process is not in [terminal.sandbox].backends"}
	}
	res := d.probeResult(ctx)
	p := sandboxselect.Probe{Compiled: true, Verdict: res.Verdict.Code, Reason: res.Verdict.Reason, Sources: sourceIDs(d.r.sources())}
	if res.Verdict.OK() {
		p.Version, p.VersionAuthenticated = res.Version, true
		return p
	}
	// A refused probe is never chosen; the row's own minimum fills the pin
	// so the refusal reaches S4 unmasked (the oci-runc precedent).
	p.Version, p.VersionAuthenticated = mxcRow().Control.Pins.RequiredMin, true
	return p
}

// version is the library version the last probe read.
func (d *mxcDriver) version() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last.Version
}

// probeResult runs (or reuses, for the probe TTL) the probe helper.
func (d *mxcDriver) probeResult(ctx context.Context) sandboxmxc.ProbeResult {
	if mxcHostOS() != "windows" {
		return sandboxmxc.Probe(sandboxmxc.HostFacts{Windows: false, Active: true}, sandboxmxc.ManifestX64)
	}
	d.mu.Lock()
	if !d.lastAt.IsZero() && time.Since(d.lastAt) < sandboxProbeTTL {
		res := d.last
		d.mu.Unlock()
		return res
	}
	d.mu.Unlock()
	timeout := mxcDefaultProbeTimeout
	if s := d.cfg.ProbeTimeoutSeconds; s > 0 {
		timeout = time.Duration(s) * time.Second
	}
	res := mxcProbeRunner(ctx, d.r.observerBin, d.r.observerDir, timeout)
	d.mu.Lock()
	d.last, d.lastAt = res, time.Now()
	d.mu.Unlock()
	if res.Rule == mxcSignedRuleID("age") {
		// The installed signed manifest is past its age floor: every launch
		// refuses until a current one is in, so the daemon fetches one in the
		// background (never blocking this probe; SBX-P3D audit finding 4).
		sandboxContentRefreshFn(content.SandboxNative, d.r.observerDir)
	}
	return res
}

// mxcSignedRuleID is the probe rule id of a signed-manifest refusal: the
// decision table row (sandboxmxc.ResolveSigned) that refused, prefixed.
func mxcSignedRuleID(row string) string { return "signed_" + row }

// mxcProbeArgv is the probe helper's argv after the binary: the daemon
// passes its own observer directory, so the helper reads the content store
// of the daemon's real config, never the default one (SBX-P3D audit
// finding 5).
func mxcProbeArgv(observerDir string) []string {
	argv := []string{mxcProbeVerb, "--active"}
	if observerDir != "" {
		argv = append(argv, mxcFlagObserverDir, observerDir)
	}
	return argv
}

// mxcProbeDirRefusal is the probe helper's refusal when it was started
// with no --observer-dir (lane LEFT-SBX, the SBX-P3D merge's left item): a
// hand-run probe would otherwise read the content store of its own shell's
// config, which need not be the daemon's, so it refuses and names the flag
// and the directory this shell's config would have used. "" when the flag
// was given.
func mxcProbeDirRefusal(observerDir, ownDir string) string {
	if observerDir != "" {
		return ""
	}
	hint := ""
	if ownDir != "" {
		hint = " (this shell's own config uses " + ownDir + "; pass it only when that is the daemon's)"
	}
	return mxcFlagObserverDir + " is required: pass the observer directory of the daemon whose content store the probe should read" + hint
}

// mxcProbeAnswer is the probe helper's answer: the ladder's result, or,
// when the gather failed, the signed manifest's refusal if it refused (so
// the availability probe says artifact_unverified exactly where a launch
// refuses; SBX-P3D audit finding 6), else probe_failed.
func mxcProbeAnswer(through sandboxmxc.ProbeResult, gatherErr error, signed sandboxmxc.SignedResult) sandboxmxc.ProbeResult {
	if gatherErr == nil {
		return through
	}
	if !signed.OK {
		return sandboxmxc.ProbeResult{Verdict: signed.Verdict, Rule: mxcSignedRuleID(signed.Rule)}
	}
	return sandboxmxc.ProbeResult{Verdict: sandboxmxc.Verdict{Code: sandboxmxc.VerdictProbeFailed, Reason: gatherErr.Error()}, Rule: "helper"}
}

// runMXCProbeHelper starts `observer sandbox-mxc-probe` and reads its JSON
// answer. The library is loaded in that process, never here, so a fault in
// native code ends the helper, not the daemon (review R2-15).
func runMXCProbeHelper(ctx context.Context, observerBin, observerDir string, timeout time.Duration) sandboxmxc.ProbeResult {
	failed := func(why string) sandboxmxc.ProbeResult {
		return sandboxmxc.ProbeResult{Verdict: sandboxmxc.Verdict{Code: sandboxmxc.VerdictProbeFailed, Reason: why}, Rule: "helper"}
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	//nolint:gosec // G204: the daemon's own binary and a fixed verb
	cmd := exec.CommandContext(cctx, observerBin, mxcProbeArgv(observerDir)...)
	cmd.Env = mxcHelperEnv(os.Environ())
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.Output()
	if cctx.Err() != nil {
		return failed(fmt.Sprintf("the MXC probe helper did not answer within %s", timeout))
	}
	var res sandboxmxc.ProbeResult
	if jerr := json.Unmarshal(out, &res); jerr != nil || res.Verdict.Code == "" {
		if err != nil {
			return failed("the MXC probe helper failed: " + err.Error())
		}
		return failed("the MXC probe helper's answer is not readable")
	}
	return res
}

// mxcHelperEnv is a helper process's environment: the daemon's, minus the
// OOB and sandbox variables a launch would carry.
func mxcHelperEnv(base []string) []string {
	out := make([]string, 0, len(base))
	for _, kv := range base {
		if isInternalChildEnv(kv) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// floor refuses a launch the local config or an org floor does not allow on
// this row (the oci-runc analogue).
func (d *mxcDriver) floor(cfg config.TerminalSandboxConfig) error {
	if cfg.PinnedNoBackend != "" {
		return fmt.Errorf("terminal_sandbox: your organization's pin of %s allows none of the sandbox backends this machine is set to use, so no backend is enabled; the sandboxed terminal is refused, never run without it", cfg.PinnedNoBackend)
	}
	if !d.listed() {
		return fmt.Errorf("terminal_sandbox: mxc-process is not in [terminal.sandbox].backends %v", cfg.Backends)
	}
	row := mxcRow()
	if floor := vocab.IsoClass(cfg.MinIsolation); floor != "" && row.Iso.Class.Rank() < floor.Rank() {
		return fmt.Errorf("terminal_sandbox: mxc-process builds %s isolation, below [terminal.sandbox].min_isolation = %s", row.Iso.Class, floor)
	}
	tier := vocab.Tier(cfg.Egress)
	if tier == "" {
		tier = vocab.TierInternet
	}
	if !row.OffersTier(tier) {
		return fmt.Errorf("terminal_sandbox: mxc-process has no %s network tier; set [terminal.sandbox].egress to internet, proxy_only or none", tier)
	}
	floors := sandboxOrgFloors()
	if !floors.InForce() {
		return nil
	}
	beta := true
	if v, ok := row.VerificationOn(sandboxHostKind()); ok {
		beta = v.Kind.IsBeta()
	}
	in := sandboxselect.Input{
		Request: sandboxselect.Request{Backend: row.ID, Tier: tier, Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true, ProviderDirect: cfg.EffectiveProviderDirect()},
		Host:    sandboxHostKind(), Floors: floors,
		Tool: sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
	}
	if drop, dropped := sandboxselect.FloorDrop(row, in, beta); dropped {
		return sandboxRefusalError{msg: isolationFloorMessage(drop)}
	}
	return nil
}

// Create checks the floors and the probe, then prepares the workspace with
// the shared step.
func (d *mxcDriver) Create(ctx context.Context, req termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	if err := d.floor(launchFloorConfig(d.r.cfg, string(d.r.egress.Mode))); err != nil {
		return termsvc.CreateResult{}, err
	}
	row := mxcRow()
	tier := vocab.Tier(d.r.egress.Mode)
	if v, judged := sandboxNativeVerdictFor(row, req.Tool, tier); judged {
		if err := sandboxNativeRefusal(req.Tool, v); err != nil {
			return termsvc.CreateResult{}, err
		}
	}
	if res := d.probeResult(ctx); !res.Verdict.OK() {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: mxc-process is not available: %s", res.Verdict.Error())
	}
	ws, err := d.r.prepareWorkspace(ctx, req)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	routed, _ := d.r.launchRouted(req.Tool, ws.dir, req.ToolArgs)
	return termsvc.CreateResult{
		Run:         termsvc.SandboxRun{ID: ws.id, Tool: req.Tool, Dir: ws.dir, ProjectRoot: req.ProjectRoot, Copy: !ws.live},
		Note:        fmt.Sprintf("sandbox: backend=mxc-process source=%s workspace=%s egress=%s", ws.src, ws.dir, d.r.egress.Mode),
		Isolation:   d.isolation(req.Tool, routed),
		ProxyRouted: routed,
	}, nil
}

// isolation is the run's G19 evidence on the mxc-process row.
func (d *mxcDriver) isolation(tool string, routed bool) termrun.Isolation {
	row := mxcRow()
	tier := vocab.Tier(d.r.egress.Mode)
	capture := sandboxRunCaptureFor(row, routed, tier, d.r.cfg.EffectiveProviderDirect())
	iso := termrun.Isolation{
		Class: string(row.Iso.Class), Stack: []string{row.ID}, EgressTier: string(tier),
		CaptureLevel: string(capture.Level), CaptureRule: capture.Rule,
		CaptureOrigin: string(vocab.OriginSandboxed), KeyCustody: string(vocab.CustodyHostBound),
	}
	if v, judged := sandboxNativeVerdictFor(row, tool, tier); judged {
		iso.NativeSandboxState = string(sandboxselect.NativeStateFor(v))
	}
	if v, ok := row.VerificationOn(sandboxHostKind()); ok {
		iso.Verification = string(v.Kind)
	}
	return iso
}

// mxcPlanFile is the per-run plan the host helper reads. It holds no
// secret by rule (TestMXCPlanFileHoldsNoSecrets): the token and the box
// record are minted by the helper itself.
type mxcPlanFile struct {
	Version     int    `json:"version"`
	RunID       string `json:"run_id"`
	ObserverDir string `json:"observer_dir"`
	Tier        string `json:"tier"`
	// ProxyPort is the daemon's model proxy port the run's proxy stream
	// forwards to.
	ProxyPort int `json:"proxy_port"`
	// ProviderBlock turns on the gateway's model-provider host block
	// (section 7.3) with the proxy's own upstream hosts added.
	ProviderBlock bool     `json:"provider_block"`
	ProviderHosts []string `json:"provider_hosts,omitempty"`
	AllowCIDRs    []string `json:"allow_cidrs,omitempty"`
	Workspace     string   `json:"workspace"`
	// ReadWrite, ReadOnly and Denied are the policy paths (the helper adds
	// the run's box directory).
	ReadWrite []string `json:"read_write"`
	ReadOnly  []string `json:"read_only"`
	Denied    []string `json:"denied,omitempty"`
	// PlaceholderFiles and PlaceholderDirs are protected paths missing at
	// launch, already listed in ReadOnly or Denied: the helper creates them
	// before the box exists and removes them afterwards when untouched
	// (finding F3, the bwrap host helper's rule).
	PlaceholderFiles []string `json:"placeholder_files,omitempty"`
	PlaceholderDirs  []string `json:"placeholder_dirs,omitempty"`
	// AbsentGitDirs are the .git folders the protection table names that
	// the host does not have at launch. No placeholder is made for them and
	// nothing is pinned there, so the box sees no .git the host lacks
	// (Windows 11 Pro live run, B5); the helper reports any of them the run
	// created (mxcAbsentGitCreated).
	AbsentGitDirs []string `json:"absent_git_dirs,omitempty"`
	// StopGraceSeconds is the stop grace after Ctrl-Break.
	StopGraceSeconds int `json:"stop_grace_seconds"`
	// ProbeTimeoutSeconds bounds the helper's own probe of the files.
	ProbeTimeoutSeconds int `json:"probe_timeout_seconds"`
	// ConfigHome is the run-local config folder of a tool whose home has
	// none (Windows 11 Pro rerun 2026-10-25, D3); nil keeps the tool's own.
	ConfigHome *mxcConfigHomePlan `json:"config_home,omitempty"`
	// NeedsWin32k is the tool row's capability (integration
	// SandboxSpec.NeedsWin32k, WINFIX2 audit finding 4): the box keeps MXC's
	// Win32k mitigation unless the tool needs user32.dll.
	NeedsWin32k bool `json:"needs_win32k,omitempty"`
	// TempDirEnv names the variables the tool reads for its own temp folder
	// (sandboxenv.TempDirEnv, D-UC1): the box gets each set to its private
	// temp directory, as TEMP and TMP are.
	TempDirEnv []string `json:"temp_dir_env,omitempty"`
}

// Attach writes the run record and the plan file, opens the run's OOB
// endpoint and returns the helper argv the PTY child runs.
func (d *mxcDriver) Attach(ctx context.Context, created termsvc.CreateResult) (termsvc.AttachResult, error) {
	res := d.probeResult(ctx)
	if !res.Verdict.OK() {
		return termsvc.AttachResult{}, fmt.Errorf("terminal_sandbox: mxc-process is not available: %s", res.Verdict.Error())
	}
	if err := d.r.writeRunRecord(created.Run); err != nil {
		return termsvc.AttachResult{}, err
	}
	fail := func(err error) (termsvc.AttachResult, error) {
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, created.Run.ID)
		_ = removeMXCPlan(d.r.observerDir, created.Run.ID)
		processMXCOOB.close(created.Run.ID)
		return termsvc.AttachResult{}, err
	}
	plan, err := d.plan(created)
	if err != nil {
		return fail(err)
	}
	// A plan that hides a path needs a BaseContainer that can deny paths
	// (finding F4); the helper checks the run's exact policy again.
	if v := sandboxmxc.DenyPathsVerdict(len(plan.Denied), res.DenyPaths); !v.OK() {
		return fail(fmt.Errorf("terminal_sandbox: mxc-process: %s", v.Error()))
	}
	planPath, err := writeMXCPlan(d.r.observerDir, plan)
	if err != nil {
		return fail(err)
	}
	if err := processMXCOOB.open(d.r.observerDir, created.Run.ID); err != nil {
		return fail(fmt.Errorf("terminal_sandbox: the run's OOB endpoint: %w", err))
	}
	d.r.unattached.Delete(created.Run.ID)
	return termsvc.AttachResult{WrapArgv: mxcWrapArgv(d.r.observerBin, planPath, created.Run.ID, d.r.observerDir)}, nil
}

// mxcWrapArgv is the PTY child's prefix; the inner launch follows its "--".
func mxcWrapArgv(observerBin, planPath, runID, observerDir string) []string {
	return []string{observerBin, mxcHostVerb, mxcFlagPlan, planPath, mxcFlagRelayRun, runID, mxcFlagObserverDir, observerDir, "--"}
}

// mxcRelayOfWrap reads the relay run back from an mxc-process wrap argv
// (bindSandboxRelayRun's source, the sandbox.RelayOfWrap analogue).
func mxcRelayOfWrap(argv []string) (runID, observerDir string, ok bool) {
	h, err := parseMXCHostArgs(argv)
	if err != nil {
		return "", "", false
	}
	return h.runID, h.observerDir, true
}

// mxcHostArgs are the host verb's parsed arguments.
type mxcHostArgs struct {
	plan, runID, observerDir string
	inner                    []string
}

// parseMXCHostArgs parses `<bin> sandbox-mxc-host --plan P --relay-run R
// --observer-dir D -- <inner...>` (argv[0] the binary) or the same without
// the binary and verb.
func parseMXCHostArgs(argv []string) (mxcHostArgs, error) {
	i := slices.Index(argv, mxcHostVerb)
	rest := argv
	if i >= 0 {
		rest = argv[i+1:]
	}
	var h mxcHostArgs
	for len(rest) > 0 {
		switch rest[0] {
		case "--":
			h.inner = rest[1:]
			rest = nil
			continue
		case mxcFlagPlan, mxcFlagRelayRun, mxcFlagObserverDir:
			if len(rest) < 2 {
				return mxcHostArgs{}, fmt.Errorf("%s needs a value", rest[0])
			}
			switch rest[0] {
			case mxcFlagPlan:
				h.plan = rest[1]
			case mxcFlagRelayRun:
				h.runID = rest[1]
			case mxcFlagObserverDir:
				h.observerDir = rest[1]
			}
			rest = rest[2:]
		default:
			return mxcHostArgs{}, fmt.Errorf("unknown argument %q", rest[0])
		}
	}
	if h.plan == "" || !sandboxrelay.ValidRunID(h.runID) || h.observerDir == "" || !filepath.IsAbs(h.observerDir) || !filepath.IsAbs(h.plan) {
		return mxcHostArgs{}, errors.New("--plan, --relay-run and --observer-dir are required (absolute paths, a short run id)")
	}
	return h, nil
}

// plan composes the run's policy from the same inputs the other drivers
// read: the workspace and the tool's writable state read-write, the
// observer binary's directory, the tool's binaries and read-only state and
// the daemon's config file read-only, the protection table's existing
// overlays as read-only or denied paths; every grant passes the shared
// observer-directory rule and every extra write grant the sensitive
// write-bind table.
func (d *mxcDriver) plan(created termsvc.CreateResult) (mxcPlanFile, error) {
	r := d.r
	run := created.Run
	home, err := os.UserHomeDir()
	if err != nil {
		return mxcPlanFile{}, fmt.Errorf("terminal_sandbox: resolve home: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(home); rerr == nil {
		home = resolved
	}
	spec, _ := integration.For(run.Tool)
	if len(spec.Sandbox.StateRW) == 0 {
		return mxcPlanFile{}, fmt.Errorf("terminal_sandbox: tool %q is not sandbox-launchable: %s", run.Tool, spec.Sandbox.Note)
	}
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil } //nolint:gosec // G703: a metadata read of the tool's config folder
	configHome, err := sandboxConfigHomeFor(spec.Sandbox.ConfigHome, run.Tool, home, os.Getenv, os.ReadFile, exists)
	if err != nil {
		return mxcPlanFile{}, err
	}
	rw, ro, denied, ph, err := d.grants(home, run, spec.Sandbox)
	if err != nil {
		return mxcPlanFile{}, err
	}
	tier := vocab.Tier(r.egress.Mode)
	if tier == "" {
		tier = vocab.TierInternet
	}
	plan := mxcPlanFile{
		Version: mxcPlanVersion, RunID: run.ID, ObserverDir: r.observerDir, Tier: string(tier),
		ProxyPort: r.proxyPort, AllowCIDRs: r.cfg.EgressAllowCIDRs, Workspace: run.Dir,
		ReadWrite: rw, ReadOnly: ro, Denied: denied,
		PlaceholderFiles: ph.files, PlaceholderDirs: ph.dirs, AbsentGitDirs: ph.absentGit,
		StopGraceSeconds: d.cfg.StopGraceSeconds, ProbeTimeoutSeconds: d.cfg.ProbeTimeoutSeconds,
		ConfigHome: configHome, NeedsWin32k: spec.Sandbox.NeedsWin32k,
		TempDirEnv: sandboxenv.TempDirEnv(run.Tool),
	}
	if capture := sandboxRunCaptureFor(mxcRow(), created.ProxyRouted, tier, r.cfg.EffectiveProviderDirect()); capture.ProviderBlock {
		plan.ProviderBlock, plan.ProviderHosts = true, r.providerHosts
	}
	return plan, nil
}

// mxcPlaceholders are the protected paths a plan creates before the box,
// and the .git folders it deliberately does not create (absentGit).
type mxcPlaceholders struct{ files, dirs, absentGit []string }

// grants are the run's read-write, read-only and denied paths (plan's
// first half): the workspace and the tool's writable state, the extra
// grants, the binaries, the daemon's config file and the protection
// overlays, a missing one with its placeholder.
func (d *mxcDriver) grants(home string, run termsvc.SandboxRun, spec integration.SandboxSpec) (rw, ro, denied []string, ph mxcPlaceholders, err error) {
	r := d.r
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil } //nolint:gosec // G703: a metadata read of a grant path from the run's own plan
	check := func(kind, p string) error {
		if err := sandbox.CheckObserverDirBind(kind, p, r.observerDir, resolveSandboxBindPath); err != nil {
			return fmt.Errorf("terminal_sandbox: %w", err)
		}
		return nil
	}
	if err := check("workspace", run.Dir); err != nil {
		return nil, nil, nil, mxcPlaceholders{}, err
	}
	rw = append(rw, run.Dir)
	for _, rel := range spec.StateRW {
		p := filepath.Join(home, rel)
		if err := check("state rw grant", p); err != nil {
			return nil, nil, nil, mxcPlaceholders{}, err
		}
		if exists(p) {
			rw = append(rw, p)
		}
	}
	env := sandboxManagedEnv{home: home, observerDir: r.observerDir, resolve: resolveSandboxBindPath}
	for _, x := range r.cfg.ExtraRWBinds {
		if err := check("extra rw grant", x); err != nil {
			return nil, nil, nil, mxcPlaceholders{}, err
		}
		spellings := []string{filepath.Clean(x)}
		if rx := resolveSandboxBindPath(x); rx != "" && filepath.Clean(rx) != spellings[0] {
			spellings = append(spellings, filepath.Clean(rx))
		}
		if sensitiveWriteBind(spellings, env) {
			return nil, nil, nil, mxcPlaceholders{}, fmt.Errorf("terminal_sandbox: extra rw bind %q is a sensitive host location (%s); the Windows sandbox never grants it writable", x, orgcontract.SandboxRefusedSensitivePath)
		}
		if exists(x) {
			rw = append(rw, x)
		}
	}
	addRO := func(kind, p string) error {
		if p == "" || !exists(p) {
			return nil
		}
		if err := check(kind, p); err != nil {
			return err
		}
		ro = append(ro, p)
		return nil
	}
	for _, x := range r.cfg.ExtraROBinds {
		if err := addRO("extra ro grant", x); err != nil {
			return nil, nil, nil, mxcPlaceholders{}, err
		}
	}
	for _, rel := range spec.StateRO {
		if err := addRO("state ro grant", filepath.Join(home, rel)); err != nil {
			return nil, nil, nil, mxcPlaceholders{}, err
		}
	}
	for _, dir := range r.toolBinDirs(run.Tool) {
		if err := addRO("tool binary dir", dir); err != nil {
			return nil, nil, nil, mxcPlaceholders{}, err
		}
	}
	binDir := filepath.Dir(r.observerBin)
	if r.observerRealDir != "" {
		binDir = r.observerRealDir
	}
	if err := addRO("observer binary dir", binDir); err != nil {
		return nil, nil, nil, mxcPlaceholders{}, err
	}
	// The inner launcher reads the daemon's config file (and only that
	// file of the observer directory).
	if cfgPath, err := config.ResolveGlobalPath(daemonConfigPath()); err == nil && exists(cfgPath) {
		ro = append(ro, cfgPath)
	}
	overlays, oerr := r.overlays(home, run.Dir, spec)
	if oerr != nil {
		return nil, nil, nil, mxcPlaceholders{}, oerr
	}
	ro, denied, ph = mxcOverlayGrants(overlays, exists, ro, denied, ph)
	return rw, ro, denied, ph, nil
}

// mxcOverlayGrants sorts the run's protected-path overlays into the
// read-only and denied grants and the placeholders the helper creates
// before the box exists (grants' last step).
func mxcOverlayGrants(overlays []sandbox.Overlay, exists func(string) bool, ro, denied []string, ph mxcPlaceholders) ([]string, []string, mxcPlaceholders) {
	for _, o := range overlays {
		// A .git the host does not have gets no placeholder and no pin
		// (Windows 11 Pro live run, B5): the git-dir rows apply only where
		// the host has the path, and a placeholder .git made the box's
		// `if exist .git` true in a folder that is not a repository. A .git
		// the run creates is reported after the run (mxcAbsentGitCreated).
		if mxcAbsentGitDir(o) {
			ph.absentGit = append(ph.absentGit, o.Path)
			continue
		}
		// Any other protected path missing at launch gets the treatment
		// bwrap gives it (finding F3): the overlay walk names its topmost
		// missing part with a placeholder the helper creates before the box
		// exists, so the box finds it present and read-only (or denied);
		// inside a .git the host has, that keeps .git/hooks from being
		// created for the next host git.
		switch o.Placeholder {
		case sandbox.PlaceholderFile:
			ph.files = append(ph.files, o.Path)
		case sandbox.PlaceholderDir:
			ph.dirs = append(ph.dirs, o.Path)
		default:
			if !exists(o.Path) {
				// Gone between the walk and here, outside any writable
				// root: nothing in the box can create it.
				continue
			}
		}
		switch o.Kind {
		case sandbox.OverlayReadOnly:
			ro = append(ro, o.Path)
		case sandbox.OverlayHideFile, sandbox.OverlayHideDir:
			denied = append(denied, o.Path)
		}
	}
	return ro, denied, ph
}

// mxcAbsentGitDir reports an overlay whose topmost missing part is a .git
// folder itself: the host has no repository there.
func mxcAbsentGitDir(o sandbox.Overlay) bool {
	return o.Placeholder == sandbox.PlaceholderDir && filepath.Base(o.Path) == ".git"
}

// mxcAbsentGitCreated returns the plan's absent .git folders that exist
// now: the run created them, with whatever config and hooks the box wrote.
func mxcAbsentGitCreated(plan mxcPlanFile) []string {
	var out []string
	for _, p := range plan.AbsentGitDirs {
		if _, err := os.Lstat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// mxcAbsentGitNotice is the line the helper prints for a .git the run
// created where the host had none, or "" when there is none.
func mxcAbsentGitNotice(created []string) string {
	if len(created) == 0 {
		return ""
	}
	return "observer: the sandboxed run created " + strings.Join(created, ", ") +
		", which this folder did not have before the run; its config and hooks were written inside the box, so check them before you run git here\n"
}

// Resize is owned by the PTY: wxc-exec and the agent are console clients
// of the terminal's own ConPTY, whose resize reaches them.
func (d *mxcDriver) Resize(context.Context, termsvc.SandboxRun, uint16, uint16) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "mxc-process: the agent shares the terminal's ConPTY"}, nil
}

// Signal is owned by the PTY: Ctrl-C reaches the agent through the
// console; the helper ignores it itself.
func (d *mxcDriver) Signal(context.Context, termsvc.SandboxRun, string) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "mxc-process: console control events reach the agent through the ConPTY"}, nil
}

// Copy is not offered: the workspace is a host directory.
func (d *mxcDriver) Copy(context.Context, termsvc.CopyRequest) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "mxc-process: the workspace is a host directory; copy on the host"}, nil
}

// Checkpoint is not offered (one-shot containers; native resume applies).
func (d *mxcDriver) Checkpoint(context.Context, termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "mxc-process: no checkpoint; the agent's native resume applies"}, nil
}

// Stop is owned by the PTY: closing the terminal ends the job the helper,
// wxc-exec and the container's process tree run in.
func (d *mxcDriver) Stop(context.Context, termsvc.SandboxRun, time.Duration) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "mxc-process: closing the terminal ends the container (MXC's kill-on-close job)"}, nil
}

// Destroy releases a run that never started: its plan, its OOB endpoint,
// its run record and its unattached workspace.
func (d *mxcDriver) Destroy(_ context.Context, run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	_ = removeMXCPlan(d.r.observerDir, run.ID)
	processMXCOOB.close(run.ID)
	return d.r.destroyBwrap(run)
}

// ---- node-local state under ~/.observer/sandbox-mxc --------------------------

// mxcStateDir is the driver's node-local directory.
func mxcStateDir(observerDir string) string { return filepath.Join(observerDir, "sandbox-mxc") }

// mxcPlanPath is a run's plan file (never granted to any box).
func mxcPlanPath(observerDir, runID string) string {
	return filepath.Join(mxcStateDir(observerDir), "plans", runID+".json")
}

// writeMXCPlan writes a run's plan file (0600, created fresh).
func writeMXCPlan(observerDir string, plan mxcPlanFile) (string, error) {
	p := mxcPlanPath(observerDir, plan.RunID)
	if err := mkdirSandboxOwned(filepath.Dir(p)); err != nil {
		return "", fmt.Errorf("terminal_sandbox: mxc plan dir: %w", err)
	}
	b, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fixed path under the observer dir
	if err != nil {
		return "", fmt.Errorf("terminal_sandbox: write mxc plan: %w", err)
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = ownSandboxRecord(p)
	}
	if werr != nil {
		_ = os.Remove(p)
		return "", werr
	}
	return p, nil
}

// readMXCPlan reads a plan file: a small regular file, not a link.
func readMXCPlan(p string) (mxcPlanFile, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return mxcPlanFile{}, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 4<<20 {
		return mxcPlanFile{}, fmt.Errorf("mxc plan %s is not a small regular file", p)
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: the plan path the daemon wrote under its observer dir
	if err != nil {
		return mxcPlanFile{}, err
	}
	var plan mxcPlanFile
	if err := json.Unmarshal(b, &plan); err != nil {
		return mxcPlanFile{}, fmt.Errorf("mxc plan: %w", err)
	}
	if plan.Version != mxcPlanVersion {
		return mxcPlanFile{}, fmt.Errorf("mxc plan: version %d, this binary reads %d (restart the daemon after an upgrade)", plan.Version, mxcPlanVersion)
	}
	if !sandboxrelay.ValidRunID(plan.RunID) || !vocab.Tier(plan.Tier).Valid() {
		return mxcPlanFile{}, errors.New("mxc plan: run id or tier refused")
	}
	if err := mxcCheckConfigHome(plan.ConfigHome); err != nil {
		return mxcPlanFile{}, fmt.Errorf("mxc plan: %w", err)
	}
	return plan, nil
}

// removeMXCPlan removes a run's plan file.
func removeMXCPlan(observerDir, runID string) error {
	err := os.Remove(mxcPlanPath(observerDir, runID))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ---- the Windows OOB transport (sandbox plan section 5.6) -------------------

// mxcOOBEndpoint is a run's OOB endpoint: an owner-only local IPC endpoint
// (a named pipe with a protected DACL on Windows, internal/localipc) that
// only the host helper reaches. The ConPTY child inherits no handles, so
// this is how the helper, the trusted launcher of the run, reaches the
// daemon's OOB reader; an AppContainer box cannot open it (the DACL names
// only this user and SYSTEM).
func mxcOOBEndpoint(observerDir, runID string) (string, error) {
	return localipc.DefaultTransport().Endpoint(filepath.Join(mxcStateDir(observerDir), "oob", runID))
}

// mxcOOBListeners holds each attached run's OOB listener until the
// launcher takes it.
type mxcOOBListeners struct {
	mu  sync.Mutex
	lns map[string]net.Listener
}

var processMXCOOB = &mxcOOBListeners{lns: map[string]net.Listener{}}

// open listens on runID's endpoint.
func (o *mxcOOBListeners) open(observerDir, runID string) error {
	if !localipc.Supported() {
		return localipc.ErrUnsupported
	}
	ep, err := mxcOOBEndpoint(observerDir, runID)
	if err != nil {
		return err
	}
	// The unix transport's socket lives in this directory; the named pipe
	// needs none, and the directory is harmless there.
	if err := mkdirSandboxOwned(filepath.Join(mxcStateDir(observerDir), "oob")); err != nil {
		return err
	}
	ln, err := localipc.DefaultTransport().Listen(ep)
	if err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if old, ok := o.lns[runID]; ok {
		_ = old.Close()
	}
	o.lns[runID] = ln
	return nil
}

// take removes and returns runID's listener.
func (o *mxcOOBListeners) take(runID string) (net.Listener, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	ln, ok := o.lns[runID]
	delete(o.lns, runID)
	return ln, ok
}

// close drops runID's listener.
func (o *mxcOOBListeners) close(runID string) {
	if ln, ok := o.take(runID); ok {
		_ = ln.Close()
	}
}

// mxcOOBSource is the launcher's OOB source for an mxc-process wrap argv:
// the first connection to the run's endpoint (the helper), its peer
// checked to be this user, within mxcOOBAcceptWait.
func mxcOOBSource(wrapArgv []string) (io.ReadCloser, bool) {
	h, err := parseMXCHostArgs(wrapArgv)
	if err != nil {
		return nil, false
	}
	ln, ok := processMXCOOB.take(h.runID)
	if !ok {
		return nil, false
	}
	return &mxcOOBReader{ln: ln}, true
}

// mxcOOBReader accepts the helper's connection on first read.
type mxcOOBReader struct {
	ln   net.Listener
	once sync.Once
	c    net.Conn
	err  error
}

func (m *mxcOOBReader) accept() {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := m.ln.Accept()
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		m.c, m.err = r.c, r.err
	case <-time.After(mxcOOBAcceptWait):
		m.err = io.EOF
	}
	_ = m.ln.Close()
	if m.err == nil {
		if perr := sandboxrelayd.PeerSameUser(m.c); perr != nil {
			_ = m.c.Close()
			m.c, m.err = nil, perr
		}
	}
}

func (m *mxcOOBReader) Read(b []byte) (int, error) {
	m.once.Do(m.accept)
	if m.err != nil {
		return 0, m.err
	}
	return m.c.Read(b)
}

func (m *mxcOOBReader) Close() error {
	_ = m.ln.Close()
	if m.c != nil {
		return m.c.Close()
	}
	return nil
}

// bindsToolState: mxc-process grants the tool's own state directory, so the box shares the tool's sign-in
// (sandboxStateBinder, operator ruling P-183).
func (*mxcDriver) bindsToolState() bool { return true }
