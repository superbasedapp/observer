//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	exthost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_openshell.go is the OpenShell driver in external gateway
// mode (OpenShell plan doc 04 R2.6 phase O1, build plan 05 section 2, lane
// O1B; decisions D2, D3 and D4 of the build decision log, OB-039 and
// OB-040). The pure decisions (the policy compiler, the create, list, get
// and delete argv, the tested-version table, the probe verdict table, the
// label grammar and the not-found classifier) are
// internal/sandboxopenshell's; this file gathers the probe's facts through
// the one exec seam (extrun's runner, openShellRunner), composes a run and
// owns the per-run state. terminal_sandbox_openshell_linux.go holds the
// host facts, the host helper, the in-box init and the labelled reaper;
// terminal_sandbox_openshell_other.go refuses on every other OS; the omit
// twin is terminal_sandbox_openshell_omit.go.
//
// What runs where: the daemon's runtime probes (only when the component is
// selected, the sandbox is on and "openshell" is in
// [terminal.sandbox].backends), prepares the workspace with the shared
// step, compiles the run (policy file and plan file) and returns the wrap
// argv. The PTY child is `observer sandbox-openshell-host --plan <file> --
// observer sandbox-host <relay flags> -- observer-openshell-inner observer
// <verb> ...`: the host helper starts the capture relay over the run's
// socket dir (rule W5), stages the run's copied files, and runs `openshell
// sandbox create --no-keep --tty ... -- observer sandbox-openshell-init
// ... -- observer sandbox-guest ... -- observer <verb> ...` as its own
// child on the same terminal, so the CLI forwards the terminal's size
// (SIGWINCH) and its exit code is the run's. Every box command after the
// create names the gateway the create-time status answer named (audit
// finding O1A-A9).
//
// The row is explicit-only and never satisfies the guard's sandbox
// requirement (the registry row's ExplicitOnly and Maturity, read by
// selection, not by this file); org floors reach it only through
// sandboxselect.FloorDrop and its capability tokens.

// The driver's ids, helper verbs and fixed values.
const (
	openShellComponentID = "terminals.sandbox.openshell"
	openShellHostVerb    = "sandbox-openshell-host"
	openShellInitVerb    = "sandbox-openshell-init"
	// openShellInnerMarker separates the host services' command from the
	// inner launch in the wrap argv (the oci-runc row's shape: the argv
	// stays a complete sandbox-host command line, so sandbox.RelayOfWrap
	// and the tier reader see it).
	openShellInnerMarker = "observer-openshell-inner"
	// openShellPlanVersion is the plan file's schema version (2: the
	// pinned gateway's server is recorded, audit finding O1B-A14).
	openShellPlanVersion = 2
	// openShellCanaryVerb is the runtime canary's helper verb: this binary,
	// bound read-only as the entrypoint of OpenShell's supervisor image of
	// the gateway's version (sandboxopenshell.CanaryImage), which a fresh
	// install holds; the default workload image is pulled only at the first
	// box create (live run O1B-L1, 2026-10-31). The probe never pulls, and
	// an image the host does not hold refuses the row with its own reason
	// (runtime_canary_image_missing), never as a failed Landlock query.
	openShellCanaryVerb = sandboxopenshell.CanaryVerb
	// openShellCmdTimeout bounds every CLI call the daemon side makes.
	openShellCmdTimeout = 30 * time.Second
	// openShellCopyCap caps one copied file (a tool's single-file state).
	openShellCopyCap = 16 << 20
)

// openShellCLISpec is the OpenShell CLI as the runner resolves it: on PATH,
// with Observer's shims excluded (toolresolve/host.NewEnv). Observer never
// installs it.
var openShellCLISpec = integration.BinaryResolveSpec{
	Names:       integration.BinaryNames{Unix: []string{sandboxopenshell.Program}},
	WindowsNote: "OpenShell has no Windows build for this row; the openshell row is native Linux only",
	InstallNote: "external gateway mode: the user installs OpenShell themselves; Observer never installs it",
}

// openShellDockerSpec is the docker CLI the runtime canary runs.
var openShellDockerSpec = integration.BinaryResolveSpec{
	Names:       integration.BinaryNames{Unix: []string{"docker"}},
	WindowsNote: "the openshell row is native Linux only",
	InstallNote: "the openshell row needs Docker Engine, installed by the user",
}

// openShellEnvInherit is the environment the daemon side hands the CLI and
// the docker canary: where the CLI keeps its gateway registry and where
// docker finds its engine. Nothing secret-shaped (the runner refuses such
// names anyway).
var openShellEnvInherit = []string{
	"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
	"OPENSHELL_GATEWAY", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "LANG",
}

func init() {
	registerSandboxDriver(sandboxDriverReg{
		backend: sandboxbackend.BackendOpenShell, component: openShellComponentID,
		build: newOpenShellDriver, release: openShellRelease,
		// A gateway left running after the component was deselected still
		// waits on run dirs the reaper cannot remove; name them (fix round
		// 1 of lane FU1). Reads names and times only, runs nothing.
		inactiveHint: func(r *sandboxRuntime, full config.Config) string {
			if r.observerDir == "" && full.Terminal.Sandbox.OpenShell.StateDir == "" {
				return ""
			}
			return openShellRunDirsHint(openShellStateDir(r.observerDir, full.Terminal.Sandbox.OpenShell.StateDir), time.Now())
		},
	})
	sandboxHelperFuncs[openShellHostVerb] = runOpenShellHost
	sandboxHelperFuncs[openShellInitVerb] = runOpenShellInit
	sandboxHelperFuncs[openShellCanaryVerb] = runOpenShellCanary
}

// openShellRunner is the driver's one exec seam: every program the daemon
// and the host helper start besides the interactive create (the openshell
// CLI's version, status, gateway info, sandbox list, get and delete, and the
// docker runtime canary) goes through extrun's runner with the component's
// id, so the process-declaration rows hold. A variable so a test hands an
// extruntest runner.
var openShellRunner = sync.OnceValue(func() *extrun.Runner { return exthost.NewRunner(exthost.Options{}) })

// openShellHostFactsFn reads the host facts the probe needs that are not a
// program's answer (a variable so a test feeds them).
var openShellHostFactsFn = openShellHostFacts

// openShellHostFactsT are the host facts: the kernel's Landlock ABI, the
// docker group membership (decision D4), the gateway's bind-mount opt-in
// as its config file states it (decision D3), and what the runtime canary
// runs as: Observer's own binary and this user's ids.
type openShellHostFactsT struct {
	LandlockABI func() int
	DockerGroup func() bool
	BindMounts  func(driver string) sandboxopenshell.Tri
	// EngineRecord reads the row's record of the container engine it first
	// used (row P8e): its path, and its bytes or the read error
	// (fs.ErrNotExist: none yet). nil reads as unreadable.
	EngineRecord func() (path string, b []byte, err error)
	// SaveEngine writes that record at the first use, never over an
	// existing one.
	SaveEngine func(b []byte) error
	// GatewayImages are the runtime image references the gateway's config
	// names under [openshell.drivers.<driver>] (row P8i; zero for none or
	// an unread config: the version's defaults then apply).
	GatewayImages func(driver string) sandboxopenshell.RuntimeImages
	// ObserverBin is the binary the canary runs ("" refuses the canary as
	// not started).
	ObserverBin string
	// IDs are the uid and gid the canary runs as.
	IDs func() (uid, gid int)
	// Managed runs one managed gateway lifecycle pass (row PG; nil in
	// managed mode refuses the row as not ready).
	Managed func(ctx context.Context) openShellManaged
}

// openShellPrereq is decision D4's prerequisite, reported as an enum: how
// this user reaches the container runtime the gateway drives.
type openShellPrereq string

// The closed openShellPrereq vocabulary.
const (
	// openShellPrereqDockerGroup: the Docker driver, and this user is in
	// the docker group, which is root-equivalent on the host.
	openShellPrereqDockerGroup openShellPrereq = "docker_group"
	// openShellPrereqDockerNoGroup: the Docker driver, and this user is not
	// in the docker group (a rootless Docker, or a socket opened another
	// way); not measured.
	openShellPrereqDockerNoGroup openShellPrereq = "docker_without_group"
	// openShellPrereqPodman: the Podman driver (rootless Podman 5 is D4's
	// preferred path); probe row P6 takes it on a tested version whose row
	// names an O1B-L2 launch receipt (sandboxopenshell.DriverAccepted).
	openShellPrereqPodman openShellPrereq = "podman"
	// openShellPrereqUnknown: the gateway's driver could not be read.
	openShellPrereqUnknown openShellPrereq = "unknown"
)

// openShellPrereqRows is D4's table, walked top-down.
var openShellPrereqRows = []struct {
	driver string
	group  bool
	any    bool
	out    openShellPrereq
}{
	{driver: "docker", group: true, out: openShellPrereqDockerGroup},
	{driver: "docker", group: false, out: openShellPrereqDockerNoGroup},
	{driver: "podman", any: true, out: openShellPrereqPodman},
}

// openShellPrereqFor classifies the prerequisite in use.
func openShellPrereqFor(driver string, inDockerGroup bool) openShellPrereq {
	for _, r := range openShellPrereqRows {
		if r.driver == driver && (r.any || r.group == inDockerGroup) {
			return r.out
		}
	}
	return openShellPrereqUnknown
}

// openShellPrereqHint is the plain sentence the probe shows for the
// prerequisite (selection never reads it).
func openShellPrereqHint(p openShellPrereq) string {
	switch p {
	case openShellPrereqDockerGroup:
		return "prerequisite docker_group: you are in the docker group, which is root-equivalent on this machine"
	case openShellPrereqDockerNoGroup:
		return "prerequisite docker_without_group: the Docker driver without docker group membership (not measured)"
	case openShellPrereqPodman:
		if sandboxopenshell.PodmanMeasuredVersions() == "none" {
			return "prerequisite podman: rootless Podman 5 is preferred where available, but no live receipt measured it yet (O1B-L2's launch half), so the row refuses it"
		}
		return "prerequisite podman: rootless Podman 5 (decision D4's preferred path), measured on OpenShell " + sandboxopenshell.PodmanMeasuredVersions() + " (live check O1B-L2's launch half); Observer's own container calls need a docker CLI that drives the Podman engine"
	}
	return ""
}

// openShellDriver is the OpenShell lifecycle service over one runtime.
type openShellDriver struct {
	r    *sandboxRuntime
	cfg  config.TerminalSandboxOpenShellConfig
	full config.Config

	mu     sync.Mutex
	last   openShellProbe
	lastAt time.Time
	// lastGen is the probe-cache generation last was taken under.
	lastGen uint64
	// targets holds the pinned gateway of each created run (run id ->
	// openShellPin), from Create to Attach.
	targets sync.Map
}

// openShellProbe is one probe's outcome with the facts the run composes
// from.
type openShellProbe struct {
	res    sandboxopenshell.ProbeResult
	facts  sandboxopenshell.ProbeFacts
	status sandboxopenshell.StatusAnswer
	prereq openShellPrereq
	// pin is the gateway every box command of a run created now names (the
	// status answer's gateway name and the configured endpoint) and the
	// server it answered from.
	pin openShellPin
	// managedHint is the managed gateway's note ("" in external mode).
	managedHint string
	// managedCustody is the managed gateway's custody in force
	// (keychain or owner_file; "" in external mode).
	managedCustody string
	// managedConfigPath is the managed gateway's own config file ("" in
	// external mode): the D3 probe reads its OCSF export there (lane OC).
	managedConfigPath string
	// engineNote says the engine's ID could not be recorded at its first
	// use ("" otherwise; row P8e).
	engineNote string
	// imageNote is row P8i's note on images named by tag or a sandbox
	// binary from supervisor_bin ("" otherwise).
	imageNote string
}

// ocsfGateway is what the egress check's D3 probe needs about the run's
// gateway (lane OC).
func (p openShellProbe) ocsfGateway() openShellOCSFGateway {
	return openShellOCSFGateway{Mode: p.facts.GatewayMode, ManagedConfigPath: p.managedConfigPath}
}

// openShellPin is a run's gateway: the Target every box command names
// (audit finding O1A-A9) and the server the create-time status answer
// gave for it (audit finding O1B-A14). A gateway name the user removes and
// registers again for another server between the create and a later call
// is not the run's gateway: every later call first asks the pinned
// target's status and acts only when the server is the recorded one, so
// the other server's "not found" never reads the run's box gone.
type openShellPin struct {
	Target sandboxopenshell.Target `json:"target"`
	Server string                  `json:"server"`
}

// newOpenShellDriver builds the driver. In the daemon it also starts the
// labelled reaper whenever openshell is listed, without waiting for a probe
// or a dashboard launch (audit finding O1B-A4): a run a crashed daemon, a
// killed helper or a CLI launch (which composes in its own process) left
// behind is reaped from daemon start. The reaper reads the install id on
// every pass, so an id a CLI launch mints later is picked up, and a pass
// with no run dir and no recorded gateway runs no program. While openshell
// is not listed the daemon stops it.
func newOpenShellDriver(r *sandboxRuntime, full config.Config) sandboxDriver {
	d := &openShellDriver{r: r, cfg: full.Terminal.Sandbox.OpenShell, full: full}
	if r.inDaemon {
		// The managed gateway's reconcile loop (lane O2): started while
		// openshell is listed in managed mode, and in not-wanted mode
		// when a gateway was recorded, so it stops once no run holds it.
		openShellGatewayReconcile(d.stateDir(), d.listed() && openShellWantsManaged(d.cfg), r.logger)
		if d.listed() {
			if openShellEnsureReaper(d.stateDir(), r.observerDir) && r.logger != nil {
				r.logger.Info("terminal_sandbox: openshell: the labelled reaper is running", "state_dir", d.stateDir(), "every", openShellPeriodicSweep.String())
			}
			// Lane O3: the loopback OCSF receiver beside the reaper.
			openShellEnsureOCSF(d.stateDir(), r.observerDir, r.logger)
		} else {
			openShellReleaseReaper()
			openShellReleaseOCSF()
		}
	}
	return d
}

// openShellRow is the registry row.
func openShellRow() sandboxbackend.Capability {
	row, _ := sandboxbackend.Get(sandboxbackend.BackendOpenShell)
	return row
}

// listed reports whether openshell is among the enabled backends or the
// launch named it.
func (d *openShellDriver) listed() bool {
	return slices.Contains(sandboxEnabledBackends(d.r.cfg), sandboxbackend.BackendOpenShell) || d.r.forceBackend == sandboxbackend.BackendOpenShell
}

// probe is the selection input. Nothing runs while openshell is not
// listed (section 10.1's opt-in rule).
func (d *openShellDriver) probe(ctx context.Context) sandboxselect.Probe {
	// The run dirs the reaper cannot remove are named either way (tracker
	// F-032): reading the state dir's names and times runs no program.
	runDirs := openShellRunDirsHint(d.stateDir(), time.Now())
	if !d.listed() {
		return openShellSurface(sandboxselect.Probe{Compiled: true, Verdict: sandboxselect.VerdictDisabledByConfig, Reason: "openshell is not in [terminal.sandbox].backends", Hint: runDirs}, d.cfg)
	}
	p := d.probeResult(ctx)
	out := sandboxselect.Probe{Compiled: true, Verdict: p.res.Verdict, Reason: p.res.Reason, Sources: sourceIDs(d.r.sources()), Hint: openShellJoinHints(openShellPrereqHint(p.prereq), p.managedHint, p.engineNote, p.imageNote, runDirs)}
	if p.res.Available() {
		out.Verdict = sandboxselect.VerdictAvailable
		// The version a pin reads is the authenticated gateway's own.
		out.Version, out.VersionAuthenticated = p.res.Version.Version.String(), true
	}
	return openShellSurface(out, d.cfg)
}

// version is the gateway version the last probe read.
func (d *openShellDriver) version() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last.res.Version.Version == (sandboxopenshell.Version{}) {
		return ""
	}
	return d.last.res.Version.Version.String()
}

// probeResult runs (or reuses) the ladder.
func (d *openShellDriver) probeResult(ctx context.Context) openShellProbe {
	d.mu.Lock()
	defer d.mu.Unlock()
	if sandboxProbeFresh(d.lastAt, d.lastGen, time.Now()) {
		return d.last
	}
	gen := sandboxProbeGeneration()
	hf := openShellHostFactsFn()
	if hf.ObserverBin == "" {
		hf.ObserverBin = d.r.observerBin
	}
	if hf.Managed == nil {
		hf.Managed = func(ctx context.Context) openShellManaged { return openShellManagedFor(ctx, d.stateDir(), d.r.logger) }
	}
	if hf.EngineRecord == nil {
		hf.EngineRecord, hf.SaveEngine = openShellEngineRecordIO(d.stateDir())
	}
	d.last, d.lastAt, d.lastGen = openShellGather(ctx, d.cfg, sandboxHostKind(), openShellRunner(), hf), time.Now(), gen
	return d.last
}

// openShellStep is one row of the gathering ladder: it fills the facts
// probe row rule reads. Gathering stops at the first row the verdict table
// refuses, so nothing after a failing row runs (no CLI call on a WSL2 host,
// no canary container before the gateway authenticated).
type openShellStep struct {
	rule   string
	gather func(ctx context.Context, g *openShellGathering)
}

// openShellGathering is the state the ladder fills.
type openShellGathering struct {
	cfg config.TerminalSandboxOpenShellConfig
	run func(ctx context.Context, spec integration.BinaryResolveSpec, args []string) extrun.Result
	// trust is the trust rule's refusal for a program ("" when it may run;
	// openShellProgram).
	trust  func(spec integration.BinaryResolveSpec) string
	runAt  func(ctx context.Context, t sandboxopenshell.Target, spec integration.BinaryResolveSpec, args []string) extrun.Result
	host   openShellHostFactsT
	out    openShellProbe
	config sandboxopenshell.Target
}

// openShellSteps is the gathering ladder, in probe row order.
var openShellSteps = []openShellStep{
	{"P0", func(_ context.Context, g *openShellGathering) { g.out.facts.GatewayMode = g.cfg.EffectiveGatewayMode() }},
	{"P1", func(context.Context, *openShellGathering) {}},
	{"P2", func(ctx context.Context, g *openShellGathering) {
		if g.trust != nil {
			if why := g.trust(openShellCLISpec); why != "" {
				g.out.facts.CLIFound, g.out.facts.CLIUntrusted = true, why
				return
			}
		}
		res := g.run(ctx, openShellCLISpec, []string{"--version"})
		g.out.facts.CLIFound = res.Outcome != extrun.OutcomeRefused && res.Outcome != extrun.OutcomeStartFailed
		if res.Outcome == extrun.OutcomeOK {
			g.out.facts.Version.CLI = string(res.Stdout)
		}
	}},
	{"PG", openShellManagedStep},
	{"P5", func(ctx context.Context, g *openShellGathering) {
		argv, err := sandboxopenshell.StatusArgv(g.config)
		if err != nil {
			return
		}
		res := g.runAt(ctx, g.config, openShellCLISpec, argv[1:])
		if res.Outcome != extrun.OutcomeOK {
			return
		}
		st, err := sandboxopenshell.ParseStatus(res.Stdout)
		if err != nil {
			return
		}
		g.out.status = st
		g.out.facts.GatewayStatus, g.out.facts.Authentication, g.out.facts.Version.Gateway = st.Status, st.Authentication, st.Version
		g.out.facts.GatewayServer, g.out.facts.GatewayName = st.Server, st.Gateway
		g.out.pin = openShellPin{Target: sandboxopenshell.Target{Gateway: st.Gateway, Endpoint: g.config.Endpoint, ConfigHome: g.config.ConfigHome}, Server: st.Server}
	}},
	{"P6", func(ctx context.Context, g *openShellGathering) {
		args := append(openShellGlobals(g.out.pin.Target), "gateway", "info", "-o", "json")
		res := g.runAt(ctx, g.out.pin.Target, openShellCLISpec, args)
		if res.Outcome == extrun.OutcomeOK {
			g.out.facts.Driver = openShellParseDriver(res.Stdout)
		}
		inGroup := g.host.DockerGroup != nil && g.host.DockerGroup()
		g.out.prereq = openShellPrereqFor(g.out.facts.Driver, inGroup)
	}},
	{"P7", func(_ context.Context, g *openShellGathering) {
		if g.host.LandlockABI != nil {
			g.out.facts.LandlockABI = g.host.LandlockABI()
		}
	}},
	{"P8e", openShellEngineStep},
	{"P8i", openShellImagesStep},
	{"P8", func(ctx context.Context, g *openShellGathering) {
		image := g.out.facts.CanaryImage
		if image == "" {
			image = sandboxopenshell.CanaryImage(g.out.res.Version.Version)
		}
		g.out.facts.CanaryImage = image
		in := sandboxopenshell.CanaryInput{Image: image, ObserverBin: g.host.ObserverBin, UID: -1, GID: -1}
		if g.host.IDs != nil {
			in.UID, in.GID = g.host.IDs()
		}
		args, err := sandboxopenshell.CanaryArgv(in)
		if err != nil {
			g.out.facts.Canary, g.out.facts.CanaryDetail = sandboxopenshell.CanaryNotStarted, err.Error()
			return
		}
		res := g.run(ctx, openShellDockerSpec, args)
		g.out.facts.Canary, g.out.facts.CanaryDetail = sandboxopenshell.ClassifyCanary(openShellCanaryRun(res))
	}},
	{"P9", func(_ context.Context, g *openShellGathering) {
		if g.host.BindMounts != nil {
			g.out.facts.BindMounts = g.host.BindMounts(g.out.facts.Driver)
		}
	}},
	{"PS", openShellGatewayPolicyStep}, // lane FU8, OSH-40
}

// openShellEngineStep is the gathering ladder's P8e step (ledger row
// OSH-48, adversarial row A9): the ID of the engine this launch's docker
// drives, and the row's record of the engine it first used, which the
// first use writes (owner-only, never over an existing record).
func openShellEngineStep(ctx context.Context, g *openShellGathering) {
	if !sandboxopenshell.DriverHasEngineIdentity(g.out.facts.Driver) {
		// The Podman driver: no stable engine ID to compare (row P8e does
		// not apply), so nothing runs and nothing is recorded.
		return
	}
	f := sandboxopenshell.EngineFacts{Record: sandboxopenshell.EngineRecordUnreadable}
	res := g.run(ctx, openShellDockerSpec, sandboxopenshell.EngineInfoArgv())
	if res.Outcome == extrun.OutcomeOK {
		f.ID, _ = sandboxopenshell.ParseEngineID(string(res.Stdout))
	}
	if f.ID == "" {
		f.Detail = strings.TrimPrefix(strings.TrimSuffix(openShellResultDetail(res), ")"), " (")
	}
	readRecord := func() {
		if g.host.EngineRecord == nil {
			return
		}
		path, b, err := g.host.EngineRecord()
		f.RecordPath = path
		f.Record, f.Recorded = sandboxopenshell.EngineRecordUnreadable, ""
		switch {
		case errors.Is(err, fs.ErrNotExist):
			f.Record = sandboxopenshell.EngineRecordAbsent
		case err == nil:
			if r, ok := sandboxopenshell.ParseEngineRecord(b); ok {
				f.Record, f.Recorded = sandboxopenshell.EngineRecordRead, r.EngineID
			}
		}
	}
	readRecord()
	if sandboxopenshell.EngineShouldRecord(f) && g.host.SaveEngine != nil {
		b, err := json.Marshal(sandboxopenshell.EngineRecord{EngineID: f.ID, FirstSeen: time.Now().Unix()})
		if err == nil {
			err = g.host.SaveEngine(b)
		}
		switch {
		case errors.Is(err, fs.ErrExist):
			// Another probe recorded first (audit finding FU7-A7): its
			// record is the first use; read it back and compare.
			readRecord()
		case err != nil:
			// Not recorded: the next probe tries again; this one has
			// nothing to compare with, which is the first use either way.
			g.out.engineNote = "the Docker engine's ID could not be recorded (" + err.Error() + ")"
		}
	}
	g.out.facts.Engine = f
}

// openShellEngineRecordIO returns the row's engine record reader and
// writer under stateDir (sandboxopenshell.EngineRecordFile): read
// no-follow and owner-checked, written once, owner-only.
func openShellEngineRecordIO(stateDir string) (func() (string, []byte, error), func([]byte) error) {
	p := filepath.Join(stateDir, sandboxopenshell.EngineRecordFile)
	read := func() (string, []byte, error) {
		b, err := openShellReadOwned(p, 4096)
		return p, b, err
	}
	save := func(b []byte) error {
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return err
		}
		return openShellWriteExcl(p, b)
	}
	return read, save
}

// openShellImagesStep is the gathering ladder's P8i step (ledger row
// OSH-48): the gateway's supervisor and sandbox runtime images (its
// config's references, else its version's defaults) and the registry
// digests the engine recorded for each; the canary then runs in that
// supervisor image.
func openShellImagesStep(ctx context.Context, g *openShellGathering) {
	var configured sandboxopenshell.RuntimeImages
	if g.host.GatewayImages != nil {
		configured = g.host.GatewayImages(g.out.facts.Driver)
	}
	images := sandboxopenshell.EffectiveRuntimeImages(configured, g.out.res.Version.Version)
	g.out.facts.CanaryImage = images.Supervisor
	g.out.facts.RuntimeImages = nil
	g.out.imageNote = sandboxopenshell.ImageTagNote(images, g.out.res.Version.Row, g.out.facts.Driver)
	for _, role := range sandboxopenshell.ImageRoles {
		ref := images.Ref(role)
		if role == sandboxopenshell.ImageSandbox && images.SandboxFromBin {
			// supervisor_bin replaces the sandbox runtime image (FU7-A10):
			// nothing to inspect; the note says what is not checked.
			g.out.facts.RuntimeImages = append(g.out.facts.RuntimeImages, sandboxopenshell.ImageFact{Role: role, Ref: ref, NotUsed: true})
			continue
		}
		args, ok := sandboxopenshell.ImageInspectArgv(ref)
		if !ok {
			g.out.facts.RuntimeImages = append(g.out.facts.RuntimeImages, sandboxopenshell.ImageFact{Role: role, Ref: ref, Detail: "the reference cannot be passed to docker"})
			continue
		}
		res := g.run(ctx, openShellDockerSpec, args)
		started := res.Outcome == extrun.OutcomeOK || res.Outcome == extrun.OutcomeExitNonZero
		g.out.facts.RuntimeImages = append(g.out.facts.RuntimeImages,
			sandboxopenshell.ClassifyImageInspect(role, ref, started, res.ExitCode, string(res.Stdout), string(res.Stderr)))
	}
}

// openShellRuleIndex is the position of a probe row in the verdict table's
// order (P0 to P10).
func openShellRuleIndex(rule string) int { return sandboxopenshell.ProbeRuleIndex(rule) }

// openShellGather walks the gathering ladder and returns the verdict.
func openShellGather(ctx context.Context, cfg config.TerminalSandboxOpenShellConfig, host sandboxbackend.HostKind, runner *extrun.Runner, hf openShellHostFactsT) openShellProbe {
	g := &openShellGathering{cfg: cfg, host: hf, config: sandboxopenshell.Target{Endpoint: cfg.Endpoint}}
	g.out.facts.Host = host
	g.out.facts.Version.Pin = cfg.Version
	g.run = func(ctx context.Context, spec integration.BinaryResolveSpec, args []string) extrun.Result {
		return openShellRun(ctx, runner, spec, args)
	}
	g.runAt = func(ctx context.Context, t sandboxopenshell.Target, spec integration.BinaryResolveSpec, args []string) extrun.Result {
		return openShellRunAt(ctx, runner, t, spec, args)
	}
	g.trust = func(spec integration.BinaryResolveSpec) string {
		_, why, _ := openShellProgram(runner, spec)
		return why
	}
	for _, st := range openShellSteps {
		st.gather(ctx, g)
		g.out.res = sandboxopenshell.Probe(g.out.facts)
		if !g.out.res.Available() && openShellRuleIndex(g.out.res.Rule) <= openShellRuleIndex(st.rule) {
			return g.out
		}
	}
	return g.out
}

// openShellBinaryFactsFn reads the trust rule's facts about a resolved
// OpenShell program (a variable so a test feeds them).
var openShellBinaryFactsFn = openShellStatBinaryFacts

// openShellProgram is the one seam every OpenShell program goes through
// (ledger row OSH-44): openshell-gateway and the openshell CLI
// (sandboxopenshell.TrustedPrograms) are resolved here, checked by the
// trust rule (sandboxopenshell.BinaryTrust) and run from the checked real
// path; why is the refusal when the program was found only where the user
// or a box could replace it, and found is false when a trusted program did
// not resolve at all (never handed to the runner by its spec, which would
// resolve it again unchecked; audit finding FU7-A5). Any other program
// goes to the runner by its spec.
func openShellProgram(runner *extrun.Runner, spec integration.BinaryResolveSpec) (prog extrun.Program, why string, found bool) {
	s := spec
	if len(spec.Names.Unix) == 0 || !slices.Contains(sandboxopenshell.TrustedPrograms, spec.Names.Unix[0]) {
		return extrun.Program{Spec: &s, AllowSymlink: true}, "", true
	}
	if runner.Resolve == nil {
		return extrun.Program{}, "", false
	}
	res := runner.Resolve(spec)
	if res.Bin == "" || !filepath.IsAbs(res.Bin) {
		return extrun.Program{}, "", false
	}
	f := openShellBinaryFactsFn(spec.Names.Unix[0], res.Bin)
	if why := sandboxopenshell.BinaryTrust(f); why != "" {
		return extrun.Program{}, why, true
	}
	return extrun.Program{Path: f.Real, AllowSymlink: true}, "", true
}

// openShellNotFound is the runner's answer for a trusted program that did
// not resolve: refused as not found, nothing started.
func openShellNotFound(spec integration.BinaryResolveSpec) extrun.Result {
	name := "the program"
	if len(spec.Names.Unix) > 0 {
		name = spec.Names.Unix[0]
	}
	return extrun.Result{Outcome: extrun.OutcomeRefused, Reason: extrun.RefuseNotFound, Detail: name + " is not installed or not on PATH", ExitCode: -1}
}

// openShellUntrusted is the runner's answer for a program the trust rule
// refused: refused, nothing started, the reason as its detail.
func openShellUntrusted(why string) extrun.Result {
	return extrun.Result{Outcome: extrun.OutcomeRefused, Reason: extrun.RefuseNotFound, Detail: why, ExitCode: -1}
}

// openShellRun runs one program through the runner under the component's
// id, with the fixed environment and the call timeout.
func openShellRun(ctx context.Context, runner *extrun.Runner, spec integration.BinaryResolveSpec, args []string) extrun.Result {
	ctx, cancel := context.WithTimeout(ctx, openShellCmdTimeout)
	defer cancel()
	prog, why, found := openShellProgram(runner, spec)
	switch {
	case !found:
		return openShellNotFound(spec)
	case why != "":
		return openShellUntrusted(why)
	}
	return runner.Run(ctx, extrun.Request{
		Component: openShellComponentID,
		Program:   prog,
		Args:      args,
		Env:       extrun.EnvSpec{Inherit: openShellEnvInherit},
		Limits:    extrun.Limits{Wall: openShellCmdTimeout, StdoutBytes: 1 << 20, StderrBytes: 64 << 10},
	})
}

// openShellGlobals renders a target's global flags (an invalid target
// renders none; the box commands' own builders refuse it).
func openShellGlobals(t sandboxopenshell.Target) []string {
	argv, err := sandboxopenshell.StatusArgv(t)
	if err != nil || len(argv) < 4 {
		return nil
	}
	return append([]string(nil), argv[1:len(argv)-3]...)
}

// openShellParseDriver reads the first compute driver's name from `openshell
// gateway info -o json` (o0-receipts.md, CLI table, "Gateway runtime
// info"); "" when it is not there.
func openShellParseDriver(b []byte) string {
	var w struct {
		ComputeDrivers []struct {
			Name string `json:"name"`
		} `json:"compute_drivers"`
	}
	if json.Unmarshal(b, &w) != nil || len(w.ComputeDrivers) == 0 {
		return ""
	}
	return strings.TrimSpace(w.ComputeDrivers[0].Name)
}

// openShellCanaryRun reads the runner's answer to the canary's docker call
// into the planner's canary facts: whether docker itself started, its exit
// code (-1 for a timeout or a signal) and its output.
func openShellCanaryRun(res extrun.Result) sandboxopenshell.CanaryRun {
	run := sandboxopenshell.CanaryRun{Started: true, ExitCode: res.ExitCode, Stdout: string(res.Stdout), Stderr: string(res.Stderr)}
	switch res.Outcome {
	case extrun.OutcomeRefused, extrun.OutcomeStartFailed:
		run.Started = false
	case extrun.OutcomeOK, extrun.OutcomeExitNonZero:
	case extrun.OutcomeTimeout, extrun.OutcomeCanceled:
		run.TimedOut, run.ExitCode = true, -1
	default:
		run.ExitCode = -1
	}
	return run
}

// floor refuses a launch the local config or an org floor does not allow on
// this row: it must be listed (or named), the tier must be one the row
// offers, and the org floors apply through sandboxselect.FloorDrop (its
// capability tokens are the only way a floor accepts this row).
func (d *openShellDriver) floor(cfg config.TerminalSandboxConfig) error {
	row := openShellRow()
	if cfg.PinnedNoBackend != "" {
		return fmt.Errorf("terminal_sandbox: your organization's pin of %s allows none of the sandbox backends this machine is set to use, so no backend is enabled; the sandboxed terminal is refused, never run without it", cfg.PinnedNoBackend)
	}
	if !slices.Contains(sandboxEnabledBackends(cfg), row.ID) && d.r.forceBackend != row.ID {
		return fmt.Errorf("terminal_sandbox: %s is not in [terminal.sandbox].backends %v", row.ID, cfg.Backends)
	}
	if floor := vocab.IsoClass(cfg.MinIsolation); floor != "" && row.Iso.Class.Rank() < floor.Rank() {
		return fmt.Errorf("terminal_sandbox: %s builds %s isolation, below [terminal.sandbox].min_isolation = %s", row.ID, row.Iso.Class, floor)
	}
	tier := vocab.Tier(cfg.Egress)
	if !row.OffersTier(tier) {
		return fmt.Errorf("terminal_sandbox: the openshell row offers the tiers %v; set [terminal.sandbox].egress to one of them", row.Net.Egress)
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
		// The gateway mode the floor gateway_modes judges (rule S7g, lane O4).
		Probes: map[string]sandboxselect.Probe{row.ID: openShellSurface(sandboxselect.Probe{}, d.cfg)},
	}
	if drop, dropped := sandboxselect.FloorDrop(row, in, beta); dropped {
		return sandboxRefusalError{msg: isolationFloorMessage(drop)}
	}
	return nil
}

// Create checks the floors and the probe, pins the run's gateway and
// prepares the workspace with the shared step.
func (d *openShellDriver) Create(ctx context.Context, req termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	if err := d.floor(launchFloorConfig(d.r.cfg, string(d.r.egress.Mode))); err != nil {
		return termsvc.CreateResult{}, err
	}
	p := d.probeResult(ctx)
	if !p.res.Available() {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: openshell is not available: %s (%s)", p.res.Reason, p.res.Verdict)
	}
	if !p.pin.Target.Pinned() {
		return termsvc.CreateResult{}, errors.New("terminal_sandbox: openshell: the gateway's status answer named no gateway, so the run's box could not be pinned to it")
	}
	if _, err := macToolSpec(req.Tool); err != nil {
		return termsvc.CreateResult{}, err
	}
	// Lane O3: the network rules must compile and, on internet, the
	// gateway must export its OCSF events to the receiver.
	egressNote, err := openShellEgressRefusal(d.r.cfg, vocab.Tier(d.r.egress.Mode), d.r.providerHostList(), d.r.observerBin, d.stateDir(), p.ocsfGateway())
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	if err := openShellExtraBindsRefusal(d.r.cfg, d.r.orgRWBinds); err != nil {
		return termsvc.CreateResult{}, err
	}
	// Before prepareWorkspace, so a refused source spends no clone.
	if err := openShellWorkspaceSourceRefusal(req.WorkspaceSource); err != nil {
		return termsvc.CreateResult{}, err
	}
	ws, err := d.r.prepareWorkspace(ctx, req)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	d.targets.Store(ws.id, p.pin)
	tier := vocab.Tier(d.r.egress.Mode)
	routed, _ := d.r.launchRouted(req.Tool, ws.dir, req.ToolArgs)
	return termsvc.CreateResult{
		Run: termsvc.SandboxRun{ID: ws.id, Tool: req.Tool, Dir: ws.dir, ProjectRoot: req.ProjectRoot, Copy: !ws.live},
		Note: fmt.Sprintf("sandbox: backend=openshell (OpenShell %s, beta) gateway=%s %s source=%s workspace=%s egress=%s prerequisite=%s home=%s bind_mounts=gateway_wide",
			p.res.Version.Version, openShellTargetName(p.pin.Target), openShellModeNote(p), ws.src, ws.dir, tier, p.prereq, openShellHomeNote(d.r.cfg.HomeMode)) + egressNote,
		Isolation:   macIsolation(openShellRow(), tier, routed, "", d.r.cfg.EffectiveProviderDirect()),
		ProxyRouted: routed,
	}, nil
}

// openShellHomeNote is the home field of the run's posture note, from the
// planner's own rule (sandboxopenshell.SharedHome); compose refuses a plan
// whose Plan.SharedHome disagrees, so the note never states a home the box
// does not have (audit finding O1B-A12).
func openShellHomeNote(homeMode string) string {
	if sandboxopenshell.SharedHome(homeMode) {
		return "shared_tmpfs"
	}
	return "readonly_bind"
}

// openShellExtraBindRows are the bind keys this row does not carry into
// the box (audit finding O1B-A12): the planner's mount scope has no root
// for them, so a launch that sets any is refused naming the key, never run
// with them silently absent. Walked top-down; the org's write binds (which
// the managed body composes into extra_rw_binds) are named first.
var openShellExtraBindRows = []struct {
	key   string
	binds func(cfg config.TerminalSandboxConfig, org []string) []string
}{
	{"your organization's write binds (extra_rw_binds set by the managed policy)", func(_ config.TerminalSandboxConfig, org []string) []string { return org }},
	{"[terminal.sandbox].extra_rw_binds", func(cfg config.TerminalSandboxConfig, org []string) []string {
		var local []string
		for _, b := range cfg.ExtraRWBinds {
			if !slices.ContainsFunc(org, func(o string) bool { return filepath.Clean(o) == filepath.Clean(b) }) {
				local = append(local, b)
			}
		}
		return local
	}},
	{"[terminal.sandbox].extra_ro_binds", func(cfg config.TerminalSandboxConfig, _ []string) []string { return cfg.ExtraROBinds }},
}

// openShellExtraBindsRefusal refuses a launch that sets extra binds.
func openShellExtraBindsRefusal(cfg config.TerminalSandboxConfig, org []string) error {
	for _, row := range openShellExtraBindRows {
		if b := row.binds(cfg, org); len(b) > 0 {
			return fmt.Errorf("terminal_sandbox: openshell does not carry %s into the box (%s); the launch is refused rather than run without them: remove them, or use another sandbox backend", row.key, strings.Join(b, ", "))
		}
	}
	return nil
}

// openShellWorkspaceSources are the workspace sources this row launches
// (audit finding O1B-R3): live only. A managed source (clone-local,
// clone-remote, worktree) prepares its workspace under the managed root,
// by default <observer dir>/workspaces, and the planner never binds
// anything under the observer dir writable, so compose would refuse it
// after the clone was spent.
var openShellWorkspaceSources = map[workspace.Source]bool{workspace.SourceLive: true}

// openShellWorkspaceSourceRefusal refuses a workspace source this row does
// not launch ("" is live, as prepareWorkspace reads it).
func openShellWorkspaceSourceRefusal(raw string) error {
	source := strings.TrimSpace(raw)
	if source == "" {
		source = string(workspace.SourceLive)
	}
	src, err := workspace.ParseSource(source)
	if err != nil {
		return err
	}
	if !openShellWorkspaceSources[src] {
		return fmt.Errorf("terminal_sandbox: openshell launches only the live workspace (your project folder as it is), not the %s source: a managed workspace is prepared under Observer's own directory, which this row never binds writable; launch with the live source, or use another sandbox backend", src)
	}
	return nil
}

// openShellTargetName names a target in a note (no secret: a gateway name
// or a loopback URL).
func openShellTargetName(t sandboxopenshell.Target) string {
	if t.Gateway != "" {
		return t.Gateway
	}
	return t.Endpoint
}

// Attach writes the run record, the policy file and the plan file and
// returns the argv the PTY child runs.
func (d *openShellDriver) Attach(ctx context.Context, created termsvc.CreateResult) (termsvc.AttachResult, error) {
	p := d.probeResult(ctx)
	if !p.res.Available() {
		return termsvc.AttachResult{}, fmt.Errorf("terminal_sandbox: openshell is not available: %s (%s)", p.res.Reason, p.res.Verdict)
	}
	v, ok := d.targets.Load(created.Run.ID)
	if !ok {
		return termsvc.AttachResult{}, errors.New("terminal_sandbox: openshell: the run has no pinned gateway (it was not created by this driver)")
	}
	pin, _ := v.(openShellPin)
	if err := d.r.writeRunRecord(created.Run); err != nil {
		return termsvc.AttachResult{}, err
	}
	wrap, err := d.compose(created, p, pin)
	if err != nil {
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, created.Run.ID)
		_ = os.RemoveAll(openShellRunDir(d.stateDir(), created.Run.ID))
		return termsvc.AttachResult{}, err
	}
	d.targets.Delete(created.Run.ID)
	d.r.unattached.Delete(created.Run.ID)
	return termsvc.AttachResult{WrapArgv: wrap}, nil
}

// stateDir is the row's state directory ([terminal.sandbox.openshell]
// .state_dir, default <observer dir>/sandbox-openshell).
func (d *openShellDriver) stateDir() string {
	return openShellStateDir(d.r.observerDir, d.cfg.StateDir)
}

// openShellStateDir resolves the state directory.
func openShellStateDir(observerDir, configured string) string {
	if configured != "" {
		return filepath.Clean(configured)
	}
	return filepath.Join(observerDir, "sandbox-openshell")
}

// openShellRunDir is one run's directory (its policy file, plan file and,
// while a host helper runs it, the helper's lock).
func openShellRunDir(stateDir, runID string) string {
	return filepath.Join(stateDir, "runs", runID)
}

// openShellSockRoot is where a run's socket dir is made (the temp dir, as
// every row's), a variable so a test points it elsewhere. The reaper
// removes only a socket dir directly under it (audit finding O1B-R2); a run
// a CLI launch planned under another TMPDIR keeps its socket dir for the
// host's own temp cleanup.
var openShellSockRoot = os.TempDir

// openShellSockDir is one run's socket dir.
func openShellSockDir(runID string) string {
	return filepath.Join(openShellSockRoot(), "observer-sbx-"+runID)
}

// openShellPlanFile is the per-run plan the host helper reads. It holds no
// secret by rule (TestOpenShellPlanFileHoldsNoSecrets): the box's
// environment is built by the helper from its own, never stored here.
type openShellPlanFile struct {
	Version int    `json:"version"`
	RunID   string `json:"run_id"`
	// Target is the pinned gateway (audit finding O1A-A9).
	Target sandboxopenshell.Target `json:"target"`
	// Server is the server the pinned gateway answered from at create
	// (audit finding O1B-A14): every later box command checks the name
	// still resolves to it.
	Server string `json:"server"`
	// GatewayVersion is the gateway version the probe read: the not-found
	// text the helper classifies is this version's (ClassifyGet).
	GatewayVersion   string `json:"gateway_version"`
	Name             string `json:"name"`
	PolicyPath       string `json:"policy_path"`
	DriverConfigJSON string `json:"driver_config_json"`
	// Env is the planner's environment for the create argv (HOME alone):
	// every other variable goes through the env file.
	Env      []string                    `json:"env"`
	Labels   []sandboxopenshell.Label    `json:"labels"`
	Home     string                      `json:"home"`
	SockDir  string                      `json:"sock_dir"`
	CopyDir  string                      `json:"copy_dir"`
	CopySync []sandboxopenshell.CopySync `json:"copy_sync,omitempty"`
	// Seed are one-way copies into the box (the observer dir's
	// executed-state files the inner launcher reads, never observer.db or
	// a secret): staged under CopyDir and copied in, never synced back.
	Seed []sandboxopenshell.CopySync `json:"seed,omitempty"`
	// ObserverBin is the observer binary, bound read-only at its host path.
	ObserverBin string `json:"observer_bin"`
	// Guest is the in-box guest helper prefix (sandbox.GuestArgv).
	Guest []string `json:"guest,omitempty"`
	// DropEnv are names the box never gets.
	DropEnv []string `json:"drop_env,omitempty"`
	// Workdir is the run's workspace (a same-path bind): the in-box init
	// starts the command there, not in OpenShell's own workdir (/sandbox,
	// which include_workdir false leaves unwritable; live run O1B-L1).
	Workdir string `json:"workdir,omitempty"`
	// Network are the network rules the plan compiled into the policy file
	// (none on the proxy_only and none tiers), and EffectiveCheck asks the
	// host helper to compare them with the gateway's effective policy for
	// the box (lane FU8, OSH-40; set for an external gateway).
	Network        []sandboxopenshell.NetRule `json:"network,omitempty"`
	EffectiveCheck bool                       `json:"effective_check,omitempty"`
}

// openShellObserverSeed is the executed-state table the box gets a
// read-only copy of (the files the inner launcher reads), never a bind:
// nothing under the observer dir is bound but Observer's own binary (audit
// finding O1A-R2).
func openShellObserverSeed(observerDir, home string) []sandboxopenshell.CopySync {
	var out []sandboxopenshell.CopySync
	for _, row := range sandboxObserverExecState {
		if row.Dir {
			continue
		}
		p := filepath.Join(observerDir, row.Rel)
		fi, err := os.Lstat(p) //nolint:gosec // G703: a fixed row under the daemon's own observer dir
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > openShellCopyCap {
			continue
		}
		// The box's copy sits at the home's own ~/.observer, where the
		// launcher looks for it.
		out = append(out, sandboxopenshell.CopySync{Source: p, Target: filepath.Join(home, ".observer", row.Rel)})
	}
	return out
}

// compose builds the run's bind plan, compiles it, writes the policy file
// and the plan file and returns the wrap argv.
func (d *openShellDriver) compose(created termsvc.CreateResult, p openShellProbe, pin openShellPin) ([]string, error) {
	r := d.r
	run := created.Run
	home, err := macRealHome()
	if err != nil {
		return nil, err
	}
	spec, err := macToolSpec(run.Tool)
	if err != nil {
		return nil, err
	}
	installID, err := openShellInstallID(d.stateDir())
	if err != nil {
		return nil, err
	}
	sockDir := openShellSockDir(run.ID)
	copyDir := filepath.Join(sockDir, "copy")
	// W4: the host helper forwards the model proxy only; OpenShell's proxy
	// owns any other egress (lane O3).
	netReq := sandbox.NetRequest{Egress: openShellHelperEgress(r.egress.Mode), ProxyPort: r.proxyPort, HostSocketDir: sockDir}
	if capture := sandboxRunCaptureFor(openShellRow(), created.ProxyRouted, vocab.Tier(r.egress.Mode), r.cfg.EffectiveProviderDirect()); capture.ProviderBlock {
		netReq.ProviderBlock, netReq.ProviderHosts = true, r.providerHostList()
	}
	overlays, pins, err := r.protection(home, run.Dir, spec)
	if err != nil {
		return nil, err
	}
	// The Windows drives the box must not show (the mount table's, with the
	// foreign homes'); an unreadable table refuses the launch.
	foreign, err := foreignMountRoots()
	if err != nil {
		return nil, err
	}
	bp, err := openShellCompileInput(openShellBindInputs{
		home: home, workspace: run.Dir, sockDir: sockDir, copyDir: copyDir,
		observerBin: r.observerBin, observerDir: r.observerDir, observerRealDir: openShellResolvedObserverDir(r.observerDir),
		spec: spec, overlays: overlays, pins: pins, toolBinDirs: r.toolBinDirs(run.Tool),
		homeMode: r.cfg.HomeMode, tier: vocab.Tier(r.egress.Mode), driver: p.facts.Driver, masks: openShellMasks(r.cfg, foreign),
		uid: os.Getuid(), gid: os.Getgid(), lstat: os.Lstat, resolve: filepath.EvalSymlinks,
	})
	if err != nil {
		return nil, err
	}
	in, notes := bp.in, bp.notes
	netIn, runEgress, err := openShellRunNet(r.cfg, vocab.Tier(r.egress.Mode), r.providerHostList(), r.observerBin)
	if err != nil {
		return nil, err
	}
	in.Net = netIn
	runEgress.Gateway = pin.Target.Gateway
	plan, err := sandboxopenshell.Compile(in)
	if err != nil {
		return nil, fmt.Errorf("terminal_sandbox: %w", err)
	}
	if plan.SharedHome != sandboxopenshell.SharedHome(in.Settings.HomeMode) {
		return nil, fmt.Errorf("terminal_sandbox: openshell: the compiled home (shared %v) is not the home the run's note states (%s)", plan.SharedHome, openShellHomeNote(in.Settings.HomeMode))
	}
	// The host helper creates exactly the placeholders the plan binds
	// read-only over (audit finding O1B-A1): one it created with no mount
	// over it would be a host file the box can write.
	if err := openShellCheckPlaceholders(plan, bp.placeholders); err != nil {
		return nil, err
	}
	host, err := sandbox.RelayHostArgv(r.observerBin, netReq, bp.placeholders, sandbox.RelayRequest{RunID: run.ID, HostObserverDir: r.observerDir})
	if err != nil {
		return nil, err
	}
	guest, err := sandbox.GuestArgv(r.observerBin, netReq)
	if err != nil {
		return nil, err
	}
	labels, err := sandboxopenshell.RunLabels(installID, run.ID)
	if err != nil {
		return nil, err
	}
	runDir := openShellRunDir(d.stateDir(), run.ID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return nil, fmt.Errorf("terminal_sandbox: openshell run dir: %w", err)
	}
	policyPath := filepath.Join(runDir, "policy.yaml")
	if err := openShellWriteExcl(policyPath, plan.PolicyYAML); err != nil {
		return nil, err
	}
	if err := openShellWriteEgress(runDir, runEgress); err != nil {
		return nil, err
	}
	pf := openShellPlanFile{
		Version: openShellPlanVersion, RunID: run.ID, Target: pin.Target, Server: pin.Server, GatewayVersion: p.res.Version.Version.String(),
		Name: sandboxopenshell.SandboxName(run.ID), PolicyPath: policyPath, DriverConfigJSON: plan.DriverConfigJSON,
		Labels: labels, Env: plan.Env, Home: home, SockDir: sockDir, CopyDir: copyDir, CopySync: plan.CopySync,
		Seed: openShellObserverSeed(r.observerDir, home), ObserverBin: r.observerBin, Guest: guest, Workdir: run.Dir,
		DropEnv: sandboxSignInDropEnv(run.Tool, false),
		Network: plan.Network, EffectiveCheck: p.facts.GatewayMode == sandboxopenshell.GatewayExternal,
	}
	// Validate the create argv now (with a stand-in command), so a bad plan
	// refuses here rather than in the helper.
	if _, err := openShellCreateArgv(pf, plan.Env, []string{r.observerBin}); err != nil {
		return nil, fmt.Errorf("terminal_sandbox: %w", err)
	}
	// The in-box init's argv too (review finding V5, tracker F-023): the
	// stand-in command above leaves it out, so a workdir or a path the init
	// refuses would otherwise first fail inside a box already created.
	if err := openShellCheckInitArgv(pf); err != nil {
		return nil, fmt.Errorf("terminal_sandbox: openshell: %w", err)
	}
	b, err := json.Marshal(pf)
	if err != nil {
		return nil, err
	}
	planPath := filepath.Join(runDir, "plan.json")
	if err := openShellWriteExcl(planPath, b); err != nil {
		return nil, err
	}
	if err := openShellRecordGateway(d.stateDir(), openShellGatewayEntry{Target: pin.Target, Server: pin.Server, Version: pf.GatewayVersion}); err != nil && r.logger != nil {
		r.logger.Warn("terminal_sandbox: openshell: recording the run's gateway for the reaper", "err", err)
	}
	if r.logger != nil && len(notes) > 0 {
		r.logger.Info("terminal_sandbox: openshell: left out of the box", "run", run.ID, "notes", strings.Join(notes, "; "))
	}
	if r.inDaemon {
		openShellEnsureReaper(d.stateDir(), r.observerDir)
	}
	wrap := []string{r.observerBin, openShellHostVerb, "--plan", planPath, "--"}
	wrap = append(wrap, host...)
	return append(wrap, openShellInnerMarker), nil
}

// openShellResolvedObserverDir is the observer dir's other spelling when
// it is a link ("" when there is one spelling).
func openShellResolvedObserverDir(observerDir string) string {
	real, err := filepath.EvalSymlinks(observerDir)
	if err != nil || real == observerDir {
		return ""
	}
	return real
}

// openShellBindInputs are the facts one run's bind plan is built from.
type openShellBindInputs struct {
	home, workspace, sockDir, copyDir         string
	observerBin, observerDir, observerRealDir string
	spec                                      integration.SandboxSpec
	overlays                                  []sandbox.Overlay
	pins                                      []string
	toolBinDirs                               []string
	homeMode                                  string
	tier                                      vocab.Tier
	driver                                    string
	uid, gid                                  int
	lstat                                     func(string) (fs.FileInfo, error)
	// resolve resolves a path's symlinks (filepath.EvalSymlinks; nil reads
	// every path as resolved).
	resolve func(string) (string, error)
	// masks are the paths the mask keys ask the box to hide
	// (openShellMasks).
	masks []openShellMask
}

// openShellOnLink is what the bind builder does with a source reached
// through a symbolic link (audit finding O1B-A6). Docker follows a link in
// a bind source while the planner checks the spelling it was given, and a
// tool would find its state at the link's path, which the box does not
// have, so a link is never bound as it stands.
type openShellOnLink int

const (
	// openShellLinkRefuse refuses the launch with a plain reason: the
	// workspace, the tool's writable state, the repository pins, the
	// protected paths and Observer's own binary.
	openShellLinkRefuse openShellOnLink = iota
	// openShellLinkLeaveOut leaves the source out with a note: a read-only
	// tool state dir, a tool bin dir or a runtime dir (the tool's resolved
	// bin dir is named on its own, toolBinDirs).
	openShellLinkLeaveOut
)

// openShellBindPlan is what the bind builder hands compose: the planner's
// input, the notes on what was left out, and the placeholders the host
// helper must create (each one bound read-only by the plan).
type openShellBindPlan struct {
	in           sandboxopenshell.Input
	notes        []string
	placeholders []sandbox.Overlay
}

// openShellCompileInput turns a run's facts into the planner's input: the
// mount scope (workspace, socket dir, the tool's state roots under the
// home, the exact bin paths) and the bind plan (the workspace and the
// tool's state read-write, every protected path read-only, the repository
// pins, Observer's binary and the tool's bin and runtime dirs read-only,
// the socket dir read-only and its copy dir read-write). A bin or runtime
// dir the planner would refuse as a scope root is left out and named in
// the notes; a protected path that would hide rather than bind refuses the
// launch (the planner has no mask mount); a bind source that is a unix
// socket refuses it (audit finding O1A-R1); a mask path inside a bound tree
// refuses it too (audit finding O1B-R1).
//
// A protected path that does not exist yet inside a bound tree is a
// placeholder: the host helper creates it before the create, so it is
// bound read-only without a stat (File from the placeholder's kind), the
// way the bubblewrap row binds read-only over the placeholders it makes
// (audit finding O1B-A1). Without that bind the box could write the
// placeholder through the writable tree around it, and a later host git or
// tool run would execute what it wrote. A protected path inside a bound
// tree that cannot be bound refuses the launch.
func openShellCompileInput(b openShellBindInputs) (openShellBindPlan, error) {
	bb := &openShellBindBuilder{b: b, seen: map[string]bool{}, resolve: b.resolve}
	if bb.resolve == nil {
		bb.resolve = func(p string) (string, error) { return p, nil }
	}
	bb.in = sandboxopenshell.Input{
		Settings: sandboxopenshell.Settings{HomeMode: b.homeMode, Egress: b.tier, Driver: b.driver},
		Home:     b.home, UID: b.uid, GID: b.gid,
		ObserverDir: b.observerDir, ObserverDirResolved: b.observerRealDir,
	}
	bb.in.Scope.Workspace, bb.in.Scope.SocketDir = b.workspace, b.sockDir
	for _, step := range []func() error{bb.addState, bb.addOverlays, bb.addPins, bb.addBins, bb.checkMasks} {
		if err := step(); err != nil {
			return openShellBindPlan{in: bb.in}, err
		}
	}
	// The socket dir and its copy dir exist only once the host helper made
	// them, so they are named without a stat.
	bb.binds = append(bb.binds,
		sandboxopenshell.Bind{Source: b.sockDir, Target: b.sockDir, ReadOnly: true},
		sandboxopenshell.Bind{Source: b.copyDir, Target: b.copyDir})
	bb.in.Binds = bb.binds
	bb.out.in = bb.in
	return bb.out, nil
}

// openShellBindBuilder is one openShellCompileInput call's state: the
// planner input being filled, the binds so far and what was left out.
type openShellBindBuilder struct {
	b       openShellBindInputs
	in      sandboxopenshell.Input
	out     openShellBindPlan
	binds   []sandboxopenshell.Bind
	seen    map[string]bool
	resolve func(string) (string, error)
}

// direct reports whether src resolves to itself, and what it resolves to
// otherwise (for the reason).
func (bb *openShellBindBuilder) direct(src string) (string, bool) {
	real, err := bb.resolve(src)
	if err != nil {
		return "nothing (a dangling link)", false
	}
	return real, filepath.Clean(real) == src
}

// linked handles a source whose resolved path differs from its spelling:
// refused, or noted and left out, by policy.
func (bb *openShellBindBuilder) linked(src, real string, onLink openShellOnLink) error {
	if onLink == openShellLinkLeaveOut {
		bb.out.notes = append(bb.out.notes, fmt.Sprintf("%s: reached through a symbolic link (it resolves to %s), so it is not bound", src, real))
		return nil
	}
	return fmt.Errorf("terminal_sandbox: openshell: %s is reached through a symbolic link (it resolves to %s); OpenShell binds are same-path and a link is never bound as it stands, so open or configure the resolved path, or use another sandbox backend", src, real)
}

// add binds an existing source at its own path (a missing one is skipped:
// the tmpfs home stands in); a link goes to linked, a unix socket refuses.
func (bb *openShellBindBuilder) add(src string, ro bool, onLink openShellOnLink) error {
	src = filepath.Clean(src)
	if bb.seen[src] {
		return nil
	}
	fi, err := bb.b.lstat(src)
	if err != nil {
		return nil
	}
	if real, ok := bb.direct(src); !ok {
		return bb.linked(src, real, onLink)
	}
	if fi.Mode()&fs.ModeSocket != 0 {
		return fmt.Errorf("terminal_sandbox: openshell: %s is a unix socket and is never bound into the box", src)
	}
	bb.seen[src] = true
	bb.binds = append(bb.binds, sandboxopenshell.Bind{Source: src, Target: src, ReadOnly: ro, File: !fi.IsDir()})
	return nil
}

// addState binds the workspace and the tool's state roots, read-write for
// StateRW and read-only for StateRO, and names the roots in the scope.
func (bb *openShellBindBuilder) addState() error {
	if err := bb.add(bb.b.workspace, false, openShellLinkRefuse); err != nil {
		return err
	}
	for _, row := range []struct {
		rels   []string
		ro     bool
		onLink openShellOnLink
	}{
		{bb.b.spec.StateRW, false, openShellLinkRefuse},
		{bb.b.spec.StateRO, true, openShellLinkLeaveOut},
	} {
		for _, rel := range row.rels {
			p := filepath.Join(bb.b.home, rel)
			bb.in.Scope.ToolState = append(bb.in.Scope.ToolState, p)
			if err := bb.add(p, row.ro, row.onLink); err != nil {
				return err
			}
		}
	}
	return nil
}

// addOverlays binds every protected path inside a bound tree read-only;
// a placeholder is bound without a stat (audit finding O1B-A1).
func (bb *openShellBindBuilder) addOverlays() error {
	bound := append([]string{bb.b.workspace}, bb.in.Scope.ToolState...)
	for _, o := range bb.b.overlays {
		if !openShellInsideAny(o.Path, bound) {
			continue // nothing the box can write reaches it
		}
		if o.Kind != sandbox.OverlayReadOnly {
			return fmt.Errorf("terminal_sandbox: openshell: %s would need a mask mount (%s), which this row cannot build", o.Path, o.Kind)
		}
		src := filepath.Clean(o.Path)
		if o.Placeholder == sandbox.PlaceholderNone {
			if _, err := bb.b.lstat(src); err != nil {
				return fmt.Errorf("terminal_sandbox: openshell: the protected path %s could not be read for its read-only bind: %w", src, err)
			}
			if err := bb.add(src, true, openShellLinkRefuse); err != nil {
				return err
			}
			continue
		}
		if err := bb.addPlaceholder(o, src); err != nil {
			return err
		}
	}
	return nil
}

// addPlaceholder binds one placeholder read-only, File from its kind, and
// hands it to the host helper.
func (bb *openShellBindBuilder) addPlaceholder(o sandbox.Overlay, src string) error {
	file, ok := openShellPlaceholderFile[o.Placeholder]
	if !ok {
		return fmt.Errorf("terminal_sandbox: openshell: the protected path %s has a placeholder kind %q this row cannot bind", src, o.Placeholder)
	}
	if bb.seen[src] {
		return fmt.Errorf("terminal_sandbox: openshell: the protected path %s is a placeholder and already bound", src)
	}
	// The helper creates the placeholder in its parent dir, which must be
	// the dir the box sees at that path (no link on the way).
	if real, ok := bb.direct(filepath.Dir(src)); !ok {
		return bb.linked(filepath.Dir(src), real, openShellLinkRefuse)
	}
	bb.seen[src] = true
	bb.binds = append(bb.binds, sandboxopenshell.Bind{Source: src, Target: src, ReadOnly: true, File: file})
	bb.out.placeholders = append(bb.out.placeholders, sandbox.Overlay{Path: src, Kind: o.Kind, Placeholder: o.Placeholder})
	return nil
}

// addPins binds the repository pins onto themselves (a file read-only, a
// dir read-write).
func (bb *openShellBindBuilder) addPins() error {
	for _, pin := range bb.b.pins {
		fi, err := bb.b.lstat(pin)
		if err != nil {
			continue
		}
		if err := bb.add(pin, !fi.IsDir(), openShellLinkRefuse); err != nil {
			return err
		}
	}
	return nil
}

// addBins binds Observer's binary and the tool's bin and runtime dirs
// read-only as exact bin paths; one the planner would refuse is left out
// with a note.
func (bb *openShellBindBuilder) addBins() error {
	bins := []string{bb.b.observerBin}
	bins = append(bins, bb.b.toolBinDirs...)
	for _, rel := range sandboxRuntimeLadder {
		bins = append(bins, filepath.Join(bb.b.home, rel))
	}
	for i, p := range bins {
		p = filepath.Clean(p)
		if bb.seen[p] {
			continue
		}
		fi, err := bb.b.lstat(p)
		if err != nil {
			continue
		}
		onLink := openShellLinkLeaveOut
		if i == 0 {
			onLink = openShellLinkRefuse // Observer's own binary runs the box
		}
		if real, ok := bb.direct(p); !ok {
			if err := bb.linked(p, real, onLink); err != nil {
				return err
			}
			continue
		}
		if err := sandboxopenshell.CheckScopeRoot(bb.in, p, fi.Mode().IsRegular()); err != nil {
			bb.out.notes = append(bb.out.notes, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		bb.in.Scope.BinPaths = append(bb.in.Scope.BinPaths, p)
		if err := bb.add(p, true, onLink); err != nil {
			return err
		}
	}
	return nil
}

// checkMasks refuses a mask path inside a tree the plan binds (audit
// finding O1B-R1): the row has no mask mount, so the box would show the path
// the key hides. A mask outside every bound tree stays allowed (nothing
// shows it: the home is a tmpfs and nothing else is bound), and so does one
// above a bound tree (the bound tree is shown, as bwrap's punched-back binds
// show it). Under home_mode "readonly" the home is a bound tree too
// (maskedTrees). The mask is compared as spelled and as resolved; the bind
// sources are resolved already (audit finding O1B-A6).
func (bb *openShellBindBuilder) checkMasks() error {
	for _, m := range bb.b.masks {
		if !filepath.IsAbs(m.path) {
			return fmt.Errorf("terminal_sandbox: openshell: %s names %q, which is not an absolute path; the launch is refused rather than run without the mask", m.key, m.path)
		}
		spelled := filepath.Clean(m.path)
		for _, p := range []string{spelled, bb.resolveLoose(spelled)} {
			for _, src := range bb.maskedTrees() {
				if isWithinPath(p, src) {
					return fmt.Errorf("terminal_sandbox: openshell cannot hide %s (%s): it lies inside %s, which the box binds, and this row has no mask mount; the launch is refused rather than run with the path showing: remove it, launch outside that tree, or use another sandbox backend", m.path, m.key, src)
				}
			}
		}
	}
	return nil
}

// maskedTrees are the host trees the box shows: every bind source, and the
// home itself when home_mode "readonly" binds it read-only (O5 sweep F-M1:
// the home mount is added by the planner's Compile, after this check, so a
// mask or a configured state dir under the home would otherwise show
// through it). In tmpfs mode the home is a tmpfs and shows nothing.
func (bb *openShellBindBuilder) maskedTrees() []string {
	out := make([]string, 0, len(bb.binds)+2)
	for _, bd := range bb.binds {
		out = append(out, bd.Source)
	}
	if !sandboxopenshell.SharedHome(bb.b.homeMode) && bb.b.home != "" {
		out = append(out, bb.b.home)
		if real := bb.resolveLoose(bb.b.home); real != bb.b.home {
			out = append(out, real)
		}
	}
	return out
}

// resolveLoose resolves p's deepest existing ancestor and keeps the rest as
// spelled (a mask path need not exist).
func (bb *openShellBindBuilder) resolveLoose(p string) string {
	rest := ""
	for cur := p; ; {
		if real, err := bb.resolve(cur); err == nil {
			return filepath.Join(real, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest, cur = filepath.Join(filepath.Base(cur), rest), parent
	}
}

// openShellMask is one path a mask key asks the box to hide, with the key
// that set it (for the refusal).
type openShellMask struct{ key, path string }

// openShellMaskRows are the mask sources this row cannot honour inside a
// bound tree (audit finding O1B-R1); together they are r.maskPaths(). The
// managed policy's mask_paths are unioned into the local key, so one row
// names both.
var openShellMaskRows = []struct {
	key   string
	paths func(cfg config.TerminalSandboxConfig, foreign []string) []string
}{
	{"[terminal.sandbox].mask_paths, yours or your organization's", func(cfg config.TerminalSandboxConfig, _ []string) []string { return cfg.MaskPaths }},
	{"the foreign-OS mount masks Observer detected", func(_ config.TerminalSandboxConfig, foreign []string) []string { return foreign }},
	// A configured state dir (the managed gateway's database and, in
	// owner_file custody, its keys) is never inside a bound tree (audit
	// finding O2-A11); the default one is under the observer dir, which is
	// never bound.
	{"[terminal.sandbox.openshell].state_dir (the managed gateway's database and keys)", func(cfg config.TerminalSandboxConfig, _ []string) []string {
		if cfg.OpenShell.StateDir == "" {
			return nil
		}
		return []string{cfg.OpenShell.StateDir}
	}},
}

// openShellMasks walks openShellMaskRows (blank entries skipped).
func openShellMasks(cfg config.TerminalSandboxConfig, foreign []string) []openShellMask {
	var out []openShellMask
	for _, row := range openShellMaskRows {
		for _, p := range row.paths(cfg, foreign) {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, openShellMask{key: row.key, path: p})
			}
		}
	}
	return out
}

// openShellPlaceholderFile is the bind's File flag for each placeholder
// kind the host helper creates (a kind not in the table refuses).
var openShellPlaceholderFile = map[sandbox.Placeholder]bool{
	sandbox.PlaceholderFile: true,
	sandbox.PlaceholderDir:  false,
}

// openShellCheckPlaceholders requires a read-only bind mount at every
// placeholder the host helper will create (audit finding O1B-A1): the
// helper creates the path on the host before the create, so a placeholder
// with no read-only mount over it would be a host file or dir the box can
// write through the writable tree around it.
func openShellCheckPlaceholders(plan sandboxopenshell.Plan, placeholders []sandbox.Overlay) error {
	for _, o := range placeholders {
		ok := false
		for _, m := range plan.Mounts {
			if m.Type == sandboxopenshell.MountTypeBind && m.Source == o.Path && m.Target == o.Path && m.ReadOnly {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("terminal_sandbox: openshell: the protected path %s would be created on the host with no read-only mount over it in the box; the launch is refused", o.Path)
		}
	}
	return nil
}

// openShellInsideAny reports whether p is one of roots or under one.
func openShellInsideAny(p string, roots []string) bool {
	for _, r := range roots {
		if r != "" && isWithinPath(p, r) {
			return true
		}
	}
	return false
}

// openShellCreateArgv builds the run's create argv from its plan file, the
// box environment (HOME first) and the box's command.
func openShellCreateArgv(pf openShellPlanFile, env, command []string) ([]string, error) {
	return sandboxopenshell.CreateArgv(sandboxopenshell.CreateInput{
		Target: pf.Target, Name: pf.Name, PolicyPath: pf.PolicyPath, DriverConfigJSON: pf.DriverConfigJSON,
		Labels: pf.Labels, Env: env, Command: command,
	})
}

// openShellInitArgv is the box's command up to the inner launch: the
// in-box init (the socket dir link, the environment file, the copies in
// and back), then the guest helper. staged are the copy dir's names of
// CopySync then Seed, in order.
func openShellInitArgv(pf openShellPlanFile, staged []string, envFile string) []string {
	out := []string{pf.ObserverBin, openShellInitVerb, "--sock-dir", pf.SockDir}
	if pf.Workdir != "" {
		out = append(out, "--cwd", pf.Workdir)
	}
	if envFile != "" {
		out = append(out, "--env-file", envFile)
	}
	for i, c := range pf.CopySync {
		out = append(out, "--copy", staged[i]+"="+c.Target)
	}
	for i, c := range pf.Seed {
		out = append(out, "--seed", staged[len(pf.CopySync)+i]+"="+c.Target)
	}
	out = append(out, "--")
	return append(out, pf.Guest...)
}

// openShellEnvFileName is the box environment's file in the copy dir: the
// environment never rides on the create argv (a process's argv is readable
// by every user of the host through /proc), only HOME does; the in-box init
// reads the file, removes it and hands the values to its child.
const openShellEnvFileName = "env"

// openShellCheckInitArgv parses, at compose, the in-box init argv the host
// helper will build from this plan (the staged names and the env file path
// it derives, the plan's guest command), with the init's own parser, so a
// plan the init would refuse (a workdir that is not absolute and clean, a
// copy target that is not) is refused before any box exists (review
// finding V5, tracker F-023). It reads no file and runs nothing.
func openShellCheckInitArgv(pf openShellPlanFile) error {
	argv := openShellInitArgv(pf, openShellStagedNames(pf), filepath.Join(pf.CopyDir, openShellEnvFileName))
	// The tool's own command follows the guest helper's in the box; a
	// stand-in keeps the command part non-empty.
	if _, err := parseOpenShellInitArgs(append(argv[2:], pf.ObserverBin)); err != nil {
		return fmt.Errorf("the in-box init would refuse this plan: %w", err)
	}
	return nil
}

// openShellStagedNames are the copy dir's names of a plan's copied files:
// CopySync first, then Seed (fixed names, never a host path).
func openShellStagedNames(pf openShellPlanFile) []string {
	out := make([]string, 0, len(pf.CopySync)+len(pf.Seed))
	for i := range pf.CopySync {
		out = append(out, filepath.Join(pf.CopyDir, fmt.Sprintf("copy-%d", i)))
	}
	for i := range pf.Seed {
		out = append(out, filepath.Join(pf.CopyDir, fmt.Sprintf("seed-%d", i)))
	}
	return out
}

// openShellEncodeEnv renders KEY=VALUE entries NUL-separated (a value may
// hold a newline); an entry that is not KEY=VALUE, or sets HOME, is left
// out.
func openShellEncodeEnv(env []string) []byte {
	var b strings.Builder
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" || k == "HOME" || strings.ContainsRune(kv, 0) {
			continue
		}
		b.WriteString(kv)
		b.WriteByte(0)
	}
	return []byte(b.String())
}

// openShellDecodeEnv is openShellEncodeEnv's inverse.
func openShellDecodeEnv(b []byte) []string {
	var out []string
	for _, kv := range strings.Split(string(b), "\x00") {
		if k, _, ok := strings.Cut(kv, "="); ok && k != "" && k != "HOME" {
			out = append(out, kv)
		}
	}
	return out
}

// openShellGatewayTOML is the slice of the gateway's config the probe reads:
// the two driver keys of decision D3 and the two runtime image keys (row
// P8i), nothing else (every other key is decoded into nothing).
type openShellGatewayTOML struct {
	OpenShell struct {
		Drivers map[string]struct {
			AllowDriverConfig   *bool  `toml:"allow_driver_config"`
			EnableBindMounts    *bool  `toml:"enable_bind_mounts"`
			SupervisorImage     string `toml:"supervisor_image"`
			SandboxRuntimeImage string `toml:"sandbox_runtime_image"`
			SupervisorBin       string `toml:"supervisor_bin"`
		} `toml:"drivers"`
	} `toml:"openshell"`
}

// openShellBindMountsFrom decides probe row P9's fact from the gateway's
// config file (D3: in external mode the opt-in lives in the user's own
// gateway config, which Observer reads and never writes): yes when both
// keys are true under [openshell.drivers.<driver>], no when the file was
// read and either is false or absent, unknown when the file could not be
// read or decoded or the driver is unknown.
func openShellBindMountsFrom(b []byte, readErr error, driver string) sandboxopenshell.Tri {
	if readErr != nil || driver == "" {
		return sandboxopenshell.TriUnknown
	}
	var c openShellGatewayTOML
	if _, err := toml.Decode(string(b), &c); err != nil {
		return sandboxopenshell.TriUnknown
	}
	d, ok := c.OpenShell.Drivers[driver]
	if ok && d.AllowDriverConfig != nil && *d.AllowDriverConfig && d.EnableBindMounts != nil && *d.EnableBindMounts {
		return sandboxopenshell.TriYes
	}
	return sandboxopenshell.TriNo
}

// openShellImagesFrom reads row P8i's configured runtime images from the
// gateway's config file: the driver's supervisor_image and
// sandbox_runtime_image ("" each when absent); zero when the file could not
// be read or decoded or the driver is unknown (the version's defaults then
// apply, and row P9 refuses an unread config anyway).
func openShellImagesFrom(b []byte, readErr error, driver string) sandboxopenshell.RuntimeImages {
	if readErr != nil || driver == "" {
		return sandboxopenshell.RuntimeImages{}
	}
	var c openShellGatewayTOML
	if _, err := toml.Decode(string(b), &c); err != nil {
		return sandboxopenshell.RuntimeImages{}
	}
	d := c.OpenShell.Drivers[driver]
	return sandboxopenshell.RuntimeImages{Supervisor: d.SupervisorImage, Sandbox: d.SandboxRuntimeImage, SandboxFromBin: strings.TrimSpace(d.SupervisorBin) != ""}
}

// openShellGatewayConfigPath is where the package's user service reads its
// config ($XDG_CONFIG_HOME/openshell/gateway.toml, o0-receipts.md
// "Package gateway (Linux)").
func openShellGatewayConfigPath(getenv func(string) string, home string) string {
	if x := getenv("XDG_CONFIG_HOME"); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, "openshell", "gateway.toml")
	}
	return filepath.Join(home, ".config", "openshell", "gateway.toml")
}

// parseOpenShellHostArgs reads `--plan <path> -- observer sandbox-host
// <flags> -- observer-openshell-inner <inner...>`.
func parseOpenShellHostArgs(args []string) (string, sandbox.HostArgs, error) {
	if len(args) < 3 || args[0] != "--plan" || args[2] != "--" {
		return "", sandbox.HostArgs{}, errors.New("usage: sandbox-openshell-host --plan <file> -- <observer> sandbox-host <flags> -- " + openShellInnerMarker + " <launch>")
	}
	rest := args[3:]
	if len(rest) < 2 || rest[1] != sandbox.HostVerb {
		return "", sandbox.HostArgs{}, errors.New("the host services are missing after --plan")
	}
	h, err := sandbox.ParseHostArgs(rest[2:])
	if err != nil {
		return "", sandbox.HostArgs{}, err
	}
	if len(h.Command) < 2 || h.Command[0] != openShellInnerMarker {
		return "", sandbox.HostArgs{}, errors.New("no inner launch after the marker")
	}
	h.Command = h.Command[1:]
	return args[1], h, nil
}

// openShellInitArgs is the in-box init's parsed command line.
type openShellInitArgs struct {
	SockDir string
	// Cwd is the dir the command starts in ("" keeps the init's own).
	Cwd     string
	EnvFile string
	Copies  [][2]string
	Seeds   [][2]string
	Command []string
}

// parseOpenShellInitArgs reads `--sock-dir D [--cwd W] [--env-file F]
// [--copy S=T]... [--seed S=T]... -- <command...>`. Every path must be
// absolute and clean.
func parseOpenShellInitArgs(args []string) (openShellInitArgs, error) {
	var a openShellInitArgs
	abs := func(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }
	pair := func(v string) ([2]string, error) {
		s, t, ok := strings.Cut(v, "=")
		if !ok || !abs(s) || !abs(t) {
			return [2]string{}, fmt.Errorf("%q is not SOURCE=TARGET with absolute paths", v)
		}
		return [2]string{s, t}, nil
	}
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			a.Command = args[i+1:]
			if a.SockDir == "" || len(a.Command) == 0 {
				return a, errors.New("the socket dir and a command are required")
			}
			return a, nil
		}
		if i+1 >= len(args) {
			return a, fmt.Errorf("%s needs a value", args[i])
		}
		v := args[i+1]
		i++
		switch args[i-1] {
		case "--sock-dir":
			if !abs(v) {
				return a, fmt.Errorf("socket dir %q is not absolute", v)
			}
			a.SockDir = v
		case "--cwd":
			if !abs(v) {
				return a, fmt.Errorf("working dir %q is not absolute", v)
			}
			a.Cwd = v
		case "--env-file":
			if !abs(v) {
				return a, fmt.Errorf("env file %q is not absolute", v)
			}
			a.EnvFile = v
		case "--copy", "--seed":
			p, err := pair(v)
			if err != nil {
				return a, err
			}
			if args[i-1] == "--copy" {
				a.Copies = append(a.Copies, p)
			} else {
				a.Seeds = append(a.Seeds, p)
			}
		default:
			return a, fmt.Errorf("unknown flag %q", args[i-1])
		}
	}
	return a, errors.New("no \"--\" before the command")
}

// openShellEnvSocketDir names the run's real socket dir to the relay
// clients in the box (the hook client and the launcher's box gate). It is
// this row's own variable, read only by the openshell init
// (terminal_sandbox_openshell_linux.go), and honoured only with the
// sandbox marker and only while the fixed guest path is the in-box init's
// link to exactly that dir (openShellBoxSocketDir). It is deliberately not
// the process_lite and Seatbelt rows' openShellSharedSockDirEnv: their
// init honours that one with the marker alone, and runs first.
const openShellEnvSocketDir = "OBSERVER_OPENSHELL_SOCK_DIR"

// openShellSharedSockDirEnv is the process_lite and Seatbelt rows' socket
// dir variable. The in-box init drops it from the command's environment,
// so in an OpenShell box only the openshell init's guarded rule chooses
// the dir.
const openShellSharedSockDirEnv = "OBSERVER_SANDBOX_SOCK_DIR"

// openShellBoxSocketDir is where the relay clients in an OpenShell box
// read the launch record (live run O1B-L1, 2026-10-31). The box's socket
// dir sits at its host path (a same-path bind) and the in-box init links
// the fixed guest path (sandbox.GuestSocketDir) to it; the relay's record
// check (sandboxrelayd.ReadBoxRecord) refuses a record whose directory is
// not a directory this user owns that no group or other may write, read
// with lstat, so read through the link it is refused ("the record's
// directory is not private": the link itself is mode 0777 and not a
// directory). The real dir passes that check unchanged (owned by the host
// user the workload runs as, mode 0700). The init names the real dir in
// openShellEnvSocketDir; it is taken only when it is absolute and clean
// and the guest path is a link to exactly it, so a box of another row (or
// a host process) is never redirected by it. The paths are the box's
// (slash-separated Linux paths); readlink is os.Readlink.
func openShellBoxSocketDir(env, guest string, readlink func(string) (string, error)) (string, bool) {
	if env == "" || !path.IsAbs(env) || path.Clean(env) != env || env == guest {
		return "", false
	}
	cur, err := readlink(guest)
	if err != nil || cur != env {
		return "", false
	}
	return env, true
}

// openShellWithSockDirEnv is env with openShellEnvSocketDir set to sockDir
// (any earlier value dropped, so neither the box environment nor its env
// file can name another dir) and openShellSharedSockDirEnv removed (so the
// process_lite init, which honours it on the marker alone, never acts in
// an OpenShell box).
func openShellWithSockDirEnv(env []string, sockDir string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, openShellSharedSockDirEnv+"=") {
			out = append(out, kv)
		}
	}
	return openShellSetEnv(out, openShellEnvSocketDir, sockDir)
}

// openShellSetEnv is env with key set to value, any earlier entry for key
// dropped.
func openShellSetEnv(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, key+"=") {
			out = append(out, kv)
		}
	}
	return append(out, key+"="+value)
}

// openShellBoxEnv is the box's environment from the helper's own: the
// shared allow-list (sandboxBoxEnv), less the host-only paths and the
// guest-unset rows, with the sandbox marker set. HOME is the planner's.
func openShellBoxEnv(environ []string, drop ...string) []string {
	environ = sandboxBoxEnv("linux", environ, drop...)
	deny := map[string]bool{"XDG_RUNTIME_DIR": true, sandboxEnvMarker: true, "HOME": true}
	for _, k := range sandbox.GuestUnsetEnv {
		deny[k] = true
	}
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		if k, _, ok := strings.Cut(kv, "="); ok && k != "" && !deny[k] {
			out = append(out, kv)
		}
	}
	return append(out, sandboxEnvMarker+"=1")
}

// Resize is owned by the PTY: the openshell CLI is the helper's child on
// the run's terminal and forwards SIGWINCH as a resize on its exec stream
// (lane O0 R5).
func (d *openShellDriver) Resize(context.Context, termsvc.SandboxRun, uint16, uint16) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "openshell: the CLI forwards the terminal's resize to the box"}, nil
}

// Signal is owned by the PTY: the host helper forwards what it receives to
// the CLI, and deletes the box when the CLI leaves without it.
func (d *openShellDriver) Signal(context.Context, termsvc.SandboxRun, string) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "openshell: the host helper forwards signals to the CLI and deletes the box after it"}, nil
}

// Copy is not offered: the workspace is bound at its host path.
func (d *openShellDriver) Copy(context.Context, termsvc.CopyRequest) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "openshell: the workspace is a host directory; copy on the host"}, nil
}

// Checkpoint is not offered (OpenShell has no snapshot).
func (d *openShellDriver) Checkpoint(context.Context, termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "openshell: no checkpoint; the agent's native resume applies"}, nil
}

// Stop is owned by the PTY: closing the terminal hangs up the host helper,
// which ends the CLI and deletes the box.
func (d *openShellDriver) Stop(context.Context, termsvc.SandboxRun, time.Duration) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "openshell: closing the terminal ends the CLI and deletes the box"}, nil
}

// Destroy releases a run that never started (or whose helper is gone): a
// pinned delete of its box when a plan names one and no helper holds the
// run, its run dir, its run record and its unattached workspace.
func (d *openShellDriver) Destroy(ctx context.Context, run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	d.targets.Delete(run.ID)
	runDir := openShellRunDir(d.stateDir(), run.ID)
	if pf, err := openShellReadPlan(filepath.Join(runDir, "plan.json")); err == nil && !openShellRunHeld(runDir) {
		// The run dir goes only on the exact not-found text (audit finding
		// O1B-A10): any other answer keeps it for the reaper, logged or not.
		if gone := openShellDeleteBox(ctx, openShellRunner(), pf); gone == sandboxopenshell.OutcomeGone {
			_ = os.RemoveAll(runDir)
		} else if d.r.logger != nil {
			d.r.logger.Warn("terminal_sandbox: openshell: a destroyed run's box was not shown gone; the reaper keeps looking", "run", run.ID, "outcome", gone)
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		_ = os.RemoveAll(runDir)
	}
	return d.r.destroyBwrap(run)
}

// openShellDeleteBox deletes a run's box through its pinned gateway and
// confirms it with a get: gone only on the version's exact not-found text
// (ClassifyGet), present or unknown otherwise. A delete the CLI refuses is
// not an error here: the get decides.
func openShellDeleteBox(ctx context.Context, runner *extrun.Runner, pf openShellPlanFile) sandboxopenshell.Outcome {
	if !openShellServerMatches(ctx, runner, openShellPin{Target: pf.Target, Server: pf.Server}) {
		// The name no longer answers from the run's server (or did not
		// answer): its "not found" would be another gateway's.
		return sandboxopenshell.OutcomeUnknown
	}
	if del, err := sandboxopenshell.DeleteArgv(pf.Target, pf.Name); err == nil {
		_ = openShellRunAt(ctx, runner, pf.Target, openShellCLISpec, del[1:])
	} else {
		return sandboxopenshell.OutcomeUnknown
	}
	return openShellGetOutcome(ctx, runner, pf.Target, pf.Name, pf.GatewayVersion)
}

// openShellServerMatches asks the pinned target's status and reports
// whether it answers from the recorded server (audit finding O1B-A14). A
// status that fails or cannot be read is not a match.
func openShellServerMatches(ctx context.Context, runner *extrun.Runner, pin openShellPin) bool {
	if pin.Server == "" || !pin.Target.Pinned() {
		return false
	}
	argv, err := sandboxopenshell.StatusArgv(pin.Target)
	if err != nil {
		return false
	}
	res := openShellRunAt(ctx, runner, pin.Target, openShellCLISpec, argv[1:])
	if res.Outcome != extrun.OutcomeOK {
		return false
	}
	st, err := sandboxopenshell.ParseStatus(res.Stdout)
	return err == nil && st.Server == pin.Server
}

// openShellGetOutcome asks the pinned gateway for one box.
func openShellGetOutcome(ctx context.Context, runner *extrun.Runner, t sandboxopenshell.Target, name, gatewayVersion string) sandboxopenshell.Outcome {
	get, err := sandboxopenshell.GetArgv(t, name)
	if err != nil {
		return sandboxopenshell.OutcomeUnknown
	}
	res := openShellRunAt(ctx, runner, t, openShellCLISpec, get[1:])
	switch res.Outcome {
	case extrun.OutcomeOK:
		return sandboxopenshell.OutcomePresent
	case extrun.OutcomeExitNonZero:
		v, err := sandboxopenshell.ParseVersion(gatewayVersion)
		if err != nil {
			return sandboxopenshell.OutcomeUnknown
		}
		return sandboxopenshell.ClassifyGet(v, res.ExitCode, string(res.Stderr))
	}
	return sandboxopenshell.OutcomeUnknown
}

// ---- node-local state under the row's state dir ----------------------------

// openShellInstallID is this install's id (random, hex), minted once:
// every box carries it, so the reaper never touches another install's
// boxes on a shared gateway. It is bound to the state dir's real path
// (ledger row OSH-42, sandboxopenshell.InstallIDSource): a copied state
// dir mints its own at its first use, so a second profile made by copying
// ~/.observer no longer shares a gateway unit, name, port or label.
func openShellInstallID(stateDir string) (string, error) {
	return openShellInstallIDWith(stateDir, openShellUnitConfigFn)
}

// openShellInstallIDWith is openShellInstallID with the unit reader
// injected (unitConfig answers a loaded unit's --config).
func openShellInstallIDWith(stateDir string, unitConfig func(unit string) (cfg string, loaded bool)) (string, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil { //nolint:gosec // G703: the row's own state dir (config-validated absolute path or under the observer dir)
		return "", fmt.Errorf("terminal_sandbox: openshell state dir: %w", err)
	}
	bound, err := openShellBoundInstallIDPath(stateDir)
	if err != nil {
		return "", fmt.Errorf("terminal_sandbox: openshell state dir: %w", err)
	}
	if b, err := openShellReadOwned(bound, 128); err == nil {
		id := strings.TrimSpace(string(b))
		if _, err := sandboxopenshell.EncodeID(id); err == nil {
			return id, nil
		}
		return "", fmt.Errorf("terminal_sandbox: %s does not hold an install id", bound)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	legacyPath := filepath.Join(stateDir, sandboxopenshell.LegacyInstallIDFile)
	legacy, err := openShellReadLegacyID(legacyPath)
	if err != nil {
		return "", err
	}
	anyBound := openShellAnyBoundInstallID(stateDir)
	unitOurs := !anyBound && legacy != "" && openShellLegacyUnitOurs(stateDir, legacy, unitConfig)
	var id string
	switch sandboxopenshell.InstallIDSource(false, anyBound, legacy != "", unitOurs) {
	case sandboxopenshell.InstallIDAdoptLegacy:
		id = legacy
	default:
		var raw [8]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", err
		}
		id = hex.EncodeToString(raw[:])
	}
	if err := openShellWriteExcl(bound, []byte(id+"\n")); errors.Is(err, fs.ErrExist) {
		return openShellInstallIDWith(stateDir, unitConfig)
	} else if err != nil {
		return "", err
	}
	if id != legacy {
		// The unbound file names this id too, so a downgrade to a build
		// before the binding reads this install's id, and a copy's file no
		// longer names the original's (audit finding FU7-A6): written
		// atomically, over the original's id when a copy mints.
		if err := openShellWriteAtomic(legacyPath, []byte(id+"\n")); err != nil {
			return "", fmt.Errorf("terminal_sandbox: write %s: %w", legacyPath, err)
		}
	}
	return id, nil
}

// openShellUnitConfigFn reads a managed gateway unit's --config: loaded
// false when the user manager answered and the unit is not loaded; loaded
// true with cfg its --config; loaded true with cfg "" when the answer is
// unknown (the manager could not be asked, or a show failed, tracker
// F-036). A failure that passes must never read as "not loaded": a copy's
// first use would then adopt the original copy's id for good.
var openShellUnitConfigFn = openShellUnitConfig

// openShellUnitConfig asks the user manager for a unit's start command
// (sandboxopenshell.UnitShowArgv) and reads its --config.
func openShellUnitConfig(unit string) (string, bool) {
	argv, err := sandboxopenshell.UnitShowArgv(unit)
	if err != nil {
		return openShellUnitAnswer(false, "")
	}
	ctx, cancel := context.WithTimeout(context.Background(), openShellCmdTimeout)
	defer cancel()
	s := openShellSystemctlSpec
	res := openShellRunner().Run(ctx, extrun.Request{
		Component: openShellComponentID,
		Program:   extrun.Program{Spec: &s, AllowSymlink: true},
		Args:      argv[1:],
		Env:       extrun.EnvSpec{Inherit: openShellUnitEnvInherit},
		Limits:    extrun.Limits{Wall: openShellCmdTimeout, StdoutBytes: 64 << 10, StderrBytes: 16 << 10},
	})
	return openShellUnitAnswer(res.Outcome == extrun.OutcomeOK, string(res.Stdout))
}

// openShellUnitAnswer reads one `systemctl --user show` answer: a show that
// did not run to an answer (ok false) is unknown, loaded with no config,
// the way the stop guard (unitIsThisLayouts) reads the same failure as a
// refusal; an answer is read by sandboxopenshell.UnitConfigPath.
func openShellUnitAnswer(ok bool, out string) (string, bool) {
	if !ok {
		return "", true
	}
	return sandboxopenshell.UnitConfigPath(out)
}

// openShellLegacyUnitOurs reports whether the legacy id may be adopted by
// stateDir as far as its gateway unit says (audit finding FU7-A3): the
// unit that id names is not loaded, or it runs this state dir's config. A
// unit running another dir's config is a pre-binding copy's gateway, and
// an unknown answer (cfg "", tracker F-036) is never ours: the caller then
// mints a fresh id, the posture the stop guard takes with the same failure.
func openShellLegacyUnitOurs(stateDir, legacy string, unitConfig func(unit string) (string, bool)) bool {
	gid, err := sandboxopenshell.IdentityFor(legacy)
	if err != nil {
		return false
	}
	cfg, loaded := unitConfig(gid.Unit)
	switch {
	case !loaded:
		return true
	case cfg == "":
		return false
	}
	return openShellSameFile(cfg, openShellLayoutConfigPath(stateDir, gid))
}

// openShellLayoutConfigPath is the managed gateway config path a state dir
// gives an identity.
func openShellLayoutConfigPath(stateDir string, gid sandboxopenshell.GatewayIdentity) string {
	if l, err := sandboxopenshell.LayoutFor(filepath.Clean(stateDir), openShellDriftRuntimePlaceholder, gid); err == nil {
		return l.ConfigPath
	}
	return filepath.Join(stateDir, "gateway", "gateway.toml")
}

// openShellSameFile reports whether two config paths name the same file:
// equal when cleaned, or equal once each one's deepest existing ancestor is
// resolved (a symlinked spelling of the state dir; the config itself may
// not exist yet).
func openShellSameFile(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b) || openShellResolvedPath(a) == openShellResolvedPath(b)
}

// openShellResolvedPath resolves p's deepest existing ancestor and joins
// the rest back on (p cleaned when nothing resolves).
func openShellResolvedPath(p string) string {
	p = filepath.Clean(p)
	for d := p; ; d = filepath.Dir(d) {
		if r, err := filepath.EvalSymlinks(d); err == nil {
			rel, err := filepath.Rel(d, p)
			if err != nil {
				return p
			}
			return filepath.Join(r, rel)
		}
		if d == filepath.Dir(d) {
			return p
		}
	}
}

// openShellReadLegacyID reads the unbound id file: "" when it does not
// exist, an error when it cannot be read or does not hold an id (audit
// finding FU7-A6: never silently minted over).
func openShellReadLegacyID(p string) (string, error) {
	b, err := openShellReadOwned(p, 128)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("terminal_sandbox: read %s: %w", p, err)
	}
	id := strings.TrimSpace(string(b))
	if _, err := sandboxopenshell.EncodeID(id); err != nil {
		return "", fmt.Errorf("terminal_sandbox: %s does not hold an install id", p)
	}
	return id, nil
}

// openShellBoundInstallIDPath is the bound id file of stateDir: its name
// carries the state dir's real path (sandboxopenshell.InstallIDFileFor).
func openShellBoundInstallIDPath(stateDir string) (string, error) {
	real, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return "", err
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return "", err
	}
	return filepath.Join(stateDir, sandboxopenshell.InstallIDFileFor(filepath.Clean(real))), nil
}

// openShellAnyBoundInstallID reports whether stateDir holds a bound id file
// of any path (an unreadable dir counts as holding one: never adopt then).
func openShellAnyBoundInstallID(stateDir string) bool {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return true
	}
	for _, e := range entries {
		if sandboxopenshell.IsBoundInstallIDFile(e.Name()) {
			return true
		}
	}
	return false
}

// openShellReadIDFile reads one id file ("" when absent or not an id).
func openShellReadIDFile(p string) string {
	b, err := openShellReadOwned(p, 128)
	if err != nil {
		return ""
	}
	id := strings.TrimSpace(string(b))
	if _, err := sandboxopenshell.EncodeID(id); err != nil {
		return ""
	}
	return id
}

// openShellReadInstallID reads this install's id without minting one (""
// when there is none yet, or the file is not a valid id): the reaper's
// label pass runs only once an id exists. It resolves as
// openShellInstallID would, without writing: this path's bound id, else
// the legacy id when it would be adopted, else none.
func openShellReadInstallID(stateDir string) string {
	return openShellReadInstallIDWith(stateDir, openShellUnitConfigFn)
}

// openShellReadInstallIDWith is openShellReadInstallID with the unit
// reader injected.
func openShellReadInstallIDWith(stateDir string, unitConfig func(unit string) (string, bool)) string {
	bound, err := openShellBoundInstallIDPath(stateDir)
	if err != nil {
		return ""
	}
	if _, err := os.Lstat(bound); err == nil { //nolint:gosec // G703: a fixed file name (InstallIDFileFor) under the row's own state dir
		return openShellReadIDFile(bound)
	}
	legacy, err := openShellReadLegacyID(filepath.Join(stateDir, sandboxopenshell.LegacyInstallIDFile))
	if err != nil || legacy == "" {
		return ""
	}
	anyBound := openShellAnyBoundInstallID(stateDir)
	if sandboxopenshell.InstallIDSource(false, anyBound, true, !anyBound && openShellLegacyUnitOurs(stateDir, legacy, unitConfig)) == sandboxopenshell.InstallIDAdoptLegacy {
		return legacy
	}
	return ""
}

// openShellGatewaysFile records every gateway this install created a box
// on, with the gateway version then, so the reaper sweeps each by its
// install label even after the run dirs are gone and classifies its answers
// with that version's texts.
func openShellGatewaysFile(stateDir string) string { return filepath.Join(stateDir, "gateways.json") }

// openShellGatewayEntry is one recorded gateway: its target, the server it
// answered from at create (audit finding O1B-A14) and its version then.
type openShellGatewayEntry struct {
	Target  sandboxopenshell.Target `json:"target"`
	Server  string                  `json:"server"`
	Version string                  `json:"version"`
}

// pin is the entry's gateway.
func (e openShellGatewayEntry) pin() openShellPin {
	return openShellPin{Target: e.Target, Server: e.Server}
}

// openShellGateways reads the recorded gateways.
func openShellGateways(stateDir string) []openShellGatewayEntry {
	b, err := openShellReadOwned(openShellGatewaysFile(stateDir), 1<<20)
	if err != nil {
		return nil
	}
	var out []openShellGatewayEntry
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

// openShellGatewaysMu serializes the gateways file's read-modify-write.
var openShellGatewaysMu sync.Mutex

// openShellRecordGateway adds e to the recorded gateways.
func openShellRecordGateway(stateDir string, e openShellGatewayEntry) error {
	openShellGatewaysMu.Lock()
	defer openShellGatewaysMu.Unlock()
	all := openShellGateways(stateDir)
	if slices.Contains(all, e) {
		return nil
	}
	return openShellWriteGateways(stateDir, append(all, e))
}

// openShellDropGateway removes the entries of one gateway (its pin, every
// version) from the recorded gateways.
func openShellDropGateway(stateDir string, pin openShellPin) error {
	openShellGatewaysMu.Lock()
	defer openShellGatewaysMu.Unlock()
	all := openShellGateways(stateDir)
	keep := slices.DeleteFunc(slices.Clone(all), func(e openShellGatewayEntry) bool { return e.pin() == pin })
	if len(keep) == len(all) {
		return nil
	}
	return openShellWriteGateways(stateDir, keep)
}

// openShellWriteGateways replaces the gateways file (a temporary file and
// a rename); the caller holds openShellGatewaysMu.
func openShellWriteGateways(stateDir string, all []openShellGatewayEntry) error {
	if all == nil {
		all = []openShellGatewayEntry{}
	}
	b, err := json.Marshal(all)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, ".gateways-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	// The temporary file is a direct child of the row's state dir (CreateTemp
	// made it there from a fixed pattern); refuse anything else before
	// removing or renaming it, so neither call can reach outside that dir.
	if !openShellDirectChild(stateDir, name) {
		return fmt.Errorf("openshell gateways file: temporary file %q is not under the state dir", name)
	}
	if werr != nil {
		_ = os.Remove(name) //nolint:gosec // G703: openShellDirectChild proved name is a direct child of stateDir
		return werr
	}
	return os.Rename(name, openShellGatewaysFile(stateDir)) //nolint:gosec // G703: openShellDirectChild proved name is a direct child of stateDir
}

// openShellDirectChild reports whether p, cleaned, is a direct child of
// dir, cleaned: the same parent and a base name that is not "." or "..".
func openShellDirectChild(dir, p string) bool {
	p = filepath.Clean(p)
	base := filepath.Base(p)
	return filepath.Dir(p) == filepath.Clean(dir) && base != "." && base != ".." && base != string(filepath.Separator)
}

// openShellWriteExcl writes a fresh owner-only file (never over an existing
// one or through a link).
func openShellWriteExcl(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a path under the row's own state dir
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(p) //nolint:gosec // G703: the file this call just created
	}
	return werr
}

// errOpenShellPlanNotThisRun is a plan whose run id is not its run dir's
// name (audit finding O1B-R2).
var errOpenShellPlanNotThisRun = errors.New("openshell plan: the run id is not its run dir's name")

// openShellReadPlan reads a plan file (owned, no symlink, capped). The plan
// must sit in the run dir named for its own run id (audit finding O1B-R2):
// the reaper's held check and every removal act on that dir, so a plan
// naming another run is never acted on.
func openShellReadPlan(p string) (openShellPlanFile, error) {
	b, err := openShellReadOwned(p, 4<<20)
	if err != nil {
		return openShellPlanFile{}, err
	}
	var pf openShellPlanFile
	if err := json.Unmarshal(b, &pf); err != nil {
		return openShellPlanFile{}, fmt.Errorf("openshell plan: %w", err)
	}
	if pf.Version != openShellPlanVersion {
		return openShellPlanFile{}, fmt.Errorf("openshell plan: version %d, this binary reads %d (restart the daemon after an upgrade)", pf.Version, openShellPlanVersion)
	}
	if pf.RunID == "" || filepath.Base(filepath.Dir(p)) != pf.RunID {
		return openShellPlanFile{}, fmt.Errorf("%w (%s names run %q)", errOpenShellPlanNotThisRun, p, pf.RunID)
	}
	if !pf.Target.Pinned() {
		return openShellPlanFile{}, errors.New("openshell plan: no pinned gateway")
	}
	if !sandboxopenshell.LoopbackServer(pf.Server) {
		return openShellPlanFile{}, errors.New("openshell plan: the pinned gateway's server is not a loopback https URL")
	}
	return pf, nil
}

// ---- the labelled reaper -----------------------------------------------------

// openShellPeriodicSweep is the reaper's interval, the oci-runc reaper's
// (ociPeriodicSweep): killing the client does not tear a box down (lane O0
// R6), so a crashed helper or daemon leaves boxes only the reaper removes.
const openShellPeriodicSweep = 30 * time.Second

// openShellReapGrace is how old an unheld run dir must be before the
// reaper treats it as abandoned: a run is planned (its dir written) before
// its host helper starts and takes the run's lock.
const openShellReapGrace = 2 * time.Minute

// openShellReaperT is the daemon-lifetime reaper: one goroutine per
// process, started when the daemon's runtime builds the driver with
// openshell listed (and again by a daemon launch), stopped when the
// daemon's runtime drops the driver or no longer lists openshell.
type openShellReaperT struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	dir    string
	obs    string
}

// processOpenShellReaper is the process's reaper.
var processOpenShellReaper = &openShellReaperT{}

// openShellEnsureReaper starts the reaper over stateDir (a no-op while it
// runs over the same dir and observer dir) and reports whether this call
// started it. observerDir is where the host helpers keep their placeholder
// ledgers ("" clears none).
func openShellEnsureReaper(stateDir, observerDir string) bool {
	rp := processOpenShellReaper
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if rp.cancel != nil && rp.dir == stateDir && rp.obs == observerDir {
		return false
	}
	rp.stopLocked()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	rp.cancel, rp.done, rp.dir, rp.obs = cancel, done, stateDir, observerDir
	go func() {
		defer close(done)
		t := time.NewTicker(openShellPeriodicSweep)
		defer t.Stop()
		for {
			openShellReapPass(ctx, openShellRunner(), stateDir, observerDir, openShellReadInstallID(stateDir), openShellRunHeld, time.Now)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return true
}

// openShellReleaseReaper stops the reaper (the daemon's runtime no longer
// has the driver active).
func openShellReleaseReaper() {
	rp := processOpenShellReaper
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.stopLocked()
}

func (rp *openShellReaperT) stopLocked() {
	if rp.cancel == nil {
		return
	}
	rp.cancel()
	<-rp.done
	rp.cancel, rp.done, rp.dir, rp.obs = nil, nil, "", ""
}

// openShellReapPass is one pass of the reaper loop: the labelled sweep,
// then the placeholder ledgers of the runs it judged abandoned, under the
// observer dir the host helpers keep them in (audit FU12-A8: the loop and
// its test drive this one function). Cleared counts the ledgers cleared.
func openShellReapPass(ctx context.Context, runner *extrun.Runner, stateDir, observerDir, installID string, held func(string) bool, now func() time.Time) openShellSweepResult {
	res := openShellSweep(ctx, runner, stateDir, installID, held, now)
	res.Cleared = openShellClearAbandonedPlaceholders(observerDir, res.Abandoned)
	return res
}

// openShellClearAbandonedPlaceholders clears the placeholder ledger of each
// abandoned run (a run dir no host helper holds, past the grace), and with
// it the protected-path placeholders a SIGKILLed helper left on the host,
// such as the read-only `{}` at ~/.claude/settings.json (build tracker
// F-052). The daemon-start sweep did this only at the next daemon start;
// the ledger's own lock still decides, so a live helper's placeholders are
// never touched. It reports how many ledgers it cleared.
func openShellClearAbandonedPlaceholders(observerDir string, runs []string) int {
	n := 0
	for _, run := range runs {
		if clearRunPlaceholderLedger(observerDir, run) {
			n++
		}
	}
	return n
}

// openShellSweepResult is what one sweep did (for tests and the log).
type openShellSweepResult struct {
	// Live are run dirs a host helper holds (or too young to judge).
	Live []string
	// Reaped are boxes deleted and shown gone.
	Reaped []string
	// Kept are boxes a delete did not show gone (unknown or present): the
	// next sweep tries again; their run dirs stay.
	Kept []string
	// Dropped are recorded gateways no longer listed: their label list came
	// back empty and no run dir names them.
	Dropped []string
	// SockDirs are abandoned runs' socket dirs the pass removed.
	SockDirs []string
	// Abandoned are the run ids of the run dirs no host helper holds,
	// past the grace: the reaper clears their placeholder ledgers
	// (openShellClearAbandonedPlaceholders, F-052).
	Abandoned []string
	// Cleared is how many of their placeholder ledgers the pass cleared
	// (openShellReapPass).
	Cleared int
}

// openShellSweep is one pass of the labelled reaper:
//
//  1. every run dir no host helper holds, older than the grace: remove its
//     socket dir (the env file a killed helper left there), delete its
//     box through the run's pinned gateway; remove the run dir only once a
//     get shows the box gone by the version's exact not-found text (an
//     unknown answer is never gone, lane O0 finding O0-A1);
//  2. every recorded gateway, listed by this install's label: a box no run
//     dir claims (the run dirs read again after the list, so a box created
//     during the sweep is claimed) is deleted the same way, confirmed by
//     its gateway's version. A list that fails reads as nothing known,
//     never as gone. A recorded gateway whose list came back empty and that
//     no run dir names is dropped from the gateways file.
//
// Every command names its gateway (audit finding O1A-A9), so a gateway the
// user switched to never answers for a box that lives on another; and every
// command first checks that the name still answers from the server
// recorded with it (audit finding O1B-A14), so a name re-registered for
// another server never reads a box gone.
func openShellSweep(ctx context.Context, runner *extrun.Runner, stateDir, installID string, held func(string) bool, now func() time.Time) openShellSweepResult {
	var res openShellSweepResult
	gateways := map[openShellPin]string{}
	for _, e := range openShellGateways(stateDir) {
		gateways[e.pin()] = e.Version
	}
	for _, run := range openShellReadRunsReaping(stateDir) {
		pf := run.plan
		if _, ok := gateways[run.pin()]; !ok {
			gateways[run.pin()] = pf.GatewayVersion
		}
		fi, serr := os.Stat(run.planPath)
		if held(run.dir) || serr != nil || now().Sub(fi.ModTime()) < openShellReapGrace {
			res.Live = append(res.Live, pf.Name)
			continue
		}
		res.Abandoned = append(res.Abandoned, pf.RunID)
		// An abandoned run's socket dir goes first (audit finding
		// O1B-A11): its helper is gone, so the relay is dead, and the box
		// environment file a killed helper left there is removed now, not
		// at reboot.
		if err := openShellRemoveSockDir(pf); err == nil {
			res.SockDirs = append(res.SockDirs, pf.SockDir)
		}
		if openShellDeleteBox(ctx, runner, pf) == sandboxopenshell.OutcomeGone {
			res.Reaped = append(res.Reaped, pf.Name)
			_ = os.RemoveAll(run.dir)
			continue
		}
		res.Kept = append(res.Kept, pf.Name)
	}
	if installID == "" {
		return res // no box was ever created under this install
	}
	labels, err := sandboxopenshell.InstallLabels(installID)
	if err != nil {
		return res
	}
	pins := make([]openShellPin, 0, len(gateways))
	for p := range gateways {
		pins = append(pins, p)
	}
	sort.Slice(pins, func(i, j int) bool {
		if a, b := openShellTargetName(pins[i].Target), openShellTargetName(pins[j].Target); a != b {
			return a < b
		}
		return pins[i].Server < pins[j].Server
	})
	for _, pin := range pins {
		list, err := sandboxopenshell.ListArgv(pin.Target, labels)
		if err != nil {
			continue
		}
		// The name must still answer from the server it was recorded with
		// (audit finding O1B-A14): another server's list is not this
		// gateway's.
		if !openShellServerMatches(ctx, runner, pin) {
			continue
		}
		out := openShellRunAt(ctx, runner, pin.Target, openShellCLISpec, list[1:])
		if out.Outcome != extrun.OutcomeOK {
			continue
		}
		// The run dirs are read AFTER the list (audit finding O1B-A2): a
		// launch plans its run (the plan file) before its helper creates
		// the box, so every box the list shows that belongs to a run has
		// its plan on disk by now, including one created while the first
		// pass was busy. A box a run dir claims is never the label pass's,
		// whatever its age.
		claimed := map[string]bool{}
		pinned := false
		for _, run := range openShellReadRuns(stateDir) {
			claimed[run.plan.Name] = true
			pinned = pinned || run.pin() == pin
		}
		// A run dir whose plan this binary cannot read (a plan version from
		// another build, an ownership or size refusal) still claims its box
		// by its name, which is the run id (O5 sweep L1): the label pass
		// never deletes a box a run dir names, live or not, and never
		// drops a gateway such a dir may pin.
		for _, dir := range openShellUnreadableRunDirs(stateDir) {
			claimed[sandboxopenshell.SandboxName(filepath.Base(dir))] = true
			// An old, unheld dir with no plan file never had a box and
			// pins no gateway (O5 audit finding O5-A4).
			pinned = pinned || !openShellPlanlessDebris(dir, time.Now())
		}
		names := openShellListedNames(string(out.Stdout))
		if len(names) == 0 && !pinned {
			// Nothing of this install lives there and no run names it:
			// stop listing it on every pass (audit finding O1B-A14).
			if openShellDropGateway(stateDir, pin) == nil {
				res.Dropped = append(res.Dropped, openShellTargetName(pin.Target))
			}
			continue
		}
		for _, name := range names {
			if claimed[name] {
				continue
			}
			pf := openShellPlanFile{Target: pin.Target, Server: pin.Server, Name: name, GatewayVersion: gateways[pin]}
			if openShellDeleteBox(ctx, runner, pf) == sandboxopenshell.OutcomeGone {
				res.Reaped = append(res.Reaped, name)
			} else {
				res.Kept = append(res.Kept, name)
			}
		}
	}
	return res
}

// openShellRunEntry is one run dir with a readable plan.
type openShellRunEntry struct {
	dir, planPath string
	plan          openShellPlanFile
}

// pin is the run's gateway.
func (e openShellRunEntry) pin() openShellPin {
	return openShellPin{Target: e.plan.Target, Server: e.plan.Server}
}

// openShellReadRuns reads every run dir's plan under the state dir (a run
// dir with no readable plan is skipped). It is quiet: only the reaper
// (openShellReadRunsReaping) logs a dir whose plan names another run, so
// the probe's and the lifecycle's own scans do not repeat that line on
// every call (fix round 1 of lane FU1).
func openShellReadRuns(stateDir string) []openShellRunEntry {
	return openShellReadRunPlans(stateDir, false)
}

// openShellReadRunsReaping is openShellReadRuns for the reaper: a run dir
// whose plan names another run is skipped with a log line (audit finding
// O1B-R2).
func openShellReadRunsReaping(stateDir string) []openShellRunEntry {
	return openShellReadRunPlans(stateDir, true)
}

// openShellReadRunPlans is the one scan behind both; warn logs the
// skipped dir.
func openShellReadRunPlans(stateDir string, warn bool) []openShellRunEntry {
	entries, _ := os.ReadDir(filepath.Join(stateDir, "runs"))
	var out []openShellRunEntry
	for _, e := range entries {
		dir := filepath.Join(stateDir, "runs", e.Name())
		planPath := filepath.Join(dir, "plan.json")
		pf, err := openShellReadPlan(planPath)
		if warn && errors.Is(err, errOpenShellPlanNotThisRun) {
			slog.Default().Warn("terminal_sandbox: openshell: the reaper skips a run dir whose plan names another run", "run_dir", dir, "err", err)
		}
		if err != nil {
			continue
		}
		out = append(out, openShellRunEntry{dir: dir, planPath: planPath, plan: pf})
	}
	return out
}

// openShellUnreadableRunDirs are the run dirs under the state dir whose
// plan openShellReadRuns could not read: real directories (never a link)
// whose name is a run id. They are never reaped and never deleted, but
// they claim their box and count as recorded runs (O5 sweep L1), so an
// upgrade that changes the plan format never reads a live run as gone.
func openShellUnreadableRunDirs(stateDir string) []string {
	entries, _ := os.ReadDir(filepath.Join(stateDir, "runs"))
	readable := map[string]bool{}
	for _, run := range openShellReadRuns(stateDir) {
		readable[filepath.Base(run.dir)] = true
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || readable[e.Name()] || !sandboxopenshell.ValidRunDirName(e.Name()) {
			continue
		}
		out = append(out, filepath.Join(stateDir, "runs", e.Name()))
	}
	return out
}

// openShellPlanlessDebris reports whether a run dir openShellUnreadableRunDirs
// returned has no plan file at all, no host helper holds it, and it is older
// than the reap grace (O5 audit finding O5-A4). Such a dir is a launch killed
// between making the dir and writing its plan: it never had a box (the plan
// is written before the helper creates one) and no build will ever read it,
// so it must not pin a managed gateway as recorded forever. A dir whose plan
// file exists but cannot be read (the upgrade case, O5 sweep L1) is never
// debris, whatever its age. Nothing is deleted.
func openShellPlanlessDebris(dir string, now time.Time) bool {
	if _, err := os.Lstat(filepath.Join(dir, "plan.json")); !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if openShellRunHeld(dir) {
		return false
	}
	fi, err := os.Stat(dir)
	return err == nil && now.Sub(fi.ModTime()) >= openShellReapGrace
}

// openShellUnreadableRunNotes names the run dirs openShellUnreadableRunDirs
// returns, each with its age, whether it has a plan file at all and whether
// it still counts as a recorded run (tracker F-032, the O5 sweep's L5
// class): row G2's wait reason and the probe's note name them, since the
// reaper never removes them. The note carries only the dir's
// name and times; nothing read from inside a dir is shown.
func openShellUnreadableRunNotes(stateDir string, now time.Time) []sandboxopenshell.RunDirNote {
	var out []sandboxopenshell.RunDirNote
	for _, dir := range openShellUnreadableRunDirs(stateDir) {
		n := sandboxopenshell.RunDirNote{Name: filepath.Base(dir), Holds: !openShellPlanlessDebris(dir, now)}
		if _, err := os.Lstat(filepath.Join(dir, "plan.json")); errors.Is(err, fs.ErrNotExist) {
			n.Planless = true
		}
		if fi, err := os.Stat(dir); err == nil {
			n.AgeSeconds = int64(now.Sub(fi.ModTime()) / time.Second)
		}
		out = append(out, n)
	}
	return out
}

// openShellRunDirsHint is the probe's note on those run dirs ("" for none),
// so `observer sandbox status` and `observer doctor` name them whether or
// not openshell is listed (a gateway left running after it was unlisted is
// exactly row G2's case).
func openShellRunDirsHint(stateDir string, now time.Time) string {
	notes := openShellUnreadableRunNotes(stateDir, now)
	if len(notes) == 0 {
		return ""
	}
	return "run dirs under " + filepath.Join(stateDir, "runs") + " whose plan this build cannot read: " + sandboxopenshell.DescribeRunDirs(notes) + "; " + sandboxopenshell.RunDirsRemedy
}

// openShellListedNames are the box names of a `sandbox list --names`
// answer that Observer could have made (the "sbo-" prefix and a valid
// name); every other line is ignored.
func openShellListedNames(out string) []string {
	var names []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "sbo-") && sandboxopenshell.ValidSandboxName(l) {
			names = append(names, l)
		}
	}
	return names
}
