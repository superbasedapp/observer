//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_oci.go is the oci-runc driver (sandbox plan v2 sections
// 4.6, 11.3 and 13 P3; lane SBX-P3A): Docker Engine or Podman on this
// machine, driven through the Engine API on a local unix socket. The pure
// decisions are internal/sandboxoci's, the Engine API client is
// internal/sandboxengine, and the real socket, stat and terminal calls live
// in terminal_sandbox_oci_linux.go. The driver registers itself with the
// sandbox runtime from init (registerSandboxDriver), so no core function
// names it; terminal_sandbox_oci_omit.go is its twin in a build without it.
//
// What runs where: the daemon's runtime probes the engine (only when the
// driver is selected, the sandbox is on and "oci-runc" is in
// [terminal.sandbox].backends), prepares the workspace with the shared
// workspace step, and writes a per-run plan file; the PTY child is
// `observer sandbox-oci-host --plan <file> -- observer sandbox-host <the
// relay and network flags> -- observer <verb> ...`, which starts the same
// host services the bwrap driver uses (sockets, relay, proxy forward,
// gateway), creates the container, reads it back, attaches, waits and
// starts it; inside, `observer sandbox-oci-init` is PID 1 and runs the
// guest helper and the agent.

// The driver's ids and helper verbs.
const (
	ociComponent = "terminals.sandbox.oci"
	ociHostVerb  = "sandbox-oci-host"
	ociInitVerb  = "sandbox-oci-init"
	// ociPathCheckVerb is the started path check (terminal_sandbox_oci_tools.go).
	ociPathCheckVerb = "sandbox-oci-pathcheck"
	// ociInstallVerb is the first-start install's setup container process:
	// the loopback forward to the install gateway, then the installer
	// (terminal_sandbox_oci_install_linux.go, lane SBX-P3C).
	ociInstallVerb = "sandbox-oci-install"
	// ociPlanVersion is the plan file's schema version.
	ociPlanVersion = 1
	// ociPidsLimit caps the tasks of one run's container.
	ociPidsLimit = 4096
	// ociInnerMarker separates the host services' flags from the inner
	// launch in the PTY child's argv.
	ociInnerMarker = "observer-oci-inner"
)

func init() {
	registerSandboxDriver(sandboxDriverReg{
		backend: sandboxbackend.BackendOCIRunc, component: ociComponent,
		build:   newOCIDriver,
		release: func() { processOCIReaper.stop() },
	})
	// The oci-runsc row (lane SBX-P3B) is the same driver component, the
	// same Engine API client and create body with runtime runsc: its own
	// registration, so the selection table and the status surfaces see a
	// second row, and nothing of it runs unless the component is selected,
	// the sandbox is on and oci-runsc is listed by name.
	registerSandboxDriver(sandboxDriverReg{
		backend: sandboxbackend.BackendOCIRunsc, component: ociComponent,
		build:   newOCIRunscDriver,
		release: func() { processOCIReaper.stop() },
	})
	sandboxHelperFuncs[ociHostVerb] = runOCIHost
	sandboxHelperFuncs[ociInitVerb] = runOCIInit
	sandboxHelperFuncs[ociPathCheckVerb] = runOCIPathCheck
	sandboxHelperFuncs[ociInstallVerb] = runOCIInstallGuest
}

// ociProbeEnvFn builds the probe ladder's I/O (a variable so a test can
// count its calls and feed facts).
var ociProbeEnvFn = ociProbeEnv

// ociDriver is the oci-runc lifecycle service over one sandbox runtime.
type ociDriver struct {
	r   *sandboxRuntime
	cfg config.TerminalSandboxOCIConfig
	// profile is the row's runtime column (sandboxoci.RuntimeProfile):
	// oci-runc's engine default, or oci-runsc's runsc with projected state.
	profile sandboxoci.RuntimeProfile

	mu     sync.Mutex
	last   sandboxoci.ProbeResult
	lastAt time.Time

	// choices holds each created run's image and repository environment
	// (run id -> ociRunChoice) until Attach composes it.
	choices sync.Map
	// watches holds a projected run's transcript watch-root removals (run
	// id -> []func()), lane SBX-P3C (G27).
	watches sync.Map
}

// newOCIDriver builds the driver; in the daemon it also starts the first
// probe in the background when oci-runc is listed, so the orphan sweep runs
// at daemon start without waiting for a dialog.
func newOCIDriver(r *sandboxRuntime, full config.Config) sandboxDriver {
	return newOCIDriverFor(r, full, sandboxoci.RuntimeOCIRunc)
}

// newOCIRunscDriver builds the oci-runsc row's driver.
func newOCIRunscDriver(r *sandboxRuntime, full config.Config) sandboxDriver {
	return newOCIDriverFor(r, full, sandboxoci.RuntimeOCIRunsc)
}

// newOCIDriverFor builds the driver for one oci-* row. The orphan sweep is
// shared by both rows (it reaps every container with this install's label,
// whatever its runtime), so it stops only when neither row is listed.
func newOCIDriverFor(r *sandboxRuntime, full config.Config, backend string) sandboxDriver {
	profile, _ := sandboxoci.RuntimeProfileFor(backend)
	// The effective block (r.cfg, the managed body composed in), so the
	// org's install-script floor reaches the driver (lane LEFT-SBX); no
	// other managed key touches [terminal.sandbox.oci], so for every other
	// key it equals the file's.
	d := &ociDriver{r: r, cfg: r.cfg.OCI, profile: profile}
	if r.inDaemon && d.listed() {
		go d.probe(context.Background())
	} else if r.inDaemon && !ociAnyListed(r.cfg) {
		processOCIReaper.stop()
	}
	if r.inDaemon {
		ociRunStateSweepOnce.Do(func() { go ociSweepRunStateAtStart(r) })
	}
	return d
}

// ociAnyListed reports whether any oci-* row is among the enabled backends.
func ociAnyListed(cfg config.TerminalSandboxConfig) bool {
	for _, p := range sandboxoci.RuntimeProfiles() {
		if slices.Contains(sandboxEnabledBackends(cfg), p.Backend) {
			return true
		}
	}
	return false
}

// backend is the driver's registry row id.
func (d *ociDriver) backend() string {
	if d.profile.Backend == "" {
		return sandboxbackend.BackendOCIRunc
	}
	return d.profile.Backend
}

// row is the driver's registry row.
func (d *ociDriver) row() sandboxbackend.Capability {
	row, _ := sandboxbackend.Get(d.backend())
	return row
}

// listed reports whether the driver's row is among the enabled backends.
func (d *ociDriver) listed() bool {
	return slices.Contains(sandboxEnabledBackends(d.r.cfg), d.backend())
}

// probe walks the OCI ladder (cached for the probe TTL). Nothing is dialled
// while oci-runc is not listed.
func (d *ociDriver) probe(ctx context.Context) sandboxselect.Probe {
	if !d.listed() {
		return sandboxselect.Probe{Compiled: true, Verdict: sandboxselect.VerdictDisabledByConfig, Reason: d.backend() + " is not in [terminal.sandbox].backends"}
	}
	res := d.probeResult(ctx)
	p := sandboxselect.Probe{Compiled: true, Verdict: res.Verdict.Code, Reason: res.Verdict.Reason, Sources: sourceIDs(d.r.sources())}
	if res.Verdict.OK() {
		p.Version, p.VersionAuthenticated = res.Identity.APIVersion, true
		p.Hint = res.Hint
		return p
	}
	// The probe's own refusal is what S4 must report (S4 runs before S2b
	// since the live checks of 2026-10-22); the row's version pin is still
	// filled with its own minimum so no later version read can mask it.
	p.Version, p.VersionAuthenticated = d.row().Control.Pins.RequiredMin, true
	return p
}

// version is the API version the last probe read.
func (d *ociDriver) version() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last.Identity.APIVersion
}

// probeResult runs (or reuses) the ladder and keeps what it established.
func (d *ociDriver) probeResult(ctx context.Context) sandboxoci.ProbeResult {
	d.mu.Lock()
	if !d.lastAt.IsZero() && time.Since(d.lastAt) < sandboxProbeTTL {
		res := d.last
		d.mu.Unlock()
		return res
	}
	d.mu.Unlock()
	env := ociProbeEnvFn(ctx, d.cfg, d.r.observerDir)
	env.Runtime = d.profile
	res := sandboxoci.Probe(env)
	if res.Verdict.OK() && res.FirstUse {
		if err := recordOCIIdentity(d.r.observerDir, res.Socket, res.Identity); err != nil {
			res.Verdict = sandboxoci.Verdict{Code: sandboxoci.VerdictSocketUntrusted, Reason: "the engine identity could not be recorded: " + err.Error()}
		}
	}
	if d.r.inDaemon {
		if res.Verdict.OK() {
			if id, err := ociInstallID(d.r.observerDir); err == nil {
				processOCIReaper.ensure(res.Socket, res.Identity.APIVersion, id, d.r.observerDir, d.r.managedRoot)
			}
		} else {
			processOCIReaper.stop()
		}
	}
	d.mu.Lock()
	d.last, d.lastAt = res, time.Now()
	d.mu.Unlock()
	return res
}

// floor refuses a launch the local config or an org floor does not allow
// on this row (the oci-runc analogue of sandboxLocalFloor).
func (d *ociDriver) floor(cfg config.TerminalSandboxConfig) error {
	if cfg.PinnedNoBackend != "" {
		return fmt.Errorf("terminal_sandbox: your organization's pin of %s allows none of the sandbox backends this machine is set to use, so no backend is enabled; the sandboxed terminal is refused, never run without it", cfg.PinnedNoBackend)
	}
	if !slices.Contains(sandboxEnabledBackends(cfg), d.backend()) && d.r.forceBackend != d.backend() {
		return fmt.Errorf("terminal_sandbox: %s is not in [terminal.sandbox].backends %v", d.backend(), cfg.Backends)
	}
	row := d.row()
	if floor := vocab.IsoClass(cfg.MinIsolation); floor != "" && row.Iso.Class.Rank() < floor.Rank() {
		return fmt.Errorf("terminal_sandbox: %s builds %s isolation, below [terminal.sandbox].min_isolation = %s", d.backend(), row.Iso.Class, floor)
	}
	tier := vocab.Tier(cfg.Egress)
	if tier == "" {
		tier = vocab.TierInternet
	}
	if !row.OffersTier(tier) {
		return fmt.Errorf("terminal_sandbox: %s has no %s network tier; set [terminal.sandbox].egress to internet, proxy_only or none", d.backend(), tier)
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
// the shared step (same-path delivery, section 6 bind_same_path).
func (d *ociDriver) Create(ctx context.Context, req termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	if err := d.floor(launchFloorConfig(d.r.cfg, string(d.r.egress.Mode))); err != nil {
		return termsvc.CreateResult{}, err
	}
	row := d.row()
	tier := vocab.Tier(d.r.egress.Mode)
	if v, judged := sandboxNativeVerdictFor(row, req.Tool, tier); judged {
		if err := sandboxNativeRefusal(req.Tool, v); err != nil {
			return termsvc.CreateResult{}, err
		}
	}
	res := d.probeResult(ctx)
	if !res.Verdict.OK() {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %s is not available: %s", d.backend(), res.Verdict.Error())
	}
	choice, choiceNote, err := d.checkRunChoice(ctx, res, req)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	// Sign-in seeding (lane BOXSIGNIN): asked or refused before any
	// workspace is made. Only a run whose tool state is projected can get
	// a copy: a row that crosses a kernel, an image's own copy of the tool,
	// or an image still to be pulled (decided again in compose, where a
	// run that turned out to bind the host's state copies nothing).
	projected := d.r.managedRoot != "" && (choice.pending != nil || sandboxoci.ProjectsState(choice.delivery, d.profile.CrossesKernel))
	choice.signIn = d.r.signInDecision(req, projected, false)
	if err := signInGate(req, choice.signIn); err != nil {
		return termsvc.CreateResult{}, err
	}
	choiceNote += " sign_in=" + choice.signIn.Code
	ws, err := d.r.prepareWorkspace(ctx, req)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	choice.source = ws.src
	d.choices.Store(ws.id, choice)
	routed, _ := d.r.launchRouted(req.Tool, ws.dir, req.ToolArgs)
	return termsvc.CreateResult{
		Run:         termsvc.SandboxRun{ID: ws.id, Tool: req.Tool, Dir: ws.dir, ProjectRoot: req.ProjectRoot, Copy: !ws.live},
		Note:        fmt.Sprintf("sandbox: backend=%s source=%s workspace=%s egress=%s%s", d.backend(), ws.src, ws.dir, d.r.egress.Mode, choiceNote),
		Isolation:   d.isolation(req.Tool, routed),
		ProxyRouted: routed,
	}, nil
}

// checkRunChoice decides the run's image (the configured one, or a
// consented .devcontainer image, which must be present) and refuses a tool
// the image cannot run (tool delivery, section 5.4).
func (d *ociDriver) checkRunChoice(ctx context.Context, res sandboxoci.ProbeResult, req termsvc.PrepareRequest) (ociRunChoice, string, error) {
	choice, note := d.runChoice(req.ProjectRoot)
	c, err := ociEngineClient(res.Socket, res.Identity.APIVersion)
	if err != nil {
		return choice, note, fmt.Errorf("terminal_sandbox: %w", err)
	}
	trust := d.imageTrust()
	installID, err := ociInstallID(d.r.observerDir)
	if err != nil {
		return choice, note, err
	}
	// A revoked image Observer pulled, and the tool caches of a revoked
	// image, go at the next launch (plan 12.3, lane SBX-P3C); nothing runs
	// while no signed manifest is installed.
	if trust.revoked != nil {
		pr, perr := ociPruneRevoked(ctx, c, d.r.observerDir, installID, trust.revoked)
		for _, ref := range pr.Removed {
			choice.notices = append(choice.notices, "the revoked image "+ref+" was removed from the engine")
		}
		choice.notices = append(choice.notices, pr.Refused...)
		if perr != nil && d.r.logger != nil {
			d.r.logger.Warn("terminal_sandbox: pruning revoked images", "err", perr)
		}
	}
	if err := d.checkRunImage(ctx, c, trust, &choice, &note, req.DeferSlowPrep); err != nil {
		return choice, note, err
	}
	if choice.pending != nil {
		// The pull and every check that reads the image run after the
		// terminal opens (R-037).
		choice.pending.req, choice.pending.installID = req, installID
		return choice, note + " image=pull(in the terminal, from " + trust.desc.Repository + ")", nil
	}
	if err := d.checkPulledChoice(ctx, c, res, req, installID, &choice, &note); err != nil {
		return choice, note, err
	}
	return choice, note, nil
}

// checkPulledChoice is the part of checkRunChoice that reads the image (it
// must be present): the image's own environment, the tool facts and the
// tool delivery, and the tool cache.
func (d *ociDriver) checkPulledChoice(ctx context.Context, c *sandboxengine.Client, res sandboxoci.ProbeResult, req termsvc.PrepareRequest, installID string, choice *ociRunChoice, notep *string) error {
	note := *notep
	defer func() { *notep = note }()
	// Refused here too (the host helper checks again before it creates), so
	// the dialog names the image's variables before any workspace is made.
	if env, err := c.ImageEnv(ctx, choice.image); err == nil {
		if v := sandboxoci.ImageEnvRefusal(env); !v.OK() {
			return fmt.Errorf("terminal_sandbox: %s", v.Error())
		}
	}
	// The first-start install (lane SBX-P3C) is asked about only with
	// install_cache on: its source, the installer's runtime in the image
	// and the host's version to pin. Off, the facts are what they were.
	var runtime []string
	var installSrc sandboxoci.InstallSource
	if d.cfg.InstallCache {
		if _, psrc, ok := ociInstallSourceFor(req.Tool); ok {
			installSrc = psrc
			runtime, _ = sandboxoci.InstallerRuntime(psrc.Kind)
		}
	}
	facts, err := d.toolFacts(ctx, c, installID, choice.image, req.Tool, ociPathCheckUser(res), runtime)
	if err != nil {
		return fmt.Errorf("terminal_sandbox: %w", err)
	}
	// A row that crosses a kernel never binds the real tool state (section
	// 5.4): the image's own copy of the tool may run on the projection.
	facts.StateProjected = sandboxoci.StateModeFor(d.profile.CrossesKernel) == sandboxoci.StateProject
	if d.cfg.InstallCache {
		facts.InstallCache = true
		facts.InstallSourceKnown = installSrc.Kind != ""
		facts.InstallVersion = d.ociInstallVersion(req.Tool, installSrc, facts.HostBinary != "")
		// A source that needs its own install script installs only under a
		// reviewed pin (lane LEFT-SBX, ruling P-136); the refusal names the
		// policy or the missing pin. With no version yet, the table refuses
		// install_version_unknown first.
		if facts.InstallSourceKnown && installSrc.NeedsScripts && sandboxoci.ValidInstallVersion(facts.InstallVersion) {
			if _, serr := sandboxoci.DecideInstallScripts(req.Tool, facts.InstallVersion, true, d.ociScriptPolicy()); serr != nil {
				return fmt.Errorf("terminal_sandbox: %w", serr)
			}
		}
	}
	delivery, v := sandboxoci.PlanToolDelivery(facts)
	if !v.OK() {
		return fmt.Errorf("terminal_sandbox: %s", v.Error())
	}
	choice.delivery = delivery
	switch delivery {
	case sandboxoci.DeliveryInstallCache:
		cc, cnote, err := d.ociCacheDecision(ctx, c, installID, choice.image, req.Tool, facts.InstallVersion)
		if err != nil {
			return fmt.Errorf("terminal_sandbox: %w", err)
		}
		choice.cache = cc
		note += cnote
	case sandboxoci.DeliveryImageInstalled:
		note += " tool=image (on a projected tool state)"
	}
	return nil
}

// checkRunImage is checkRunChoice's image step: a repository's
// .devcontainer image must be present, and Observer's default image must be
// the signed one (pulled by digest when absent) before any workspace is made.
func (d *ociDriver) checkRunImage(ctx context.Context, c *sandboxengine.Client, trust ociImageTrust, choice *ociRunChoice, note *string, deferPull bool) error {
	if choice.image != trust.image {
		ok, err := c.ImagePresent(ctx, choice.image)
		if err != nil || !ok {
			return fmt.Errorf("terminal_sandbox: %s: the repository's .devcontainer image %s is not present; pull it with `observer sandbox oci pull --devcontainer`", sandboxoci.VerdictImageMissing, choice.image)
		}
	} else if trust.desc != nil {
		// Observer's default image: the engine's copy must be the signed one
		// (repository at the signed digest, the signed image id) before any
		// workspace is made (plan 12.3, A12).
		id, err := c.ImageIdentity(ctx, choice.image)
		if err != nil {
			return fmt.Errorf("terminal_sandbox: %s: the engine did not answer about the image: %w", sandboxoci.VerdictArtifactUnverified, err)
		}
		if !id.Present && deferPull && trust.refusal == "" && !trust.stale {
			// A daemon launch pulls after its terminal opens, so the
			// announcement reaches the terminal before the download starts
			// (R-037); the image-dependent checks follow the pull there.
			choice.pending = &ociPendingPrep{trust: trust}
			return nil
		}
		if !id.Present {
			// The user's launch pulls it by digest, saying from where and
			// how large it is (lane SBX-P3C); a stale manifest refuses.
			first := true
			_, size, perr := ociPullDefault(ctx, c, trust, d.r.observerDir, func(l string) {
				if d.r.logger != nil {
					d.r.logger.Info("terminal_sandbox: default image", "progress", l)
				}
				if first {
					// The announcement (source, declared size, bounds) is the
					// run's first terminal line as well as the log's.
					first = false
					choice.notices = append(choice.notices, "before the download: "+l)
				}
			})
			if perr != nil {
				return fmt.Errorf("terminal_sandbox: %w", perr)
			}
			msg := fmt.Sprintf("Observer's default image %s (%s) was pulled from %s for this launch", choice.image, sandboxoci.HumanBytes(size), trust.desc.Repository)
			choice.notices = append(choice.notices, msg)
			*note += " image=pulled(" + sandboxoci.HumanBytes(size) + " from " + trust.desc.Repository + ")"
			if id, err = c.ImageIdentity(ctx, choice.image); err != nil {
				return fmt.Errorf("terminal_sandbox: %s: the engine did not answer about the pulled image: %w", sandboxoci.VerdictArtifactUnverified, err)
			}
		}
		if r := ociCheckDefaultImage(trust, id); !r.OK {
			return fmt.Errorf("terminal_sandbox: %s", r.Error())
		}
		if trust.stale {
			*note += " image=last-known-good (the default image's manifest has expired)"
		}
	}
	return nil
}

// isolation is the run's G19 evidence on the oci-runc row.
func (d *ociDriver) isolation(tool string, routed bool) termrun.Isolation {
	row := d.row()
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

// ociPlanFile is the per-run plan the host helper reads. It holds no
// secret by rule (TestOCIPlanFileHoldsNoSecrets): the container's
// environment is built by the helper from its own, never stored here.
type ociPlanFile struct {
	Version     int               `json:"version"`
	Socket      string            `json:"socket"`
	Engine      sandboxoci.Engine `json:"engine"`
	Mode        sandboxoci.Mode   `json:"mode"`
	Fingerprint string            `json:"fingerprint"`
	APIVersion  string            `json:"api_version"`
	Host        sandboxoci.Host   `json:"host"`
	// AllowRootful repeats the setting the probe applied, so the helper's
	// own socket re-check applies it too.
	AllowRootful bool `json:"allow_rootful"`
	// ExtraEnv are a consented .devcontainer's allowed containerEnv
	// entries (repository content, never a secret); the helper checks each
	// name again.
	ExtraEnv []string `json:"extra_env,omitempty"`
	// Return, when set, is the return step the helper runs after the
	// container ends (a clone-local copy, section 6): paths only.
	Return *workspace.ReturnRequest `json:"return,omitempty"`
	// Create is the bind plan; its Entrypoint is the prefix up to the inner
	// launch, which the helper appends from its own argv.
	Create sandboxoci.CreatePlan `json:"create"`
	// Backend is the row (oci-runc or oci-runsc; empty in a plan written
	// before the oci-runsc row, which is oci-runc).
	Backend string `json:"backend,omitempty"`
	// Projections are the run's projected state directories (oci-runsc):
	// after the container ends the helper reads the guest's db-copy
	// copies from each, no-follow and capped, into DBCopyDest.
	Projections []sandboxoci.ProjectedDir `json:"projections,omitempty"`
	DBCopyDest  string                    `json:"db_copy_dest,omitempty"`
	// ConfigPath is the daemon's resolved config file, so the helper's
	// return-step scan reads the daemon's components and records into the
	// daemon's database, never a default one (lane sec-box audit finding
	// 4). Empty in a plan from an older daemon: the helper then records
	// nothing and the commit scan's box-ref walk covers the returned ref.
	ConfigPath string `json:"config_path,omitempty"`
	// Install is the first-start install step the helper runs (after asking
	// on the run's terminal) before the agent's container is created; nil
	// when the tool needs none (lane SBX-P3C).
	Install *ociInstallStep `json:"install,omitempty"`
	// PathPrefix is put in front of the box's PATH (the tool cache's bin
	// directory of a cache-installed tool); "" for none.
	PathPrefix string `json:"path_prefix,omitempty"`
	// TranscriptRoots are the projection's watched transcript subtrees on
	// the host (G27): the helper leaves them a settle time after the run
	// before the projection is removed, so the watcher reads the last lines.
	TranscriptRoots []string `json:"transcript_roots,omitempty"`
	// Tool, Transcripts and TranscriptsWatched: the run's tool, its
	// projection's transcript subtrees with their box paths, and whether the
	// daemon's watcher took them for the run's life. A run no watcher took
	// (a CLI launch) is read once by the helper after the run, before the
	// projection is removed (ociIngestUnwatched, lane LEFT-SBX), so its
	// transcripts are kept.
	Tool               string                      `json:"tool,omitempty"`
	Transcripts        []sandboxoci.TranscriptRoot `json:"transcripts,omitempty"`
	TranscriptsWatched bool                        `json:"transcripts_watched,omitempty"`
	// Notices are lines the helper shows first on the run's terminal (the
	// default image pulled for this launch, a revoked image removed).
	Notices []string `json:"notices,omitempty"`
	// DropEnv are variable names the box never gets (sandboxenv.Spec.Drop):
	// on a projected run, the relocation variables of the tool's sign-in
	// files, so the tool reads the projected state, the seeded copy
	// included (sandboxSignInDropEnv, lane BOXSIGNIN).
	DropEnv []string `json:"drop_env,omitempty"`
	// ReturnRefused is why a copy run has no return step (a clone-remote
	// copy whose return could not be planned, audit finding 8): the run's
	// record of it, said again on the terminal when the run ends.
	ReturnRefused string `json:"return_refused,omitempty"`
}

// ociPlanConfigPath is the daemon's resolved config file for a plan, ""
// when it cannot be resolved.
func ociPlanConfigPath() string {
	p, err := config.ResolveGlobalPath(daemonConfigPath())
	if err != nil {
		return ""
	}
	return p
}

// Attach writes the run record and the plan file and returns the helper
// argv the PTY child runs.
func (d *ociDriver) Attach(ctx context.Context, created termsvc.CreateResult) (termsvc.AttachResult, error) {
	res := d.probeResult(ctx)
	if !res.Verdict.OK() {
		return termsvc.AttachResult{}, fmt.Errorf("terminal_sandbox: %s is not available: %s", d.backend(), res.Verdict.Error())
	}
	if err := d.r.writeRunRecord(created.Run); err != nil {
		return termsvc.AttachResult{}, err
	}
	compose := d.compose
	if v, ok := d.choices.Load(created.Run.ID); ok {
		if ch, _ := v.(ociRunChoice); ch.pending != nil {
			// The default image is pulled after the terminal opens (R-037).
			compose = func(created termsvc.CreateResult, res sandboxoci.ProbeResult) ([]string, error) {
				return d.attachDeferred(created, res, ch)
			}
		}
	}
	wrap, err := compose(created, res)
	if err != nil {
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, created.Run.ID)
		return termsvc.AttachResult{}, err
	}
	d.r.unattached.Delete(created.Run.ID)
	return termsvc.AttachResult{WrapArgv: wrap}, nil
}

// compose builds the bind plan, writes the plan file and returns the argv.
func (d *ociDriver) compose(created termsvc.CreateResult, res sandboxoci.ProbeResult) ([]string, error) {
	r := d.r
	run := created.Run
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("terminal_sandbox: resolve home: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(home); rerr == nil {
		home = resolved
	}
	spec, _ := integration.For(run.Tool)
	if len(spec.Sandbox.StateRW) == 0 {
		return nil, fmt.Errorf("terminal_sandbox: tool %q is not sandbox-launchable: %s", run.Tool, spec.Sandbox.Note)
	}
	if err := d.checkBinds(home, spec.Sandbox); err != nil {
		return nil, err
	}
	installID, err := ociInstallID(r.observerDir)
	if err != nil {
		return nil, err
	}

	netReq := sandbox.NetRequest{Egress: r.egress.Mode, ProxyPort: r.proxyPort, EgressAllowCIDRs: r.cfg.EgressAllowCIDRs}
	if capture := sandboxRunCaptureFor(d.row(), created.ProxyRouted, vocab.Tier(r.egress.Mode), r.cfg.EffectiveProviderDirect()); capture.ProviderBlock {
		netReq.ProviderBlock, netReq.ProviderHosts = true, r.providerHosts
	}
	netReq.HostSocketDir = filepath.Join(os.TempDir(), "observer-sbx-"+run.ID)

	overlays, pins, err := r.protection(home, run.Dir, spec.Sandbox)
	if err != nil {
		return nil, err
	}
	var placeholders []sandbox.Overlay
	for _, o := range overlays {
		if o.Placeholder != "" {
			placeholders = append(placeholders, o)
		}
	}
	host, err := sandbox.RelayHostArgv(r.observerBin, netReq, placeholders, sandbox.RelayRequest{RunID: run.ID, HostObserverDir: r.observerDir})
	if err != nil {
		return nil, err
	}
	guest, err := sandbox.GuestArgv(r.observerBin, netReq)
	if err != nil {
		return nil, err
	}

	choice := ociRunChoice{image: d.imageTrust().image}
	if v, ok := d.choices.LoadAndDelete(run.ID); ok {
		choice, _ = v.(ociRunChoice)
	}
	// A row that crosses a kernel, and an image's own copy of the tool on
	// any row (its version is never proven equal to the host's, Opus M19),
	// gets per-run projected state directories in place of the real tool
	// state (section 5.4, ociProjection).
	proj, err := d.projection(home, run, spec.Sandbox, sandboxoci.ProjectsState(choice.delivery, d.profile.CrossesKernel))
	if err != nil {
		return nil, err
	}
	// The tool's seed row (G27): non-secret files in, transcript subtrees
	// watched for the run's life.
	transcripts, err := ociSeedProjection(home, proj, run.Tool)
	if err != nil {
		_ = ociRemoveRunState(r.observerDir, r.managedRoot, run.ID)
		return nil, fmt.Errorf("terminal_sandbox: %w", err)
	}
	// The consented sign-in copy (lane BOXSIGNIN), inside the projection
	// so it goes with it on every end path. The terminal and the daemon log
	// name the tool and the file names, never a value.
	if err := d.seedRunSignIn(home, proj, run, &choice); err != nil {
		_ = ociRemoveRunState(r.observerDir, r.managedRoot, run.ID)
		return nil, fmt.Errorf("terminal_sandbox: %w", err)
	}
	plan := d.bindPlan(home, run, spec.Sandbox, overlays, netReq.HostSocketDir, proj)
	ociPinMounts(&plan, pins)
	plan.RunID, plan.InstallID = run.ID, installID
	plan.Runtime = d.profile.CreateRuntime
	plan.Image = choice.image
	plan.User = res.User
	plan.Engine = res.Identity.Engine
	plan.EngineSocket = res.Socket
	plan.ObserverDir = r.observerDir
	plan.ReadonlyRootfs = true
	plan.StopGraceSeconds = d.cfg.StopGraceSeconds
	plan.PidsLimit = ociPidsLimit
	if choice.cache.volume != "" {
		// The tool cache (lane SBX-P3C), read-only in the agent's box.
		plan.Volumes = append(plan.Volumes, sandboxoci.VolumeMount{Name: choice.cache.volume, Target: sandboxoci.ToolCacheMount, ReadOnly: true})
	}
	plan.Entrypoint = append(append([]string{r.observerBin, ociInitVerb}, ociInitDBCopyArgs(proj)...), "--")
	plan.Entrypoint = append(plan.Entrypoint, guest...)
	// Validate now (with a stand-in inner launch), so a bad plan refuses
	// the launch here rather than in the helper.
	check := plan
	check.Entrypoint = append(append([]string(nil), plan.Entrypoint...), r.observerBin)
	if _, _, err := sandboxoci.BuildCreate(check); err != nil {
		return nil, fmt.Errorf("terminal_sandbox: %w", err)
	}

	var ret *workspace.ReturnRequest
	if run.Copy && choice.source == workspace.SourceCloneLocal && run.ProjectRoot != "" {
		rr := workspace.ReturnRequest{SourceRepo: run.ProjectRoot, CopyDir: run.Dir, ManagedRoot: r.managedRoot, RunID: run.ID}
		if _, err := workspace.PlanReturn(rr); err == nil {
			ret = &rr
		}
	}
	var returnRefused string
	if run.Copy && choice.source == workspace.SourceCloneRemote {
		rr, rerr := ociCloneRemoteReturn(r.managedRoot, run)
		if rerr != nil {
			returnRefused = "the box's commits will not be returned from this clone-remote copy: " + rerr.Error() + "; the copy is kept at " + run.Dir
			choice.notices = append(choice.notices, returnRefused)
			if r.logger != nil {
				r.logger.Warn("terminal_sandbox: no clone-remote return", "run", run.ID, "err", rerr)
			}
		}
		ret = rr
	}
	// The daemon's watcher takes the transcripts for the run's life; a run
	// it does not take (a CLI launch has none) is read once by the helper
	// after the run (ociIngestUnwatched).
	watched := d.watchProjection(run.ID, run.Tool, run.Dir, transcripts)
	planPath, err := writeOCIPlan(r.observerDir, ociPlanFile{
		Version: ociPlanVersion, Socket: res.Socket, Engine: res.Identity.Engine, Mode: res.Identity.Mode,
		Fingerprint: res.Identity.Fingerprint, APIVersion: res.Identity.APIVersion, Host: ociHost(),
		AllowRootful: d.cfg.AllowRootful, ExtraEnv: choice.extraEnv, Return: ret, Create: plan,
		Backend: d.backend(), Projections: proj, DBCopyDest: ociDBCopyDest(r.observerDir, proj, run.ID),
		ConfigPath: ociPlanConfigPath(), Install: choice.cache.install, PathPrefix: choice.cache.binDir, Notices: choice.notices,
		TranscriptRoots: ociTranscriptHosts(transcripts), ReturnRefused: returnRefused,
		Tool: run.Tool, Transcripts: transcripts, TranscriptsWatched: watched,
		DropEnv: sandboxSignInDropEnv(run.Tool, len(proj) > 0),
	}, run.ID)
	if err != nil {
		d.unwatchProjection(run.ID)
		return nil, err
	}
	wrap := []string{r.observerBin, ociHostVerb, "--plan", planPath, "--"}
	wrap = append(wrap, host...)
	if f := ociReadoptKeep; f != nil {
		f(r.observerDir, run.ID, planPath, append(append([]string(nil), wrap...), ociInnerMarker), r.cfg, string(r.egress.Mode))
	}
	// The marker is the host services' command: it keeps the argv a
	// complete sandbox-host command line (sandbox.RelayOfWrap binds the
	// run's capture health from it), and the helper takes the inner launch
	// from after it.
	return append(wrap, ociInnerMarker), nil
}

// checkBinds refuses a launch whose binds would expose what the box must
// never see (SBX-P3A merge findings F1 and F8), before any plan is built:
//   - the relay's observer-dir rule, the SAME function bwrap's
//     validateRelayBinds calls (sandbox.CheckObserverDirBind): no tool state,
//     extra read-only or extra read-write bind may be the observer
//     directory, hold it, or lie inside it outside its workspaces tree
//     (observer.db, the run records and their secrets), on the written and
//     the resolved spelling;
//   - the sensitive write-bind table of rulings P-050 and P-054
//     (orgcontract.SandboxSensitiveWriteBind, through sensitiveWriteBind) on
//     every extra read-write bind: a container's binds are its only view of
//     the host, so a writable system directory, home, shell startup file,
//     credential store, .git directory or git hook is refused by name. The
//     developer's own ~/.config binds keep the table's one exception.
func (d *ociDriver) checkBinds(home string, spec integration.SandboxSpec) error {
	r := d.r
	check := func(kind, p string) error {
		if err := sandbox.CheckObserverDirBind(kind, p, r.observerDir, resolveSandboxBindPath); err != nil {
			return fmt.Errorf("terminal_sandbox: %w", err)
		}
		return nil
	}
	for _, rel := range spec.StateRW {
		if err := check("state rw bind", filepath.Join(home, rel)); err != nil {
			return err
		}
	}
	for _, x := range r.cfg.ExtraROBinds {
		if err := check("extra ro bind", x); err != nil {
			return err
		}
	}
	org := map[string]bool{}
	for _, b := range r.orgRWBinds {
		org[filepath.Clean(b)] = true
	}
	var local []string
	for _, x := range r.cfg.ExtraRWBinds {
		if !org[filepath.Clean(x)] {
			local = append(local, x)
		}
	}
	env := sandboxManagedEnv{home: home, localRWBinds: local}
	for _, x := range r.cfg.ExtraRWBinds {
		if err := check("extra rw bind", x); err != nil {
			return err
		}
		spellings := []string{filepath.Clean(x)}
		if rx := resolveSandboxBindPath(x); rx != "" && filepath.Clean(rx) != spellings[0] {
			spellings = append(spellings, filepath.Clean(rx))
		}
		if sensitiveWriteBind(spellings, env) {
			return fmt.Errorf("terminal_sandbox: extra rw bind %q is a sensitive host location (%s: a system directory, a home or a directory holding one, a shell startup file, a credential store, a .git directory or a git hook); the container sandbox never binds it writable", x, orgcontract.SandboxRefusedSensitivePath)
		}
	}
	return nil
}

// ociMaskPaths are the host paths bwrap masks with a tmpfs that a container
// bind could show again: the foreign-OS mounts and the operator's
// [terminal.sandbox].mask_paths (r.maskPaths, A1: /mnt/c on WSL2), and the
// host socket and interop directories (hostSocketMasks). One that cannot be
// listed is skipped; the rest still apply.
func (d *ociDriver) ociMaskPaths() []string {
	out := d.r.maskPaths()
	if masks, err := hostSocketMasks(os.Getuid()); err == nil {
		for _, m := range masks {
			out = append(out, m.Path)
		}
	}
	return out
}

// maskUnderBinds masks every mask path a bind shows (SBX-P3A merge finding
// F8: a bind of /mnt on WSL2 would otherwise show /mnt/c): an empty private
// tmpfs at the path inside the box, under which a deeper bind (a workspace on
// /mnt/c) is still mounted, because the engine mounts in depth order. A bind
// of exactly a mask path is the operator's explicit choice and is kept, as
// bwrap's ordered binds keep it.
func maskUnderBinds(p *sandboxoci.CreatePlan, masks []string, seen map[string]bool) {
	for _, m := range masks {
		m = filepath.Clean(strings.TrimSpace(m))
		if m == "" || m == "." || !filepath.IsAbs(m) {
			continue
		}
		for _, b := range p.Binds {
			src := filepath.Clean(b.Source)
			if src == m || !ociWithin(m, src) {
				continue
			}
			target := filepath.Join(b.Target, strings.TrimPrefix(m, src))
			if !seen[target] && !slices.Contains(p.Tmpfs, target) {
				seen[target] = true
				p.Tmpfs = append(p.Tmpfs, target)
			}
			break
		}
	}
}

// bindPlan composes the container's mounts from the same inputs the bwrap
// plan reads: the workspace and the tool's writable state read-write at
// their own paths, the tool's binaries and runtimes, the observer binary
// and the tool's read-only state read-only, the socket dir at the guest
// path, the operator's extra binds, and the protection table's overlays
// (hidden or read-only). Nothing else of the host is in the box: the
// container's root is the image, read-only.
func (d *ociDriver) bindPlan(home string, run termsvc.SandboxRun, spec integration.SandboxSpec, overlays []sandbox.Overlay, sockDir string, proj []sandboxoci.ProjectedDir) sandboxoci.CreatePlan {
	r := d.r
	var p sandboxoci.CreatePlan
	p.WorkDir = run.Dir
	seen := map[string]bool{}
	bind := func(src, dst string, ro, mustExist bool) {
		if src == "" || dst == "" || seen[dst] {
			return
		}
		if mustExist {
			if _, err := os.Stat(src); err != nil {
				return
			}
			if real, err := filepath.EvalSymlinks(src); err == nil {
				src = real
			}
		}
		seen[dst] = true
		p.Binds = append(p.Binds, sandboxoci.Bind{Source: src, Target: dst, ReadOnly: ro})
	}
	bind(run.Dir, run.Dir, false, false)
	if len(proj) > 0 {
		// Projected: each state path is its per-run directory, created by
		// the daemon, never the real one.
		for _, pd := range proj {
			bind(pd.Host, pd.Target, false, false)
		}
	} else {
		for _, rel := range spec.StateRW {
			bind(filepath.Join(home, rel), filepath.Join(home, rel), false, true)
		}
	}
	for _, x := range r.cfg.ExtraRWBinds {
		bind(x, x, false, true)
	}
	for _, x := range r.cfg.ExtraROBinds {
		bind(x, x, true, true)
	}
	for _, rel := range spec.StateRO {
		bind(filepath.Join(home, rel), filepath.Join(home, rel), true, true)
	}
	for _, dir := range r.toolBinDirs(run.Tool) {
		bind(dir, dir, true, true)
	}
	for _, rel := range sandboxRuntimeLadder {
		bind(filepath.Join(home, rel), filepath.Join(home, rel), true, true)
	}
	bind(r.observerBin, r.observerBin, true, true)
	if r.observerRealDir != "" {
		bind(r.observerRealDir, r.observerRealDir, true, true)
	}
	bind(sockDir, sandbox.GuestSocketDir, true, false)

	// The home and /tmp are private tmpfs mounts, unless the workspace IS
	// the home (a project at ~), whose bind then stands in for it.
	if run.Dir != home {
		p.Tmpfs = append(p.Tmpfs, home)
	}
	p.Tmpfs = append(p.Tmpfs, "/tmp")
	// A read-write bind that shows the observer directory (a project at
	// the home directory) blinds it again with a tmpfs, as bwrap's plan
	// step 8b does; the read-only overlays below put back what the inner
	// launcher reads.
	for _, b := range p.Binds {
		if !b.ReadOnly && ociWithin(r.observerDir, b.Source) {
			p.Tmpfs = append(p.Tmpfs, r.observerDir)
			break
		}
	}

	maskUnderBinds(&p, d.ociMaskPaths(), seen)
	d.overlayMounts(&p, overlays, seen, bind)
	return p
}

// ociPinMounts adds the launch's pins (sandboxRuntime.protection: every
// repository folder and .git under an org write bind, and a live
// workspace's own .git) to the plan, as bwrap's plan does (lane
// SHR-FOLLOWUPS, ledger SBX-BE-10): each existing, non-symlink path inside
// a read-write bind is bound onto itself, so the box cannot rename it aside
// and plant a replacement the read-only overlays would no longer cover. A
// path already mounted (a read-only .git pointer file's overlay, itself a
// mount point) or whose nearest enclosing mount is not a read-write bind
// (sandbox.PinWritable: outside every write bind, or under a read-only bind,
// a hidden directory or a tmpfs nested in one, audit finding 1 of lane
// SHR-FOLLOWUPS) is left out, as the Apple container row leaves it out;
// sandboxoci's spec rule refuses such a pin as a backstop.
func ociPinMounts(p *sandboxoci.CreatePlan, pins []string) {
	taken := map[string]bool{}
	var mounts []sandbox.PinMount
	for _, b := range p.Binds {
		taken[b.Target] = true
		mounts = append(mounts, sandbox.PinMount{Target: b.Target, Writable: !b.ReadOnly})
	}
	for _, f := range p.HideFiles {
		taken[f] = true
	}
	for _, d := range p.HideDirs {
		taken[d] = true
		mounts = append(mounts, sandbox.PinMount{Target: d})
	}
	for _, d := range p.Tmpfs {
		mounts = append(mounts, sandbox.PinMount{Target: d})
	}
	for _, pin := range pins {
		if taken[pin] {
			continue
		}
		fi, err := os.Lstat(pin)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if !sandbox.PinWritable(pin, mounts) {
			continue
		}
		taken[pin] = true
		p.Pins = append(p.Pins, pin)
	}
}

// overlayMounts adds the protection table's overlays to the plan: hidden
// files and directories, and read-only re-binds (placeholders included,
// which the host helper creates before the container), for every overlay a
// bind makes visible in the box.
func (d *ociDriver) overlayMounts(p *sandboxoci.CreatePlan, overlays []sandbox.Overlay, seen map[string]bool, bind func(src, dst string, ro, mustExist bool)) {
	r := d.r
	visible := func(path string) bool {
		if ociWithin(path, r.observerDir) {
			return true
		}
		for _, b := range p.Binds {
			if ociWithin(path, b.Target) {
				return true
			}
		}
		return false
	}
	for _, o := range overlays {
		if !visible(o.Path) || seen[o.Path] {
			continue
		}
		inObserver := ociWithin(o.Path, r.observerDir)
		switch o.Kind {
		case sandbox.OverlayHideFile:
			if !inObserver {
				seen[o.Path] = true
				p.HideFiles = append(p.HideFiles, o.Path)
			}
		case sandbox.OverlayHideDir:
			if !inObserver {
				seen[o.Path] = true
				p.HideDirs = append(p.HideDirs, o.Path)
			}
		case sandbox.OverlayReadOnly:
			// A placeholder is created by the host helper before the
			// container, so it need not exist now.
			bind(o.Path, o.Path, true, o.Placeholder == "")
		}
	}
}

// ociWithin reports whether p is root or inside it.
func ociWithin(p, root string) bool {
	if root == "" {
		return false
	}
	p, root = filepath.Clean(p), filepath.Clean(root)
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// projection creates the run's projected state directories when project is
// set (a row that crosses a kernel, or an image's own copy of the tool,
// sandboxoci.ProjectsState): one per writable state path, under <managed
// workspaces>/<run>.state, 0700 and empty; ociSeedProjection then seeds the
// tool's non-secret files and transcript subtrees from its G27 row. Nil
// otherwise, and the real state is bound as before.
func (d *ociDriver) projection(home string, run termsvc.SandboxRun, spec integration.SandboxSpec, project bool) ([]sandboxoci.ProjectedDir, error) {
	if !project {
		return nil, nil
	}
	root := ociProjectionRoot(d.r.managedRoot, run.ID)
	proj, err := sandboxoci.PlanProjection(root, home, spec.StateRW)
	if err != nil {
		return nil, fmt.Errorf("terminal_sandbox: %w", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("terminal_sandbox: create the projected state root: %w", err)
	}
	for _, pd := range proj {
		if err := os.Mkdir(pd.Host, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("terminal_sandbox: create a projected state dir: %w", err)
		}
	}
	return proj, nil
}

// ociInitDBCopyArgs are the init's flags that run the db-copy one-shot in
// each projected state directory once the agent has exited.
func ociInitDBCopyArgs(proj []sandboxoci.ProjectedDir) []string {
	var out []string
	for _, pd := range proj {
		out = append(out, ociInitDBCopyFlag, pd.Target)
	}
	return out
}

// ociInitDBCopyFlag is the init's flag naming one projected state
// directory (its path in the box).
const ociInitDBCopyFlag = "--db-copy"

// ociDBCopyDest is where the host keeps the guest's copies for run, under
// the driver's own state dir (never bound into a box); "" with no
// projection.
func ociDBCopyDest(observerDir string, proj []sandboxoci.ProjectedDir, runID string) string {
	if len(proj) == 0 {
		return ""
	}
	return ociDBCopyRunDir(observerDir, runID)
}

// ociProjectionRoot is a run's projected state root, <managed>/<run>.state
// ("" with no managed root).
func ociProjectionRoot(managedRoot, runID string) string {
	if managedRoot == "" {
		return ""
	}
	return filepath.Join(managedRoot, runID+sandboxoci.ProjectionLeaf)
}

// ociDBCopyRunDir is where a run's db-copy output is kept,
// <observer>/sandbox-oci/dbcopies/<run>.
func ociDBCopyRunDir(observerDir, runID string) string {
	return filepath.Join(ociDBCopiesDir(observerDir), runID)
}

// ociDBCopiesDir holds every run's db-copy output.
func ociDBCopiesDir(observerDir string) string {
	return filepath.Join(ociStateDir(observerDir), "dbcopies")
}

// ociRemoveRunState removes what a run of a projecting row (oci-runsc) leaves
// on the host: its projected state root and its db-copy output (audit
// SBX-P3B F4: up to 64 copies of 256 MiB each, which nothing reads yet). A
// path that is there but is not a plain directory (a symlink) is left alone
// and reported.
func ociRemoveRunState(observerDir, managedRoot, runID string) error {
	if !sandboxoci.ValidToken(runID) {
		return fmt.Errorf("terminal_sandbox: %q is not a run id", runID)
	}
	var errs []error
	for _, p := range []string{ociProjectionRoot(managedRoot, runID), ociDBCopyRunDir(observerDir, runID)} {
		if p == "" {
			continue
		}
		st, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil && !st.IsDir() {
			err = fmt.Errorf("terminal_sandbox: %s is not a directory, left alone", p)
		}
		if err == nil {
			err = os.RemoveAll(p)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ociSweepRunState removes the run state (ociRemoveRunState) of every run
// that left some and is not live, and reports how many runs it cleaned. A
// run is live while live says so.
func ociSweepRunState(observerDir, managedRoot string, live func(runID string) bool) (int, error) {
	ids := map[string]bool{}
	collect := func(dir, suffix string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			id, ok := strings.CutSuffix(e.Name(), suffix)
			if ok && e.IsDir() && sandboxoci.ValidToken(id) {
				ids[id] = true
			}
		}
	}
	if managedRoot != "" {
		collect(managedRoot, sandboxoci.ProjectionLeaf)
	}
	collect(ociDBCopiesDir(observerDir), "")
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	slices.Sort(sorted)
	n := 0
	var errs []error
	for _, id := range sorted {
		if live(id) {
			continue
		}
		if err := ociRemoveRunState(observerDir, managedRoot, id); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ociRunLive reports a run live while its relay run record exists. A record
// that cannot be looked up counts as live, so the sweep never removes the
// state of a run it cannot rule out.
func ociRunLive(observerDir string) func(runID string) bool {
	return func(runID string) bool {
		_, err := os.Lstat(filepath.Join(sandboxrelayd.RunsDir(observerDir), runID+".json")) //nolint:gosec // G703: a metadata read of a run record under the observer dir (runID is a token)
		return !errors.Is(err, fs.ErrNotExist)
	}
}

// ociRunStateSweepOnce runs the daemon-start sweep once per process.
var ociRunStateSweepOnce sync.Once

// ociStartSweepEnderWait bounds how long the daemon-start sweep waits for
// the daemon's run ender (a seam for tests).
var ociStartSweepEnderWait = 30 * time.Second

// ociSweepRunStateAtStart is the daemon-start sweep of orphaned run state:
// the records of dead helpers are pruned first, so a run whose helper is
// gone is not live. They are pruned only through the daemon's run ender
// (pruneGoneRelayRuns), which this sweep waits for, so a sandboxed CLI run
// whose helper and CLI were killed while the daemon was down is ended with
// process_gone, never left reading running (R2); without the ender the
// records stay and a later sweep ends them.
func ociSweepRunStateAtStart(r *sandboxRuntime) {
	awaitRelayGoneRunEnder(ociStartSweepEnderWait)
	pruneGoneRelayRuns(r.observerDir)
	n, err := ociSweepRunState(r.observerDir, r.managedRoot, ociRunLive(r.observerDir))
	// The clone-remote return repositories (lane LEFT-SBX): one whose run
	// ended with nothing returned, or past the retention bound.
	if rn, rerr := ociSweepReturnRepos(r.managedRoot, ociRunLive(r.observerDir), time.Now(), ociReturnRepoRetention(r.cfg.WorkspaceRetentionDays)); r.logger != nil && (rn > 0 || rerr != nil) {
		r.logger.Info("terminal_sandbox: swept clone-remote return repositories", "removed", rn, "err", rerr)
	}
	if r.logger == nil {
		return
	}
	if err != nil {
		r.logger.Warn("terminal_sandbox: sweeping orphaned oci run state", "removed", n, "err", err)
	} else if n > 0 {
		r.logger.Info("terminal_sandbox: removed orphaned oci run state", "runs", n)
	}
}

// Resize is owned by the PTY: the host helper turns the terminal's resize
// into the engine's resize call.
func (d *ociDriver) Resize(context.Context, termsvc.SandboxRun, uint16, uint16) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "oci-runc: the host helper passes the terminal's resize to the engine"}, nil
}

// Signal is owned by the PTY: the host helper forwards what it receives.
func (d *ociDriver) Signal(context.Context, termsvc.SandboxRun, string) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "oci-runc: the host helper forwards signals to a running container"}, nil
}

// Copy is not offered: the workspace is bound at its host path.
func (d *ociDriver) Copy(context.Context, termsvc.CopyRequest) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "oci-runc: the workspace is a host directory; copy on the host"}, nil
}

// Checkpoint is not offered by this row (Podman's checkpoint is a later
// item; the agent's native resume applies).
func (d *ociDriver) Checkpoint(context.Context, termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: "oci-runc: no checkpoint; the agent's native resume applies"}, nil
}

// Stop is owned by the PTY: closing the terminal hangs up the host helper,
// which stops the container with its grace and removes it.
func (d *ociDriver) Stop(context.Context, termsvc.SandboxRun, time.Duration) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: "oci-runc: closing the terminal stops and removes the container"}, nil
}

// Destroy releases a run that never started: its plan file, its projected
// state and db-copy output (audit SBX-P3B F4), its run record and its
// unattached workspace.
func (d *ociDriver) Destroy(_ context.Context, run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	d.choices.Delete(run.ID)
	d.unwatchProjection(run.ID)
	_ = removeOCIPlan(d.r.observerDir, run.ID)
	if err := ociRemoveRunState(d.r.observerDir, d.r.managedRoot, run.ID); err != nil && d.r.logger != nil {
		d.r.logger.Warn("terminal_sandbox: removing a run's projected state", "run", run.ID, "err", err)
	}
	return d.r.destroyBwrap(run)
}

// ---- node-local state under ~/.observer/sandbox-oci -------------------------

// ociStateDir is the driver's node-local directory.
func ociStateDir(observerDir string) string { return filepath.Join(observerDir, "sandbox-oci") }

// ociInstallID is this node's install id, minted once (random, hex): every
// container carries it, so the orphan sweep never touches another install's
// containers on a shared engine.
func ociInstallID(observerDir string) (string, error) {
	dir := ociStateDir(observerDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("terminal_sandbox: oci state dir: %w", err)
	}
	p := filepath.Join(dir, "install-id")
	if b, err := readOwnedNoFollow(p, 128); err == nil {
		if id := strings.TrimSpace(string(b)); sandboxoci.ValidToken(id) {
			return id, nil
		}
		return "", fmt.Errorf("terminal_sandbox: %s does not hold an install id", p)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw[:])
	f, err := ociCreateExcl(p)
	if errors.Is(err, fs.ErrExist) {
		return ociInstallID(observerDir)
	}
	if err != nil {
		return "", fmt.Errorf("terminal_sandbox: write install id: %w", err)
	}
	_, werr := f.WriteString(id + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return id, werr
}

// ociEnginesFile holds the engine identities recorded at first use, keyed
// by socket path (section 4.6: a substituted socket is refused).
func ociEnginesFile(observerDir string) string {
	return filepath.Join(ociStateDir(observerDir), "engines.json")
}

// ociIdentities reads the recorded identities.
func ociIdentities(observerDir string) map[string]sandboxoci.Identity {
	b, err := readOwnedNoFollow(ociEnginesFile(observerDir), 1<<20)
	if err != nil {
		return nil
	}
	var m map[string]sandboxoci.Identity
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// recordOCIIdentity records the identity first seen on a socket.
func recordOCIIdentity(observerDir, socket string, id sandboxoci.Identity) error {
	m := ociIdentities(observerDir)
	if m == nil {
		m = map[string]sandboxoci.Identity{}
	}
	if _, ok := m[socket]; ok {
		return nil
	}
	m[socket] = id
	return writeOCIStateFile(ociEnginesFile(observerDir), m)
}

// forgetOCIIdentity drops the identity recorded for socket (after the
// user checked a changed daemon: `observer sandbox oci forget-engine`).
func forgetOCIIdentity(observerDir, socket string) error {
	m := ociIdentities(observerDir)
	if _, ok := m[socket]; !ok {
		return nil
	}
	delete(m, socket)
	return writeOCIStateFile(ociEnginesFile(observerDir), m)
}

// writeOCIStateFile writes v as JSON through a fresh temporary file and a
// rename, owner-only.
func writeOCIStateFile(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(name)
		return werr
	}
	return os.Rename(name, p)
}

// ociPlanPath is a run's plan file: under the daemon's own observer dir,
// never bound into any box.
func ociPlanPath(observerDir, runID string) string {
	return filepath.Join(ociStateDir(observerDir), "plans", runID+".json")
}

// writeOCIPlan writes a run's plan file (0600, created fresh).
func writeOCIPlan(observerDir string, plan ociPlanFile, runID string) (string, error) {
	p := ociPlanPath(observerDir, runID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", fmt.Errorf("terminal_sandbox: oci plan dir: %w", err)
	}
	b, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	f, err := ociCreateExcl(p)
	if err != nil {
		return "", fmt.Errorf("terminal_sandbox: write oci plan: %w", err)
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(p)
		return "", werr
	}
	return p, nil
}

// readOCIPlan reads a plan file (owned, no symlink, capped).
func readOCIPlan(p string) (ociPlanFile, error) {
	b, err := readOwnedNoFollow(p, 4<<20)
	if err != nil {
		return ociPlanFile{}, err
	}
	var plan ociPlanFile
	if err := json.Unmarshal(b, &plan); err != nil {
		return ociPlanFile{}, fmt.Errorf("oci plan: %w", err)
	}
	if plan.Version != ociPlanVersion {
		return ociPlanFile{}, fmt.Errorf("oci plan: version %d, this binary reads %d (restart the daemon after an upgrade)", plan.Version, ociPlanVersion)
	}
	return plan, nil
}

// removeOCIPlan removes a run's plan file.
func removeOCIPlan(observerDir, runID string) error {
	err := os.Remove(ociPlanPath(observerDir, runID))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
