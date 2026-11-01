//go:build !sbo_omit_terminals

package main

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termlease"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// launch_dashboard.go wires the dashboard's embedded web-terminal launch
// seam (dashapi.LaunchManager) to the terminal application service
// (internal/termsvc) over internal/termsession. termsvc owns the run identity,
// the fresh-launch authorization, and the correlation model; termsession owns
// only the PTY/viewer lifecycle. The dashboard never imports either — this
// adapter is the single boundary that translates the dashboard's server-derived
// specs into termsvc calls and maps errors onto the dashboard's sentinels
// (the same pattern as handoffRunner behind BuildHandoff).

// launchManagerAdapter bridges the terminal service + PTY manager to
// dashapi.LaunchManager.
type launchManagerAdapter struct {
	svc *termsvc.Service
	mgr *termsession.Manager
	// budgetState loads the daemon's config and database for the managed
	// hard-budget rows of a dashboard fresh launch (OSH-R-007). Nil (a test
	// adapter) leaves those rows out.
	budgetState func(ctx context.Context, configPath string) (config.Config, *sql.DB, func(), error)
	// remoteAuthz runs the §4.δ authorization conjunction and mints the
	// unforgeable WriterGrant for a remote writer acquire. Nil until the
	// remote-execute tier is wired (Phase 4 §4.γ/§4.δ) — a nil authorizer fails
	// AcquireWriterRemote closed. The returned recheck func (nil for the
	// single-use capability path) is the standing-path TOCTOU close: it is run
	// AFTER the lease install and must return true for the lease to survive —
	// false means the standing secret was revoked/rotated while the (argon2)
	// verify was in flight, so the just-installed lease is torn down.
	remoteAuthz func(dashapi.RemoteWriterRequest) (termlease.WriterGrant, func() dashapi.ControlDenialReason, error)
	// attachAudit records the metadata-only terminal_attach spawn-audit row (F4,
	// session-attach design §3.5) for attach-socket launches. Nil when no DB is
	// wired (auditing disabled). Built in buildTerminalStack over the SAME
	// SpawnAuditKind vocabulary the dashboard resume handler uses.
	attachAudit func(runID, tool, handle string)
	// instances owns the instance switcher's SSH local port forwards
	// (docs/ssh-terminals.md "Instance switcher"). Nil when the terminal stack
	// was not built — the dashboard's optional-seam assertion still succeeds,
	// and every verb then degrades honestly through the nil-safe Manager
	// methods rather than panicking.
	instances sshInstances
	// remoteIDs remembers what each live forward's REMOTE daemon says about
	// its own build and hostname (T-425, instance_identity.go). Zero value
	// ready.
	remoteIDs remoteIdentityCache
	// guard is the process-wide egress-policy Guard (P7 gateway-arc item 3:
	// the sandbox_enforce lane). Nil when guarding is disabled/no DB — every
	// consumer must nil-check via guard.Mode(), which itself has no
	// nil-receiver guard.
	guard *guard.Guard
	// repoTrust builds the repository trust row's dependencies for one
	// dashboard launch from the current config (launch_trust.go); it gives
	// nil while security.trust is inactive, and is itself nil in a build
	// without the module. Its ask defers to the inner launcher, which asks
	// in the PTY.
	repoTrust func() *repoTrustDeps
	// sandboxProber backs the same B9 probe the dashboard's own
	// /api/terminal/sandbox endpoint uses, reused here so CreateFresh's
	// auto-upgrade decision and the dashboard's own availability display never
	// disagree. Nil when [terminal.sandbox] is disabled.
	sandboxProber dashapi.SandboxProber
	// nf is the node.features policy handle (P7 gateway-arc item 4's
	// org_disallow honor path). Nil-safe: a nil nf allows every tool.
	nf *nodeFeaturesHandle
	// toolGate reads whether a hook_block tool's tool-gate hook is
	// registered and current on this node (toolgate_node.go). Nil reads as
	// not current, so a hook_block tool is sandboxed like any other.
	toolGate func(tool string) nodeToolGateState
}

// newSpawnAuditSink builds the metadata-only spawn-audit closure (F4,
// session-attach design §3.5) that persists one remote_audit row per terminal
// spawn through the ONE store seam (store.InsertRemoteAudit). kind is a
// dashapi.SpawnAuditKind value resolved once at wiring; an empty kind or a nil
// DB yields a nil sink (auditing disabled). Metadata ONLY — the run identity,
// the tool label, and the opaque handle (correlation, like the lease-audit
// Route) — NEVER argv, env, or terminal content. Best-effort + bounded; a failed
// audit never affects the spawn.
func newSpawnAuditSink(database *sql.DB, kind string) func(runID, tool, handle string) {
	if database == nil || kind == "" {
		return nil
	}
	st := store.New(database)
	return func(runID, tool, handle string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = st.InsertRemoteAudit(ctx, store.RemoteAuditEvent{
			Kind:      kind,
			SessionID: runID,   // the run identity minted at spawn (never a secret)
			Principal: "local", // an attach socket is owner-only (AF_UNIX 0600)
			Route:     handle,  // correlate on the terminal handle like every terminal event
			Decision:  "ok",
			Detail:    tool,
		})
	}
}

// applyTerminalBounds maps the [terminal] knobs onto the termsession Options.
// IdleTimeout "0"/empty maps to 0 = idle reaping DISABLED (the seeded config
// default — live sessions stay until their child exits); a positive duration
// opts back into reaping. It is validated at config load, so a parse failure
// here is only a defensive log.
func applyTerminalBounds(opts *termsession.Options, tc config.TerminalConfig, logger *slog.Logger) {
	opts.MaxConcurrent = tc.MaxConcurrent
	opts.RingBytes = tc.RingBytes
	opts.MaxSubscribers = tc.MaxSubscribers
	if tc.IdleTimeout != "" {
		if d, err := time.ParseDuration(tc.IdleTimeout); err == nil {
			opts.IdleTimeout = d
		} else {
			logger.Warn("terminal: ignoring invalid idle_timeout", "value", tc.IdleTimeout, "err", err)
		}
	}
}

// terminalLaunchPolicy resolves the fresh-launch authorization from config.
// [terminal].enabled gates the terminal-wide surface, so fresh launch requires
// BOTH it and the [terminal.launch].allow_fresh_agent opt-in.
func terminalLaunchPolicy(tc config.TerminalConfig) termsvc.Policy {
	return termsvc.Policy{
		AllowFresh:          terminalAllowFreshAgent(tc),
		AllowedTools:        tc.Launch.AllowedTools,
		AllowedProjectRoots: tc.Launch.AllowedProjectRoots,
		AllowShell:          tc.Enabled && tc.Launch.AllowShell,
		// SSH remote-system shells. Like AllowShell this requires BOTH the
		// terminal-wide surface and its OWN opt-in — an SSH shell runs
		// arbitrary commands on ANOTHER machine, so [terminal.launch].
		// allow_shell (a LOCAL shell) deliberately does not imply it.
		//
		// The profile list is threaded in whole: it IS the authorization model
		// (a name the operator never wrote can never become a connection), so
		// the daemon holds exactly the list config declared, converted once at
		// this boundary into the pure sshprofile type.
		AllowSSH:    tc.Enabled && tc.SSH.Enabled,
		SSHProfiles: config.SSHProfiles(tc.SSH),
		SSHOptions:  config.SSHOptions(tc.SSH),
	}
}

// SetTerminalLimits live-applies the dashboard-editable [terminal] concurrency
// cap + idle-reap timeout onto the PTY manager with no restart. It satisfies the
// OPTIONAL interface the /api/terminal/limits verb type-asserts on the dashboard
// LaunchManager seam (the dashboard never widens LaunchManager for this — the
// dozens of test fakes must stay compiling; a fake lacking this method makes the
// verb report restart_required). Nil-safe: a nil adapter or nil manager is a
// no-op, so the assertion succeeding but the manager being absent degrades to
// "persisted, live-apply skipped" rather than panicking.
func (a *launchManagerAdapter) SetTerminalLimits(maxConcurrent int, idleTimeout time.Duration) {
	if a == nil || a.mgr == nil {
		return
	}
	a.mgr.SetLimits(maxConcurrent, idleTimeout)
}

// TerminalPolicyLive satisfies the dashboard's OPTIONAL terminalPolicyLive
// seam: true when the terminal service reads the launch policy through the
// live config holder (terminal_config_live.go), so a [terminal.launch] save
// binds on the next launch and the dashboard must not say "restart". Nil-safe.
func (a *launchManagerAdapter) TerminalPolicyLive() bool {
	return a != nil && a.svc.PolicyLive()
}

// --- dashapi.LaunchManager implementation ---

func (a *launchManagerAdapter) Create(spec dashapi.LaunchSpec) (string, error) {
	res, err := a.svc.LaunchHandoff(context.Background(), termsvc.HandoffRequest{
		Tool:        spec.Subcommand, // the launcher verb doubles as the tool label here
		Subcommand:  spec.Subcommand,
		SessionID:   spec.SessionID,
		Carry:       spec.Carry,
		FromMessage: spec.FromMessage,
		Rows:        spec.Rows,
		Cols:        spec.Cols,
	})
	if err != nil {
		return "", mapLaunchErr(err)
	}
	return res.Handle, nil
}

func (a *launchManagerAdapter) CreateFresh(spec dashapi.FreshLaunchSpec) (string, error) {
	// P7 gateway-arc item 4: org_disallow honor path. Checked before termsvc's
	// own AllowedTools/AllowedProjectRoots authorization, so a tool the org
	// policy disallows never reaches the launcher at all. a.nf is nil-safe —
	// no org policy (or no tools stanza) allows every tool.
	// Request-grants G8: a verified org tool access grant lets a launch of a
	// disallowed tool through; the refusal names the request path. This
	// gate only PEEKS (review M3-10): the inner `observer <tool>` launcher
	// the PTY runs counts the use, once, when it starts the tool, so a
	// launch refused below (sandbox, allowed tools) spends nothing.
	// P7 gateway-arc item 3: sandbox-enforce lane. When the process-wide
	// guard is in enforce mode and this tool's enforcement channel ON THIS
	// NODE (integration.Capability.NodeEnforcement: a hook_block tool counts
	// as hook_block only while its tool-gate hook is registered and current
	// here, toolgate_node.go; sandbox availability on THIS platform comes
	// from the same prober the dashboard's own /api/terminal/sandbox endpoint
	// consults) is sandbox_enforce, auto-upgrade an unsandboxed request
	// rather than letting a tool with no working gate launch unguarded.
	// Never downgrades an already-sandboxed request; never forces a sandbox
	// that isn't actually available (the channel degrades to
	// recorded_acceptance there, so the request proceeds unsandboxed honestly
	// rather than failing closed on a platform that can't sandbox at all).
	//
	// D-178 / D-221 (operator ruling 2026-10-04): what a missing sandbox
	// degrades to is the ORGANIZATION's choice, read from the signed org
	// guard bundle through Guard.OrgFallbacks (the defaults on an individual
	// node). recorded_acceptance (the default) keeps the honest unsandboxed
	// launch above; org_disallow refuses a proxied tool's launch with a
	// reason instead. Both decisions are one per-node call (D-262): a
	// hook_block tool whose gate is not current here reaches the org's
	// fallback like a tool with no hook.
	//
	// T-497 (D-333): the decision ("enforcing" is Guard.GateEnforcement
	// .Tool, review M2-13) and its wording live in ONE owner,
	// sandboxLaunchDecision (launch_sandbox_gate.go). `observer <tool>`
	// launches from any terminal reach the same owner through the shared
	// admission chokepoint, so the two paths cannot drift.
	//
	// T-910: a project-scope hook switch in the launch's project makes the
	// tool's hook not current for THIS launch.
	//
	// F0-4: the gates above (tool.disallow, repo.trust, hook.switch,
	// sandbox.select) and their order are rows of the launch-gate table
	// (launch_gates.go); the termsvc authorization below runs after it.
	run := &launchGateRun{
		ctx:    context.Background(),
		path:   launchPathDashboardFresh,
		tool:   spec.Tool,
		stderr: io.Discard,
		toolLaunchAllowed: func(tool string) bool {
			allowed, _, _ := a.nf.ToolLaunchAllowed(tool)
			return allowed
		},
		launchDir:     func() (string, error) { return spec.ProjectRoot, nil },
		baseToolGate:  a.toolGate,
		sandboxGateOn: func(*launchGateRun) bool { return true },
		guardFor:      func(*launchGateRun) *guard.Guard { return a.guard },
		sandboxProbe: func() bool {
			return a.sandboxProber != nil && a.sandboxProber.ProbeSandbox(context.Background()).Available
		},
		sandboxRefusal: dashboardSandboxRefusal,
		sandboxed:      spec.Sandbox,
		repoTrustFor: func(*launchGateRun) *repoTrustDeps {
			if a.repoTrust == nil {
				return nil
			}
			return a.repoTrust()
		},
		// OSH-R-007: the managed hard budget is admitted daemon-side before
		// the PTY spawns (rows state.load, budget.authority, budget.guard,
		// budget.spend), from the daemon's own config and database. Coverage
		// stays with the inner launcher, which has the real route evidence.
		configPath:   daemonConfigPath(),
		daemonRunsFn: func() bool { return true },
		stateSource:  a.budgetState,
		budgetExempt: spec.Shell || a.budgetState == nil,
	}
	if run.budgetExempt {
		// A plain shell (or a test adapter with no state source) is not
		// judged by the budget rows, so it never reads the daemon's config
		// or database either (audit follow-up F4).
		run.stateSource = noLaunchState
	}
	if err := walkLaunchGates(run, launchGates); err != nil {
		return "", err
	}
	spec.Sandbox = run.sandboxed
	res, err := a.svc.LaunchFresh(context.Background(), termsvc.FreshRequest{
		Tool:        spec.Tool,
		Subcommand:  spec.Subcommand,
		ProjectRoot: crossmount.TranslateForeignPath(spec.ProjectRoot),
		Rows:        spec.Rows,
		Cols:        spec.Cols,
		Shell:       spec.Shell,
		Model:       spec.Model,
		// B9: the sandbox request (already fail-closed-validated by
		// handleTerminalLaunch against the probe before this spec was built).
		// LaunchFresh re-checks the seam is present (nil Sandboxer →
		// ErrSandboxUnavailable) and runs Prepare before minting the run.
		Sandbox:         spec.Sandbox,
		WorkspaceSource: spec.WorkspaceSource,
		WorkspaceRemote: spec.WorkspaceRemote,
		WorkspaceBranch: spec.WorkspaceBranch,
		SandboxBackend:  spec.Backend,
		SignInSeed:      spec.SignInSeed,
		SignInAsk:       spec.SignInAsk,
	})
	if err != nil {
		return "", mapFreshErr(err)
	}
	return res.Handle, nil
}

// CreateSSH spawns an OUTBOUND SSH remote-system shell through the terminal
// application service (docs/plans/ssh-remote-profiles-plan-2026-08-27.md).
//
// Note what is NOT here: no crossmount.TranslateForeignPath, no project root,
// no subcommand, no model. The spec carries a profile NAME and the PTY
// geometry; the service resolves every connection parameter from the operator's
// own config. Errors map through mapSSHErr onto the dashboard sentinels.
func (a *launchManagerAdapter) CreateSSH(spec dashapi.SSHLaunchSpec) (string, error) {
	res, err := a.svc.LaunchSSH(context.Background(), termsvc.SSHRequest{
		Profile: spec.Profile,
		Rows:    spec.Rows,
		Cols:    spec.Cols,
	})
	if err != nil {
		return "", mapSSHErr(err)
	}
	return res.Handle, nil
}

// SSHProfiles projects the service's configured profiles onto the dashboard's
// picker rows. It is a pure projection of config — never a mutation — and it
// deliberately narrows what crosses the seam: the full key PATH stays behind,
// and only its BASENAME (KeyHint) is exposed, so the dashboard never discloses
// the operator's filesystem layout.
func (a *launchManagerAdapter) SSHProfiles() (bool, []dashapi.SSHProfileInfo) {
	enabled, profiles := a.svc.SSHProfileList()
	if len(profiles) == 0 {
		return enabled, nil
	}
	out := make([]dashapi.SSHProfileInfo, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, dashapi.SSHProfileInfo{
			Name:    p.Name,
			Label:   p.Display(),
			Target:  p.Target(),
			Jump:    p.Jump,
			HasKey:  p.KeyPath != "",
			KeyHint: p.KeyHint(),
		})
	}
	return enabled, out
}

// --- dashboard instanceManager implementation (instance switcher) ---
//
// The three methods below satisfy the dashboard's OPTIONAL instanceManager
// seam. They are pure projections of the sshforward.Manager: this adapter adds
// no policy of its own, because every authorization decision (feature enabled,
// profile known, profile still valid, host key trusted) already lives in the
// one owner. A nil manager is honest rather than fatal — Enabled/List are
// nil-safe, and the verbs return ErrDisabled.

// Instances lists the operator's configured remote Observer installs plus each
// one's live forward state. Like SSHProfiles this narrows what crosses the
// seam: the key PATH stays behind and only its basename travels.
func (a *launchManagerAdapter) Instances() (bool, []dashapi.InstanceInfo) {
	if a == nil || a.instances == nil {
		return false, nil
	}
	rows := a.instances.List()
	if len(rows) == 0 {
		return a.instances.Enabled(), nil
	}
	out := make([]dashapi.InstanceInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, a.remoteIDs.annotate(r))
	}
	return a.instances.Enabled(), out
}

// ConnectInstance opens (or re-uses) the local port forward for a profile.
func (a *launchManagerAdapter) ConnectInstance(name string) (dashapi.InstanceInfo, error) {
	if a == nil || a.instances == nil {
		return dashapi.InstanceInfo{}, dashapi.ErrInstancesDisabled
	}
	inst, err := a.instances.Connect(name)
	if err != nil {
		return dashapi.InstanceInfo{}, err
	}
	return a.remoteIDs.annotate(inst), nil
}

// DisconnectInstance closes the forward and returns the resulting row. The
// post-disconnect snapshot is read back rather than synthesized so the UI is
// updated from the manager's own state, not from this adapter's assumption
// about it.
func (a *launchManagerAdapter) DisconnectInstance(name string) (dashapi.InstanceInfo, error) {
	if a == nil || a.instances == nil {
		return dashapi.InstanceInfo{}, dashapi.ErrInstancesDisabled
	}
	if err := a.instances.Disconnect(name); err != nil {
		return dashapi.InstanceInfo{}, err
	}
	inst, ok := a.instances.Get(name)
	if !ok {
		return dashapi.InstanceInfo{}, dashapi.ErrInstanceUnknown
	}
	return inst, nil
}

// TestInstance runs the bounded, non-interactive connectivity probe
// (sshforward.Manager.Test) for a profile and projects the result onto the
// dashboard wire shape. Like Connect/Disconnect it re-validates the profile
// first (inside Manager.Test), so a request can never probe a machine the
// operator did not write down; unlike them it opens no forward and leaves no
// live state, so it needs no post-call snapshot read-back.
func (a *launchManagerAdapter) TestInstance(name string) (dashapi.InstanceTestResult, error) {
	if a == nil || a.instances == nil {
		return dashapi.InstanceTestResult{}, dashapi.ErrInstancesDisabled
	}
	return a.instances.Test(name)
}

// TestSSHProfileDraft satisfies the dashboard's OPTIONAL sshProfileTester
// seam (T-488): the profile editor's test-connect for a profile the operator
// has not saved yet. It converts the draft at the ONE config boundary
// (config.SSHProfile) and runs sshforward's read-only probe, which validates
// it exactly like config load does and never opens a forward.
func (a *launchManagerAdapter) TestSSHProfileDraft(p config.SSHProfileConfig) (dashapi.InstanceTestResult, error) {
	if a == nil || a.instances == nil {
		return dashapi.InstanceTestResult{}, dashapi.ErrInstancesDisabled
	}
	return a.instances.TestProfile(p)
}

// CreateResume spawns a NATIVE resume of a closed session (session-attach
// design Phase 3) through the terminal application service, which enforces the
// SAME fresh-launch policy as CreateFresh (a dashboard-initiated Execute
// respects [terminal.launch] — unlike the owner-only CLI attach socket). It
// returns the opaque handle AND the durable run id; errors map onto the
// dashboard sentinels through mapFreshErr (fresh-disabled / tool-not-allowed /
// project-root-denied + the termsession spawn errors).
func (a *launchManagerAdapter) CreateResume(spec dashapi.ResumeLaunchSpec) (string, string, error) {
	res, err := a.svc.LaunchResume(context.Background(), termsvc.ResumeRequest{
		Tool:            spec.Tool,
		Subcommand:      spec.Subcommand,
		ProjectRoot:     crossmount.TranslateForeignPath(spec.ProjectRoot),
		SourceSessionID: spec.SessionID,
		ExtraArgs:       spec.ExtraArgs,
		Rows:            spec.Rows,
		Cols:            spec.Cols,
	})
	if err != nil {
		return "", "", mapFreshErr(err)
	}
	return res.Handle, res.RunID, nil
}

// CreateSetup spawns a fixed, server-derived local operator setup command
// (e.g. the one-time Tailscale operator grant) DIRECTLY through the PTY manager
// — bypassing termsvc (AI-launch policy) and terminal_run identity, with no OOB
// channel. Env is the daemon's own os.Environ() (a setup command needs a sane
// PATH/TERM) with internal child vars stripped PLUS the OBSERVER_DAEMON_CHILD
// marker via setupChildEnv, so this non-termsvc path still satisfies the "every
// daemon child carries the marker" invariant (finding: marker completeness). The
// session is SpecSetup → local-writer-only.
//
// Dir is setupChildDir() for EVERY setup command, never the daemon's inherited
// cwd: see setupWorkDir for why.
func (a *launchManagerAdapter) CreateSetup(spec dashapi.SetupSpec) (string, error) {
	handle, err := a.mgr.Create(termsession.Spec{
		Kind:       termsession.SpecSetup,
		SetupArgv:  spec.Argv,
		SetupLabel: spec.Label, // keys the setup single-flight (one PTY per kind)
		Env:        setupChildEnvFor(setupProgram(spec.Argv)),
		Dir:        setupChildDir(),
		Rows:       spec.Rows,
		Cols:       spec.Cols,
	})
	if err != nil {
		return "", mapLaunchErr(err)
	}
	return handle, nil
}

// setupChildDir is the working directory a setup PTY (guided install and
// uninstall, the Tailscale operator grant, the ETW register) starts in: the
// operator's home, else the OS temp dir, else "" (inherit, the old behaviour).
func setupChildDir() string {
	home, _ := os.UserHomeDir()
	return setupWorkDir(home, os.TempDir(), func(p string) bool {
		fi, err := os.Stat(p) //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
		return err == nil && fi.IsDir()
	})
}

// setupWorkDir picks the first candidate that is an absolute, existing
// directory. It is pure (the directory test is injected) so the ladder is
// table-tested.
//
// Why a setup PTY must not inherit the daemon's cwd: a daemon started by a
// service manager, a login script or `nohup` from a system directory runs with
// cwd "/" (demo node 1, 2026-10-02: /proc/<daemon>/cwd -> /), which an ordinary
// user cannot write. Vendor installers routinely download into the CURRENT
// directory before extracting - goose's download_cli.sh does
// `curl -sLf "$URL" --output "$FILE"` - so from "/" curl fails with exit 23
// (write error), `-s` hides the reason, and the script reports a misleading
// "Failed to download from fallback url ..." although the asset exists and is
// reachable. A user typing the same command into a fresh terminal is in their
// home directory; the guided install now is too.
func setupWorkDir(home, tmp string, isDir func(string) bool) string {
	for _, cand := range []string{home, tmp} {
		cand = strings.TrimSpace(cand)
		if cand != "" && filepath.IsAbs(cand) && isDir != nil && isDir(cand) {
			return cand
		}
	}
	return ""
}

// setupProgram returns the PROGRAM a setup argv runs (its head), or "" for an
// empty argv. It is what setupChildEnvFor prepends the directory of, so a
// guided install whose argv[0] dashboardInstallPlanFor already resolved to an
// absolute path (DI-04a) also gets that directory on the setup PTY's own PATH
// — which is how an npm shim in a login-only prefix finds its node (DI-04b).
func setupProgram(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return argv[0]
}

func (a *launchManagerAdapter) Subscribe(handle string) (dashapi.LaunchSubscription, error) {
	sub, err := a.mgr.Subscribe(handle)
	if err != nil {
		return nil, err
	}
	return sub, nil // *termsession.Subscription satisfies dashapi.LaunchSubscription
}

// SubscribeRemote is the remote-principal viewer path: it refuses a SpecSetup
// (privileged, local-only) session at the manager seam so a paired remote device
// can never READ a setup PTY's output (a typed sudo password / login URL).
func (a *launchManagerAdapter) SubscribeRemote(handle string) (dashapi.LaunchSubscription, error) {
	sub, err := a.mgr.SubscribeRemote(handle)
	if err != nil {
		return nil, err
	}
	return sub, nil
}

// IsSetupSession reports whether a handle is a SpecSetup (privileged, local-only)
// session — the dashboard redacts these from remote snapshots and refuses their
// remote termination.
// noLaunchState is a dashboard walk's state source when the adapter has no
// budgetState: no config and no database, so the rows that read them stay
// inert.
func noLaunchState(context.Context, string) (config.Config, *sql.DB, func(), error) {
	return config.Config{}, nil, nil, nil
}

// RunSandboxed reports whether handle is a live run termsvc launched and
// whether it runs in a sandbox, the answer the dashboard's Jump-in gate
// judges a join with (OSH-R-003). isRun is false for a setup PTY or an
// unknown handle.
func (a *launchManagerAdapter) RunSandboxed(handle string) (sandboxed, isRun bool) {
	if a == nil || a.svc == nil {
		return false, false
	}
	return a.svc.Sandboxed(handle)
}

func (a *launchManagerAdapter) IsSetupSession(handle string) bool {
	return a.mgr.IsSetupSession(handle)
}

// IsRemoteSensitiveSession reports whether a handle is a remote-deny-by-default
// run — an external `observer <tool> --attach` session (KindAttach) OR a native
// resume of a real closed transcript (KindResume) — resolved from the run
// identity termsvc minted at spawn and the shared termrun.IsRemoteSensitiveKind
// table (dispatch on run SHAPE, never a tool name — CLAUDE.md #3/#5). The
// dashboard denies a remote-exposed caller the snapshot row and the websocket
// for such a handle by default (§3.2). Because termsvc retains byMeta through
// ExitLinger (F1), this keeps classifying an exited-but-lingering handle as
// sensitive for as long as the Manager can still replay its bytes. Unknown/reaped
// handle ⇒ false.
func (a *launchManagerAdapter) IsRemoteSensitiveSession(handle string) bool {
	kind, _, ok := a.svc.KindForHandle(handle)
	return ok && termrun.IsRemoteSensitiveKind(kind)
}

func (a *launchManagerAdapter) Unsubscribe(sub dashapi.LaunchSubscription) {
	if ts, ok := sub.(*termsession.Subscription); ok {
		a.mgr.Unsubscribe(ts)
	}
}

func (a *launchManagerAdapter) AcquireWriterLocal(handle string) (dashapi.LaunchWriter, error) {
	l, err := a.mgr.AcquireWriterLocal(handle)
	if err != nil {
		return nil, err
	}
	return l, nil // *termsession.WriterLease satisfies dashapi.LaunchWriter
}

// termsvcLaunchPolicy resolves the termlease.LaunchPolicy leg of the §4.δ
// conjunction: a remote writer may target ONLY a live, termsvc-tracked terminal
// run. A setup session (the one-time local operator grant) is created directly
// through the manager with no termsvc run, so it has no RunIDForHandle mapping
// and is refused here — in addition to the manager's own local-writer-only pin.
// An unknown/dead handle is likewise refused (fail closed). The richer tool/
// project-root allow-list refinement is a documented Phase-4 follow-up; the run
// was already policy-checked at launch, so a live run is the minimal applicable
// policy.
type termsvcLaunchPolicy struct{ svc *termsvc.Service }

func (p termsvcLaunchPolicy) Allowed(handle string) bool {
	if p.svc == nil {
		return false
	}
	_, ok := p.svc.RunIDForHandle(handle)
	return ok
}

// wireRemoteExecute installs the §4.δ remote-writer authorizer onto the adapter
// once the [remote] substrate exists. authz owns the device-session +
// capability stores (the SAME instances the local approve-execute mint uses),
// so a capability minted at approve-execute is the one consumed here.
// allowTerminal reads the live remote.allow_terminal gate; RemoteExposed comes
// from the request's boundary-resolved provenance flag — NEVER a client body
// field. Until this is called, AcquireWriterRemote stays fail-closed.
func (a *launchManagerAdapter) wireRemoteExecute(authz dashapi.TerminalControlAuthorizer, allowTerminal func() bool) {
	policy := termsvcLaunchPolicy{svc: a.svc}
	a.remoteAuthz = func(req dashapi.RemoteWriterRequest) (termlease.WriterGrant, func() dashapi.ControlDenialReason, error) {
		// A standing terminal-control secret (opt-in §B) rides the SAME
		// acquire-writer cap field, distinguished by its collision-free prefix.
		// Route it to the AuthorizeStanding leg — the IDENTICAL §4.δ conjunction
		// with a reusable-standing-secret verify replacing the single-use
		// capability consume. This is a boundary branch on CREDENTIAL SHAPE, not
		// a second websocket path (CLAUDE.md #3).
		if isStandingCredential(credOf(req)) {
			standing, ok := authz.(dashapi.StandingTerminalVerifier)
			if !ok {
				return termlease.WriterGrant{}, nil, dashapi.NewControlDeniedError(
					dashapi.ControlDenialUnavailable, false, dashapi.ErrLaunchExecuteUnavailable,
				)
			}
			// TOCTOU close (finding 1): capture the standing generation BEFORE
			// the verify. Every revoke/rotate bumps it BEFORE killing writers,
			// so if it moved by the time the lease is installed, the verify
			// raced an admin transition and the lease must not survive.
			gen := standing.StandingTerminalGeneration()
			sr := termlease.AuthorizeRequest{
				Handle:          req.Handle,
				DeviceSessionID: req.DeviceSessionID,
				RemoteExposed:   req.RemoteExposed,
				AllowTerminal:   allowTerminal(),
			}
			setCred(&sr, credOf(req)) // the standing secret rides the credential field
			grant, err := termlease.AuthorizeStanding(sr, authz, policy, standing)
			// The install-time recheck fences ALL THREE lifecycle races that can
			// land during the slow argon2 verify: the SECRET lifecycle
			// (generation bumped by mint/rotate/revoke/disable), the SESSION
			// lifecycle (device revoke / logout / rotate / revoke-all do NOT
			// bump the generation, so re-validate the session directly — finding
			// 1 residual), AND the allow_terminal GATE (an allow_terminal→false
			// flip + its RevokeAllRemoteWriters sweep can complete BEFORE this
			// not-yet-installed lease exists, so re-read the LIVE gate — finding
			// 3 residual: without this a verify that read allow_terminal=true at
			// gate time could leave a surviving writer past the disable). Any of
			// the three moving means the acquire raced an admin transition and
			// the just-installed lease must not survive.
			recheck := func() dashapi.ControlDenialReason {
				if standing.StandingTerminalGeneration() != gen {
					// AuthTransient, not Auth (2026-07-25): the secret VERIFIED
					// successfully microseconds ago — what moved is the server's
					// standing generation, i.e. this acquire raced an admin
					// mint/rotate/revoke/disable. The lease is still refused
					// (the TOCTOU close is unchanged), but blaming the device's
					// credential made it delete a secret that may well still be
					// valid; if it is genuinely dead the very next attempt is
					// judged and returns a real Auth denial.
					return dashapi.ControlDenialAuthTransient
				}
				if authz.Validate(req.DeviceSessionID) != nil {
					return dashapi.ControlDenialSessionInvalid
				}
				if !allowTerminal() {
					return dashapi.ControlDenialTerminalDisabled
				}
				return ""
			}
			return grant, recheck, err
		}
		// authz satisfies BOTH termlease.SessionValidator (Validate) and
		// termlease.CapabilityConsumer (ConsumeTerminalControl); pass it as both.
		// The single-use consume is atomic (no slow argon2), so its race window
		// is tiny — but a session revoke OR an allow_terminal→false flip can
		// still land between the gate read and the lease install. Re-validate
		// the session AND re-read the LIVE allow_terminal gate at install time
		// so neither a since-revoked/logged-out device nor a just-disabled
		// terminal toggle can leave a surviving writer here (finding 1 + finding
		// 3 residuals, uniform with the standing path). allow_terminal is read
		// LIVE at gate time below AND fenced again in the recheck.
		grant, err := termlease.Authorize(termlease.AuthorizeRequest{
			Handle:          req.Handle,
			DeviceSessionID: req.DeviceSessionID,
			CapabilityToken: req.CapabilityToken,
			Confirm:         req.Confirm,
			RemoteExposed:   req.RemoteExposed, // boundary-resolved provenance
			AllowTerminal:   allowTerminal(),   // LIVE allow_terminal (finding 3 residual)
		}, authz, policy, authz)
		recheck := func() dashapi.ControlDenialReason {
			if authz.Validate(req.DeviceSessionID) != nil {
				return dashapi.ControlDenialSessionInvalid
			}
			if !allowTerminal() {
				return dashapi.ControlDenialTerminalDisabled
			}
			return ""
		}
		return grant, recheck, err
	}
}

// wireRemoteExecuteTier connects the remote-execute authorizer to the launch
// manager once BOTH the [remote] substrate and the PTY launcher exist. It is a
// no-op — leaving AcquireWriterRemote fail-closed (ErrLaunchExecuteUnavailable) —
// when either is absent. Both `observer dashboard` and `observer start` call it
// with the identical assembly, so the two commands share one authorization path.
// browsableRoot is the ONE owner of "which directory does the Files/Git surface
// serve for this run" — consulted by BOTH the panel's token→root seam
// (projectRootResolver) and the Snapshot flag that enables its buttons
// (LaunchInfo.HasProjectRoot), so the button and the endpoint can never
// disagree.
//
// Two answers, in order:
//
//   - svc.ProjectRoot — the AUTHORIZED root, present only when the launch
//     requested a root the operator allow-listed under
//     [terminal.launch].allowed_project_roots. Reported Authorized=true.
//   - svc.SpawnDir — the FACTUAL directory the run's child executes in (the
//     daemon's own cwd for a default-cwd launch). Reported Authorized=false.
//
// Serving the second is the 2026-08-28 operator ruling, deliberately overruling
// the previous conservative gating that left Files/Git disabled for every
// default-cwd launch. The allow-list governs which roots a dashboard client may
// REQUEST at launch time; it was never a statement about which directory an
// already-running, owner-local terminal may browse. What widens is WHICH root is
// browsable, not who may browse: the panel handlers keep every per-request
// containment guard (fsview traversal/symlink re-verification, gitview argv
// hardening) and the remote [remote].allow_terminal_view gate unchanged.
//
// SSH runs are the one exclusion, and on shape rather than tool name: a
// termrun.KindSSH child's shell lives on ANOTHER machine, so its local spawn dir
// (the daemon's cwd, where the ssh client happens to run) is not the terminal's
// working directory at all. Browsing it would be a false claim, so the zero
// TerminalRoot is returned and the buttons stay honestly disabled.
//
// The zero value means "nothing browsable" and never carries a path.
func browsableRoot(svc *termsvc.Service, handle string) dashapi.TerminalRoot {
	if svc == nil {
		return dashapi.TerminalRoot{}
	}
	if root, ok := svc.ProjectRoot(handle); ok && root != "" {
		return dashapi.TerminalRoot{Path: root, Authorized: true}
	}
	if kind, _, ok := svc.KindForHandle(handle); ok && kind == termrun.KindSSH {
		return dashapi.TerminalRoot{}
	}
	spawnDir, ok := svc.SpawnDir(handle)
	if !ok || spawnDir == "" {
		return dashapi.TerminalRoot{}
	}
	return dashapi.TerminalRoot{Path: spawnDir}
}

// projectRootResolver adapts the launch manager's termsvc.Service into the
// dashboard's token→root seam (Arc A project panel). It reports known=false for
// an unknown OR exited token (RunIDForHandle tracks LIVE runs only — an exited
// handle lingers in byMeta for classification but is not browsable) and
// (Path="", known=true) for a live run with no local directory to browse.
// The directory decision itself belongs to browsableRoot. Returns nil when the
// manager isn't the concrete adapter (or has no service), which leaves the panel
// endpoints disabled (404).
func projectRootResolver(launchMgr dashapi.LaunchManager) func(string) (dashapi.TerminalRoot, bool) {
	a, ok := launchMgr.(*launchManagerAdapter)
	if !ok || a == nil || a.svc == nil {
		return nil
	}
	svc := a.svc
	return func(token string) (dashapi.TerminalRoot, bool) {
		if _, live := svc.RunIDForHandle(token); !live {
			return dashapi.TerminalRoot{}, false
		}
		return browsableRoot(svc, token), true
	}
}

// sessionResolver adapts the launch manager's termsvc.Service into the
// dashboard's token→session-link seam (Session Cockpit). It reports
// known=false for an unknown OR exited token (RunIDForHandle tracks LIVE runs
// only — same liveness posture as projectRootResolver). For a live run it
// carries the run identity (id + kind + tool) and, once the daemon has
// correlated the run, its observer session id + link confidence; a live-but-
// uncorrelated run returns known=true with an empty SessionID and 0 Confidence.
// Returns nil when the manager isn't the concrete adapter (or has no service),
// which leaves the cockpit endpoint disabled (404).
func sessionResolver(launchMgr dashapi.LaunchManager) func(string) (dashapi.TerminalSessionLink, bool) {
	a, ok := launchMgr.(*launchManagerAdapter)
	if !ok || a == nil || a.svc == nil {
		return nil
	}
	svc := a.svc
	return func(token string) (dashapi.TerminalSessionLink, bool) {
		// Single-lock resolve (F4): liveness + run identity + correlation are
		// read atomically, so a run ending mid-resolve can't yield known=true
		// with a deleted correlation. A miss on the session link inside is an
		// honest "live run, not correlated yet" — known=true, empty SessionID,
		// zero Confidence (correlation is scored + async).
		runID, kind, tool, sessionID, confidence, live := svc.ResolveHandleLink(token)
		if !live {
			return dashapi.TerminalSessionLink{}, false
		}
		return dashapi.TerminalSessionLink{
			RunID:      runID,
			Kind:       string(kind),
			Tool:       tool,
			SessionID:  sessionID,
			Confidence: confidence,
		}, true
	}
}

func wireRemoteExecuteTier(cfg config.Config, launchMgr dashapi.LaunchManager, remoteCtrl dashapi.RemoteController) {
	a, ok := launchMgr.(*launchManagerAdapter)
	if !ok || a == nil {
		return
	}
	authz, ok := remoteCtrl.(dashapi.TerminalControlAuthorizer)
	if !ok {
		return
	}
	// Read allow_terminal LIVE from the controller (finding 3 residual), not the
	// startup cfg snapshot: a dashboard allow_terminal→false / remote-disable
	// hot-swaps the controller's flag (ReloadAllowTerminal), so BOTH the
	// single-use and standing acquire paths immediately refuse without a restart.
	// remoteCtrl.AllowTerminal() returns the construction value until the first
	// hot-swap, so the initial behaviour is identical to the cfg snapshot.
	a.wireRemoteExecute(authz, remoteCtrl.AllowTerminal)
	// The takeover flag is a post-authorization policy input. Bind the manager to
	// the controller's live reader; the cfg fallback keeps additive fake
	// controllers deterministic. The manager invokes this source at Decide while
	// holding the session write fence.
	allowRemoteTakeover := func() bool { return cfg.Remote.AllowRemoteTerminalTakeover }
	if live, ok := remoteCtrl.(interface{ AllowRemoteTerminalTakeover() bool }); ok {
		allowRemoteTakeover = live.AllowRemoteTerminalTakeover
	}
	a.mgr.SetAllowRemoteTakeoverSource(allowRemoteTakeover)
}

// AcquireWriterRemote runs the single §4.δ authorization conjunction over the
// request-derived inputs (via the injected authorizer that owns the capability
// store + session validator + launch policy + live allow_terminal), mints the
// unforgeable WriterGrant, and acquires the remote writer lease. Until the
// remote-execute tier is wired (a nil authorizer), it fails closed.
func (a *launchManagerAdapter) AcquireWriterRemote(req dashapi.RemoteWriterRequest) (dashapi.LaunchWriter, error) {
	if a.remoteAuthz == nil {
		return nil, dashapi.NewControlDeniedError(dashapi.ControlDenialUnavailable, false, dashapi.ErrLaunchExecuteUnavailable)
	}
	grant, recheck, err := a.remoteAuthz(req)
	if err != nil {
		return nil, mapRemoteAcquireDenial(err, false)
	}
	l, err := a.mgr.AcquireWriterRemote(req.Handle, grant)
	if err != nil {
		return nil, mapRemoteAcquireDenial(err, !grant.Standing())
	}
	// Standing-path TOCTOU close (finding 1): the reusable-secret verify runs
	// OUTSIDE any lock (argon2 is slow by design), so a revoke/rotate can land
	// between the verify's snapshot and this install. Re-check the standing
	// generation NOW — after the lease exists, so the admin kill sweep and this
	// check overlap: either the kill sees the installed lease (and revokes it),
	// or the generation moved (and we tear it down here). No input can have
	// ridden the lease yet — it has not been returned to the bridge.
	if recheck != nil {
		if reason := recheck(); reason != "" {
			l.Release()
			return nil, dashapi.NewControlDeniedError(reason, !grant.Standing(), nil)
		}
	}
	return l, nil
}

func mapRemoteAcquireDenial(err error, capabilityConsumed bool) error {
	var typed *dashapi.ControlDeniedError
	if errors.As(err, &typed) {
		return err
	}
	reason := dashapi.ControlDenialUnavailable
	switch {
	case errors.Is(err, termlease.ErrCapabilityRejected):
		reason = dashapi.ControlDenialAuth
	case errors.Is(err, termlease.ErrStandingRevoked):
		// The standing secret has been revoked and not re-provisioned: nothing
		// exists at rest for the device's saved secret to match, now or ever
		// (a re-mint issues a different one). PERMANENT — the device should
		// clear it, exactly as for a judged rejection.
		reason = dashapi.ControlDenialAuthRevoked
	case errors.Is(err, termlease.ErrStandingUnavailable):
		// The standing leg refused without judging the secret AND the refusal
		// may lift on its own (standing access momentarily switched off with
		// the secret still at rest, or rate-limited) — deny, but never blame
		// the credential.
		reason = dashapi.ControlDenialAuthTransient
	case errors.Is(err, termlease.ErrTerminalDisabled):
		reason = dashapi.ControlDenialTerminalDisabled
	case errors.Is(err, termlease.ErrNoDeviceSession):
		reason = dashapi.ControlDenialSessionInvalid
	case errors.Is(err, termlease.ErrPolicyDenied), errors.Is(err, termlease.ErrNotRemoteExposed), errors.Is(err, termlease.ErrMissingField), errors.Is(err, termsession.ErrNoGrant), errors.Is(err, termsession.ErrSetupSessionLocalOnly):
		reason = dashapi.ControlDenialPolicyDenied
	case errors.Is(err, termsession.ErrHeldLocally):
		reason = dashapi.ControlDenialHeldLocally
	case errors.Is(err, termsession.ErrWriterHeld):
		reason = dashapi.ControlDenialHeldByRemote
	case errors.Is(err, termsession.ErrNotFound):
		reason = dashapi.ControlDenialNotFound
	}
	return dashapi.NewControlDeniedError(reason, capabilityConsumed, err)
}

// Close is the dashboard's Stop & close: the run's end records
// dashboard_stop before the PTY is closed (Windows 11 Pro run 4, N3).
func (a *launchManagerAdapter) Close(handle string) {
	a.svc.MarkEnding(handle, termrun.EndDashboardStop)
	a.mgr.Close(handle)
}

// EndReasonForExit is the end reason the exit frame names: the one the
// terminal service recorded or marked for handle's run, else what the exit
// code alone says (internal/termrun/endreason.go).
func (a *launchManagerAdapter) EndReasonForExit(handle string, code int) string {
	if r := a.svc.EndReasonForHandle(handle); r != "" {
		return r
	}
	return termrun.EndReasonForExit(code)
}

// RevokeAllRemoteWriters delegates to the PTY manager's remote-only global kill
// (leaving the owner-local loopback writer untouched) through the ONE
// termsession revocation funnel — the admin-transition seam the dashboard drives
// for remote disable / rotate / allow_terminal→false (§8.1 item 8).
func (a *launchManagerAdapter) RevokeAllRemoteWriters(reason string) int {
	return a.mgr.RevokeAllRemoteWriters(reason)
}

// RevokeRemoteWriterByHolder delegates to the manager's single-device kill,
// matching on the unified holder key (grant.Holder() = sha256(device-session)
// [:8]). Used by a device-session revoke. The parameter is the holder key, not a
// raw device fingerprint — it is already the hashed, truncated holder identity.
func (a *launchManagerAdapter) RevokeRemoteWriterByHolder(holderKey, reason string) bool {
	return a.mgr.RevokeRemoteWriterByHolder(holderKey, reason)
}

// SessionForRun delegates the run→correlated-session lookup to termsvc so the
// dashboard's /api/attach/sessions handler can key a handoff row by the FORKED
// session it is driving rather than the SOURCE session the spec stamped at
// spawn. Returns ("", false) when no correlation link exists yet — the caller
// fails open to an empty session id.
func (a *launchManagerAdapter) SessionForRun(runID string) (string, bool) {
	return a.svc.SessionForRun(runID)
}

func (a *launchManagerAdapter) Snapshot() []dashapi.LaunchInfo {
	live := a.mgr.Snapshot()
	// GC retained run classification (termsvc.byMeta) for handles the Manager no
	// longer tracks (reaped past ExitLinger). This is the Snapshot-enrichment
	// prune half of the F1 exit-linger fix: EndRunByHandle keeps byMeta alive so
	// the remote sensitivity gates stay honest through linger; this drops it once
	// the handle is truly gone. The Manager's Snapshot is the ONE live view, so
	// the adapter that already reads it is the one owner that prunes.
	liveHandles := make(map[string]struct{}, len(live))
	for _, s := range live {
		liveHandles[s.ID] = struct{}{}
	}
	a.svc.PruneEndedHandles(liveHandles)
	out := make([]dashapi.LaunchInfo, 0, len(live))
	for _, s := range live {
		info := dashapi.LaunchInfo{
			ID:           s.ID,
			Subcommand:   s.Subcommand,
			SessionID:    s.SessionID,
			CreatedAt:    s.CreatedAt,
			Attached:     s.Viewers > 0,
			Viewers:      s.Viewers,
			WriterHolder: s.WriterHolder,
			Setup:        s.Setup,
			Exited:       s.Exited,
			ExitCode:     s.ExitCode,
			// PTY geometry (Feature 2): carried straight from the manager snapshot.
			InitialRows: s.InitialRows,
			InitialCols: s.InitialCols,
			Rows:        s.Rows,
			Cols:        s.Cols,
		}
		// HasProjectRoot drives the dashboard's Files/Git panel button enablement
		// straight from the snapshot — the raw path is NOT carried on the wire
		// (LaunchInfo flows to remote viewers); only the gated panel endpoint
		// serves it. It reads the SAME browsableRoot decision the panel endpoint
		// resolves, so a default-cwd launch enables the buttons on its own working
		// directory (operator ruling 2026-08-28) and an SSH run leaves them off.
		if browsableRoot(a.svc, s.ID).Path != "" {
			info.HasProjectRoot = true
		}
		// B9 (plan §6): the "sandboxed" pill on the Terminals list/header,
		// read from the run's in-memory sandboxed flag (no DB column — G19).
		if sb, ok := a.svc.Sandboxed(s.ID); ok {
			info.Sandboxed = sb
		}
		if iso, ok := a.svc.Isolation(s.ID); ok && info.Sandboxed {
			info.Isolation = launchIsolationFor(iso)
			if runID, ok := a.svc.RunIDForHandle(s.ID); ok {
				relayPillHealth(info.Isolation, runID)
			}
		}
		if runID, ok := a.svc.RunIDForHandle(s.ID); ok {
			info.RunID = runID
			// An attach run carries no source session at spawn — it is
			// correlated to an observer session later via the OOB flow. Fill the
			// established correlation ONLY when the PTY spec supplied no session
			// id, so a handoff row's own SessionID is never clobbered.
			if info.SessionID == "" {
				if sid, ok := a.svc.SessionForRun(runID); ok {
					info.SessionID = sid
				}
			}
		}
		// Label the run Kind + Tool from the run identity the service minted at
		// spawn so the dashboard can gate "Jump in" on run SHAPE (attach) rather
		// than a tool name.
		if kind, tool, ok := a.svc.KindForHandle(s.ID); ok {
			info.Kind = string(kind)
			info.Tool = tool
		}
		out = append(out, info)
	}
	return out
}

// launchIsolationFor is the run pill's view of a run's G19 evidence; nil
// for a run that recorded no isolation class.
func launchIsolationFor(iso termrun.Isolation) *dashapi.LaunchIsolation {
	if iso.Class == "" || iso.Class == "none" {
		return nil
	}
	out := &dashapi.LaunchIsolation{
		Class: iso.Class, EgressTier: iso.EgressTier, CaptureLevel: iso.CaptureLevel,
		CaptureRule: iso.CaptureRule, Verification: iso.Verification,
	}
	if len(iso.Stack) > 0 {
		out.Backend = iso.Stack[0]
	}
	return out
}

// leaseAuditKind maps a termsession writer-lease transition to its typed
// remote_audit event kind (Phase-4 execute-tier audit lifecycle, plan §8.1).
// Table-driven so a new lease kind is one row, never a nested branch.
func leaseAuditKind(ev termsession.LeaseEvent) string {
	switch ev.Kind {
	case termsession.LeaseAcquired:
		return "terminal_writer_acquire"
	case termsession.LeaseReleased:
		return "terminal_writer_release"
	case termsession.LeaseRevoked:
		return "terminal_writer_revoke"
	case termsession.LeaseTakenOver:
		if ev.Actor != "" && ev.Actor != "local" {
			return "terminal_remote_takeover"
		}
		return "terminal_local_takeover"
	default:
		return "terminal_writer_" + string(ev.Kind)
	}
}

// leaseHolderPrincipal classifies a lease holder ("local" vs a remote device
// fingerprint) into a capability class for the audit principal column — never
// the raw identity.
func leaseHolderPrincipal(holder string) string {
	if holder == "" || holder == "local" {
		return "local"
	}
	return "remote"
}

// newLeaseAuditSink is the FUNC SEAM (CLAUDE.md #1/#2) bridging termsession's
// OnLeaseEvent tap to typed, node-local remote_audit rows through the ONE store
// seam (store.InsertRemoteAudit). termsession stays store-free: it emits only
// the content-free LeaseEvent; this cmd-side closure persists it. Metadata
// ONLY — the terminal handle, the holder fingerprint (already truncated by
// termlease, never the raw bearer), a coarse reason, and the transition kind;
// NEVER a capability, confirm, grant, terminal byte, command, or env. A nil DB
// yields a nil sink (auditing disabled). The insert is best-effort + bounded (a
// failed audit never affects a lease transition) and synchronous so persisted
// rows preserve transition order (remote_audit orders by autoincrement id).
func newLeaseAuditSink(database *sql.DB) func(termsession.LeaseEvent) {
	if database == nil {
		return nil
	}
	st := store.New(database)
	return func(ev termsession.LeaseEvent) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// A privileged SpecSetup PTY is LOCAL-ONLY for its whole lifecycle, but
		// remote_audit is a View-tier route paired remote devices can read. Its
		// opaque handle must therefore never land there (a remote viewer could
		// otherwise learn the handle + its lease-activity timing). Store an opaque
		// "setup:<label>" route instead — the fact of the setup op is legitimate
		// audit (row kept), only the handle leakage is closed, and the label (e.g.
		// "tailscale-login") carries MORE local-owner forensic value than the
		// ephemeral handle. Redacted AT EMIT, so it is uniform for every reader
		// (local + remote). FIX A(i), second adversarial review 2026-07-16.
		route := ev.Handle // the opaque terminal session handle
		if ev.Setup {
			route = "setup"
			if ev.Label != "" {
				route = "setup:" + ev.Label
			}
		}
		principalID := ev.Holder
		detail := ev.Reason
		if ev.Kind == termsession.LeaseTakenOver && ev.Actor != "" {
			principalID = ev.Actor
			detail = "actor " + ev.Actor + " superseded " + ev.Holder + ": " + ev.Reason
		}
		_ = st.InsertRemoteAudit(ctx, store.RemoteAuditEvent{
			TS:        ev.At,
			Kind:      leaseAuditKind(ev),
			SessionID: principalID, // takeover actor, otherwise holder; never the raw id
			Principal: leaseHolderPrincipal(principalID),
			Route:     route,
			Decision:  "ok",
			Detail:    detail, // coarse, non-sensitive transition direction + reason
		})
	}
}

// credOf returns the credential the remote writer-acquire request carries in
// its capability field — a single-use capability token OR (opt-in §B) a
// standing terminal-control secret. The acquire boundary branches on the
// credential SHAPE (remoteauth.IsStandingSecret), so both ride one field.
func credOf(req dashapi.RemoteWriterRequest) string { return req.CapabilityToken }

// setCred puts the credential onto a termlease authorize request's capability
// field (the standing-secret path; AuthorizeStanding reads it as the secret).
func setCred(r *termlease.AuthorizeRequest, cred string) { r.CapabilityToken = cred }

// mapLaunchErr translates termsession's sentinels onto the dashboard's so the
// HTTP handler can pick an honest status without importing termsession.
func mapLaunchErr(err error) error {
	switch {
	case errors.Is(err, termsession.ErrTooManySessions):
		return dashapi.ErrLaunchTooMany
	case errors.Is(err, termsession.ErrPlatformUnsupported):
		return dashapi.ErrLaunchUnsupported
	case errors.Is(err, termsession.ErrSetupInFlight):
		return dashapi.ErrLaunchSetupInFlight
	default:
		return err
	}
}

// mapFreshErr translates the termsvc fresh-launch authorization sentinels (and
// the underlying termsession spawn errors) onto the dashboard's.
// mapSSHErr maps the termsvc SSH sentinels onto the dashboard's, falling
// through to the shared spawn-error mapping (too-many-sessions, unsupported
// platform) for everything else.
func mapSSHErr(err error) error {
	switch {
	case errors.Is(err, termsvc.ErrSSHLaunchDisabled):
		return dashapi.ErrLaunchSSHDisabled
	case errors.Is(err, termsvc.ErrSSHProfileUnknown):
		return dashapi.ErrLaunchSSHProfileUnknown
	case errors.Is(err, termsvc.ErrSSHProfileInvalid):
		return dashapi.ErrLaunchSSHProfileInvalid
	default:
		return mapLaunchErr(err)
	}
}

func mapFreshErr(err error) error {
	switch {
	case errors.Is(err, termsvc.ErrFreshLaunchDisabled):
		return dashapi.ErrLaunchFreshDisabled
	case errors.Is(err, termsvc.ErrToolNotAllowed):
		return dashapi.ErrLaunchToolNotAllowed
	case errors.Is(err, termsvc.ErrShellLaunchDisabled):
		return dashapi.ErrLaunchShellDisabled
	case errors.Is(err, termsvc.ErrProjectRootDenied):
		return dashapi.ErrLaunchProjectRootDenied
	default:
		return mapLaunchErr(err)
	}
}
