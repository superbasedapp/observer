package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/remoteauth"
	"github.com/marmutapp/superbased-observer/internal/sshforward"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termlease"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
	"github.com/marmutapp/superbased-observer/internal/toolresolve/host"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// launch_dashboard.go wires the dashboard's embedded web-terminal launch
// seam (dashboard.LaunchManager) to the terminal application service
// (internal/termsvc) over internal/termsession. termsvc owns the run identity,
// the fresh-launch authorization, and the correlation model; termsession owns
// only the PTY/viewer lifecycle. The dashboard never imports either — this
// adapter is the single boundary that translates the dashboard's server-derived
// specs into termsvc calls and maps errors onto the dashboard's sentinels
// (the same pattern as handoffRunner behind BuildHandoff).

// launchManagerAdapter bridges the terminal service + PTY manager to
// dashboard.LaunchManager.
type launchManagerAdapter struct {
	svc *termsvc.Service
	mgr *termsession.Manager
	// remoteAuthz runs the §4.δ authorization conjunction and mints the
	// unforgeable WriterGrant for a remote writer acquire. Nil until the
	// remote-execute tier is wired (Phase 4 §4.γ/§4.δ) — a nil authorizer fails
	// AcquireWriterRemote closed. The returned recheck func (nil for the
	// single-use capability path) is the standing-path TOCTOU close: it is run
	// AFTER the lease install and must return true for the lease to survive —
	// false means the standing secret was revoked/rotated while the (argon2)
	// verify was in flight, so the just-installed lease is torn down.
	remoteAuthz func(dashboard.RemoteWriterRequest) (termlease.WriterGrant, func() dashboard.ControlDenialReason, error)
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
	instances *sshforward.Manager
	// guard is the process-wide egress-policy Guard (P7 gateway-arc item 3:
	// the sandbox_enforce lane). Nil when guarding is disabled/no DB — every
	// consumer must nil-check via guard.Mode(), which itself has no
	// nil-receiver guard.
	guard *guard.Guard
	// sandboxProber backs the same B9 probe the dashboard's own
	// /api/terminal/sandbox endpoint uses, reused here so CreateFresh's
	// auto-upgrade decision and the dashboard's own availability display never
	// disagree. Nil when [terminal.sandbox] is disabled.
	sandboxProber dashboard.SandboxProber
	// nf is the node.features policy handle (P7 gateway-arc item 4's
	// org_disallow honor path). Nil-safe: a nil nf allows every tool.
	nf *nodeFeaturesHandle
}

// newSpawnAuditSink builds the metadata-only spawn-audit closure (F4,
// session-attach design §3.5) that persists one remote_audit row per terminal
// spawn through the ONE store seam (store.InsertRemoteAudit). kind is a
// dashboard.SpawnAuditKind value resolved once at wiring; an empty kind or a nil
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
		AllowFresh:          tc.Enabled && tc.Launch.AllowFreshAgent,
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

// --- dashboard.LaunchManager implementation ---

func (a *launchManagerAdapter) Create(spec dashboard.LaunchSpec) (string, error) {
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

func (a *launchManagerAdapter) CreateFresh(spec dashboard.FreshLaunchSpec) (string, error) {
	// P7 gateway-arc item 4: org_disallow honor path. Checked before termsvc's
	// own AllowedTools/AllowedProjectRoots authorization, so a tool the org
	// policy disallows never reaches the launcher at all. a.nf is nil-safe —
	// no org policy (or no tools stanza) allows every tool.
	if allowed, _ := a.nf.ToolAllowed(spec.Tool); !allowed {
		return "", dashboard.ErrLaunchToolNotAllowed
	}
	// P7 gateway-arc item 3: sandbox-enforce lane. When the process-wide
	// guard is in enforce mode and the integration registry's EFFECTIVE
	// enforcement channel for this tool (accounting for sandbox availability
	// on THIS platform, via the same prober the dashboard's own
	// /api/terminal/sandbox endpoint consults) is sandbox_enforce,
	// auto-upgrade an unsandboxed request rather than silently letting a
	// hookless tool launch unguarded. Never downgrades an already-sandboxed
	// request; never forces a sandbox that isn't actually available —
	// EffectiveEnforcement degrades to recorded_acceptance in that case, so
	// the request proceeds unsandboxed honestly rather than failing closed
	// on a platform that can't sandbox at all.
	if a.guard != nil && a.guard.Mode() == policy.ModeEnforce && !spec.Sandbox {
		if c, ok := integration.For(spec.Tool); ok {
			sandboxAvailable := false
			if a.sandboxProber != nil {
				sandboxAvailable = a.sandboxProber.ProbeSandbox(context.Background()).Available
			}
			if c.EffectiveEnforcement(sandboxAvailable) == integration.EnforceSandbox {
				spec.Sandbox = true
			}
		}
	}
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
func (a *launchManagerAdapter) CreateSSH(spec dashboard.SSHLaunchSpec) (string, error) {
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
func (a *launchManagerAdapter) SSHProfiles() (bool, []dashboard.SSHProfileInfo) {
	enabled, profiles := a.svc.SSHProfileList()
	if len(profiles) == 0 {
		return enabled, nil
	}
	out := make([]dashboard.SSHProfileInfo, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, dashboard.SSHProfileInfo{
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
func (a *launchManagerAdapter) Instances() (bool, []dashboard.InstanceInfo) {
	if a == nil {
		return false, nil
	}
	rows := a.instances.List()
	if len(rows) == 0 {
		return a.instances.Enabled(), nil
	}
	out := make([]dashboard.InstanceInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, instanceInfo(r))
	}
	return a.instances.Enabled(), out
}

// ConnectInstance opens (or re-uses) the local port forward for a profile.
func (a *launchManagerAdapter) ConnectInstance(name string) (dashboard.InstanceInfo, error) {
	if a == nil || a.instances == nil {
		return dashboard.InstanceInfo{}, dashboard.ErrInstancesDisabled
	}
	inst, err := a.instances.Connect(name)
	if err != nil {
		return dashboard.InstanceInfo{}, mapInstanceErr(err)
	}
	return instanceInfo(inst), nil
}

// DisconnectInstance closes the forward and returns the resulting row. The
// post-disconnect snapshot is read back rather than synthesized so the UI is
// updated from the manager's own state, not from this adapter's assumption
// about it.
func (a *launchManagerAdapter) DisconnectInstance(name string) (dashboard.InstanceInfo, error) {
	if a == nil || a.instances == nil {
		return dashboard.InstanceInfo{}, dashboard.ErrInstancesDisabled
	}
	if err := a.instances.Disconnect(name); err != nil {
		return dashboard.InstanceInfo{}, mapInstanceErr(err)
	}
	inst, ok := a.instances.Get(name)
	if !ok {
		return dashboard.InstanceInfo{}, dashboard.ErrInstanceUnknown
	}
	return instanceInfo(inst), nil
}

// TestInstance runs the bounded, non-interactive connectivity probe
// (sshforward.Manager.Test) for a profile and projects the result onto the
// dashboard wire shape. Like Connect/Disconnect it re-validates the profile
// first (inside Manager.Test), so a request can never probe a machine the
// operator did not write down; unlike them it opens no forward and leaves no
// live state, so it needs no post-call snapshot read-back.
func (a *launchManagerAdapter) TestInstance(name string) (dashboard.InstanceTestResult, error) {
	if a == nil || a.instances == nil {
		return dashboard.InstanceTestResult{}, dashboard.ErrInstancesDisabled
	}
	result, err := a.instances.Test(name)
	if err != nil {
		return dashboard.InstanceTestResult{}, mapInstanceErr(err)
	}
	return instanceTestResult(result), nil
}

// instanceInfo projects one manager row onto the dashboard wire shape.
func instanceInfo(r sshforward.Instance) dashboard.InstanceInfo {
	return dashboard.InstanceInfo{
		Name:          r.Name,
		Label:         r.Label,
		Target:        r.Target,
		DashboardPort: r.DashboardPort,
		HasKey:        r.HasKey,
		KeyHint:       r.KeyHint,
		Jump:          r.Jump,
		State:         string(r.State),
		LocalPort:     r.LocalPort,
		URL:           r.URL,
		Error:         r.Error,
	}
}

// instanceTestResult projects sshforward's TestResult onto the dashboard wire
// shape (milliseconds rather than a time.Duration, so the JSON stays a plain
// number).
func instanceTestResult(r sshforward.TestResult) dashboard.InstanceTestResult {
	return dashboard.InstanceTestResult{
		KnownHostsChecked: r.KnownHostsChecked,
		KnownHostsOK:      r.KnownHostsOK,
		AuthOK:            r.AuthOK,
		LatencyMS:         r.Latency.Milliseconds(),
		Stderr:            r.Stderr,
	}
}

// mapInstanceErr maps sshforward's sentinels onto the dashboard's, keeping the
// manager's own message (which is where the actionable known_hosts guidance
// lives) by wrapping rather than replacing.
func mapInstanceErr(err error) error {
	switch {
	case errors.Is(err, sshforward.ErrDisabled):
		return dashboard.ErrInstancesDisabled
	case errors.Is(err, sshforward.ErrUnknownProfile):
		return fmt.Errorf("%w: %w", dashboard.ErrInstanceUnknown, err)
	case errors.Is(err, sshforward.ErrInvalidProfile):
		return fmt.Errorf("%w: %w", dashboard.ErrInstanceInvalid, err)
	case errors.Is(err, sshforward.ErrHostKeyUnknown):
		return fmt.Errorf("%w: %w", dashboard.ErrInstanceHostKeyUnknown, err)
	case errors.Is(err, sshforward.ErrForwardFailed):
		return fmt.Errorf("%w: %w", dashboard.ErrInstanceForwardFailed, err)
	default:
		return err
	}
}

// CreateResume spawns a NATIVE resume of a closed session (session-attach
// design Phase 3) through the terminal application service, which enforces the
// SAME fresh-launch policy as CreateFresh (a dashboard-initiated Execute
// respects [terminal.launch] — unlike the owner-only CLI attach socket). It
// returns the opaque handle AND the durable run id; errors map onto the
// dashboard sentinels through mapFreshErr (fresh-disabled / tool-not-allowed /
// project-root-denied + the termsession spawn errors).
func (a *launchManagerAdapter) CreateResume(spec dashboard.ResumeLaunchSpec) (string, string, error) {
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
func (a *launchManagerAdapter) CreateSetup(spec dashboard.SetupSpec) (string, error) {
	handle, err := a.mgr.Create(termsession.Spec{
		Kind:       termsession.SpecSetup,
		SetupArgv:  spec.Argv,
		SetupLabel: spec.Label, // keys the setup single-flight (one PTY per kind)
		Env:        setupChildEnvFor(setupProgram(spec.Argv)),
		Rows:       spec.Rows,
		Cols:       spec.Cols,
	})
	if err != nil {
		return "", mapLaunchErr(err)
	}
	return handle, nil
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

func (a *launchManagerAdapter) Subscribe(handle string) (dashboard.LaunchSubscription, error) {
	sub, err := a.mgr.Subscribe(handle)
	if err != nil {
		return nil, err
	}
	return sub, nil // *termsession.Subscription satisfies dashboard.LaunchSubscription
}

// SubscribeRemote is the remote-principal viewer path: it refuses a SpecSetup
// (privileged, local-only) session at the manager seam so a paired remote device
// can never READ a setup PTY's output (a typed sudo password / login URL).
func (a *launchManagerAdapter) SubscribeRemote(handle string) (dashboard.LaunchSubscription, error) {
	sub, err := a.mgr.SubscribeRemote(handle)
	if err != nil {
		return nil, err
	}
	return sub, nil
}

// IsSetupSession reports whether a handle is a SpecSetup (privileged, local-only)
// session — the dashboard redacts these from remote snapshots and refuses their
// remote termination.
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

func (a *launchManagerAdapter) Unsubscribe(sub dashboard.LaunchSubscription) {
	if ts, ok := sub.(*termsession.Subscription); ok {
		a.mgr.Unsubscribe(ts)
	}
}

func (a *launchManagerAdapter) AcquireWriterLocal(handle string) (dashboard.LaunchWriter, error) {
	l, err := a.mgr.AcquireWriterLocal(handle)
	if err != nil {
		return nil, err
	}
	return l, nil // *termsession.WriterLease satisfies dashboard.LaunchWriter
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
func (a *launchManagerAdapter) wireRemoteExecute(authz dashboard.TerminalControlAuthorizer, allowTerminal func() bool) {
	policy := termsvcLaunchPolicy{svc: a.svc}
	a.remoteAuthz = func(req dashboard.RemoteWriterRequest) (termlease.WriterGrant, func() dashboard.ControlDenialReason, error) {
		// A standing terminal-control secret (opt-in §B) rides the SAME
		// acquire-writer cap field, distinguished by its collision-free prefix.
		// Route it to the AuthorizeStanding leg — the IDENTICAL §4.δ conjunction
		// with a reusable-standing-secret verify replacing the single-use
		// capability consume. This is a boundary branch on CREDENTIAL SHAPE, not
		// a second websocket path (CLAUDE.md #3).
		if remoteauth.IsStandingSecret(credOf(req)) {
			standing, ok := authz.(dashboard.StandingTerminalVerifier)
			if !ok {
				return termlease.WriterGrant{}, nil, dashboard.NewControlDeniedError(
					dashboard.ControlDenialUnavailable, false, dashboard.ErrLaunchExecuteUnavailable,
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
			recheck := func() dashboard.ControlDenialReason {
				if standing.StandingTerminalGeneration() != gen {
					// AuthTransient, not Auth (2026-07-25): the secret VERIFIED
					// successfully microseconds ago — what moved is the server's
					// standing generation, i.e. this acquire raced an admin
					// mint/rotate/revoke/disable. The lease is still refused
					// (the TOCTOU close is unchanged), but blaming the device's
					// credential made it delete a secret that may well still be
					// valid; if it is genuinely dead the very next attempt is
					// judged and returns a real Auth denial.
					return dashboard.ControlDenialAuthTransient
				}
				if authz.Validate(req.DeviceSessionID) != nil {
					return dashboard.ControlDenialSessionInvalid
				}
				if !allowTerminal() {
					return dashboard.ControlDenialTerminalDisabled
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
		recheck := func() dashboard.ControlDenialReason {
			if authz.Validate(req.DeviceSessionID) != nil {
				return dashboard.ControlDenialSessionInvalid
			}
			if !allowTerminal() {
				return dashboard.ControlDenialTerminalDisabled
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
func browsableRoot(svc *termsvc.Service, handle string) dashboard.TerminalRoot {
	if svc == nil {
		return dashboard.TerminalRoot{}
	}
	if root, ok := svc.ProjectRoot(handle); ok && root != "" {
		return dashboard.TerminalRoot{Path: root, Authorized: true}
	}
	if kind, _, ok := svc.KindForHandle(handle); ok && kind == termrun.KindSSH {
		return dashboard.TerminalRoot{}
	}
	spawnDir, ok := svc.SpawnDir(handle)
	if !ok || spawnDir == "" {
		return dashboard.TerminalRoot{}
	}
	return dashboard.TerminalRoot{Path: spawnDir}
}

// projectRootResolver adapts the launch manager's termsvc.Service into the
// dashboard's token→root seam (Arc A project panel). It reports known=false for
// an unknown OR exited token (RunIDForHandle tracks LIVE runs only — an exited
// handle lingers in byMeta for classification but is not browsable) and
// (Path="", known=true) for a live run with no local directory to browse.
// The directory decision itself belongs to browsableRoot. Returns nil when the
// manager isn't the concrete adapter (or has no service), which leaves the panel
// endpoints disabled (404).
func projectRootResolver(launchMgr dashboard.LaunchManager) func(string) (dashboard.TerminalRoot, bool) {
	a, ok := launchMgr.(*launchManagerAdapter)
	if !ok || a == nil || a.svc == nil {
		return nil
	}
	svc := a.svc
	return func(token string) (dashboard.TerminalRoot, bool) {
		if _, live := svc.RunIDForHandle(token); !live {
			return dashboard.TerminalRoot{}, false
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
func sessionResolver(launchMgr dashboard.LaunchManager) func(string) (dashboard.TerminalSessionLink, bool) {
	a, ok := launchMgr.(*launchManagerAdapter)
	if !ok || a == nil || a.svc == nil {
		return nil
	}
	svc := a.svc
	return func(token string) (dashboard.TerminalSessionLink, bool) {
		// Single-lock resolve (F4): liveness + run identity + correlation are
		// read atomically, so a run ending mid-resolve can't yield known=true
		// with a deleted correlation. A miss on the session link inside is an
		// honest "live run, not correlated yet" — known=true, empty SessionID,
		// zero Confidence (correlation is scored + async).
		runID, kind, tool, sessionID, confidence, live := svc.ResolveHandleLink(token)
		if !live {
			return dashboard.TerminalSessionLink{}, false
		}
		return dashboard.TerminalSessionLink{
			RunID:      runID,
			Kind:       string(kind),
			Tool:       tool,
			SessionID:  sessionID,
			Confidence: confidence,
		}, true
	}
}

func wireRemoteExecuteTier(cfg config.Config, launchMgr dashboard.LaunchManager, remoteCtrl dashboard.RemoteController) {
	a, ok := launchMgr.(*launchManagerAdapter)
	if !ok || a == nil {
		return
	}
	authz, ok := remoteCtrl.(dashboard.TerminalControlAuthorizer)
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
func (a *launchManagerAdapter) AcquireWriterRemote(req dashboard.RemoteWriterRequest) (dashboard.LaunchWriter, error) {
	if a.remoteAuthz == nil {
		return nil, dashboard.NewControlDeniedError(dashboard.ControlDenialUnavailable, false, dashboard.ErrLaunchExecuteUnavailable)
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
			return nil, dashboard.NewControlDeniedError(reason, !grant.Standing(), nil)
		}
	}
	return l, nil
}

func mapRemoteAcquireDenial(err error, capabilityConsumed bool) error {
	var typed *dashboard.ControlDeniedError
	if errors.As(err, &typed) {
		return err
	}
	reason := dashboard.ControlDenialUnavailable
	switch {
	case errors.Is(err, termlease.ErrCapabilityRejected):
		reason = dashboard.ControlDenialAuth
	case errors.Is(err, termlease.ErrStandingRevoked):
		// The standing secret has been revoked and not re-provisioned: nothing
		// exists at rest for the device's saved secret to match, now or ever
		// (a re-mint issues a different one). PERMANENT — the device should
		// clear it, exactly as for a judged rejection.
		reason = dashboard.ControlDenialAuthRevoked
	case errors.Is(err, termlease.ErrStandingUnavailable):
		// The standing leg refused without judging the secret AND the refusal
		// may lift on its own (standing access momentarily switched off with
		// the secret still at rest, or rate-limited) — deny, but never blame
		// the credential.
		reason = dashboard.ControlDenialAuthTransient
	case errors.Is(err, termlease.ErrTerminalDisabled):
		reason = dashboard.ControlDenialTerminalDisabled
	case errors.Is(err, termlease.ErrNoDeviceSession):
		reason = dashboard.ControlDenialSessionInvalid
	case errors.Is(err, termlease.ErrPolicyDenied), errors.Is(err, termlease.ErrNotRemoteExposed), errors.Is(err, termlease.ErrMissingField), errors.Is(err, termsession.ErrNoGrant), errors.Is(err, termsession.ErrSetupSessionLocalOnly):
		reason = dashboard.ControlDenialPolicyDenied
	case errors.Is(err, termsession.ErrHeldLocally):
		reason = dashboard.ControlDenialHeldLocally
	case errors.Is(err, termsession.ErrWriterHeld):
		reason = dashboard.ControlDenialHeldByRemote
	case errors.Is(err, termsession.ErrNotFound):
		reason = dashboard.ControlDenialNotFound
	}
	return dashboard.NewControlDeniedError(reason, capabilityConsumed, err)
}

func (a *launchManagerAdapter) Close(handle string) { a.mgr.Close(handle) }

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

func (a *launchManagerAdapter) Snapshot() []dashboard.LaunchInfo {
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
	out := make([]dashboard.LaunchInfo, 0, len(live))
	for _, s := range live {
		info := dashboard.LaunchInfo{
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

// dashResolveEnvTTL bounds how long the dashboard reuses a captured
// toolresolve.Env before rebuilding it. A short window (not a forever-memoized
// value) is what keeps the "a fresh install becomes visible in a daemon-side
// preflight without a restart" story honest (F7): a rebuild is not free — the
// crossmount home walk, a login-shell PATH capture bounded at 3s PER ATTEMPT
// (bash/zsh try `-lic` first and fall back to `-lc`, so up to two), and the
// lazy `npm prefix -g` probe bounded at a further 3s on the first Resolve that
// reaches it — so per-call rebuilds would be wasteful, but a process-lifetime
// memo would pin the PATH snapshot taken at first launch forever. Each probe is
// memoized ON the Env, so those costs are paid once per rebuild, not per tool.
var dashResolveEnvTTL = 30 * time.Second

var (
	dashResolveEnvMu   sync.Mutex
	dashResolveEnvVal  toolresolve.Env
	dashResolveEnvAt   time.Time
	dashResolveEnvHave bool
	// dashResolveEnvNow + dashResolveEnvBuild are package-private seams a test
	// substitutes to drive TTL expiry deterministically (restore in a defer);
	// production keeps the real clock and the real host env capture.
	dashResolveEnvNow   = time.Now
	dashResolveEnvBuild = func() toolresolve.Env { return host.NewEnv(host.Options{}) }
)

// dashResolveEnv returns the toolresolve.Env driving the dashboard's tool-
// resolution seams (tool-binary-resolution arc §5), rebuilding it via
// host.NewEnv when the cached value is older than dashResolveEnvTTL so a
// daemon-side preflight reflects a freshly installed binary without a restart
// (F7). Concurrency-safe; the rebuild happens under the lock so a burst of
// preflights past the TTL rebuilds exactly once.
func dashResolveEnv() toolresolve.Env {
	dashResolveEnvMu.Lock()
	defer dashResolveEnvMu.Unlock()
	now := dashResolveEnvNow()
	if !dashResolveEnvHave || now.Sub(dashResolveEnvAt) >= dashResolveEnvTTL {
		dashResolveEnvVal = dashResolveEnvBuild()
		dashResolveEnvAt = now
		dashResolveEnvHave = true
	}
	return dashResolveEnvVal
}

// installOSForGOOS maps the daemon GOOS to an integration.InstallHint.OS token
// ("linux" | "darwin" | "windows"), the same convention toolresolve uses to
// filter hints. It is the ONE place the cmd-side install seam picks the OS a
// grounded hint must match.
func installOSForGOOS(goos string) string {
	switch goos {
	case "windows":
		return "windows"
	case "darwin":
		return "darwin"
	default:
		return "linux"
	}
}

// toolPreflightSeam builds the dashboard.Options.ToolPreflight closure: it
// resolves a launchable tool NAME to a dashboard.ToolPreflight verdict via the
// SAME ladder the actual launcher (cmd/observer/launch.go resolveToolBin)
// honors, so a preflight never diverges from the launch it predicts (F1). It
// reports ok=false for an unknown tool, a tool that is not
// integration.TerminalLaunchable (no grounded LaunchSpec, or a deprecated /
// dead product the harness lifecycle policy stops advertising), or one with no
// grounded Binary spec (the honest floor the endpoint turns into a 400).
//
// Ladder, mirroring resolveToolBin (the --<tool>-path FLAG has no dashboard
// equivalent, so only the config override is mirrored):
//
//  1. [launch.tools.<tool>].path config override — what the launcher checks
//     BEFORE the resolution ladder. Present + stats as a file ⇒ verdict "ok"
//     with Bin=that path and a note that it is configured; present + missing
//     (or a dir) ⇒ verdict "not_found" with a note NAMING the stale config key
//     (never a silent fall-through to the ladder — the launch would fail AT the
//     override, so preflighting past it would lie). A config that fails to load
//     falls open to the ladder (a broken config never blocks a preflight).
//  2. the pure internal/toolresolve ladder over the registry Binary row.
//
// InstallCommand is the same preferred + permission-safe plan the install
// endpoint will run: an exact-OS official channel wins over a generic one, and
// a Unix npm-global fallback is redirected to the user's ~/.local prefix.
// CanInstall is true only when such a plan exists AND the live allow_install
// kill-switch is on. The argv NEVER crosses this seam.
func toolPreflightSeam(configPath string, allowInstall func() bool) func(string) (dashboard.ToolPreflight, bool) {
	return func(tool string) (dashboard.ToolPreflight, bool) {
		ic, ok := integration.For(tool)
		if !ok || !integration.TerminalLaunchable(ic) || ic.Binary == nil {
			// ONE lookup ladder (T2): an id that is not a terminal-launchable
			// tool may still be an ADVERTISED GUI launch row. The dashboard
			// handler stays name-free — it asks this seam and renders whatever
			// comes back — so the decision about which registry the id belongs
			// to lives here, in one place, and never in an HTTP handler.
			return guiPreflight(tool, configPath, allowInstall)
		}
		// Step 1: config override parity with resolveToolBin. Fail open on a
		// config load error so a broken config never blocks the ladder.
		if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil {
			if tc, ok := cfg.Launch.Tools[tool]; ok && tc.Path != "" {
				key := fmt.Sprintf("[launch.tools.%s].path", tool)
				if fi, statErr := os.Stat(tc.Path); statErr != nil || fi.IsDir() {
					return dashboard.ToolPreflight{
						Tool:    tool,
						Verdict: string(toolresolve.VerdictNotFound),
						Notes: []string{fmt.Sprintf(
							"%s = %q is set but no binary is there — fix the path or remove the entry",
							key, tc.Path,
						)},
					}, true
				}
				return dashboard.ToolPreflight{
					Tool:    tool,
					Verdict: string(toolresolve.VerdictOK),
					Bin:     tc.Path,
					Notes:   []string{fmt.Sprintf("configured via %s", key)},
				}, true
			}
		}
		// Step 2: registry-driven resolution ladder over the Binary row.
		r := toolresolve.Resolve(*ic.Binary, dashResolveEnv())
		pf := dashboard.ToolPreflight{
			Tool:    tool,
			Verdict: string(r.Verdict),
			Bin:     r.Bin,
			Notes:   r.Notes,
		}
		if plan, ok := dashboardInstallPlanFor(ic.Binary.Installs, runtime.GOOS, dashboardInstallHome(), dashInstallArgv0); ok {
			pf.InstallCommand = plan.Display
			pf.CanInstall = allowInstall != nil && allowInstall()
			if plan.Note != "" {
				pf.Notes = append(pf.Notes, plan.Note)
			}
		} else {
			// No guided plan for this OS — say WHY rather than letting the
			// dialog dead-end on "X is not installed." with no next step
			// (DI-03). The reason is registry-grounded when the row carries
			// one; otherwise it is the shared vendor-docs sentence.
			pf.InstallNote = installNoteFor(ic.Binary, runtime.GOOS)
		}
		return pf, true
	}
}

// installNoteFor renders the honest reason a launchable tool has no guided
// install plan on this OS (audit DI-03). It is pure — no filesystem, no
// registry lookup — so the sentence the dialog shows is table-testable.
//
// Two grounded carriers feed it, in the order the operator needs them:
//
//   - Binary.WindowsNote, when running on Windows and the row has no Windows
//     binary spelling at all: that is the deeper "there is no Windows build"
//     fact, and stating it first stops the operator hunting for an installer
//     that cannot exist.
//   - Binary.InstallNote, the per-row reason no InstallHint covers this OS.
//
// When neither is set the shared vendor-docs sentence is the floor — never a
// fabricated channel, and never an empty string (the dialog would render
// nothing, which is the DI-03 dead end itself).
func installNoteFor(spec *integration.BinaryResolveSpec, goos string) string {
	if spec == nil {
		return toolresolve.NoGroundedInstallMsg
	}
	var parts []string
	if goos == "windows" && len(spec.Names.Windows) == 0 {
		if note := strings.TrimSpace(spec.WindowsNote); note != "" {
			parts = append(parts, note)
		}
	}
	if note := strings.TrimSpace(spec.InstallNote); note != "" {
		parts = append(parts, note)
	} else {
		parts = append(parts, toolresolve.NoGroundedInstallMsg)
	}
	return strings.Join(parts, " — ")
}

// toolInstallHintSeam builds the dashboard.Options.ToolInstallHint closure: it
// returns the SERVER-SIDE install argv + display for a tool NAME, sourced ONLY
// from the compile-time registry (tool-binary-resolution arc §Security — the
// request contributes only the map key, so the argv-injection surface is zero).
// Exact-OS hints win over generic hints. Unix npm-global hints are made
// permission-safe by installing beneath ~/.local instead of npm's frequently
// root-owned /usr/lib/node_modules prefix. A tool with no usable grounded hint
// yields ok=false (the endpoint's 400), as does a row the harness lifecycle
// policy no longer advertises (Capability.Advertised is false) — guided
// install must never push an operator into a sunset or dead product. It is
// deliberately gated on Advertised, not TerminalLaunchable: installing is not
// launching (operator decision 2026-09-02), so a non-launchable but active row
// keeps its install hint.
func toolInstallHintSeam() func(string) ([]string, string, bool) {
	return func(tool string) ([]string, string, bool) {
		installs, ok := installHintsFor(tool)
		if !ok {
			return nil, "", false
		}
		plan, ok := dashboardInstallPlanFor(installs, runtime.GOOS, dashboardInstallHome(), dashInstallArgv0)
		if !ok {
			return nil, "", false
		}
		return plan.Argv, plan.Display, true
	}
}

// installHintsFor is the ONE lookup ladder behind both install-facing seams: a
// registry ADAPTER row first, then a GUI launch row. It returns the grounded
// install hints for whichever carrier owns the id, gated on Advertised() in
// both cases — guided install must never push an operator into a sunset or dead
// product, nor into an UNVERIFIED GUI row whose executable was never grounded.
//
// Both rungs gate on Advertised() rather than launchability, because installing
// is not launching (operator decision 2026-09-02, pinned by
// TestTerminalInstallIsNotGatedByAllowedTools): a non-launchable but active row
// keeps its install hint.
func installHintsFor(id string) ([]integration.InstallHint, bool) {
	if ic, ok := integration.For(id); ok && ic.Advertised() && ic.Binary != nil {
		return ic.Binary.Installs, true
	}
	if g, ok := integration.GUILaunchFor(id); ok && g.Advertised() {
		return g.Spec.Binary.Installs, true
	}
	return nil, false
}

// guiPreflight is the GUI rung of toolPreflightSeam: it resolves an ADVERTISED
// GUI launch row through toolresolve.ResolveGUI and composes the SAME
// install-plan / install-note surface a terminal tool gets, so the dialog
// renders one shape for both kinds.
//
// Two GUI-specific honesty rules:
//
//   - A foreign_only verdict on a WSL daemon is reported as "ok_off_path", not
//     as the terminal path's dead end: the daemon CAN exec a Windows .exe
//     through interop, so the app is launchable — with the note that the
//     routing environment will not cross the boundary. The verdict is derived
//     through toolresolve.ForeignInteropLaunchable, the same read the launcher
//     itself makes, so preflight and launch can never disagree.
//   - A Windows packaged app resolves to verdict "ok" with an EMPTY Bin (the
//     AUMID launch). The pure resolver cannot verify the AppX registration
//     without touching the registry, and the cmd side deliberately does not add
//     a probe here either — so the note says it was not probed rather than
//     asserting the app is installed.
func guiPreflight(id, configPath string, allowInstall func() bool) (dashboard.ToolPreflight, bool) {
	g, ok := integration.GUILaunchFor(id)
	if !ok || !g.Advertised() {
		return dashboard.ToolPreflight{}, false
	}
	kind := string(integration.LaunchKindGUI)

	// Config-override parity with the launcher's own first rung, exactly as the
	// terminal arm above does it.
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil {
		if tc, ok := cfg.Launch.Tools[id]; ok && tc.Path != "" {
			key := fmt.Sprintf("[launch.tools.%s].path", id)
			if fi, statErr := os.Stat(tc.Path); statErr != nil || fi.IsDir() {
				return dashboard.ToolPreflight{
					Tool: id, Kind: kind,
					Verdict: string(toolresolve.VerdictNotFound),
					Notes: []string{fmt.Sprintf(
						"%s = %q is set but no binary is there — fix the path or remove the entry",
						key, tc.Path)},
				}, true
			}
			return dashboard.ToolPreflight{
				Tool: id, Kind: kind,
				Verdict: string(toolresolve.VerdictOK),
				Bin:     tc.Path,
				Notes:   []string{fmt.Sprintf("configured via %s", key)},
			}, true
		}
	}

	r := toolresolve.ResolveGUI(g.Spec, dashResolveEnv())
	pf := dashboard.ToolPreflight{
		Tool: id, Kind: kind,
		Verdict: string(r.Verdict),
		Bin:     r.Bin,
		Notes:   r.Notes,
	}
	if _, interop := toolresolve.ForeignInteropLaunchable(r); interop && crossmount.IsWSL() {
		pf.Verdict = string(toolresolve.VerdictOKOffPath)
		pf.Notes = append(pf.Notes,
			"Windows app, launched through WSL interop; routing env will not propagate")
	}
	if r.Verdict == toolresolve.VerdictOK && r.Bin == "" && g.Spec.AppsFolderAUMID != "" {
		pf.Notes = append(pf.Notes, "packaged app (not probed)")
	}
	if plan, ok := dashboardInstallPlanFor(g.Spec.Binary.Installs, runtime.GOOS, dashboardInstallHome(), dashInstallArgv0); ok {
		pf.InstallCommand = plan.Display
		pf.CanInstall = allowInstall != nil && allowInstall()
		if plan.Note != "" {
			pf.Notes = append(pf.Notes, plan.Note)
		}
	} else {
		pf.InstallNote = installNoteFor(&g.Spec.Binary, runtime.GOOS)
	}
	return pf, true
}

type dashboardInstallPlan struct {
	Argv    []string
	Display string
	// Note is an honest caveat about the plan itself (empty when there is
	// none) — today: the plan's program could not be resolved to an absolute
	// path on this daemon, so the spawn falls back to a PATH lookup that may
	// fail. It is surfaced through the preflight's Notes, never as an error:
	// the plan is still the right command to show the operator.
	Note string
}

// installArgv0Lookup resolves an install plan's PROGRAM name (argv[0], e.g.
// "npm", "bash", "uv") to an absolute path, reporting ok=false when it is on
// neither the daemon's PATH nor the operator's login-shell PATH. It is injected
// so dashboardInstallPlanFor stays a pure, table-testable function (CLAUDE.md
// #1); nil disables the resolution and keeps the registry's bare name.
type installArgv0Lookup func(name string) (string, bool)

// dashInstallArgv0 is the production installArgv0Lookup: it walks the SAME
// merged PATH (process + login shell) internal/toolresolve resolves tools on,
// and accepts the first regular, executable file with that name.
//
// This is audit DI-04a. The install PTY execs argv[0] through exec.Command,
// which resolves it against the DAEMON's process PATH only — never the child
// env we hand it — so on a daemon whose PATH lacks the operator's node prefix
// every npm install plan failed before it started. Resolving the program here,
// server-side, is not a widened trust surface: argv[0] is a compile-time
// registry constant, never request-derived, and the request still contributes
// only the tool name.
func dashInstallArgv0(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	if filepath.IsAbs(name) {
		return name, true
	}
	dirs, _ := toolresolve.MergedPathDirs(dashResolveEnv())
	for _, dir := range dirs {
		cand := filepath.Join(dir, name)
		fi, err := os.Stat(cand)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		return cand, true
	}
	return "", false
}

func dashboardInstallHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// dashboardInstallPlanFor selects and normalizes one registry-grounded install
// hint for the dashboard. Exact OS beats OS-agnostic, and an exact-OS vendor
// script beats an exact package-manager fallback: a user-local installer should
// not lose to a generic npm -g (or Linux Homebrew) row merely because the
// registry lists it first.
func dashboardInstallPlanFor(hints []integration.InstallHint, goos, home string, lookArgv0 installArgv0Lookup) (dashboardInstallPlan, bool) {
	want := installOSForGOOS(goos)
	var chosen *integration.InstallHint
	for i := range hints {
		if hints[i].OS == want && (chosen == nil || dashboardInstallChannelRank(hints[i].Channel) < dashboardInstallChannelRank(chosen.Channel)) {
			chosen = &hints[i]
		}
	}
	if chosen == nil {
		for i := range hints {
			if hints[i].OS == "" {
				chosen = &hints[i]
				break
			}
		}
	}
	if chosen == nil || len(chosen.Argv) == 0 {
		return dashboardInstallPlan{}, false
	}

	argv := append([]string(nil), chosen.Argv...)
	if chosen.Channel != "npm" || goos == "windows" || !hasNPMGlobalFlag(argv) {
		return resolvePlanArgv0(dashboardInstallPlan{Argv: argv, Display: chosen.Display}, goos, lookArgv0), true
	}
	if strings.TrimSpace(home) == "" {
		// Do not fall back to a likely root-owned global prefix. An absent home is
		// an honest inability to construct the permission-safe guided plan.
		return dashboardInstallPlan{}, false
	}

	prefix := filepath.Join(home, ".local")
	localized := make([]string, 0, len(argv)+2)
	insertedPrefix := false
	for _, arg := range argv {
		switch arg {
		case "-g", "--global":
			if !insertedPrefix {
				localized = append(localized, "--global", "--prefix", prefix)
				insertedPrefix = true
			}
		default:
			localized = append(localized, arg)
		}
	}
	return resolvePlanArgv0(
		dashboardInstallPlan{Argv: localized, Display: displayInstallArgv(localized)},
		goos, lookArgv0,
	), true
}

// resolvePlanArgv0 rewrites a plan's argv[0] to the absolute program the merged
// PATH resolves it to (DI-04a). Display is left alone — the operator should see
// `npm install …`, not a 60-character absolute path — so the human command
// and the executed program deliberately differ in spelling only.
//
// It is a no-op on Windows, where the spawner itself does the PATHEXT-aware
// resolution (termsession.resolveSpawnArgv) and a bare name is correct. When
// nothing resolves, the bare name is KEPT (exec.LookPath on the daemon PATH
// stays the fallback) and the plan carries an honest Note instead of failing:
// the command is still the right one to show, and installing its program may
// well be the operator's next step.
func resolvePlanArgv0(plan dashboardInstallPlan, goos string, look installArgv0Lookup) dashboardInstallPlan {
	if goos == "windows" || look == nil || len(plan.Argv) == 0 || plan.Argv[0] == "" {
		return plan
	}
	abs, ok := look(plan.Argv[0])
	if !ok {
		plan.Note = fmt.Sprintf(
			"the install command runs %q, which is on neither the daemon's PATH nor the login shell's — install it first, or the guided install will fail",
			plan.Argv[0])
		return plan
	}
	argv := append([]string(nil), plan.Argv...)
	argv[0] = abs
	plan.Argv = argv
	return plan
}

// dashboardInstallChannelRank ranks install CHANNELS for the guided dialog: a
// vendor script (user-local, no privileges) beats a package manager, and a
// package manager beats the npm fallback. scoop sits with brew/winget — the
// same SHAPE (an OS package manager the operator already trusts); the row lists
// exactly the closed Channel vocabulary (integration.InstallHint.Channel:
// npm|script|brew|winget|uv|scoop — choco was deliberately NOT adopted), so a
// newly grounded channel is added HERE when it is added there (CLAUDE.md #5).
func dashboardInstallChannelRank(channel string) int {
	switch channel {
	case "script":
		return 0
	case "brew", "winget", "scoop":
		return 1
	default:
		return 2
	}
}

func hasNPMGlobalFlag(argv []string) bool {
	for _, arg := range argv {
		if arg == "-g" || arg == "--global" {
			return true
		}
	}
	return false
}

func displayInstallArgv(argv []string) string {
	out := make([]string, len(argv))
	for i, arg := range argv {
		if arg != "" && !strings.ContainsAny(arg, " \t\r\n\"'\\") {
			out[i] = arg
			continue
		}
		out[i] = strconv.Quote(arg)
	}
	return strings.Join(out, " ")
}

// recentModelsSeam builds the dashboard.Options.RecentModels closure: it
// resolves a tool NAME to its recently-used models by calling
// store.Store.LoadRecentModelsForTool over the daemon's own database
// (mirroring toolPreflightSeam's role — a plain func so the dashboard
// package never needs a live *store.Store, just the returned data struct).
// A nil database (no store wiring, e.g. an early boot path) is handled by
// the caller passing a nil seam instead of calling this constructor —
// dashboard.Options.RecentModels being nil is itself the honest disabled
// state (see modelSuggestionsFor).
func recentModelsSeam(database *sql.DB) func(context.Context, string) ([]store.RecentToolModel, error) {
	st := store.New(database)
	return func(ctx context.Context, tool string) ([]store.RecentToolModel, error) {
		return st.LoadRecentModelsForTool(ctx, tool, dashboard.RecentModelsWindow, dashboard.RecentModelsLimit)
	}
}

// allowToolInstallSeam builds the dashboard.Options.AllowToolInstall closure: a
// LIVE read of [terminal.launch].allow_install (default true) so a config edit
// flips the guided-install kill-switch with no daemon restart. A config-load
// error fails SAFE (returns false → the endpoint 403s), matching the honest
// "disabled" posture the dashboard prefers over spawning an install on a
// half-broken config.
func allowToolInstallSeam(configPath string) func() bool {
	return func() bool {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return false
		}
		return cfg.Terminal.Launch.AllowInstall
	}
}

// refreshWatchRootsSeam builds dashboard.Options.RefreshWatchRoots: a
// fire-and-forget kick that re-detects adapters and hot-adds newly-
// existing session directories into the live watcher. Retries on a short
// schedule because Muse/Prime (and peers) typically create their
// sessions/ tree a moment AFTER LaunchFresh returns — a single
// immediate Scan would still miss. Fail-open: errors are logged, never
// surfaced to the launch/install HTTP response. Nil w → nil seam.
func refreshWatchRootsSeam(w *watcher.Watcher) func() {
	if w == nil {
		return nil
	}
	return func() {
		go refreshWatchRootsWithRetry(w, slog.Default())
	}
}

// refreshWatchRootsRetryDelays is the post-launch/install retry schedule.
// Attempt 0 is immediate; later attempts cover the "sessions dir appears
// after first tool write" window without waiting for the ~30s poller.
var refreshWatchRootsRetryDelays = []time.Duration{0, 2 * time.Second, 8 * time.Second}

func refreshWatchRootsWithRetry(w *watcher.Watcher, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	for i, d := range refreshWatchRootsRetryDelays {
		if d > 0 {
			time.Sleep(d)
		}
		res, err := w.RefreshRoots(context.Background())
		if err != nil {
			log.Warn("watcher refresh after terminal install/launch",
				"attempt", i+1, "err", err)
			continue
		}
		log.Info("watcher refresh after terminal install/launch",
			"attempt", i+1, "files_processed", res.FilesProcessed)
	}
}

// credOf returns the credential the remote writer-acquire request carries in
// its capability field — a single-use capability token OR (opt-in §B) a
// standing terminal-control secret. The acquire boundary branches on the
// credential SHAPE (remoteauth.IsStandingSecret), so both ride one field.
func credOf(req dashboard.RemoteWriterRequest) string { return req.CapabilityToken }

// setCred puts the credential onto a termlease authorize request's capability
// field (the standing-secret path; AuthorizeStanding reads it as the secret).
func setCred(r *termlease.AuthorizeRequest, cred string) { r.CapabilityToken = cred }

// mapLaunchErr translates termsession's sentinels onto the dashboard's so the
// HTTP handler can pick an honest status without importing termsession.
func mapLaunchErr(err error) error {
	switch {
	case errors.Is(err, termsession.ErrTooManySessions):
		return dashboard.ErrLaunchTooMany
	case errors.Is(err, termsession.ErrPlatformUnsupported):
		return dashboard.ErrLaunchUnsupported
	case errors.Is(err, termsession.ErrSetupInFlight):
		return dashboard.ErrLaunchSetupInFlight
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
		return dashboard.ErrLaunchSSHDisabled
	case errors.Is(err, termsvc.ErrSSHProfileUnknown):
		return dashboard.ErrLaunchSSHProfileUnknown
	case errors.Is(err, termsvc.ErrSSHProfileInvalid):
		return dashboard.ErrLaunchSSHProfileInvalid
	default:
		return mapLaunchErr(err)
	}
}

func mapFreshErr(err error) error {
	switch {
	case errors.Is(err, termsvc.ErrFreshLaunchDisabled):
		return dashboard.ErrLaunchFreshDisabled
	case errors.Is(err, termsvc.ErrToolNotAllowed):
		return dashboard.ErrLaunchToolNotAllowed
	case errors.Is(err, termsvc.ErrShellLaunchDisabled):
		return dashboard.ErrLaunchShellDisabled
	case errors.Is(err, termsvc.ErrProjectRootDenied):
		return dashboard.ErrLaunchProjectRootDenied
	default:
		return mapLaunchErr(err)
	}
}
