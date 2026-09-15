package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/quiesce"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_wire.go is the ONE composition point for enterprise update
// management inside `observer start` (the obs_wire.go pattern). Everything
// the feature needs from the daemon is assembled here, so start.go's own
// change is a short block rather than a dozen scattered lines.
//
// It owns four things:
//
//  1. the process-wide DRAIN GATE, which internal/proxy receives as an
//     interface on its Options (cmd/observer/proxy.go) and which the apply
//     closes and reopens;
//  2. the CHILD SELF-CHECK — when this process was spawned by an older
//     daemon's handshake, it must report `ready` or the parent rolls back;
//  3. the BOOT-TIME `applying` DETECTOR, for the case the handshake cannot
//     see: a kill after the old parent exited, or a host reboot;
//  4. the AUTO-APPLY loop, which is off unless [update].auto_apply resolves
//     true.

// updateGateOnce guards the process-wide drain gate.
var (
	updateGateOnce sync.Once
	updateGate     *quiesce.Gate
)

// updateDrainGate returns the process's single admission gate.
//
// A package-level singleton rather than a field threaded through
// buildProxy's frozen return arity: there is exactly one proxy and one
// updater per process, and the alternative — a ninth return value on a
// function whose signature is deliberately pinned — would be a worse
// coupling than one accessor with a stated invariant.
func updateDrainGate() *quiesce.Gate {
	updateGateOnce.Do(func() { updateGate = quiesce.NewGate() })
	return updateGate
}

// updateRuntime is the daemon-side update machinery.
type updateRuntime struct {
	cfg        config.Config
	configPath string
	store      *store.Store
	org        *orgclient.Client
	logger     *slog.Logger
	quiescence *quiesce.Quiescence
	// applying serialises applies: two concurrent binary swaps on one node
	// is not a race to make thread-safe, it is a state to forbid.
	applying sync.Mutex
	// releaseListeners gives up the proxy + dashboard sockets so the
	// successor can bind them while this process stays alive to watch it.
	// See SetReleaseListeners.
	releaseListeners func()
	releaseOnce      sync.Once
	// released records that releaseListenersNow actually fired. It is the
	// fact H1 turns on: once the sockets are gone this process is not a
	// daemon any more, so an apply that does NOT end in a handover must end
	// in an exit rather than in a live process serving nothing.
	released atomic.Bool
	// autoFailManifest / autoFailCount / autoNextAttempt are the auto-apply
	// loop's backoff memory. Written and read only by AutoApplyLoop's single
	// goroutine.
	autoFailManifest int64
	autoFailCount    int
	autoNextAttempt  time.Time
	// extensionVersion is what the VS Code extension last told us (W5,
	// ruling R6). atomic because the report arrives on a dashboard request
	// goroutine while the push composer reads it. Empty = no extension has
	// reported, which is NOT the same as "0".
	extensionVersion atomic.Value
	// detection caches the install-method verdict; it cannot change without a
	// reinstall, and Detect() stats the filesystem.
	detection atomic.Value
}

// newUpdateRuntime assembles the daemon-side updater. It returns nil when
// [update].enabled is false, and every method is nil-safe, so the disabled
// path is byte-identical to a daemon built before this feature existed.
func newUpdateRuntime(cfg config.Config, configPath string, s *store.Store, org *orgclient.Client, mgr *termsession.Manager, logger *slog.Logger) *updateRuntime {
	if !cfg.Update.Enabled || s == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &updateRuntime{
		cfg: cfg, configPath: configPath, store: s, org: org, logger: logger,
		quiescence: &quiesce.Quiescence{
			Gate: updateDrainGate(),
			Live: []quiesce.LiveWork{{
				// FORCIBLE: a dashboard terminal has an owner who can be
				// warned, unlike a backfill. That is the whole distinction
				// the flag encodes.
				Name:     "dashboard terminal sessions",
				Count:    mgr.LiveCount,
				Forcible: true,
			}},
		},
	}
}

// managedPosture resolves the §3.9 carve-out inputs.
//
// EnterpriseGranted is only visible through the enrolment grant the org
// client holds, which is why this asks the client rather than the config: a
// caller that read the TOML alone would silently answer "BYO" for half the
// managed fleet.
func (u *updateRuntime) managedPosture() update.ManagedPosture {
	if u == nil {
		return update.ManagedPosture{}
	}
	if u.org != nil {
		share := u.org.ShareOptions()
		return update.ManagedPosture{AdminManaged: share.AdminManaged, EnterpriseGranted: share.EnterpriseGranted}
	}
	return update.ManagedPosture{AdminManaged: u.cfg.OrgClient.Share.AdminManaged}
}

// autoApply resolves the effective [update].auto_apply and why.
func (u *updateRuntime) autoApply() (bool, string) {
	if u == nil {
		return false, "off - [update].enabled is false on this node"
	}
	posture := u.managedPosture()
	effective, explicit := u.cfg.Update.EffectiveAutoApply(update.AutoApplyDefault(posture))
	return effective, update.AutoApplyReason(explicit, effective, posture)
}

// PublishPosture wires the static half of the org-bound posture row.
//
// Called once at start, after the install-method table has run. Until it is
// called, store.SelectUpdatePosture returns nil and the push envelope carries
// no update_posture key at all — the pre-feature shape, exactly.
func (u *updateRuntime) PublishPosture() {
	if u == nil {
		return
	}
	exePath := resolvedExecutablePath()
	det := update.Detect(update.PathProbe{
		ExecPath: exePath, GOOS: runtime.GOOS,
		Writable: pathIsReplaceable(exePath), SiblingExists: fileExistsIn,
	})
	auto, _ := u.autoApply()
	u.detection.Store(&det)
	store.SetUpdatePostureEnv(store.UpdatePostureEnv{
		Version:          version,
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		InstallMethod:    string(det.Method),
		AutoApply:        auto,
		Channel:          strings.TrimSpace(u.cfg.Update.Channel),
		ExtensionVersion: u.ExtensionVersion(),
	})
}

// SetExtensionVersion records the VS Code extension's own version and
// republishes the posture (ruling R6, W5).
//
// The daemon cannot discover this on its own: the extension is a separate
// process on its own release channel, so the ONLY honest source is the
// extension telling us. An empty report means "no extension version to
// report" — never "0" — and clears any previously recorded value, which is
// what an uninstall looks like from here.
//
// Republishing rather than merely storing is the point: store.SelectUpdatePosture
// reads the injected env, so without the re-publish the value would sit in this
// struct and never reach the org board.
func (u *updateRuntime) SetExtensionVersion(v string) {
	if u == nil {
		return
	}
	u.extensionVersion.Store(strings.TrimSpace(v))
	u.PublishPosture()
}

// ExtensionVersion reports the last version an extension told us about.
func (u *updateRuntime) ExtensionVersion() string {
	if u == nil {
		return ""
	}
	v, _ := u.extensionVersion.Load().(string)
	return v
}

// UpdateStatus composes GET /api/update/status for the node's own dashboard
// (W5: the Settings -> Health card and the update banner).
//
// It is a pure READ of state this daemon already holds — the update_state row
// the push cycle and the apply path write, the install-method verdict resolved
// at start, and the org client's in-memory record of a min-version refusal. It
// makes no outbound request, which is what lets the plan's "no new background
// fetch" hold for the banner.
func (u *updateRuntime) UpdateStatus(ctx context.Context) (dashboard.UpdateStatusResult, error) {
	if u == nil {
		// [update].enabled = false. The zero value says the feature is off,
		// which the card renders as such — never as "up to date".
		return dashboard.UpdateStatusResult{}, nil
	}
	st, err := u.store.LoadUpdateState(ctx)
	if err != nil {
		return dashboard.UpdateStatusResult{}, err
	}
	auto, why := u.autoApply()
	det := u.installDetection()
	channel := strings.TrimSpace(u.cfg.Update.Channel)
	if channel == "" {
		channel = strings.TrimSpace(string(st.Channel))
	}
	res := dashboard.UpdateStatusResult{
		Enabled:            true,
		Version:            version,
		Channel:            channel,
		State:              string(st.State),
		Reason:             string(st.Reason),
		ErrorClass:         string(st.ErrorClass),
		TargetVersion:      strings.TrimSpace(st.TargetVersion),
		ManifestVersion:    st.LastManifestVersion,
		LastManifestSeenAt: strings.TrimSpace(st.LastManifestSeenAt),
		InstallMethod:      string(det.Method),
		SelfApply:          det.SelfApply,
		Advice:             update.AdviceFor(det, st.TargetVersion),
		AutoApply:          auto,
		AutoApplyReason:    why,
		Window:             strings.TrimSpace(u.cfg.Update.Window),
	}
	if u.org != nil {
		if ref := u.org.AgentTooOld(); ref != nil {
			res.OrgRefusal = &dashboard.UpdateOrgRefusal{
				Message:     ref.Message,
				MinVersion:  ref.MinVersion,
				YourVersion: ref.YourVersion,
				At:          ref.At.UTC().Format(time.RFC3339),
			}
		}
	}
	return res, nil
}

// installDetection returns the cached install-method verdict, resolving it on
// demand if PublishPosture has not run yet.
//
// Cached because Detect() stats the filesystem and probes a package manager,
// and the dashboard card can be polled; the answer cannot change without a
// reinstall, which restarts the daemon anyway.
func (u *updateRuntime) installDetection() update.Detection {
	if d, _ := u.detection.Load().(*update.Detection); d != nil {
		return *d
	}
	exePath := resolvedExecutablePath()
	det := update.Detect(update.PathProbe{
		ExecPath: exePath, GOOS: runtime.GOOS,
		Writable: pathIsReplaceable(exePath), SiblingExists: fileExistsIn,
	})
	u.detection.Store(&det)
	return det
}

// ReportChildSelfCheck is §3.7 step 8's child half.
//
// It runs ONLY when this process was spawned by an older daemon's handshake,
// and only after the four things a boot crash breaks have already succeeded:
// the config loaded and validated, the database opened (with its migrations
// complete), the listeners bound, and the version is the one the parent was
// trying to reach. Reporting earlier would make the handshake a formality.
//
// A failure to REPORT is not a failure to run: the parent will time out and
// roll back on its own, which is the fail-safe direction.
func (u *updateRuntime) ReportChildSelfCheck(ctx context.Context) {
	nonce := handshakeChildNonce()
	if nonce == "" {
		return
	}
	if u == nil {
		// The feature is disabled on the NEW binary. Report ready anyway:
		// the parent is waiting, and a daemon that came up healthy must not
		// be rolled back because its config turned the updater off.
		_ = reportHandshakeReady(nonce)
		return
	}
	row, err := u.store.LoadUpdateState(ctx)
	if err != nil {
		_ = reportHandshakeFailure("the update state could not be read")
		return
	}
	target := strings.TrimSpace(row.TargetVersion)
	if target != "" && target != version {
		_ = reportHandshakeFailure(fmt.Sprintf("this binary is %s, the apply targeted %s", version, target))
		return
	}
	if err := reportHandshakeReady(nonce); err != nil {
		u.logger.Warn("update handshake: could not report ready", "err", err)
		return
	}
	u.logger.Info("update handshake: reported ready to the previous daemon", "version", version)
}

// RecoverAtBoot handles a node that starts while its state says `applying`
// and NO parent is watching — a kill after the old parent exited, or a host
// reboot. It is the residual ruling R14 names a supervisor for.
//
// The rule is decided by which binary is actually running, because that is
// the only fact that survives the crash: if this process IS the target, the
// swap completed and the apply simply lost its witness; if it is not, the
// swap did not happen or was already undone.
func (u *updateRuntime) RecoverAtBoot(ctx context.Context) {
	if u == nil || handshakeChildNonce() != "" {
		return // a watched child settles through the handshake instead
	}
	row, err := u.store.LoadUpdateState(ctx)
	if err != nil || row.State != update.StateApplying {
		return
	}
	// Put back an executable if a two-rename swap was interrupted. This runs
	// before anything else because a node with no binary at its own path
	// cannot be recovered by any later step.
	if recovered, rerr := recoverInterruptedSwap(osSwapFS{}, resolvedExecutablePath(), row.PreviousVersion); rerr != nil {
		u.logger.Warn("update: could not recover an interrupted swap", "err", rerr)
	} else if recovered {
		u.logger.Warn("update: restored the previous executable after an interrupted swap")
	}

	target := strings.TrimSpace(row.TargetVersion)
	settled, detail := update.StateFailed, fmt.Sprintf(
		"the daemon restarted while an apply was in progress and no parent was watching; the running binary is %s, the apply targeted %s", version, target)
	class := update.ErrorHealthcheck
	if target != "" && target == version {
		settled, class = update.StateApplied, update.ErrorNone
		detail = fmt.Sprintf("the apply completed but lost its watching parent (a restart or a host reboot); the running binary is the target %s", version)
	}
	row.State = settled
	row.ErrorClass = class
	row.ApplyingStartedAt = ""
	if settled == update.StateApplied {
		row.AppliedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := u.store.SaveUpdateState(ctx, row); err != nil {
		u.logger.Warn("update: could not settle an orphaned apply", "err", err)
	}
	_ = u.store.AppendUpdateEvent(ctx, store.UpdateEventRow{
		FromVersion: row.PreviousVersion, ToVersion: target,
		ManifestVersion: row.LastManifestVersion, State: settled, ErrorClass: class, Detail: detail,
	})
	u.logger.Warn("update: settled an orphaned apply at boot", "state", settled, "detail", detail)
}

// ApplySeam is the dashboard.Options.UpdateApplyFunc value.
func (u *updateRuntime) ApplySeam() func(context.Context, dashboard.UpdateApplyRequest) (dashboard.UpdateApplyResult, error) {
	if u == nil {
		return nil
	}
	return func(ctx context.Context, req dashboard.UpdateApplyRequest) (dashboard.UpdateApplyResult, error) {
		out, err := u.ApplyDetached(ctx, applyRequestFromDashboard(req))
		return dashboard.UpdateApplyResult{
			State: string(out.State), Reason: string(out.Reason), ErrorClass: string(out.ErrorClass),
			Detail: out.Detail, Steps: out.Steps, Applied: out.Applied,
			RolledBack: out.RolledBack, Deferred: out.Deferred,
			Accepted: out.Accepted, EventID: out.EventID,
		}, err
	}
}

// ApplyDetached takes an apply request and RETURNS, running the apply itself
// on its own goroutine and its own context.
//
// Why the apply cannot ride the request goroutine. `POST /api/update/apply`
// is an ACTIVE connection for as long as its handler runs, and the dashboard
// stops with http.Server.Shutdown on a 5s budget — a budget that waits for
// active connections. The apply releases the listeners mid-handshake, which
// begins that shutdown, so a child that takes longer than ~4.25s to boot (a
// migration on a large database is ordinary) made Shutdown return
// DeadlineExceeded, which start.go's errgroup turned into os.Exit(1) — the
// PARENT dying with the child alive, `applying` never settled and nobody left
// to roll back. That is the execve-replace failure the handshake exists to
// avoid, reached by way of an HTTP timeout.
//
// So the handshake owns its own context (context.WithoutCancel of a
// background one, never the request's), the caller gets 202 plus the ledger
// row id, and `observer update history` is where the outcome is read. A
// --dry-run is the one exception: it performs nothing, returns in
// milliseconds, and its whole value is the plan it prints back.
func (u *updateRuntime) ApplyDetached(ctx context.Context, req updateApplyRequest) (applyOutcome, error) {
	if u == nil {
		return applyOutcome{}, errors.New("observer update: updates are disabled on this node")
	}
	if req.DryRun {
		return u.Apply(ctx, req)
	}
	// The lock is taken HERE, not inside the goroutine, so a second request
	// is refused with an error the caller can see rather than accepted with a
	// 202 that will do nothing.
	if !u.applying.TryLock() {
		return applyOutcome{}, errors.New("observer update: an apply is already in progress on this node")
	}
	verb := "apply"
	if req.Rollback {
		verb = "rollback"
	}
	id, _ := u.store.AppendUpdateEventID(context.WithoutCancel(ctx), store.UpdateEventRow{
		FromVersion: version, State: update.StateAvailable,
		Detail: "accepted a dashboard-initiated " + verb + "; it runs off the request goroutine so the handshake owns its own budget",
	})
	go func() {
		defer u.applying.Unlock()
		out, err := u.applyLocked(context.WithoutCancel(context.Background()), req)
		if err != nil {
			u.logger.Warn("update: the detached apply failed", "state", out.State,
				"error_class", out.ErrorClass, "detail", out.Detail, "err", err)
			return
		}
		u.logger.Info("update: the detached apply finished", "state", out.State, "detail", out.Detail)
	}()
	return applyOutcome{
		State: update.StateApplying, Accepted: true, EventID: id,
		Detail: "accepted; the daemon is running this " + verb + " on its own budget. Follow it with `observer update history`.",
	}, nil
}

// StatusSeam is the dashboard.Options.UpdateStatusFunc value (W5).
//
// It returns a NON-NIL func even when the runtime is nil, so a daemon with
// [update].enabled = false answers 200 with Enabled:false — the honest
// disabled shape the card renders as "update management is off on this node",
// rather than a 404 the frontend would read as "old daemon".
func (u *updateRuntime) StatusSeam() func(context.Context) (dashboard.UpdateStatusResult, error) {
	return func(ctx context.Context) (dashboard.UpdateStatusResult, error) {
		return u.UpdateStatus(ctx)
	}
}

// ExtensionVersionSeam is the dashboard.Options.UpdateExtensionVersionFunc
// value (W5, ruling R6). Nil when the feature is off, which makes the route
// answer 501 and tells the extension to stop retrying for this session.
func (u *updateRuntime) ExtensionVersionSeam() func(string) {
	if u == nil {
		return nil
	}
	return u.SetExtensionVersion
}

// applyRequestFromDashboard maps the loopback wire onto the internal shape.
func applyRequestFromDashboard(req dashboard.UpdateApplyRequest) updateApplyRequest {
	return updateApplyRequest{Version: req.Version, Force: req.Force, DryRun: req.DryRun, Rollback: req.Rollback}
}

// Apply runs one apply (or rollback) in the DAEMON process.
func (u *updateRuntime) Apply(ctx context.Context, req updateApplyRequest) (applyOutcome, error) {
	if u == nil {
		return applyOutcome{}, errors.New("observer update: updates are disabled on this node")
	}
	// Two concurrent binary swaps on one node is a state to forbid, not a
	// race to make thread-safe.
	if !u.applying.TryLock() {
		return applyOutcome{}, errors.New("observer update: an apply is already in progress on this node")
	}
	defer u.applying.Unlock()
	return u.applyLocked(ctx, req)
}

// applyLocked is Apply's body, with u.applying ALREADY held by the caller.
//
// The split exists for ApplyDetached, which must take the lock before it
// answers 202 (so a second request is refused, not silently dropped) and
// release it when the goroutine it spawned is done.
func (u *updateRuntime) applyLocked(ctx context.Context, req updateApplyRequest) (applyOutcome, error) {
	if req.Rollback {
		return u.rollback(ctx)
	}
	row, err := u.store.LoadUpdateState(ctx)
	if err != nil {
		return applyOutcome{}, err
	}
	man, art, err := u.resolveTarget(ctx, row, req.Version)
	if err != nil {
		return applyOutcome{}, err
	}
	win, err := update.ParseWindow(u.cfg.Update.Window)
	if err != nil {
		return applyOutcome{}, err
	}
	schema, err := u.store.SchemaVersion(ctx)
	if err != nil {
		return applyOutcome{}, err
	}
	exePath := resolvedExecutablePath()
	det := update.Detect(update.PathProbe{
		ExecPath: exePath, GOOS: runtime.GOOS,
		Writable: pathIsReplaceable(exePath), SiblingExists: fileExistsIn,
	})
	deps := applyDeps{
		Store:                 u.store,
		Quiescence:            u.quiescence,
		Download:              u.download,
		VerifyVendorSignature: verifyVendorSignature,
		Probe:                 probeBinaryVersion,
		Supervise: func(sctx context.Context, exe, stateDir string, timeout time.Duration) (handshakeResult, error) {
			// preflightRestart's instinct, kept and strengthened: the config
			// is re-Loaded and re-Validated BEFORE the successor is spawned,
			// so a config that would not come back never reaches the
			// handshake.
			if err := preflightRestart(u.configPath); err != nil {
				return handshakeResult{Detail: err.Error()}, err
			}
			// Give up the sockets only NOW — after the drain, after the
			// rollback and snapshot are staged, and after the swap. Doing it
			// earlier would leave the node unreachable during steps that can
			// still abort with the old binary intact.
			u.releaseListenersNow()
			return superviseNewBinary(sctx, exe, os.Args[1:], stateDir, timeout, u.logger)
		},
		FS: osSwapFS{}, GOOS: runtime.GOOS, Logger: u.logger,
		// The DB-restoring rollback branch closes this process's handle
		// BEFORE the live file is renamed aside, then reopens on whatever is
		// at the path afterwards so the rollback's own ledger row lands in
		// the database that survives it.
		CloseDB:     u.store.CloseDatabase,
		ReopenStore: func() (updateStateStore, error) { return reopenUpdateStore(u.cfg.Observer.DBPath) },
		FreeBytes:   updateFreeBytes,
	}
	opts := applyOptions{
		Manifest: man, Artifact: art,
		Installed: update.Installed{
			Version: version, SchemaVersion: schema, ExecPath: exePath, Detection: det,
		},
		StateDir: updateStateDirFor(u.cfg),
		DBPath:   u.cfg.Observer.DBPath,
		Window:   win,
		Force:    req.Force,
		DryRun:   req.DryRun,
		// The manifest's own answer to "does this release advance the
		// schema". Zero (a manifest minted before the field existed) still
		// means "may advance", so the conservative snapshot is the default
		// and a declared equal version is what skips a multi-gigabyte
		// VACUUM INTO on every apply.
		TargetSchemaVersion: man.SchemaVersion,
		AllowDowngrade:      u.cfg.Update.AllowDowngrade,
		DrainTimeout:        durationOr(u.cfg.Update.DrainTimeout, quiesce.DefaultDrainTimeout),
		HandshakeTimeout:    durationOr(u.cfg.Update.HandshakeTimeout, time.Minute),
		MaxDownloadBytes:    u.cfg.Update.MaxDownloadBytes,
	}
	out, err := runUpdateApply(ctx, deps, opts)
	exiting := u.finishApply(out, opts.Manifest.Version)
	// The retention pass is skipped on exactly one path: a rollback that
	// followed a listener release. That branch may have CLOSED and replaced
	// this process's database (the snapshot restore), so the pass would run
	// against a handle that is gone — and the restored binary performs it on
	// its next apply anyway. A successful handover still prunes: the parent is
	// alive for another half-second and the pass spares every path the live
	// state row still names.
	if !exiting || out.Applied {
		if _, perr := u.store.PruneUpdateArtifacts(ctx, opts.StateDir, u.cfg.Update.KeepPreviousDays); perr != nil {
			u.logger.Warn("update: retention pass failed", "err", perr)
		}
	}
	return out, err
}

// finishApply decides whether this process survives its own apply, and
// reports true when it does not.
//
// TWO ENDINGS, ONE RULE: a process that has released its listeners must not
// outlive them.
//
//   - Applied: the child passed its self-check and IS the daemon now. Exiting
//     0 is the last step of the sequence, not an error path.
//   - Anything else, once the listeners were released (H1): the rollback put
//     the previous binary back, but THIS process is a live main PID bound to
//     nothing. Before this it simply returned — `Restart=always` never fired,
//     because the main PID never exited, and the developer's proxied session
//     got ConnectionRefused with no supervisor able to notice. Exiting
//     NON-ZERO is the honest end: a supervisor restarts the restored binary,
//     and an unsupervised operator sees a dead daemon rather than a silently
//     deaf one.
//
// An apply that never got as far as releasing the listeners (a blocked plan,
// a failed download, a drain timeout) changes nothing: this process is still
// serving, and it goes on serving.
func (u *updateRuntime) finishApply(out applyOutcome, targetVersion string) bool {
	switch {
	case out.Applied:
		u.logger.Info("update applied; the previous daemon is exiting in favour of the new binary",
			"version", targetVersion, "detail", out.Detail)
		go u.exitAfterHandover()
		return true
	case u.released.Load():
		u.logger.Error("update: the handshake did not hand over and the listeners are already released; exiting so the restored binary serves again",
			"state", out.State, "error_class", out.ErrorClass, "detail", out.Detail)
		go u.exitAfterFailedHandover(out)
		return true
	default:
		return false
	}
}

// exitAfterHandover ends the old process a moment after the handshake, so
// the HTTP reply that reported success can flush first. The delay mirrors
// RestartFunc's 300ms for the same reason.
func (u *updateRuntime) exitAfterHandover() {
	time.Sleep(500 * time.Millisecond)
	updateExitFunc(0)
}

// exitAfterFailedHandover ends a process that released its listeners and then
// did NOT hand over (H1).
//
// Non-zero on purpose. Zero would tell a supervisor "this ended as intended",
// and journald/`systemctl status` would say the same to the operator, when
// what actually happened is an apply that failed and rolled back. The ledger
// row was already written by recordOutcome — including, on the DB-restoring
// branch, through a handle on the RESTORED database — so the reason survives
// the exit even though this process does not.
//
// The delay mirrors exitAfterHandover's: an HTTP reply that reported the
// outcome gets to flush first.
func (u *updateRuntime) exitAfterFailedHandover(out applyOutcome) {
	u.logger.Warn("update: this daemon is exiting non-zero after a rollback; a supervisor (or the operator) starts the restored binary",
		"state", out.State, "rolled_back", out.RolledBack)
	time.Sleep(500 * time.Millisecond)
	updateExitFunc(1)
}

// updateExitFunc is os.Exit behind a seam so a test can observe the handover
// without ending the test binary.
var updateExitFunc = os.Exit

// reopenUpdateStore opens a fresh handle on the agent database at path.
//
// Used on exactly one path: after a rollback has restored the pre-apply
// snapshot over the live file. db.Open runs migrations, which is right here —
// the file is the OLD schema and this is the OLD binary, so its own migration
// set is already applied and the call is a no-op that also proves the restored
// file opens at all.
func reopenUpdateStore(path string) (updateStateStore, error) {
	database, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		return nil, err
	}
	return store.New(database), nil
}

// updateFreeBytes reports free space for the §2.4 headroom gate, or an error
// on a platform with no portable free-space syscall — which the gate treats as
// "skip the check", never as "refuse".
func updateFreeBytes(path string) (uint64, error) {
	if !diskHeadroomCheckSupported {
		return 0, errors.New("free-space checks are not supported on this platform")
	}
	return statfsFreeBytes(path)
}

// rollback restores the previous binary, and the snapshot when the schema
// advanced.
func (u *updateRuntime) rollback(ctx context.Context) (applyOutcome, error) {
	row, err := u.store.LoadUpdateState(ctx)
	if err != nil {
		return applyOutcome{}, err
	}
	schemaNow, err := u.store.SchemaVersion(ctx)
	if err != nil {
		return applyOutcome{}, err
	}
	decision := update.DecideRollback(update.RollbackInput{
		State:                 row.State,
		HasPreviousBinary:     fileExists(row.PreviousBinaryPath),
		PreviousSchemaVersion: row.PreviousSchemaVersion,
		CurrentSchemaVersion:  schemaNow,
		HasDBBackup:           fileExists(row.PreviousDBBackupPath),
	})
	if decision.Refuse {
		return applyOutcome{State: decision.State, ErrorClass: decision.ErrorClass, Detail: decision.Reason},
			errors.New(decision.Reason)
	}
	// A rollback replaces the running binary too, so it drains exactly like
	// an apply. Skipping the drain here would make the recovery path the one
	// that hands a live session ConnectionRefused.
	_, resume, derr := u.quiescence.Drain(ctx, quiesce.DrainOptions{
		Timeout: durationOr(u.cfg.Update.DrainTimeout, quiesce.DefaultDrainTimeout),
	})
	defer resume()
	if derr != nil {
		return applyOutcome{State: update.StateFailed, ErrorClass: update.ErrorDrain, Detail: derr.Error()}, derr
	}
	exePath := resolvedExecutablePath()
	if decision.RestoreBinary {
		if err := restoreBinary(osSwapFS{}, runtime.GOOS, row.PreviousBinaryPath, exePath, row.PreviousVersion); err != nil {
			return applyOutcome{State: update.StateFailed, ErrorClass: update.ErrorSwap, Detail: err.Error()}, err
		}
	}
	// The state writer for the rest of this function. It is a variable
	// because the DB-restoring branch replaces the file underneath us and the
	// rollback's own record has to land in the file that SURVIVES.
	var writer updateStateStore = u.store
	if decision.RestoreDB {
		// Close before renaming, for the same reason the failed-handshake
		// path does: a handle left open on the old inode keeps this process
		// writing to observer.db.failed-update while hook processes, which
		// open by path, write to the restored file.
		if cerr := u.store.CloseDatabase(); cerr != nil {
			u.logger.Warn("update: closing the database before restoring the snapshot failed", "err", cerr)
		}
		if err := restoreDatabaseSnapshot(row.PreviousDBBackupPath, u.cfg.Observer.DBPath); err != nil {
			return applyOutcome{State: update.StateFailed, ErrorClass: update.ErrorHealthcheck, Detail: err.Error()}, err
		}
		reopened, rerr := reopenUpdateStore(u.cfg.Observer.DBPath)
		if rerr != nil {
			u.logger.Warn("update: reopening the restored database failed; this rollback is not recorded in the ledger", "err", rerr)
			writer = nil
		} else {
			writer = reopened
		}
	}
	row.State = update.StateRolledBack
	row.TargetVersion = row.PreviousVersion
	row.ErrorClass = decision.ErrorClass
	row.ApplyingStartedAt = ""
	detail := "operator-invoked rollback: " + decision.Reason
	if decision.DiscardsDataWindow {
		detail += "; rows ingested after the pre-apply snapshot were discarded"
	}
	if writer != nil {
		_ = writer.SaveUpdateState(ctx, row)
		_ = writer.AppendUpdateEvent(ctx, store.UpdateEventRow{
			FromVersion: version, ToVersion: row.PreviousVersion,
			ManifestVersion: row.LastManifestVersion, State: update.StateRolledBack,
			ErrorClass: decision.ErrorClass, Detail: detail,
		})
	}
	out := applyOutcome{
		State: update.StateRolledBack, ErrorClass: decision.ErrorClass,
		RolledBack: true, Detail: decision.Reason,
	}
	go u.exitAfterHandover()
	return out, nil
}

// resolveTarget picks the manifest and artifact for this apply.
func (u *updateRuntime) resolveTarget(_ context.Context, row store.UpdateStateRow, wantVersion string) (update.Manifest, update.Artifact, error) {
	var man update.Manifest
	if u.org != nil {
		if st := u.org.UpdateStatus(); st.Version != "" {
			man = update.Manifest{
				Schema: update.SchemaV1, Channel: st.Channel, ManifestVersion: st.ManifestVersion,
				Version: st.Version, Notes: st.Notes, NotesURL: st.NotesURL, EOSAt: st.EOSAt,
				Artifacts: []update.Artifact{st.Artifact},
			}
		}
	}
	if man.Version == "" && strings.TrimSpace(row.ManifestJSON) != "" {
		decoded, err := update.DecodeManifest([]byte(row.ManifestJSON))
		if err != nil {
			return update.Manifest{}, update.Artifact{}, fmt.Errorf("observer update: the stored manifest could not be decoded: %w", err)
		}
		man = decoded
	}
	if man.Version == "" {
		return update.Manifest{}, update.Artifact{}, errors.New("observer update: this node holds no accepted manifest yet")
	}
	if v := strings.TrimSpace(wantVersion); v != "" && v != man.Version {
		return update.Manifest{}, update.Artifact{}, fmt.Errorf(
			"observer update: this node is eligible for %s, not %s; an update is served by the org, not chosen by the node", man.Version, v)
	}
	art, ok := update.SelectArtifact(man, "agent", runtime.GOOS, runtime.GOARCH)
	if !ok {
		return update.Manifest{}, update.Artifact{}, fmt.Errorf(
			"observer update: manifest %d builds nothing for %s/%s", man.ManifestVersion, runtime.GOOS, runtime.GOARCH)
	}
	return man, art, nil
}

// download is the mirror fetch, and it exists only when the node is enrolled.
func (u *updateRuntime) download(ctx context.Context, version, filename string, dst io.Writer, maxBytes int64) error {
	if u.org == nil {
		return errors.New("this node is not enrolled with an org server, and an org server is the only place a node fetches update bytes from")
	}
	return u.org.DownloadUpdateArtifact(ctx, version, filename, dst, maxBytes)
}

// AutoApplyLoop applies whatever the org has published, on the node's own
// schedule, when [update].auto_apply resolves true.
//
// It is a POLL of state the push cycle already refreshed, not a second
// outbound rail: the manifest arrives on the connection the node already
// makes, and this loop only decides when to act on it. A node with nothing
// published performs no work and makes no request.
func (u *updateRuntime) AutoApplyLoop(ctx context.Context) {
	if u == nil {
		return
	}
	auto, why := u.autoApply()
	if !auto {
		u.logger.Info("update: auto-apply is off", "reason", why)
		return
	}
	u.logger.Info("update: auto-apply is on", "reason", why)
	ticker := time.NewTicker(updateAutoApplyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if now := time.Now(); u.autoNextAttempt.After(now) {
			// A deterministic failure is being backed off. Saying nothing
			// would be indistinguishable from a healthy quiet node.
			u.logger.Debug("update: auto-apply is backing off a failed manifest",
				"manifest_version", u.autoFailManifest, "next_attempt", u.autoNextAttempt.Format(time.RFC3339))
			continue
		}
		out, err := u.Apply(ctx, updateApplyRequest{})
		u.noteAutoApplyOutcome(out)
		switch {
		case err != nil && out.State == "":
			// Nothing published, not enrolled, or already applying — all
			// normal conditions on a quiet node, logged at debug so a fleet
			// with nothing to do stays quiet.
			u.logger.Debug("update: auto-apply found nothing to do", "err", err)
		case out.Deferred:
			u.logger.Info("update: auto-apply deferred", "state", out.State, "reason", out.Reason, "detail", out.Detail)
		case err != nil:
			u.logger.Warn("update: auto-apply failed", "state", out.State, "error_class", out.ErrorClass, "detail", out.Detail)
		}
	}
}

// deterministicApplyFailures are the error classes that will produce the SAME
// answer on the next tick, given the same manifest and the same node.
//
// Re-running one of these every ten minutes is not a retry, it is a loop: it
// re-downloads the archive and (before the manifest declares its schema
// version) re-takes a full VACUUM INTO snapshot of a database that may be
// tens of gigabytes, forever. That is the automatic full-file rewrite the
// 2026-08-26 disk-exhaustion audit made a hard invariant against.
//
// Deliberately NOT listed: download and drain. A failed fetch or a busy node
// is a transient condition and the plain ten-minute cadence is the right
// answer for both.
var deterministicApplyFailures = map[update.ErrorClass]bool{
	update.ErrorHash:       true,
	update.ErrorSignature:  true,
	update.ErrorProbe:      true,
	update.ErrorSwap:       true,
	update.ErrorPermission: true,
}

// autoApplyMaxBackoff caps the backoff. An operator who fixes the underlying
// condition (frees disk, repairs a permission, publishes a corrected
// manifest) must not wait a day for the node to notice.
const autoApplyMaxBackoff = 6 * time.Hour

// noteAutoApplyOutcome advances or clears the loop's backoff.
//
// The key is the MANIFEST VERSION, not the error: a new manifest is a new
// question, so publishing a fixed release re-arms the node on the very next
// tick regardless of how long the previous one had backed off to.
func (u *updateRuntime) noteAutoApplyOutcome(out applyOutcome) {
	if !deterministicApplyFailures[out.ErrorClass] {
		u.autoFailManifest, u.autoFailCount, u.autoNextAttempt = 0, 0, time.Time{}
		return
	}
	manifestVersion := int64(0)
	if u.store != nil {
		if row, err := u.store.LoadUpdateState(context.Background()); err == nil {
			manifestVersion = row.LastManifestVersion
		}
	}
	if manifestVersion != u.autoFailManifest {
		u.autoFailManifest, u.autoFailCount = manifestVersion, 0
	}
	u.autoFailCount++
	wait := updateAutoApplyInterval << u.autoFailCount
	if wait > autoApplyMaxBackoff || wait <= 0 {
		wait = autoApplyMaxBackoff
	}
	u.autoNextAttempt = time.Now().Add(wait)
	u.logger.Warn("update: auto-apply hit a deterministic failure; backing off rather than re-running it every cycle",
		"error_class", out.ErrorClass, "manifest_version", manifestVersion,
		"attempt", u.autoFailCount, "next_attempt_in", wait.String())
}

// updateAutoApplyInterval is how often an auto-applying node re-checks its
// own cached posture. It is deliberately slower than the push cycle: the
// manifest cannot arrive faster than the push that nudges it, and a tighter
// loop would only re-evaluate a maintenance window more often.
const updateAutoApplyInterval = 10 * time.Minute

// updateRuntimeOnce caches the process's single updateRuntime.
var (
	updateRuntimeOnce sync.Once
	updateRuntimeInst *updateRuntime
)

// updateRuntimeFor builds (once) the daemon-side updater.
//
// It is memoised so `observer start` can reach it from two places — the
// dashboard Options literal and the post-listener wiring block — without
// threading a variable between them, and so a second call can never produce
// a SECOND drain gate or a second apply mutex, which would silently defeat
// both.
func updateRuntimeFor(cfg config.Config, configPath string, s *store.Store, org *orgclient.Client, mgr *termsession.Manager, logger *slog.Logger) *updateRuntime {
	updateRuntimeOnce.Do(func() {
		updateRuntimeInst = newUpdateRuntime(cfg, configPath, s, org, mgr, logger)
	})
	return updateRuntimeInst
}

// currentUpdateRuntime returns the memoised runtime WITHOUT building one.
//
// It exists because the listener scope is created after the dashboard branch
// has already assembled the runtime, and rebuilding one there would need cfg,
// the database, the org client and the terminal manager — none of which are
// in scope at that point, and all of which would risk a SECOND drain gate.
// Returns nil when the feature is disabled or the daemon never reached the
// wiring block; every method is nil-safe.
func currentUpdateRuntime() *updateRuntime { return updateRuntimeInst }

// waitForListener blocks until addr accepts a TCP connection or ctx ends.
//
// It is announceDashboardReady's dial loop without the banner: the update
// handshake needs the same fact ("the listener is actually accepting"), and
// deriving it from a successful dial rather than from "New() returned" is
// what makes a bind failure visible to the watching parent instead of
// reported as a healthy start.
func waitForListener(ctx context.Context, addr string) {
	if strings.TrimSpace(addr) == "" {
		return
	}
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// SetReleaseListeners wires the listener-release seam of §3.7 step 7.
//
// The old daemon must give up its sockets BEFORE it forks the successor —
// otherwise the child fails to bind, and every apply on a node with a live
// proxy or dashboard rolls back with EADDRINUSE. That is a deterministic
// failure, not a race, which is why this is a wired seam rather than an
// optimisation.
//
// It is NOT the same act as shutting down: the process stays alive, still
// holding update_state, still able to kill the child and restore the previous
// binary. Cancelling the daemon's own context instead would end the
// supervisor along with the listeners, which is precisely the
// execve-replace failure the handshake exists to avoid.
//
// Nil (the default, and the case on a --no-dashboard daemon that never
// reaches the wiring block) means "nothing to release", which is honest: an
// apply then proceeds and the child binds whatever this process was not
// holding.
func (u *updateRuntime) SetReleaseListeners(release func()) {
	if u == nil {
		return
	}
	u.releaseListeners = release
}

// releaseListenersNow gives up the sockets, once.
//
// Once, because the release is irreversible: this process does not re-bind
// after a failed handshake — the RESTORED binary is what serves again, and
// the operator's supervisor (or their own relaunch) starts it. That is stated
// here rather than left implied, because "resumes admission" in ruling R13
// means the proxy's admission GATE reopens, not that a released socket comes
// back.
//
// And because it is irreversible, THIS PROCESS MUST NOT OUTLIVE IT. A parent
// that released its sockets, rolled back, and then simply returned would be a
// live main PID holding :8820 and :8081 with nobody listening — Restart=always
// never fires, and the developer's proxied session gets ConnectionRefused,
// which is precisely the outage CLAUDE.md's daemon-restart rule exists to
// prevent. exitAfterFailedHandover is the other half of this Once.
func (u *updateRuntime) releaseListenersNow() {
	if u == nil || u.releaseListeners == nil {
		return
	}
	u.releaseOnce.Do(func() {
		u.logger.Info("update: releasing the proxy and dashboard listeners for the new binary")
		u.released.Store(true)
		u.releaseListeners()
		// A moment for the graceful shutdowns to actually let go of the
		// ports, so the child's bind does not race a socket in TIME_WAIT-ish
		// teardown. Bounded and small: the handshake timeout is the real
		// bound on how long a successor may take.
		time.Sleep(listenerReleaseGrace)
	})
}

// listenerReleaseGrace is how long the parent waits after cancelling the
// listener scope before spawning the successor.
const listenerReleaseGrace = 750 * time.Millisecond
