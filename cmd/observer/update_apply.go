package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/quiesce"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_apply.go executes §3.7 of
// docs/plans/enterprise-update-management-plan-2026-09-07.md — the effectful
// half of an apply. The DECISIONS live in internal/update (which artifact,
// whether a snapshot is required, what a failed handshake means); this file
// only performs them, in order, and records what happened.
//
// The whole file is written around one rule: APPLY IS FAIL-CLOSED (§2.4).
// Every doubt at every step — a hash mismatch, a missing or unverifiable
// vendor signature, a --version probe that disagrees, an unwritable target,
// an install method the node does not own, a closed window, a drain that did
// not complete, a live PTY without --force-in-window, a snapshot that could
// not be written — aborts with a state and an error class and leaves the
// running binary untouched. There is no partial apply.
//
// And around a second: THE OLD PROCESS IS THE ACTOR. It stages the rollback
// before touching anything live, it swaps, it watches the child, and it is
// still alive to restore if the child fails. That is what makes rollback
// fail-safe on a machine with no supervisor installed (ruling R14).

// updateStateStore is the storage seam. An interface rather than *store.Store
// so the whole sequence — including the three handshake failure shapes — is
// testable against a fake that needs no SQLite file.
type updateStateStore interface {
	LoadUpdateState(ctx context.Context) (store.UpdateStateRow, error)
	SaveUpdateState(ctx context.Context, row store.UpdateStateRow) error
	AppendUpdateEvent(ctx context.Context, ev store.UpdateEventRow) error
	TransitionUpdateState(ctx context.Context, next update.State, mutate func(*store.UpdateStateRow), ev store.UpdateEventRow) error
	SchemaVersion(ctx context.Context) (int, error)
	SnapshotDatabase(ctx context.Context, dest string) error
}

// applyDeps is everything the apply reaches the world through. Every field
// is injected; this file resolves nothing from the environment on its own.
type applyDeps struct {
	// Store is the node's update state and ledger.
	Store updateStateStore
	// Quiescence is the ONE drain seam (proxy admission + live PTYs). Nil
	// means nothing to drain, which is the truth on a CLI-driven apply with
	// no daemon running.
	Quiescence *quiesce.Quiescence
	// Download streams one artifact from the ORG MIRROR ONLY (ruling R8: a
	// node never contacts GitHub, npm or a CDN as part of an update).
	Download func(ctx context.Context, version, filename string, dst io.Writer, maxBytes int64) error
	// VerifyVendorSignature checks the artifact bytes against the
	// compiled-in vendor key. It returns an error for a bad signature and
	// update.ErrNoVendorKey when this build carries no real key yet.
	VerifyVendorSignature func(archivePath string, a update.Artifact) error
	// Probe runs the staged binary with --version and returns what it said.
	Probe func(ctx context.Context, binPath string) (string, error)
	// Supervise is the fork-exec-and-watch handshake (§3.7 step 7).
	Supervise func(ctx context.Context, exePath, stateDir string, timeout time.Duration) (handshakeResult, error)
	// FS is the swap seam.
	FS swapFS
	// GOOS selects the swap strategy.
	GOOS string
	// CloseDB closes the *sql.DB this process holds on the LIVE agent
	// database, and ReopenStore opens a fresh handle on whatever file is at
	// that path afterwards.
	//
	// They exist for exactly one step: restoring the pre-apply snapshot over
	// the live database. restoreDatabaseSnapshot renames the migrated file
	// aside and moves the snapshot in, and a process that keeps its old
	// handle open goes on writing to an ORPHANED INODE — the watcher and the
	// ingest path appending rows to observer.db.failed-update while hook
	// processes, which open by path, write to the restored file. The
	// discarded window would then be "until the operator notices" rather
	// than the drain-plus-handshake ruling R15 promises.
	//
	// Nil on a caller with no database handle of its own. Both are called
	// ONLY on the DB-restoring rollback branch, never on the happy path.
	CloseDB     func() error
	ReopenStore func() (updateStateStore, error)
	// FreeBytes reports the space available on the filesystem holding a
	// path, for the §2.4 headroom gate. Nil (or an error) SKIPS the check —
	// a platform with no portable free-space syscall must not have every
	// apply refused on a number it cannot read.
	FreeBytes func(path string) (uint64, error)
	// Now is the clock.
	Now func() time.Time
	// Logger is optional.
	Logger *slog.Logger
}

// applyOptions is one apply request.
type applyOptions struct {
	// Manifest is the VERIFIED manifest and Artifact the row selected for
	// this platform. Verification has already happened
	// (internal/orgclient/update.go runs update.Verify); this file never
	// re-decides trust, it re-checks BYTES.
	Manifest update.Manifest
	Artifact update.Artifact
	// Installed describes the running binary.
	Installed update.Installed
	// StateDir is [update].state_dir.
	StateDir string
	// Window is the node's local maintenance window.
	Window update.Window
	// Force ignores the window and, INSIDE an admin maintenance window,
	// permits an apply with a live dashboard PTY. It never shortens the
	// drain and never skips verification.
	Force bool
	// InAdminWindow reports whether the org's rollout window currently
	// permits an apply. Force + InAdminWindow together are what §3.7
	// requires before a live PTY is run over.
	InAdminWindow bool
	// DryRun prints the plan and performs nothing.
	DryRun bool
	// DrainTimeout / HandshakeTimeout are the two budgets.
	DrainTimeout     time.Duration
	HandshakeTimeout time.Duration
	// MaxDownloadBytes is [update].max_download_bytes, the ceiling applied
	// ON TOP of the artifact's own declared size.
	MaxDownloadBytes int64
	// TargetSchemaVersion is the target binary's schema version when known;
	// zero means unknown, which BuildApplyPlan treats as "may advance".
	TargetSchemaVersion int
	// AllowDowngrade is [update].allow_downgrade — node consent for an
	// admin-minted downgrade manifest.
	AllowDowngrade bool
	// DBPath is the live agent database. It is needed ONLY on the rollback
	// path, to restore the pre-apply snapshot over it, and it is passed
	// explicitly rather than resolved here because a snapshot restored over
	// the wrong file is unrecoverable.
	DBPath string
}

// applyOutcome is what the caller reports and the ledger records.
type applyOutcome struct {
	State      update.State
	Reason     update.Reason
	ErrorClass update.ErrorClass
	// Detail is operator-facing and MAY name a local path. It never leaves
	// the node: the org-bound posture carries State/Reason/ErrorClass only.
	Detail string
	// Steps is the dry-run plan.
	Steps []string
	// Applied reports that the handshake succeeded and the CALLER MUST NOW
	// EXIT — the child is the daemon.
	Applied bool
	// RolledBack / Deferred describe the two non-failure endings.
	RolledBack bool
	Deferred   bool
	// DiscardedWindowFrom names the snapshot whose successor rows were
	// discarded by a rollback, so `observer update history` can state the
	// data window honestly (ruling R15).
	DiscardedWindowFrom time.Time
	// Accepted reports that the daemon TOOK the request and is running the
	// apply off the request goroutine; EventID is the update_events row that
	// records the acceptance, so the caller can follow it in
	// `observer update history`.
	//
	// They exist because an apply is a drain plus a handshake — minutes on a
	// slow child — and holding the HTTP request open for it made the
	// dashboard's own 5s Shutdown budget able to kill the supervising parent
	// mid-handshake. The request lifecycle and the handshake are now separate
	// things, which is what they always were.
	Accepted bool
	EventID  int64
}

// errNoVendorKeyLocal mirrors the "this build cannot verify a vendor
// signature yet" condition without importing a symbol internal/update does
// not export. It is compared by errors.Is at the one call site.
var errNoVendorKeyLocal = errors.New("no vendor artifact-verification key is compiled into this build")

// errUnsupportedSigTypeLocal marks an artifact whose declared
// upstream_sig_type is a scheme this agent does not implement. The manifest
// validator no longer accepts any such scheme, so this fires only on a
// manifest cached before that was true, or on a hand-edited row. Like
// errNoVendorKeyLocal it maps to blocked{unsigned_artifact}, because it is a
// CANNOT-verify, not a failed-verify.
var errUnsupportedSigTypeLocal = errors.New("the artifact's vendor signature scheme is not one this build can verify")

// applyRun is ONE apply in progress: the injected world, the request, the
// plan built from them, and the clock every ledger row is stamped with. The
// §3.7 steps are methods on it, so each phase is a function of a stated size
// and every fail-closed exit has the same shape.
//
// A phase returns (outcome, done, err). done means the apply ENDED in that
// phase — deferred, failed or applied — and the sequence stops; the outcome
// and error are then the caller's, unchanged.
type applyRun struct {
	deps    applyDeps
	opts    applyOptions
	plan    update.ApplyPlan
	now     func() time.Time
	started time.Time
}

// applyStage is what step 5 stages before anything on the live path is
// touched: the schema version to roll back TO, and the pre-apply database
// snapshot (empty when the plan needs none).
type applyStage struct {
	schemaBefore int
	snapshotPath string
	snapshotAt   time.Time
}

// runUpdateApply performs §3.7 steps 0-8.
func runUpdateApply(ctx context.Context, deps applyDeps, opts applyOptions) (applyOutcome, error) {
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	r := &applyRun{deps: deps, opts: opts, now: now, started: now()}

	plan, err := update.BuildApplyPlan(update.PlanInput{
		Installed:           opts.Installed,
		Manifest:            opts.Manifest,
		Artifact:            opts.Artifact,
		TargetSchemaVersion: opts.TargetSchemaVersion,
		StateDir:            opts.StateDir,
		Now:                 now(),
		Window:              opts.Window,
		Force:               opts.Force,
	})
	if err != nil {
		return applyOutcome{}, err
	}
	r.plan = plan

	// Steps 0: the gates that answer before a byte is downloaded.
	if out, done, gerr := r.gate(ctx); done {
		return out, gerr
	}

	// The staged binary now lives BESIDE the installed executable (so the
	// swap's rename never crosses a filesystem). That makes cleaning it up
	// this function's job on every exit that is not a completed swap: a
	// dotted, version-stamped leftover in /usr/local/bin is ours, and
	// state_dir retention will never see it.
	defer func() {
		if _, err := os.Stat(r.plan.StagedBinaryPath); err == nil {
			_ = os.Remove(r.plan.StagedBinaryPath)
		}
	}()

	// Steps 1-4: fetch, verify, extract, probe.
	if out, done, ferr := r.fetchAndVerify(ctx); done {
		return out, ferr
	}

	// Step 4a: the bounded drain. resume() is deferred immediately and
	// unconditionally — ruling R13's guarantee is that a node is never left
	// refusing traffic because an apply gave up, and a defer is the only
	// version of that guarantee an early return cannot skip. It is deferred
	// HERE, in the function that owns the rest of the sequence, so the
	// guarantee covers every later exit too.
	res, resume, derr := r.deps.Quiescence.Drain(ctx, quiesce.DrainOptions{
		Timeout:  r.opts.DrainTimeout,
		Force:    r.opts.Force,
		InWindow: r.opts.InAdminWindow,
	})
	defer resume()
	if out, done, qerr := r.afterDrain(ctx, res, derr); done {
		return out, qerr
	}

	// Step 5: stage the rollback WHILE QUIESCED.
	stage, out, done, serr := r.stageRollback(ctx)
	if done {
		return out, serr
	}

	// Steps 6-8: swap, hand over, and — if the child does not come up —
	// roll back while this process is still alive to do it.
	return r.swapAndHandshake(ctx, stage)
}

// gate runs the step-0 refusals: a blocked plan, a downgrade without consent,
// an artifact with no vendor signature, the dry-run print, and the disk
// headroom check. Each one ends the apply before anything is downloaded.
func (r *applyRun) gate(ctx context.Context) (applyOutcome, bool, error) {
	// A blocked plan is a DEFER, not an error: "this node cannot self-apply"
	// is a fleet fact the admin must see on the board, not a fault the
	// operator must clear.
	if r.plan.Blocked {
		out := applyOutcome{
			State: r.plan.State, Reason: r.plan.Reason, Detail: r.plan.Advice,
			Steps: r.plan.Steps, Deferred: true,
		}
		return out, true, r.record(ctx, out)
	}

	// Downgrade refusal, re-checked HERE and not only at fetch time (§3.2
	// rule 7, the TUF rollback defence). update.Verify already applied it to
	// the manifest when the rail accepted it, but an apply can also run from
	// a manifest CACHED in update_state — by `observer update apply` on a
	// node whose daemon is not running, or after a restart — and a rule that
	// only guards one of the two entry points is not a rule. A downgrade
	// happens ONLY through an admin-minted manifest naming the exact target
	// in allow_downgrade_to, AND node consent.
	if !update.IsUpdateAvailable(r.opts.Installed.Version, r.plan.TargetVersion) {
		consented := r.opts.AllowDowngrade &&
			strings.TrimSpace(r.opts.Manifest.AllowDowngradeTo) != "" &&
			strings.TrimSpace(r.opts.Manifest.AllowDowngradeTo) == strings.TrimSpace(r.plan.TargetVersion)
		if !consented {
			out := applyOutcome{
				State: update.StateBlocked, Reason: update.ReasonDowngrade, Deferred: true,
				Detail: fmt.Sprintf("manifest %d targets %s, which is not newer than the installed %s; a downgrade needs an admin-minted allow_downgrade_to naming it AND [update].allow_downgrade on this node",
					r.opts.Manifest.ManifestVersion, r.plan.TargetVersion, r.opts.Installed.Version),
				Steps: r.plan.Steps,
			}
			return out, true, r.record(ctx, out)
		}
	}

	// The vendor-signature gate runs BEFORE the download, deliberately: an
	// artifact with no vendor signature must be refused "without downloading
	// a second byte" (§4 W3). Until the W6 release pipeline produces those
	// signatures this is the fail-closed interim that keeps the
	// two-signature claim from quietly becoming one.
	if strings.TrimSpace(r.opts.Artifact.UpstreamSig) == "" {
		out := applyOutcome{
			State: update.StateBlocked, Reason: update.ReasonUnsignedArtifact, Deferred: true,
			Detail: fmt.Sprintf("artifact %s carries no vendor signature; refusing to apply an artifact this node cannot independently verify",
				r.opts.Artifact.Filename),
			Steps: r.plan.Steps,
		}
		return out, true, r.record(ctx, out)
	}

	if r.opts.DryRun {
		return applyOutcome{State: update.StateAvailable, Steps: r.plan.Steps}, true, nil
	}

	// §2.4's disk-headroom gate, run BEFORE a byte is downloaded rather than
	// only before step 5: both the archive and the VACUUM INTO snapshot land
	// under state_dir, so one check answers for both, and refusing early
	// costs the mirror nothing. This is the 2026-08-26 disk-exhaustion
	// audit's rule applied to the update path — a full-file rewrite is never
	// started on a filesystem that cannot hold it.
	if out, ok := headroomBlock(r.deps, r.opts, r.plan); ok {
		return out, true, r.record(ctx, out)
	}
	return applyOutcome{}, false, nil
}

// fetchAndVerify runs §3.7 steps 1-4: download to an O_EXCL .part under the
// declared ceiling, hash the ARCHIVE against the SIGNED manifest, verify the
// vendor signature over those bytes, extract the ONE named member, hash it,
// and PROBE it. Nothing here has touched the live path, so every doubt is a
// plain failure.
func (r *applyRun) fetchAndVerify(ctx context.Context) (applyOutcome, bool, error) {
	if err := os.MkdirAll(filepath.Dir(r.plan.PartialPath), 0o755); err != nil {
		out, oerr := r.fail(ctx, update.ErrorPermission, fmt.Sprintf("creating the staging directory: %v", err))
		return out, true, oerr
	}
	ceiling := r.plan.MaxBytes
	if r.opts.MaxDownloadBytes > 0 && (ceiling <= 0 || r.opts.MaxDownloadBytes < ceiling) {
		ceiling = r.opts.MaxDownloadBytes
	}
	if err := downloadArtifact(ctx, r.deps, r.opts, r.plan, ceiling); err != nil {
		out, oerr := r.fail(ctx, update.ErrorDownload, err.Error())
		return out, true, oerr
	}
	sum, err := sha256File(r.plan.DownloadPath)
	if err != nil {
		out, oerr := r.fail(ctx, update.ErrorHash, err.Error())
		return out, true, oerr
	}
	if !strings.EqualFold(sum, r.plan.ExpectedArchiveSHA256) {
		_ = os.Remove(r.plan.DownloadPath)
		out, oerr := r.fail(ctx, update.ErrorHash,
			fmt.Sprintf("archive sha256 %s does not match the signed manifest; the download was discarded", sum))
		return out, true, oerr
	}

	if out, done, verr := r.verifyVendorSignature(ctx); done {
		return out, true, verr
	}

	memberSum, err := extractMember(r.plan.DownloadPath, r.plan.StagedBinaryPath, r.opts.Artifact)
	if err != nil {
		out, oerr := r.fail(ctx, update.ErrorHash, err.Error())
		return out, true, oerr
	}
	if !strings.EqualFold(memberSum, r.plan.ExpectedMemberSHA256) {
		_ = os.Remove(r.plan.StagedBinaryPath)
		out, oerr := r.fail(ctx, update.ErrorHash,
			fmt.Sprintf("member sha256 %s does not match the signed manifest", memberSum))
		return out, true, oerr
	}
	if out, done, perr := r.probeStagedBinary(ctx); done {
		return out, true, perr
	}
	if err := markState(ctx, r.deps, update.StateDownloading, r.opts, r.plan, ""); err != nil {
		return applyOutcome{}, true, err
	}
	if err := markState(ctx, r.deps, update.StateVerified, r.opts, r.plan,
		"archive, vendor signature, member hash and --version probe all verified"); err != nil {
		return applyOutcome{}, true, err
	}
	return applyOutcome{}, false, nil
}

// verifyVendorSignature is §3.7 step 3: the vendor signature over the archive
// bytes, verified offline against the compiled-in public key. A compromised
// mirror can then deny service but cannot substitute a binary.
func (r *applyRun) verifyVendorSignature(ctx context.Context) (applyOutcome, bool, error) {
	if r.deps.VerifyVendorSignature == nil {
		return applyOutcome{}, false, nil
	}
	verr := r.deps.VerifyVendorSignature(r.plan.DownloadPath, r.opts.Artifact)
	if verr == nil {
		return applyOutcome{}, false, nil
	}
	_ = os.Remove(r.plan.DownloadPath)
	if errors.Is(verr, errNoVendorKeyLocal) {
		out := applyOutcome{
			State: update.StateBlocked, Reason: update.ReasonUnsignedArtifact, Deferred: true,
			Detail: "this build carries no vendor artifact-verification key yet, so the artifact's signature cannot be checked; refusing to apply rather than trusting the mirror alone",
		}
		return out, true, r.record(ctx, out)
	}
	if errors.Is(verr, errUnsupportedSigTypeLocal) {
		// CANNOT verify, not FAILED to verify — the same distinction the
		// no-key branch draws, and for the same reason: an admin staring at
		// the fleet board must be able to tell "your release was signed with
		// a scheme this agent does not implement" apart from "the signature
		// is wrong".
		out := applyOutcome{
			State: update.StateBlocked, Reason: update.ReasonUnsignedArtifact, Deferred: true,
			Detail: verr.Error(),
		}
		return out, true, r.record(ctx, out)
	}
	out, oerr := r.fail(ctx, update.ErrorSignature, verr.Error())
	return out, true, oerr
}

// probeStagedBinary is the acceptance gate the VS Code extension already
// applies to a cached binary: a file that hashes correctly but does not run,
// or that reports a different version, is still not something to swap in.
func (r *applyRun) probeStagedBinary(ctx context.Context) (applyOutcome, bool, error) {
	if r.deps.Probe == nil {
		return applyOutcome{}, false, nil
	}
	got, perr := r.deps.Probe(ctx, r.plan.StagedBinaryPath)
	if perr != nil {
		_ = os.Remove(r.plan.StagedBinaryPath)
		out, oerr := r.fail(ctx, update.ErrorProbe, fmt.Sprintf("probing the staged binary: %v", perr))
		return out, true, oerr
	}
	if !versionProbeMatches(got, r.plan.TargetVersion) {
		_ = os.Remove(r.plan.StagedBinaryPath)
		out, oerr := r.fail(ctx, update.ErrorProbe,
			fmt.Sprintf("the staged binary reports version %q, not the target %q", strings.TrimSpace(got), r.plan.TargetVersion))
		return out, true, oerr
	}
	return applyOutcome{}, false, nil
}

// afterDrain turns the drain's outcome into the apply's. Live work inside the
// window is a DEFER (the owners get warned first); a timeout or any other
// drain fault is a failure with admission already restored by the caller's
// deferred resume().
func (r *applyRun) afterDrain(ctx context.Context, res quiesce.Result, derr error) (applyOutcome, bool, error) {
	switch {
	case derr != nil && errors.Is(derr, quiesce.ErrLiveWork):
		out := applyOutcome{
			State: update.StateAvailable, Reason: update.ReasonWindow, Deferred: true,
			Detail: fmt.Sprintf("deferred: %s still live (use --force inside a maintenance window to proceed after warning the owners)",
				strings.Join(res.Busy, ", ")),
		}
		return out, true, r.record(ctx, out)
	case derr != nil && errors.Is(derr, quiesce.ErrDrainTimeout):
		out, oerr := r.fail(ctx, update.ErrorDrain,
			fmt.Sprintf("%d proxied request(s) were still in flight after %s; admission has been restored and the apply was abandoned",
				res.InFlight, r.opts.DrainTimeout))
		return out, true, oerr
	case derr != nil:
		out, oerr := r.fail(ctx, update.ErrorDrain, derr.Error())
		return out, true, oerr
	}
	return applyOutcome{}, false, nil
}

// stageRollback is §3.7 step 5: preserve the running binary and, when the
// target advances the schema, snapshot the database — all WHILE QUIESCED and
// BEFORE anything on the live path is touched.
func (r *applyRun) stageRollback(ctx context.Context) (applyStage, applyOutcome, bool, error) {
	var stage applyStage
	if err := preserveExecutable(r.opts.Installed.ExecPath, r.plan.RollbackBinaryPath); err != nil {
		out, oerr := r.fail(ctx, update.ErrorPermission, err.Error())
		return stage, out, true, oerr
	}
	schemaBefore, err := r.deps.Store.SchemaVersion(ctx)
	if err != nil {
		out, oerr := r.fail(ctx, update.ErrorPermission, err.Error())
		return stage, out, true, oerr
	}
	stage.schemaBefore = schemaBefore
	if r.plan.NeedsDBSnapshot {
		if err := r.deps.Store.SnapshotDatabase(ctx, r.plan.DBBackupPath); err != nil {
			// A snapshot that cannot be written ABORTS the apply before the
			// live path is touched. Proceeding would put the node one
			// migration away from a state no rollback could undo.
			out, oerr := r.fail(ctx, update.ErrorPermission,
				fmt.Sprintf("the pre-apply database snapshot could not be written, so the apply was abandoned before touching the running binary: %v", err))
			return stage, out, true, oerr
		}
		stage.snapshotPath = r.plan.DBBackupPath
		stage.snapshotAt = r.now()
	}
	if err := markApplying(ctx, r.deps, r.opts, r.plan, stage.schemaBefore, stage.snapshotPath, r.now()); err != nil {
		return stage, applyOutcome{}, true, err
	}
	return stage, applyOutcome{}, false, nil
}

// swapAndHandshake is §3.7 steps 6-8: the atomic swap, the
// fork-exec-and-watch handover, and — when the child does not come up — the
// rollback the STILL-ALIVE parent performs.
func (r *applyRun) swapAndHandshake(ctx context.Context, stage applyStage) (applyOutcome, error) {
	if _, err := swapBinary(r.deps.FS, r.deps.GOOS, r.plan.StagedBinaryPath, r.opts.Installed.ExecPath,
		r.plan.RollbackBinaryPath, r.opts.Installed.Version); err != nil {
		return r.fail(ctx, update.ErrorSwap, err.Error())
	}

	hs, herr := r.deps.Supervise(ctx, r.opts.Installed.ExecPath, r.opts.StateDir, r.opts.HandshakeTimeout)
	if herr == nil && hs.Ready {
		out := applyOutcome{
			State: update.StateApplied, Applied: true,
			Detail: fmt.Sprintf("%s -> %s: %s (child pid %d)", r.opts.Installed.Version, r.plan.TargetVersion, hs.Detail, hs.ChildPID),
		}
		if err := markApplied(ctx, r.deps, r.opts, r.plan, r.now()); err != nil {
			return out, err
		}
		_ = r.deps.Store.AppendUpdateEvent(ctx, store.UpdateEventRow{
			At: r.now(), FromVersion: r.opts.Installed.Version, ToVersion: r.plan.TargetVersion,
			ManifestVersion: r.opts.Manifest.ManifestVersion, State: update.StateApplied,
			Detail: out.Detail, DurationMS: r.now().Sub(r.started).Milliseconds(),
		})
		return out, nil
	}

	// Step 8: the child failed, exited or hung — and the OLD process is
	// still alive to act on it.
	return rollbackAfterFailedHandshake(ctx, r.deps, r.opts, r.plan, stage.schemaBefore,
		stage.snapshotPath, stage.snapshotAt, hs.Detail, r.started)
}

// record writes one outcome to the ledger. It is the run-scoped spelling of
// recordOutcome, so a phase never has to carry `started` around by hand.
func (r *applyRun) record(ctx context.Context, out applyOutcome) error {
	return recordOutcome(ctx, r.deps, r.opts, out, r.started)
}

// fail is the run-scoped spelling of failOutcome.
func (r *applyRun) fail(ctx context.Context, class update.ErrorClass, detail string) (applyOutcome, error) {
	return failOutcome(ctx, r.deps, r.opts, class, detail, r.started)
}

// rollbackAfterFailedHandshake is §3.7 step 8. It is reached from all three
// failure shapes — a failed self-check, an exit before the self-check, and a
// silent hang — because the parent's response to each is identical.
func rollbackAfterFailedHandshake(
	ctx context.Context, deps applyDeps, opts applyOptions, plan update.ApplyPlan,
	schemaBefore int, snapshotPath string, snapshotAt time.Time, detail string, started time.Time,
) (applyOutcome, error) {
	// No clock is resolved here on purpose: every timestamp this step reports
	// was taken BEFORE the swap (snapshotAt) or is stamped by recordOutcome
	// from the run's own clock. Reading deps.Now here only ever produced an
	// unused local.
	schemaNow, err := deps.Store.SchemaVersion(ctx)
	if err != nil {
		schemaNow = schemaBefore
	}
	decision := update.DecideRollback(update.RollbackInput{
		State:                 update.StateApplying,
		HasPreviousBinary:     fileExists(plan.RollbackBinaryPath),
		PreviousSchemaVersion: schemaBefore,
		CurrentSchemaVersion:  schemaNow,
		HasDBBackup:           snapshotPath != "" && fileExists(snapshotPath),
	})

	if decision.Refuse {
		out := applyOutcome{
			State: decision.State, ErrorClass: decision.ErrorClass,
			Detail: fmt.Sprintf("%s; %s", detail, decision.Reason),
		}
		return out, recordOutcome(ctx, deps, opts, out, started)
	}

	if decision.RestoreBinary {
		if err := restoreBinary(deps.FS, deps.GOOS, plan.RollbackBinaryPath, opts.Installed.ExecPath, opts.Installed.Version); err != nil {
			out := applyOutcome{
				State: update.StateFailed, ErrorClass: update.ErrorSwap,
				Detail: fmt.Sprintf("%s; restoring the previous binary FAILED: %v (it is preserved at %s)", detail, err, plan.RollbackBinaryPath),
			}
			return out, recordOutcome(ctx, deps, opts, out, started)
		}
	}
	if decision.RestoreDB {
		// CLOSE FIRST. The next two lines rename the live database aside and
		// move the snapshot in; a handle still open on the old inode would
		// keep this process writing into observer.db.failed-update while
		// every hook process (which opens by path) wrote to the restored
		// file. A failure to close is not a reason to skip the restore — the
		// node would then be running an older binary against a migrated
		// schema — so it is logged and the restore proceeds.
		if deps.CloseDB != nil {
			if cerr := deps.CloseDB(); cerr != nil && deps.Logger != nil {
				deps.Logger.Warn("update: closing the database before restoring the snapshot failed", "err", cerr)
			}
		}
		if err := restoreDatabaseSnapshot(snapshotPath, opts.DBPath); err != nil {
			out := applyOutcome{
				State: update.StateFailed, ErrorClass: update.ErrorHealthcheck,
				Detail: fmt.Sprintf("%s; the previous binary was restored but the database snapshot could not be: %v (it is preserved at %s)",
					detail, err, snapshotPath),
			}
			deps.Store = reopenedStore(deps)
			return out, recordOutcome(ctx, deps, opts, out, started)
		}
		// The ledger row for THIS rollback must land in the file that
		// survives it. The migrated database is gone; anything written
		// before the rename went with it. So the outcome below is recorded
		// through a handle on the RESTORED file, and a node whose reopen
		// fails records nothing rather than pretending it did.
		deps.Store = reopenedStore(deps)
	}

	out := applyOutcome{
		State: decision.State, ErrorClass: decision.ErrorClass, RolledBack: true,
		Detail: fmt.Sprintf("%s; %s", detail, decision.Reason),
	}
	if decision.DiscardsDataWindow {
		out.DiscardedWindowFrom = snapshotAt
		out.Detail += fmt.Sprintf(" (rows ingested after %s were discarded)", snapshotAt.UTC().Format(time.RFC3339))
	}
	return out, recordOutcome(ctx, deps, opts, out, started)
}

// downloadArtifact streams to an O_EXCL .part and renames on success, so a
// half-downloaded file can never be mistaken for a complete artifact by a
// retry.
func downloadArtifact(ctx context.Context, deps applyDeps, opts applyOptions, plan update.ApplyPlan, ceiling int64) error {
	if deps.Download == nil {
		return errors.New("no artifact source is wired; updates are served only by the org server this node is enrolled with")
	}
	if err := os.Remove(plan.PartialPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clearing %s: %w", plan.PartialPath, err)
	}
	f, err := os.OpenFile(plan.PartialPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", plan.PartialPath, err)
	}
	derr := deps.Download(ctx, opts.Manifest.Version, opts.Artifact.Filename, f, ceiling)
	closeErr := f.Close()
	if derr != nil {
		_ = os.Remove(plan.PartialPath)
		return derr
	}
	if closeErr != nil {
		_ = os.Remove(plan.PartialPath)
		return closeErr
	}
	if err := os.Remove(plan.DownloadPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clearing %s: %w", plan.DownloadPath, err)
	}
	if err := os.Rename(plan.PartialPath, plan.DownloadPath); err != nil {
		_ = os.Remove(plan.PartialPath)
		return fmt.Errorf("publishing the download: %w", err)
	}
	return nil
}

// versionProbeMatches compares a --version line against the target.
//
// It matches on the version TOKEN rather than on an exact string, because
// `observer --version` prints a sentence and a future release may print a
// different one. What must not be tolerated is a probe that reports a
// DIFFERENT version — that is the mismatch the gate exists for.
//
// So the rule is not "the target appears somewhere": it is "every
// version-shaped token in the output IS the target". An output that names the
// target AND another version ("observer v1.32.0 (v1.33.0 available)") is
// exactly the shape a loose contains-check would wave through, and it is
// precisely the case where the staged binary is not what the manifest says.
func versionProbeMatches(got, target string) bool {
	got = strings.TrimSpace(got)
	target = strings.TrimSpace(target)
	if got == "" || target == "" {
		return false
	}
	if got == target {
		return true
	}
	bare := strings.TrimPrefix(target, "v")
	matched := false
	for _, field := range strings.Fields(strings.ReplaceAll(got, "\n", " ")) {
		f := strings.Trim(field, "\"',;()[]")
		if !looksLikeVersionToken(f) {
			continue
		}
		if f == target || f == bare {
			matched = true
			continue
		}
		// A version-shaped token that is NOT the target: refuse, whatever
		// else the output says.
		return false
	}
	return matched
}

// looksLikeVersionToken reports whether s is shaped like a semver token
// ("v1.33.0", "1.33.0", "1.33.0-rc.1"). Deliberately shape-only: it decides
// what versionProbeMatches is allowed to IGNORE, so anything it misclassifies
// as prose is simply not evidence either way.
func looksLikeVersionToken(s string) bool {
	s = strings.TrimPrefix(s, "v")
	if s == "" || !strings.Contains(s, ".") {
		return false
	}
	if s[0] < '0' || s[0] > '9' {
		return false
	}
	digits, dots := 0, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '.':
			dots++
		}
	}
	return digits >= 2 && dots >= 1
}

// restoreDatabaseSnapshot puts the pre-apply snapshot back over the live
// database.
//
// The live file is renamed aside first rather than deleted: if the rename-in
// then fails, the node still has a database, and an operator has both files.
func restoreDatabaseSnapshot(snapshotPath, dbPath string) error {
	if strings.TrimSpace(snapshotPath) == "" {
		return errors.New("no snapshot path recorded")
	}
	if strings.TrimSpace(dbPath) == "" {
		return errors.New("no database path recorded, so the snapshot cannot be restored automatically")
	}
	aside := dbPath + ".failed-update"
	if err := os.Remove(aside); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clearing %s: %w", aside, err)
	}
	if err := os.Rename(dbPath, aside); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("moving the migrated database aside: %w", err)
	}
	if err := os.Rename(snapshotPath, dbPath); err != nil {
		_ = os.Rename(aside, dbPath)
		return fmt.Errorf("restoring the snapshot: %w", err)
	}
	// WAL and SHM belong to the file that is now gone; leaving them would
	// let SQLite replay a journal from a database that no longer exists.
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(dbPath + suffix)
	}
	return nil
}

// reopenedStore returns a handle on the database that is at DBPath NOW, or
// nil when this caller has no way to open one.
//
// nil is a real answer, not a failure: recordOutcome already treats a nil
// store as "nothing to record", which is the honest state after a snapshot
// restore whose reopen failed — better than writing the rollback's own ledger
// row into a file that has just been renamed aside.
func reopenedStore(deps applyDeps) updateStateStore {
	if deps.ReopenStore == nil {
		return nil
	}
	st, err := deps.ReopenStore()
	if err != nil {
		if deps.Logger != nil {
			deps.Logger.Warn("update: reopening the restored database failed; this rollback is not recorded in the ledger", "err", err)
		}
		return nil
	}
	return st
}

// headroomMultiplier is §2.4's "3x the archive size": one for the downloaded
// archive, one for the extracted member, one for the slack an extraction and a
// rename need on a filesystem that is not empty.
const headroomMultiplier = 3

// headroomBlock is the §2.4 disk-headroom gate.
//
// It is a DEFER (blocked + a reason), never an error: "this node does not have
// room for the update" is a fleet fact an admin acts on, exactly like an
// install method that cannot self-apply. It answers (out, false) — proceed —
// whenever it cannot read a number, because a platform with no portable
// free-space syscall must not have every apply refused on a guess.
func headroomBlock(deps applyDeps, opts applyOptions, plan update.ApplyPlan) (applyOutcome, bool) {
	if deps.FreeBytes == nil || plan.MaxBytes <= 0 {
		return applyOutcome{}, false
	}
	dir := opts.StateDir
	if strings.TrimSpace(dir) == "" {
		return applyOutcome{}, false
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return applyOutcome{}, false
	}
	free, err := deps.FreeBytes(dir)
	if err != nil {
		return applyOutcome{}, false
	}
	need := plan.MaxBytes * headroomMultiplier
	dbBytes := int64(0)
	if plan.NeedsDBSnapshot {
		if info, serr := os.Stat(opts.DBPath); serr == nil {
			dbBytes = info.Size()
			need += dbBytes
		}
	}
	if free >= uint64(need) {
		return applyOutcome{}, false
	}
	detail := fmt.Sprintf(
		"not enough free space under %s: the apply needs about %d MB (%dx the %d MB archive",
		dir, need>>20, headroomMultiplier, plan.MaxBytes>>20)
	if dbBytes > 0 {
		detail += fmt.Sprintf(" plus a %d MB database snapshot", dbBytes>>20)
	}
	detail += fmt.Sprintf(") and %d MB is available", free>>20)
	return applyOutcome{
		State: update.StateBlocked, Reason: update.ReasonNoDiskSpace, Deferred: true,
		Detail: detail, Steps: plan.Steps,
	}, true
}

// fileExists is the one stat this file performs on its own behalf.
func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// markState moves the node forward through the state machine.
func markState(ctx context.Context, deps applyDeps, next update.State, opts applyOptions, plan update.ApplyPlan, detail string) error {
	return moveUpdateState(ctx, deps.Store, next, func(row *store.UpdateStateRow) {
		row.TargetVersion = plan.TargetVersion
		row.LastManifestVersion = opts.Manifest.ManifestVersion
		row.Channel = opts.Manifest.Channel
		row.Reason = ""
		row.ErrorClass = ""
	}, store.UpdateEventRow{
		FromVersion: opts.Installed.Version, ToVersion: plan.TargetVersion,
		ManifestVersion: opts.Manifest.ManifestVersion, State: next, Detail: detail,
	})
}

// markApplying writes the rollback triple. Everything a restore needs is on
// disk and in the row BEFORE the swap, because the process that performs the
// restore may not be the process that planned it.
func markApplying(ctx context.Context, deps applyDeps, opts applyOptions, plan update.ApplyPlan, schemaBefore int, snapshotPath string, at time.Time) error {
	return moveUpdateState(ctx, deps.Store, update.StateApplying, func(row *store.UpdateStateRow) {
		row.TargetVersion = plan.TargetVersion
		row.PreviousVersion = opts.Installed.Version
		row.PreviousBinaryPath = plan.RollbackBinaryPath
		row.PreviousSchemaVersion = schemaBefore
		row.PreviousDBBackupPath = snapshotPath
		row.ApplyingStartedAt = at.UTC().Format(time.RFC3339)
		row.Reason = ""
		row.ErrorClass = ""
	}, store.UpdateEventRow{
		FromVersion: opts.Installed.Version, ToVersion: plan.TargetVersion,
		ManifestVersion: opts.Manifest.ManifestVersion, State: update.StateApplying,
		Detail: applyingDetail(plan, schemaBefore, snapshotPath),
	})
}

// applyingDetail names the snapshot in the ledger, so the discarded window is
// recoverable from history rather than from memory.
func applyingDetail(plan update.ApplyPlan, schemaBefore int, snapshotPath string) string {
	if snapshotPath == "" {
		return fmt.Sprintf("quiesced; rollback staged at %s; schema %d (no snapshot: the target does not advance it)",
			plan.RollbackBinaryPath, schemaBefore)
	}
	return fmt.Sprintf("quiesced; rollback staged at %s; schema %d; pre-apply snapshot at %s",
		plan.RollbackBinaryPath, schemaBefore, snapshotPath)
}

// markApplied settles the row after a successful handshake.
func markApplied(ctx context.Context, deps applyDeps, opts applyOptions, plan update.ApplyPlan, at time.Time) error {
	row, err := deps.Store.LoadUpdateState(ctx)
	if err != nil {
		return err
	}
	row.State = update.StateApplied
	row.TargetVersion = plan.TargetVersion
	row.AppliedAt = at.UTC().Format(time.RFC3339)
	row.ApplyingStartedAt = ""
	row.ErrorClass = ""
	row.Reason = ""
	return deps.Store.SaveUpdateState(ctx, row)
}

// failOutcome records a failure and returns it.
func failOutcome(ctx context.Context, deps applyDeps, opts applyOptions, class update.ErrorClass, detail string, started time.Time) (applyOutcome, error) {
	out := applyOutcome{State: update.StateFailed, ErrorClass: class, Detail: detail}
	return out, recordOutcome(ctx, deps, opts, out, started)
}

// recordOutcome writes the terminal state and its ledger line.
//
// It never returns the storage error as the apply's error: an apply that
// succeeded and then failed to write its own ledger line has still succeeded,
// and reporting otherwise would make the caller roll back a good update.
func recordOutcome(ctx context.Context, deps applyDeps, opts applyOptions, out applyOutcome, started time.Time) error {
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	if deps.Store == nil {
		return nil
	}
	row, err := deps.Store.LoadUpdateState(ctx)
	if err == nil {
		row.State = out.State
		row.Reason = out.Reason
		row.ErrorClass = out.ErrorClass
		row.TargetVersion = opts.Manifest.Version
		row.LastManifestVersion = opts.Manifest.ManifestVersion
		if opts.Manifest.Channel != "" {
			row.Channel = opts.Manifest.Channel
		}
		row.ApplyingStartedAt = ""
		if serr := deps.Store.SaveUpdateState(ctx, row); serr != nil && deps.Logger != nil {
			deps.Logger.Warn("update: recording the outcome state failed", "err", serr)
		}
	}
	if aerr := deps.Store.AppendUpdateEvent(ctx, store.UpdateEventRow{
		At: now(), FromVersion: opts.Installed.Version, ToVersion: opts.Manifest.Version,
		ManifestVersion: opts.Manifest.ManifestVersion, State: out.State,
		ErrorClass: out.ErrorClass, Detail: out.Detail,
		DurationMS: now().Sub(started).Milliseconds(),
	}); aerr != nil && deps.Logger != nil {
		deps.Logger.Warn("update: recording the outcome event failed", "err", aerr)
	}
	return nil
}

// moveUpdateState walks the state machine, re-arming through `available`
// when the direct edge is not legal.
//
// The two-step is deliberate rather than a loosening. state.go makes every
// terminal state (applied / failed / rolled_back / blocked / stale_manifest)
// able to return to `available`, precisely so a LATER manifest can re-arm a
// node that already finished — or failed — an apply. Without this, the second
// apply on a node that succeeded once would be refused as an illegal
// applied -> downloading move, and the honest fix is to say what actually
// happened (a new manifest made an update available again) rather than to
// widen the transition table until nothing is illegal.
func moveUpdateState(ctx context.Context, st updateStateStore, next update.State, mutate func(*store.UpdateStateRow), ev store.UpdateEventRow) error {
	err := st.TransitionUpdateState(ctx, next, mutate, ev)
	if err == nil || next == update.StateAvailable {
		return err
	}
	if rearm := st.TransitionUpdateState(ctx, update.StateAvailable, nil, store.UpdateEventRow{
		State: update.StateAvailable, Detail: "re-armed: a newer manifest is available",
	}); rearm != nil {
		return err
	}
	return st.TransitionUpdateState(ctx, next, mutate, ev)
}
