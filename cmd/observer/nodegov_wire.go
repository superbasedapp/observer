package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/govern/sidecar"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/orgenrol"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Admin-controlled Plane B, the node-side install seam
// (docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §3, Phase 1a).
// This file is the direct structural peer of gatewayProvidersHandle in
// policyresource_wire.go: it is the ONE holder of the accepted
// node.governance resource's identity, the ONE reader of the enrolment
// grant, and the ONE place the two are intersected (through the pure
// internal/govern resolver) into the posture the dashboard enforces and the
// P0-6 reporter reports.
//
// Note what it is NOT: it never writes the grant (cmd/observer/org.go does,
// after a human confirms) and it never applies anything outside the
// dashboard surface (Phase 1a carries sections + notice only).

// governanceGrantRefreshInterval bounds how stale the in-memory grant may
// be. The grant is written by a SEPARATE process (`observer enroll`) while
// the daemon runs, so a purely event-driven cache would need a restart to
// notice a new grant; a bounded re-read costs one indexed SELECT per
// interval and removes that restart.
const governanceGrantRefreshInterval = 15 * time.Second

// sidecarRefreshInterval bounds how stale the sidecar's own written_at stamp
// may become. The daemon rewrites an UNCHANGED posture this often so
// written_at stays a meaningful liveness signal for `observer doctor
// governance`; a CHANGED posture is written immediately (§1.4).
const sidecarRefreshInterval = 5 * time.Minute

// sidecarWriteAttempts / sidecarWriteBackoff bound the brief retry the
// Windows case needs (review m4): os.Rename over an existing file works
// there, but can still fail ERROR_ACCESS_DENIED against an AV scanner or the
// search indexer holding the destination. On final failure the writer takes
// the §1.4.1 INERT path — never a daemon error, never a crash.
const (
	sidecarWriteAttempts = 3
	sidecarWriteBackoff  = 50 * time.Millisecond
)

// startupSidecar is the governance posture the RUNNING daemon process was
// actually built from — the sidecar its own startup config.Load consumed, or
// the zero value when there was none.
//
// It is what makes pending_restart reachable (§1.6 / review M3). The shipped
// Phase-1a point reader set CachedAcceptedVersion and RunningVersion to the
// same g.Version in both branches, so as-shipped the node would have
// reported `effective` the instant it wrote a sidecar carrying pins the
// running process had never read — precisely the overclaim Phase 1b exists
// to avoid.
type startupSidecar struct {
	Version int64
	Hash    string
	// PinnedHash is the content address of the PINNED MAP ALONE. Sections
	// and share stay HOT, so a body that changes only those converges to
	// `effective` without a restart; only a changed pinned map moves the
	// point to pending_restart.
	PinnedHash string
}

// startupSidecarFrom maps a config.GovernanceOutcome onto the daemon's
// running identity. It is the ONE mapper, so "what this process is built
// from" has a single definition.
func startupSidecarFrom(out config.GovernanceOutcome) startupSidecar {
	return startupSidecar{
		Version:    out.Version,
		Hash:       out.Hash,
		PinnedHash: governancePinnedHash(out.Pinned),
	}
}

// governancePinnedHash is the content address of a pinned map alone. Both
// sides of the pending_restart comparison go through it, so the comparison
// can never be a map-iteration-order accident.
//
// HOT keys (config.GovernanceHotKey — today only the push-interval ceiling)
// are left out: the daemon applies them live, so a changed value converges
// without a restart and must never move the point to pending_restart.
func governancePinnedHash(pinned map[string]any) string {
	keys := make([]string, 0, len(pinned))
	for k := range pinned {
		if config.GovernanceHotKey(k) {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		_, _ = fmt.Fprintf(h, "%s\x1e%v\x1e", k, pinned[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// nodeGovernanceState is the org-rail half of the truth: what the policy
// rail last DELIVERED and this node accepted. The grant half is loaded from
// the store; the intersection is computed on read, never stored, so grant
// expiry is decided by the clock at read time.
type nodeGovernanceState struct {
	delivered govern.Delivered
	// applyFailedVersion / applyRejectCode are unused in Phase 1a (applying
	// a section list cannot fail — there is nothing to realize beyond
	// storing it), and are deliberately absent rather than stubbed.
}

// nodeGovernanceHandle is the daemon-lifetime seam.
//
// A nil handle is a node with no governance wiring at all: every method is
// nil-safe and Effective returns the zero (dormant) posture, so a build or a
// code path that never constructs one behaves exactly like an ungranted
// node.
type nodeGovernanceHandle struct {
	mu    sync.Mutex
	state nodeGovernanceState

	grant       *govern.Grant
	live        govern.LiveIdentity
	lastRefresh time.Time

	// loadIdentity reads the grant + live enrolment identity from the store.
	// Injected so the handle unit-tests without a DB.
	loadIdentity func(ctx context.Context) (*govern.Grant, govern.LiveIdentity, error)
	now          func() time.Time
	logger       *slog.Logger

	// --- Phase 1b: the sidecar (§1.2/§1.4) ---

	// sidecarPath is where the daemon materializes the resolved posture.
	// Empty = no sidecar is written at all, which is the correct behaviour
	// for `observer dashboard` and for any build with no DB: ONE WRITER
	// (CLAUDE.md #4), and it is the daemon.
	sidecarPath string
	// writerVersion is stamped into the file for diagnostics only.
	writerVersion string
	// sidecarWriteErr is the §1.4.1 first-class INERT condition. Without it,
	// a node whose ~/.observer is read-only, whose filesystem is full, or
	// whose SELinux policy denies the write resolves StateApplied, returns an
	// empty InertReason, emits EnforceMode "enforce" — and acks EFFECTIVE
	// while NO PROCESS ON THE MACHINE CAN READ THE PINS. That is exactly the
	// false compliance claim Phase 1b exists to close, re-entering through
	// the back door.
	sidecarWriteErr error
	// lastWrittenHash / lastWrittenAt drive the change detection: a changed
	// posture is written immediately, an unchanged one is rewritten every
	// sidecarRefreshInterval so written_at stays a liveness signal.
	lastWrittenHash string
	lastWrittenAt   time.Time
	// startup is the posture the RUNNING process was built from (§1.6).
	startup startupSidecar
	// featureExceptions reports the verified feature-access grants lifting
	// pinned keys (request-grants G8, SetFeatureExceptions); nil = none.
	featureExceptions func(ctx context.Context, keys []string, now time.Time) map[string]sidecar.Exception
	// pageGrants reports the pages and tabs honoured page-access grants show
	// (T-435, SetPageGrants); nil = none. Its answer is cached for
	// pageGrantRefreshInterval because Effective runs on every dashboard
	// request.
	pageGrants      func(ctx context.Context, now time.Time) []string
	pageGrantCache  []string
	pageGrantReadAt time.Time

	// effectivePins is the Track C item 3 reader: the effective value of
	// every reportable pinnable key in the config THIS PROCESS is running.
	// Injected (never a config field on the handle) for the same reason
	// loadIdentity is: the handle stays testable without a config tree, and
	// nil simply reports nothing — which is the correct behaviour for every
	// short-lived CLI process that builds a handle to read a posture.
	effectivePins func() map[string]string

	// verified is the daemon's last verified copy of what this handle wrote
	// (T-845, guardorglock_wire.go): set by SetSidecar, filled after every
	// successful write, and read by the posture loop, which records it in
	// the MAC'd org lock and repairs a file that no longer matches it.
	verified *governanceCopy
}

// SetEffectivePinReader installs the Track C item 3 effective-pin reader.
// Only the DAEMON sets it: it is the only process that reports policy-ack,
// and the only one whose config is the one actually in force.
func (h *nodeGovernanceHandle) SetEffectivePinReader(fn func() map[string]string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.effectivePins = fn
}

// readEffectivePins runs the injected reader, or returns nil when none is
// installed. Nil means "not reported", never "nothing is pinned".
func (h *nodeGovernanceHandle) readEffectivePins() map[string]string {
	h.mu.Lock()
	fn := h.effectivePins
	h.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// effectivePinValues reads the live value of every REPORTABLE pinnable key
// (internal/policyfam/nodegov.ReportableKeys — bools and closed-enum strings
// only) out of cfg and renders it in the closed wire spelling.
//
// It is the ONE place the two halves meet: internal/config owns "what a
// dotted key means" (PinnableEffectiveValues) and nodegov owns "what may be
// said about it" (NormalizeReportedValue). Neither half can widen the wire
// on its own.
func effectivePinValues(cfg config.Config) map[string]string {
	keys := nodegov.ReportableKeys()
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		names = append(names, k.Key)
	}
	live := config.PinnableEffectiveValues(cfg, names)
	if len(live) == 0 {
		return nil
	}
	out := make(map[string]string, len(live))
	for _, k := range keys {
		v, ok := live[k.Key]
		if !ok {
			continue
		}
		if spelled, ok := k.NormalizeReportedValue(v); ok {
			out[k.Key] = spelled
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SetSidecar attaches the sidecar writer. Calling it is what makes this
// handle the ONE writer; a handle without it resolves and reports exactly as
// Phase 1a did.
func (h *nodeGovernanceHandle) SetSidecar(path, writerVersion string, startup startupSidecar) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.sidecarPath, h.writerVersion, h.startup = path, writerVersion, startup
	h.verified = newGovernanceCopy(path)
	h.lastWrittenHash, h.lastWrittenAt = "", time.Time{}
	h.mu.Unlock()
}

// SidecarPath reports where this handle writes, for the disclosure surfaces.
func (h *nodeGovernanceHandle) SidecarPath() string {
	if h == nil {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sidecarPath
}

// SidecarWriteErr reports the current write failure, if any. `observer
// doctor governance` and `observer org grant show` name the path AND the
// errno, because an admin looking at accepted_inert needs the developer to
// be able to answer "why" in one command.
func (h *nodeGovernanceHandle) SidecarWriteErr() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sidecarWriteErr
}

// WriteSidecar materializes the currently-resolved posture, if it changed or
// the file has gone stale. It is called at every point the posture can
// change: after Apply (a new body accepted by the poller), after the LKG
// install at startup, and on the refresh tick.
//
// It never returns an error to its caller and never fails the daemon: a
// failed write becomes an INERT condition instead (§1.4.1), which is a
// louder and more honest signal than a log line.
func (h *nodeGovernanceHandle) WriteSidecar(ctx context.Context) {
	if h == nil {
		return
	}
	h.mu.Lock()
	path, writerVersion := h.sidecarPath, h.writerVersion
	lastHash, lastAt := h.lastWrittenHash, h.lastWrittenAt
	h.mu.Unlock()
	if path == "" {
		return
	}
	eff := h.Effective(ctx)
	now := h.now()
	// A SOLO node creates nothing. "Dormant is written, not deleted" (§1.4)
	// is about a node that WAS governed and no longer is — presence with an
	// empty pinned map is unambiguous there, while absence is
	// indistinguishable from "the daemon never ran". A node that never held
	// a grant has nothing to disambiguate, and §8's solo claim is literally
	// "no file, no new default, no new write". So: skip unless the node is
	// governed, or a file already exists that must be converged to dormant.
	if eff.State == govern.StateNoGrant {
		if _, statErr := os.Stat(path); statErr != nil {
			return
		}
	}
	file := sidecarFileFor(eff, writerVersion, now)
	h.mu.Lock()
	fx := h.featureExceptions
	h.mu.Unlock()
	exceptions := pinnedFeatureExceptions(ctx, fx, file.Pinned, now)
	// The change key is the posture AND its exceptions: a grant arriving or
	// lapsing rewrites the files at once even when the posture did not move.
	written := eff.Hash + "|" + exceptionsDigest(exceptions)
	if written == lastHash && !lastAt.IsZero() && now.Sub(lastAt) < sidecarRefreshInterval {
		return
	}
	// The sidecar first, then its exceptions file: a reader between the two
	// writes sees a new posture hash with the old binding, which lifts
	// nothing (every pin applies), never an exception for the wrong posture.
	//
	// T-845: both writes happen inside the verified copy's write section, so
	// the posture loop's repair check can never see a half-finished write as
	// a tamper (and restore the previous bytes over the new ones).
	h.mu.Lock()
	vc := h.verified
	h.mu.Unlock()
	var err, exErr error
	vc.write(func() (sidecarRaw, exceptionsRaw []byte, ok bool) {
		sidecarRaw, err = writeGovernanceSidecar(path, file)
		if err == nil {
			exceptionsRaw, exErr = writeGovernanceExceptions(sidecar.ExceptionsPath(path), file.EffectiveHash, writerVersion, now, exceptions)
		}
		return sidecarRaw, exceptionsRaw, err == nil && exErr == nil
	})

	h.mu.Lock()
	defer h.mu.Unlock()
	h.sidecarWriteErr = err
	if err != nil {
		// Force the next tick to retry rather than sitting on a stale
		// "written" marker.
		h.lastWrittenHash, h.lastWrittenAt = "", time.Time{}
		h.logger.Warn("governance: could not write the effective-settings file - this node is reporting NOT effective until it can",
			"path", path, "err", err)
		return
	}
	if exErr != nil {
		// Not a governance failure: an exceptions file that did not land
		// leaves every pin in force (the stricter reading). Retry next tick.
		h.lastWrittenHash, h.lastWrittenAt = "", time.Time{}
		h.logger.Warn("governance: could not write the feature-access exceptions file - every pinned setting stays in force until it can",
			"path", sidecar.ExceptionsPath(path), "err", exErr)
		return
	}
	h.lastWrittenHash, h.lastWrittenAt = written, now
}

// SetFeatureExceptions binds the feature-access grant reader (request-grants
// G8): for the keys the posture pins, the verified grants that lift them and
// until when. Called once at daemon construction, where the long-lived DB
// handle exists; nil-safe.
func (h *nodeGovernanceHandle) SetFeatureExceptions(fn func(ctx context.Context, keys []string, now time.Time) map[string]sidecar.Exception) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.featureExceptions = fn
	h.lastWrittenHash, h.lastWrittenAt = "", time.Time{}
	h.mu.Unlock()
}

// pinnedFeatureExceptions asks fx about the pinned keys (sorted) and keeps
// only answers for keys that are pinned: an exception lifts a pin and never
// sets a value. nil when nothing is pinned, nothing is bound or nothing is
// lifted, so a node holding no feature grant writes the same bytes as
// before.
func pinnedFeatureExceptions(ctx context.Context, fx func(context.Context, []string, time.Time) map[string]sidecar.Exception, pinned map[string]any, now time.Time) map[string]sidecar.Exception {
	if fx == nil || len(pinned) == 0 {
		return nil
	}
	keys := make([]string, 0, len(pinned))
	for k := range pinned {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out map[string]sidecar.Exception
	for k, ex := range fx(ctx, keys, now) {
		if _, ok := pinned[k]; !ok || ex.GrantID <= 0 {
			continue
		}
		if out == nil {
			out = map[string]sidecar.Exception{}
		}
		out[k] = ex
	}
	return out
}

// exceptionsDigest is a stable digest of the exceptions map for change
// detection.
func exceptionsDigest(ex map[string]sidecar.Exception) string {
	if len(ex) == 0 {
		return ""
	}
	keys := make([]string, 0, len(ex))
	for k := range ex {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sum := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(sum, "%s=%d@%s;", k, ex[k].GrantID, ex[k].Until)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// daemonFeatureExceptions is the production reader behind
// SetFeatureExceptions: orgclient.FeatureGrantExceptions over the daemon's
// own store (the same re-verified grant read the guard uses), each mapped
// onto the instant it stops being honoured. Any failure is no exception.
func daemonFeatureExceptions(st *store.Store) func(context.Context, []string, time.Time) map[string]sidecar.Exception {
	return func(ctx context.Context, keys []string, now time.Time) map[string]sidecar.Exception {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		got, err := orgclient.FeatureGrantExceptions(cctx, st, keys, now)
		if err != nil || len(got) == 0 {
			return nil
		}
		out := make(map[string]sidecar.Exception, len(got))
		for k, ex := range got {
			out[k] = sidecar.Exception{GrantID: ex.GrantID, Until: sidecar.FormatTime(time.Unix(0, ex.UntilNs))}
		}
		return out
	}
}

// sidecarFileFor maps a resolved posture onto the on-disk shape.
//
// A DORMANT posture is written, not deleted (§1.4): presence-with-empty is
// unambiguous, whereas absence is indistinguishable from "the daemon never
// ran". So the state travels verbatim and the directive maps go empty.
func sidecarFileFor(eff govern.Effective, writerVersion string, now time.Time) sidecar.File {
	f := sidecar.File{
		Schema:         sidecar.MaxSchema,
		WriterVersion:  writerVersion,
		WrittenAt:      sidecar.FormatTime(now),
		State:          string(eff.State),
		OrgName:        eff.OrgName,
		FamilyVersion:  eff.Version,
		EffectiveHash:  eff.Hash,
		GrantExpiresAt: sidecar.FormatTime(eff.ExpiresAt),
	}
	if !eff.Active {
		return f
	}
	f.Pinned, f.Share, f.Features = eff.Pinned, eff.Share, eff.Features
	return f
}

// writeGovernanceSidecar writes the file atomically and then VERIFIES it by
// reading it back.
//
// Verification is part of the write, not assumed (§1.4.1): a write that
// "succeeded" onto a filesystem that silently discarded it is the same
// condition as a failed write and must take the same path, or the node would
// ack effective over a file no reader can use.
func writeGovernanceSidecar(path string, file sidecar.File) ([]byte, error) {
	raw, err := sidecar.Encode(file)
	if err != nil {
		return nil, err
	}
	return raw, writeGovernanceSidecarBytes(path, raw, file.EffectiveHash, file.State)
}

// writeGovernanceFileBytes is the atomic, fsynced, retried write both
// governance files use (the handle's write and the verified copy's repair).
func writeGovernanceFileBytes(path string, raw []byte, tempPattern string) error {
	var lastErr error
	for attempt := 0; attempt < sidecarWriteAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(sidecarWriteBackoff)
		}
		lastErr = fsatomic.WriteFile(path, raw, fsatomic.Options{TempPattern: tempPattern, Fsync: true})
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

// writeGovernanceSidecarBytes writes encoded sidecar bytes and verifies them
// by reading them back (the §1.4.1 contract above), for both the handle's
// write and the verified copy's repair: one write path for the file.
func writeGovernanceSidecarBytes(path string, raw []byte, effectiveHash, state string) error {
	if err := writeGovernanceFileBytes(path, raw, ".governance-effective-*.tmp"); err != nil {
		return err
	}
	back, rerr := os.ReadFile(path) //nolint:gosec // the path is the node's own resolved sidecar
	if rerr != nil {
		return fmt.Errorf("read back: %w", rerr)
	}
	decoded, derr := sidecar.Decode(back)
	if derr != nil {
		return fmt.Errorf("read back: %w", derr)
	}
	if decoded.EffectiveHash != effectiveHash || decoded.State != state {
		return fmt.Errorf("read back: the file on disk does not match what was written (state %q hash %q)",
			decoded.State, decoded.EffectiveHash)
	}
	return nil
}

// writeGovernanceExceptions writes the feature-access exceptions file beside
// the governance sidecar (request-grants G8), bound to the sidecar's
// effective hash, with the same atomic write and read-back verification as
// the sidecar. It is a SEPARATE file so the sidecar body stays readable by
// released observers (a strict decoder refuses an unknown field and an
// update rollback puts an older binary next to this file). With no
// exception in force the file is removed; if it cannot be removed it is
// overwritten with an empty set, so nothing stays lifted.
func writeGovernanceExceptions(path, effectiveHash, writerVersion string, now time.Time, exceptions map[string]sidecar.Exception) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	if len(exceptions) == 0 {
		rmErr := os.Remove(path)
		if rmErr == nil || errors.Is(rmErr, os.ErrNotExist) {
			return nil, nil
		}
		exceptions = map[string]sidecar.Exception{}
	}
	raw, err := sidecar.EncodeExceptions(sidecar.ExceptionsFile{
		Schema:        sidecar.ExceptionsMaxSchema,
		WriterVersion: writerVersion,
		WrittenAt:     sidecar.FormatTime(now),
		EffectiveHash: effectiveHash,
		Exceptions:    exceptions,
	})
	if err != nil {
		return nil, err
	}
	if err := writeGovernanceFileBytes(path, raw, ".governance-exceptions-*.tmp"); err != nil {
		return nil, err
	}
	back, rerr := os.ReadFile(path) //nolint:gosec // the path is derived from the node's own resolved sidecar
	if rerr != nil {
		return nil, fmt.Errorf("read back: %w", rerr)
	}
	decoded, derr := sidecar.DecodeExceptions(back)
	if derr != nil {
		return nil, fmt.Errorf("read back: %w", derr)
	}
	if decoded.EffectiveHash != effectiveHash || exceptionsDigest(decoded.Exceptions) != exceptionsDigest(exceptions) {
		return nil, errors.New("read back: the exceptions file on disk does not match what was written")
	}
	return raw, nil
}

// newNodeGovernanceHandle builds the seam over an identity loader. A nil
// loader yields a handle that is permanently ungranted (dormant), which is
// the correct behaviour for a build with no org client wired.
func newNodeGovernanceHandle(loadIdentity func(ctx context.Context) (*govern.Grant, govern.LiveIdentity, error), logger *slog.Logger) *nodeGovernanceHandle {
	if logger == nil {
		logger = slog.Default()
	}
	return &nodeGovernanceHandle{loadIdentity: loadIdentity, now: time.Now, logger: logger}
}

// SetIdentityLoader attaches the store-backed grant/identity loader. It is
// separate from construction because the handle must exist BEFORE the
// daemon's long-lived DB handle does (the install seam is threaded into the
// policy-resource paths built earlier). Setting it invalidates the cached
// identity so the very next Effective reads through.
func (h *nodeGovernanceHandle) SetIdentityLoader(fn func(ctx context.Context) (*govern.Grant, govern.LiveIdentity, error)) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.loadIdentity = fn
	h.lastRefresh = time.Time{}
	h.mu.Unlock()
}

// Apply records an accepted node.governance resource and materializes the
// resulting posture into the sidecar.
//
// For the SECTIONS class there is nothing to install into another
// subsystem: the dashboard route guard and the SPA both READ the resolved
// posture, so recording it IS applying it. The Phase-1b `pinned` class is
// different — it reaches other processes only through the sidecar, and the
// daemon's own subsystems only at the next restart, which is why this point
// can now report pending_restart (§1.6).
func (h *nodeGovernanceHandle) Apply(res orgclient.PolicyResourceResult) {
	if h == nil {
		return
	}
	spec, ok := res.Spec.(nodegov.PolicySpec)
	if !ok {
		// Defensive: every real call site passes what CompileFamilyBody
		// compiled for this family. Mirrors applyGatewayProviders.
		return
	}
	inert := res.InertReason
	if !res.EnforceAllowed && inert == "" {
		inert = "not_preauthorized"
	}
	h.mu.Lock()
	h.state.delivered = govern.Delivered{
		Present:     true,
		Version:     res.Version,
		BodyHash:    res.BodyHash,
		Spec:        spec,
		InertReason: inert,
	}
	h.mu.Unlock()
	h.WriteSidecar(context.Background())
	if inert != "" {
		h.logger.Info("policy resource: node.governance accepted but INERT - this node's dashboard is unchanged",
			"version", res.Version, "reason", inert)
	}
}

// Clear forgets the org-rail resource (a withdrawn policy, an identity
// change, or an unenrol). The node reverts to its local surface on the next
// request; there is no restart-bound residue in Phase 1a.
func (h *nodeGovernanceHandle) Clear() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.state = nodeGovernanceState{}
	h.mu.Unlock()
	// Rewrite the sidecar as DORMANT rather than removing it: presence with
	// an empty pinned map is unambiguous, absence is indistinguishable from
	// "the daemon never ran". `observer unenroll` is the one path that
	// deletes the file, and it does so after tombstoning the generation.
	h.WriteSidecar(context.Background())
}

// InvalidateIdentity forces the next Effective to re-read the grant and the
// live enrolment identity. start.go hands it to the dashboard's enrolment
// manager, so an enrol, grant decision or leave made from Settings >
// Enrolment shows at once. An `observer enroll` / `observer unenroll` in
// ANOTHER process is still only observed at the next refresh interval.
func (h *nodeGovernanceHandle) InvalidateIdentity() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.lastRefresh = time.Time{}
	h.mu.Unlock()
}

// Effective resolves the posture this node actually applies. It is the ONE
// read every surface goes through (the dashboard route guard, GET
// /api/governance, the P0-6 reader, the CLI).
//
// It is cheap and non-blocking on the hot path: at most one indexed SELECT
// per governanceGrantRefreshInterval, and a pure function call otherwise.
func (h *nodeGovernanceHandle) Effective(ctx context.Context) govern.Effective {
	if h == nil {
		return govern.Resolve(govern.Delivered{}, nil, govern.LiveIdentity{}, time.Now())
	}
	h.refreshIdentity(ctx)
	h.mu.Lock()
	delivered, grant, live := h.state.delivered, h.grant, h.live
	h.mu.Unlock()
	eff := govern.Resolve(delivered, grant, live, h.now())
	if eff.VisibilityActive() {
		eff.GrantedPages = h.grantedPages(ctx)
	}
	return eff
}

// pageGrantRefreshInterval bounds how stale a page-access grant's arrival or
// lapse can look on the dashboard.
const pageGrantRefreshInterval = 5 * time.Second

// grantedPages returns the cached page-access grant targets, re-reading them
// when the cache is older than pageGrantRefreshInterval.
func (h *nodeGovernanceHandle) grantedPages(ctx context.Context) []string {
	h.mu.Lock()
	fn, cached, at := h.pageGrants, h.pageGrantCache, h.pageGrantReadAt
	now := h.now()
	h.mu.Unlock()
	if fn == nil {
		return nil
	}
	if !at.IsZero() && now.Sub(at) >= 0 && now.Sub(at) < pageGrantRefreshInterval {
		return cached
	}
	got := fn(ctx, now)
	h.mu.Lock()
	h.pageGrantCache, h.pageGrantReadAt = got, now
	h.mu.Unlock()
	return got
}

// SetPageGrants binds the page-access grant reader (T-435). Called once at
// daemon construction; nil-safe.
func (h *nodeGovernanceHandle) SetPageGrants(fn func(ctx context.Context, now time.Time) []string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.pageGrants = fn
	h.pageGrantCache, h.pageGrantReadAt = nil, time.Time{}
	h.mu.Unlock()
}

// daemonPageGrants is the production reader behind SetPageGrants: the
// re-verified grant cache over the daemon's own store. Any failure is no
// page shown.
func daemonPageGrants(st *store.Store) func(context.Context, time.Time) []string {
	return func(ctx context.Context, now time.Time) []string {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		got, err := orgclient.PageGrants(cctx, st, now)
		if err != nil {
			return nil
		}
		return got
	}
}

// refreshIdentity re-reads the grant + live identity when the cached copy is
// older than the refresh interval (or was invalidated). A load FAILURE
// leaves the previous copy in place and logs — the fail-safe direction for
// an authority record is to keep what was last verified, not to invent one.
func (h *nodeGovernanceHandle) refreshIdentity(ctx context.Context) {
	h.mu.Lock()
	load := h.loadIdentity
	fresh := !h.lastRefresh.IsZero() && h.now().Sub(h.lastRefresh) < governanceGrantRefreshInterval
	h.mu.Unlock()
	if load == nil || fresh {
		return
	}
	grant, live, err := load(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastRefresh = h.now()
	if err != nil {
		h.logger.Warn("governance: could not read the enrolment grant - keeping the last known posture", "err", err)
		return
	}
	h.grant, h.live = grant, live
}

// governanceFacts is the plain snapshot the P0-6 node-dashboard point reader
// consumes.
type governanceFacts struct {
	HasOrgRail  bool
	Version     int64
	BodyHash    string
	InertReason string
	// RunningVersion / RunningHash identify the sidecar the RUNNING daemon
	// process was built from (§1.6). They are NOT the delivered version:
	// pinned settings are restart-bound for the daemon's own subsystems,
	// because start.go reads config once.
	RunningVersion int64
	RunningHash    string
	// PinnedConverged is false when the currently-resolved pinned map
	// differs from the one the running process read at startup — the ONE
	// condition that makes this point report pending_restart. Sections and
	// share stay hot, so a body that changes only those converges to
	// `effective` without a restart.
	PinnedConverged bool

	// --- gen2 (P4-2) — see policystate.PointFacts's own doc comments for
	// the exact semantics; these are computed only when d.Present (there is
	// nothing accepted to describe otherwise) and are copied verbatim onto
	// policystate.PointFacts by newNodeGovernancePointReader, which then
	// lets internal/policystate.Resolve gate them onto the wire row to the
	// node-dashboard point alone.

	// AcceptedAuthority is govern.HonoredAuthority(grant).
	AcceptedAuthority []string
	// ExtractionEffective is govern.ExtractionTokensInForce(eff,
	// AcceptedAuthority).
	ExtractionEffective []string
	// DroppedClasses maps a directive class name to the wire reason it was
	// not applied — either translated from eff.Dropped (the
	// eff.State != StateApplied case) or synthesized for the classes that
	// depend on a sidecar write that then failed (the writeErr != nil
	// case). Nil when nothing was dropped.
	DroppedClasses map[string]string

	// GrantUnverified is TRUE when the resolver reported
	// govern.StateGrantSignatureInvalid: the stored grant document no longer
	// verifies under the organization key this node holds (Track C item 1).
	//
	// WHICH WIRE FIELD CARRIES IT, AND WHY. It maps onto the node.governance
	// row's EXISTING (delivered_unaccepted, sig_invalid) pair — the field
	// that already carries this point's governance state — rather than onto a
	// new reason code. Two reasons, and the second is decisive:
	//
	//   - It is true as stated: a signature this node required did not
	//     verify, so nothing was installed. The pair's existing prose is
	//     about the BODY's signature and this is the GRANT's, which is a
	//     loss of precision the ledger records (docs/security.md TAMPER-1);
	//     the node-local surfaces (`observer org status`, `observer org grant
	//     show`, `observer doctor`) name the exact cause.
	//   - The server validates ack reasons against a CLOSED set and 400s the
	//     WHOLE report on an unknown one. A new reason code would therefore
	//     take fleet reporting down on every server older than this release —
	//     the exact trap ReasonAuthorityRetired's comment in internal/govern
	//     warns about. Reusing an existing pair is wire-safe in both
	//     directions with no negotiation.
	GrantUnverified bool

	// EffectivePins is the Track C item 3 map — the effective value of every
	// reportable pinnable key on THIS machine right now, read from the
	// config this process is actually running, not from the delivered body.
	// That is the whole point: a pin the org published and this node acked
	// can still fail to be in force, and only the live value says so.
	EffectivePins map[string]string
}

// Facts snapshots the handle for the P0-6 reader. The resolved posture
// decides inertness: a delivered body that the GRANT does not authorize is
// exactly as inert as one the node's own preauthorize_enforce gate refused,
// and both must report accepted_inert / not_preauthorized rather than
// effective — that is the §3.7 honesty rule ("a partial application can
// never masquerade as convergence").
//
// WHAT THE ADMIN CAN AND CANNOT SEE (review M4, revised by P4-2).
// govern.Effective.Dropped — which names WHICH directive class was refused
// and why — used to be NODE-LOCAL only: rendered on the developer's own
// Enrolment page and by `observer org grant show`, folded into
// Effective.Hash so a partial application cannot hash-match the delivered
// body, but never travelling. P4-2 is exactly the wire-shape change that
// residual 7 (Phase-2 wire item) named: DroppedClasses now carries a
// per-directive-class reason, translated through the closed gen2 vocabulary
// (orgcontract.ReasonNotPreauthorized / ReasonSidecarUnwritable — never a
// raw govern-internal string), alongside AcceptedAuthority and
// ExtractionEffective. All three are gated onto the wire row by
// internal/policystate.Resolve to the node-dashboard point alone: the
// server 400s the whole report if they appear on any other family/point, so
// do not thread them through any other PointReader.
//
// Do NOT "helpfully" plumb an unrecognized govern reason through to the ack
// as-is: the server validates ack reasons against a closed set and 400s the
// WHOLE report on an unknown one, so every govDroppedToWire /
// sidecarUnwritableDroppedClasses value must stay inside that closed set.
func (h *nodeGovernanceHandle) Facts(ctx context.Context) governanceFacts {
	if h == nil {
		return governanceFacts{}
	}
	h.mu.Lock()
	d := h.state.delivered
	h.mu.Unlock()
	h.mu.Lock()
	startup, writeErr := h.startup, h.sidecarWriteErr
	h.mu.Unlock()

	f := governanceFacts{
		HasOrgRail:     d.Present,
		Version:        d.Version,
		BodyHash:       d.BodyHash,
		RunningVersion: startup.Version,
		RunningHash:    startup.Hash,
	}
	// Resolve BEFORE the not-delivered early return: a tampered grant must be
	// reported whether or not the organization has published a body, and the
	// resolver answers StateGrantSignatureInvalid in both cases (the
	// integrity row precedes the no-policy row in the §3.7 table).
	eff := h.Effective(ctx)
	f.GrantUnverified = eff.State == govern.StateGrantSignatureInvalid
	if !d.Present {
		f.PinnedConverged = true
		return f
	}
	h.mu.Lock()
	grant := h.grant
	h.mu.Unlock()
	f.EffectivePins = h.readEffectivePins()
	f.AcceptedAuthority = govern.HonoredAuthority(grant)
	f.ExtractionEffective = govern.ExtractionTokensInForce(eff, f.AcceptedAuthority)
	f.PinnedConverged = governancePinnedHash(eff.Pinned) == startup.PinnedHash
	switch {
	case eff.State != govern.StateApplied:
		f.InertReason = orgcontract.ReasonNotPreauthorized
		f.DroppedClasses = govDroppedToWire(eff.Dropped)
	case writeErr != nil:
		// §1.4.1: the daemon resolved StateApplied but cannot materialize
		// the posture, so NO process on this machine can read the pins.
		// Reporting `effective` here would be the exact false compliance
		// claim Phase 1b exists to remove. Distinct from the
		// eff.State != StateApplied case above: govern itself dropped
		// nothing (StateApplied ⟺ eff.Dropped is empty — see
		// applyIntersection), so DroppedClasses is synthesized from the
		// delivered spec's own PRESENT sidecar-dependent classes instead of
		// translated from eff.Dropped.
		f.InertReason = orgcontract.ReasonSidecarUnwritable
		f.DroppedClasses = sidecarUnwritableDroppedClasses(d.Spec)
	}
	return f
}

// govDroppedToWire translates govern.Effective.Dropped entries into the
// gen2 wire's closed DroppedClasses vocabulary (P4-2). Every govern-internal
// reason for the eff.State != StateApplied case (ReasonNotPreauthorized,
// ReasonAuthorityRetired — see internal/govern/resolve.go's
// directiveClasses) folds onto orgcontract.ReasonNotPreauthorized: gen2 has
// no retired-specific wire value, and "not currently authorized" is the
// honest generalization of "authorized only by a token this org has since
// retired". A future govern drop reason this function does not recognize
// also folds here rather than forwarding an unvetted string past the wire's
// closed vocabulary.
func govDroppedToWire(dropped []govern.Dropped) map[string]string {
	if len(dropped) == 0 {
		return nil
	}
	out := make(map[string]string, len(dropped))
	for _, d := range dropped {
		out[d.Directive] = orgcontract.ReasonNotPreauthorized
	}
	return out
}

// sidecarUnwritableDroppedClasses scopes the ReasonSidecarUnwritable
// DroppedClasses entries to exactly the directive classes that were PRESENT
// in the delivered spec AND actually depend on the sidecar to reach another
// process. "sections" is deliberately excluded: the dashboard route guard
// and the SPA both read Effective directly (never the sidecar), so a
// sidecar write failure never affects it.
//
// This scoping is sound because eff.State == govern.StateApplied (Facts's
// precondition for reaching this branch) implies eff.Dropped is empty —
// applyIntersection sets StateInert if and only if len(Dropped) > 0 — so
// every class PRESENT in the delivered spec really was authorized and
// applied in memory; the sidecar write is the only thing that then failed.
func sidecarUnwritableDroppedClasses(spec nodegov.PolicySpec) map[string]string {
	out := map[string]string{}
	if len(spec.Pinned) > 0 {
		out["pinned"] = orgcontract.ReasonSidecarUnwritable
	}
	if len(spec.Share) > 0 {
		out["share"] = orgcontract.ReasonSidecarUnwritable
	}
	if len(spec.Features) > 0 {
		out["features"] = orgcontract.ReasonSidecarUnwritable
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// newNodeGovernancePointReader builds the node.governance PointReader (spec
// §3.8). Its facts come from the install seam, which is the only holder of
// the accepted resource's identity.
//
// Mode is a PROJECTION, exactly as for gateway.providers: node.governance
// bodies carry no mode field, because hiding a page always mutates the live
// surface the moment it is applied. enforce = governance is in force,
// observe = a body was accepted but is NOT in force (which is also what the
// server's accepted_inert ⇒ observe rule requires), off = nothing installed.
//
// pending_restart WAS unreachable for this point in Phase 1a, because every
// schema-1 directive is hot. Phase 1b's `pinned` class is NOT hot for the
// daemon's own subsystems (start.go reads config once), so cached no longer
// always equals running: RunningVersion now comes from the sidecar the
// RUNNING process was built from (§1.6 / review M3), and the point reports
// pending_restart from the moment it writes a sidecar whose pinned map
// differs from that, until the daemon is restarted.
func newNodeGovernancePointReader(
	gh *nodeGovernanceHandle,
	lastFetch func() orgclient.PolicyResourceFetchOutcome,
	now func() time.Time,
) policystate.PointReader {
	return func(ctx context.Context) (policystate.PointFacts, error) {
		g := gh.Facts(ctx)
		o := orgclient.PolicyResourceFetchOutcome{}
		if lastFetch != nil {
			o = lastFetch()
		}
		reject := wirePolicyResourceRejectReason(o.RejectCode)
		if g.GrantUnverified {
			// Track C item 1: a grant that no longer verifies outranks
			// whatever the last FETCH did — nothing this rail delivered can
			// be in force when the authority record behind it is not the one
			// the organization signed. See governanceFacts.GrantUnverified
			// for why this pair and not a new reason code.
			reject = orgcontract.ReasonSigInvalid
		}
		f := policystate.PointFacts{
			HasOrgRail:          g.HasOrgRail,
			InertReason:         g.InertReason,
			LastSeen:            now(),
			LatestFetchRejected: reject != "",
			RejectCode:          reject,
			RejectedVersion:     o.Version,
			Unreachable:         o.Unreachable,
			AcceptedAuthority:   g.AcceptedAuthority,
			ExtractionEffective: g.ExtractionEffective,
			DroppedClasses:      g.DroppedClasses,
			EffectivePins:       g.EffectivePins,
		}
		switch {
		case g.HasOrgRail && g.InertReason != "":
			f.CachedAcceptedVersion = g.Version
			f.RunningVersion = g.Version
			f.EffectiveHash = g.BodyHash
			f.EnforceMode = "observe"
		case g.HasOrgRail && !g.PinnedConverged:
			// A pinned map the running process has never read. The
			// collector derives pending_restart from
			// RunningVersion < CachedAcceptedVersion, so the running
			// version must be the STARTUP one — and when that happens to
			// equal (or exceed) the delivered version, 0 is the honest
			// answer: nothing from this family's pins is running yet. A
			// zero running version also empties the hash by the collector's
			// own R3-B2 rule, which is exactly right.
			f.CachedAcceptedVersion = g.Version
			f.RunningVersion = g.RunningVersion
			if f.RunningVersion >= g.Version {
				f.RunningVersion = 0
			}
			f.EffectiveHash = g.RunningHash
			f.EnforceMode = "enforce"
		case g.HasOrgRail:
			f.CachedAcceptedVersion = g.Version
			f.RunningVersion = g.Version
			f.EffectiveHash = g.BodyHash
			f.EnforceMode = "enforce"
		default:
			// No org rail. There is NO local governance overlay — a node
			// governs itself by definition — so this is always no_policy,
			// never local_effective.
			f.EnforceMode = "off"
		}
		return f, nil
	}
}

// governanceIdentityLoader returns the store-backed identity loader the
// handle refreshes through: the live enrolment (org_key + generation), the
// live org policy key pin, and this identity's grant.
//
// The pin is read through the SAME cmd-side reader the policy-resource LKG
// path uses (loadPolicyResourceKeyPin), so "the key this node pins" has one
// definition here.
func governanceIdentityLoader(st *store.Store) func(ctx context.Context) (*govern.Grant, govern.LiveIdentity, error) {
	if st == nil {
		return nil
	}
	return func(ctx context.Context) (*govern.Grant, govern.LiveIdentity, error) {
		enr, err := st.LoadEnrolment(ctx)
		if err != nil {
			return nil, govern.LiveIdentity{}, err
		}
		if enr == nil {
			// Unenrolled: no identity, therefore no grant can be live.
			return nil, govern.LiveIdentity{}, nil
		}
		orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
		live := govern.LiveIdentity{Enrolled: true, OrgKey: orgKey}
		gen, ok, err := st.LoadEnrolmentGeneration(ctx, orgKey)
		if err != nil {
			return nil, govern.LiveIdentity{}, err
		}
		if ok {
			if gen.Tombstoned {
				// A tombstoned generation is an unenrolled identity that has
				// not finished tearing down: report it as not enrolled so
				// govern's identity rule fires.
				return nil, govern.LiveIdentity{}, nil
			}
			live.Generation = gen.Generation
		}
		pin, err := loadPolicyResourceKeyPin(ctx, st, enr.OrgServerURL)
		if err != nil {
			return nil, govern.LiveIdentity{}, err
		}
		live.KeyPinSHA256 = pin

		row, ok, err := st.LoadEnrolmentGrant(ctx, orgKey)
		if err != nil {
			return nil, live, err
		}
		if !ok {
			return nil, live, nil
		}
		grant := grantFromStore(row, enr)
		// The developer sees the org's NAME, never its id: the grant row
		// stores the id in org_name, so prefer the enrolment's name (what
		// `observer org status` prints). Display only; integrity below
		// verifies the stored row, not this field.
		grant.OrgName = orgenrol.DisplayName(row.OrgID, enr.OrgServerURL, enr.OrgName, row.OrgName)
		// Track C item 1: RE-VERIFY the stored grant on every identity
		// refresh, not only at enrolment. A key-material read failure is
		// "unchecked", never "invalid" — see verifyStoredGrantIntegrity.
		grant.Integrity, grant.ConsentEvidence = verifyStoredGrantIntegrity(ctx, st, enr.OrgServerURL, enr.Tenancy, row)
		return grant, live, nil
	}
}

// verifyStoredGrantIntegrity re-verifies the grant row against the org
// distribution public key this node recorded at enrolment, and resolves the
// result into the plain govern.GrantIntegrity enum.
//
// This is THE seam for Track C item 1 (docs/plans/
// org-guardrail-control-wave-2026-09-21.md): internal/govern does no crypto
// and no I/O, so the check runs here, once per identity refresh (every
// governanceGrantRefreshInterval), and travels into the resolver as data.
//
// It is deliberately CONSERVATIVE about what it calls invalid. Every path
// that means "this node cannot check" — no key material, an unreadable pin
// store, a grant row that predates key binding — returns Unchecked, which is
// the zero value and leaves the resolver on exactly its pre-Track-C
// behaviour. Only a document that is PRESENT, checkable, and fails to verify
// returns Invalid.
//
// Note which expiry is verified: SignedExpiresAt, the value the organization
// actually signed. RenewEnrolmentGrant moves the WORKING expires_at forward
// inside that window and leaves the signature untouched, so verifying
// against the working clock would make every renewed grant look tampered.
func verifyStoredGrantIntegrity(ctx context.Context, st *store.Store, orgURL, tenancy string, row store.EnrolmentGrant) (govern.GrantIntegrity, govern.ConsentEvidence) {
	return orgclient.StoredGrantIntegrity(ctx, st, orgURL, tenancy, row)
}

// storedGrantIntegrity is the pure half of verifyStoredGrantIntegrity: it
// maps the store row onto the stored grant document and hands it to
// grantverify.Verify, the ONE verifier the daemon and `observer doctor`
// share (the signed-consent candidate table, GRANT-INTEG-2, and the consent
// evidence each candidate proves, Sol A3-03, live there).
func storedGrantIntegrity(row store.EnrolmentGrant, tenancy string, pub ed25519.PublicKey) (govern.GrantIntegrity, govern.ConsentEvidence) {
	return orgclient.StoredGrantIntegrityWith(row, tenancy, pub)
}

// grantFromStore maps the store row onto the resolver's plain struct. One
// mapper, so the store row shape never leaks past this file. enr is the
// enrolment the node holds (nil when unknown): its tenancy and org id, with
// the row's replacement generation, are the facts govern.GrantIsManaged
// decides managed tenancy on (OSH-R-013, P-204); the caller fills
// Integrity where it can verify the stored grant.
func grantFromStore(row store.EnrolmentGrant, enr *store.Enrolment) *govern.Grant {
	tenancy, enrolmentOrgID := "", ""
	if enr != nil {
		tenancy, enrolmentOrgID = enr.Tenancy, enr.OrgID
	}
	return &govern.Grant{
		Tenancy:               tenancy,
		EnrolmentOrgID:        enrolmentOrgID,
		ReplacementGeneration: row.ReplacementGeneration,
		OrgKey:                row.OrgKey,
		Generation:            row.Generation,
		OrgID:                 row.OrgID,
		OrgName:               row.OrgName,
		OrgServerURL:          row.OrgServerURL,
		KeyPinSHA256:          row.KeyPinSHA256,
		Authority:             row.Authority,
		ConsentMode:           row.ConsentMode,
		ConsentActor:          row.ConsentActor,
		GrantedAt:             row.GrantedAt,
		ExpiresAt:             row.ExpiresAt,
		Signature:             row.Signature,
		ReceiptHash:           row.ReceiptHash,
	}
}

// loadNodeGovernanceLKG installs the node.governance family from its
// on-disk, signature-verified Last-Known-Good cache WITHOUT an org client —
// the case `observer dashboard` is in (it runs no policy poller at all).
//
// Without it, a governed developer could simply run `observer dashboard`
// instead of `observer start` and get an ungoverned surface: a bypass that
// needs no root, no patched binary, and no DB edit, which is a materially
// lower bar than the ones §11.2 honestly accepts.
//
// It is deliberately NON-REPAIRING and conservative: it installs only when
// the verified cache matches the durable replay floor exactly (the §6.5
// matrix's row 3, the steady state). Anything else — no cache, no durable
// state, a version disagreement, a family the operator has not accepted —
// leaves this node ungoverned, which is the same answer it would give if the
// resource had never been published.
func loadNodeGovernanceLKG(ctx context.Context, cfg config.Config, st *store.Store, ngov *nodeGovernanceHandle, logger *slog.Logger) {
	_ = loadNodeGovernanceLKGStatus(ctx, cfg, st, ngov, logger)
}

// lkgStatus is what loadNodeGovernanceLKGStatus found (T-395). The daemon
// paths ignore it (their answer is "ungoverned unless installed", by design);
// `observer config set` dispatches on it so a posture it cannot read is never
// reported as an unmanaged machine.
type lkgStatus int

const (
	// lkgNoStore: no store or handle was given.
	lkgNoStore lkgStatus = iota
	// lkgEnrolmentUnreadable: the enrolment or its generation could not be
	// read from the database.
	lkgEnrolmentUnreadable
	// lkgNotEnrolled: no enrolment, or a tombstoned (left) generation, or an
	// enrolment that never received a generation.
	lkgNotEnrolled
	// lkgFamilyNotAccepted: the operator does not accept node.governance.
	lkgFamilyNotAccepted
	// lkgNoPolicy: enrolled, and no node.governance resource was ever
	// applied here (no cache and no durable state).
	lkgNoPolicy
	// lkgUnverified: a node.governance resource WAS applied (durable state
	// exists) but its cache is missing, fails verification or disagrees
	// with the durable floor.
	lkgUnverified
	// lkgInstalled: the verified cache was installed.
	lkgInstalled
)

// loadNodeGovernanceLKGStatus is loadNodeGovernanceLKG reporting what it
// found. It installs exactly when loadNodeGovernanceLKG always has.
func loadNodeGovernanceLKGStatus(ctx context.Context, cfg config.Config, st *store.Store, ngov *nodeGovernanceHandle, logger *slog.Logger) lkgStatus {
	if st == nil || ngov == nil {
		return lkgNoStore
	}
	if logger == nil {
		logger = slog.Default()
	}
	enr, err := st.LoadEnrolment(ctx)
	if err != nil {
		return lkgEnrolmentUnreadable
	}
	if enr == nil {
		return lkgNotEnrolled
	}
	orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	genRow, ok, err := st.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil {
		return lkgEnrolmentUnreadable
	}
	if !ok || genRow.Tombstoned {
		return lkgNotEnrolled
	}
	// node.governance bodies never declare a RequiredCapabilities entry (the
	// judge capability is an admission.input/egress concern), so this loader
	// carries no live-capability set; nil keeps the subset check trivially
	// satisfied for this family and never depends on the admission runtime,
	// which this node-governance path does not have a handle to.
	opts := policyResourceOptionsFor(cfg, nil)
	if !containsString(policyfam.FamilyNodeGovernance, opts.AcceptFamilies) {
		return lkgFamilyNotAccepted
	}
	stateRow, hasState, serr := st.LoadPolicyResourceState(ctx, orgKey, policyfam.FamilyNodeGovernance)
	if serr != nil {
		return lkgEnrolmentUnreadable
	}
	path := filepath.Join(opts.CacheDir, orgKey, strconv.FormatInt(genRow.Generation, 10),
		policyfam.FamilyNodeGovernance+".json")
	cached, cerr := verifyCachedPolicyResource(ctx, st, enr.OrgServerURL, policyfam.FamilyNodeGovernance, path, opts.NodeAttrs)
	if cerr != nil {
		if hasState {
			return lkgUnverified
		}
		return lkgNoPolicy
	}
	if !hasState || stateRow.Generation != genRow.Generation ||
		cached.resource.Version != stateRow.FloorVersion || cached.digest != stateRow.MsgDigest {
		return lkgUnverified
	}
	enforceAllowed, inertReason := policyResourceEnforceGate(policyfam.FamilyNodeGovernance, cached.spec, opts.PreauthorizeEnforce)
	ngov.Apply(orgclient.PolicyResourceResult{
		Status: orgclient.PRApplied, Family: policyfam.FamilyNodeGovernance,
		Version: cached.resource.Version, BodyHash: cached.resource.BodyHash,
		EnforceAllowed: enforceAllowed, InertReason: inertReason, Spec: cached.spec,
		OrgKey: orgKey, Generation: genRow.Generation,
	})
	logger.Info("governance: installed verified node.governance cache", "version", cached.resource.Version,
		"enforce_allowed", enforceAllowed)
	return lkgInstalled
}

// VerifiedCopy returns the handle's verified copy of the governance files it
// writes (nil before SetSidecar).
func (h *nodeGovernanceHandle) VerifiedCopy() *governanceCopy {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.verified
}
