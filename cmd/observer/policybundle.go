package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Org policy-bundle poll orchestration (guard spec §14.2, G13). The
// orgclient owns the wire + verification; this runner owns what the
// cmd layer always owns (the mcpsecRunner / dialectRunner pattern):
// turning a REJECTED poll into an R-205 guard event through the real
// engine, persisting via the one-owner store seam, and alerting.

// orgBundleCachePath resolves [guard.rules].org_bundle to an absolute
// path ("" when unset — the channel is then off for this daemon).
func orgBundleCachePath(cfg config.Config) string {
	p := cfg.Guard.Rules.OrgBundle
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "~/") || p == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
	}
	return filepath.FromSlash(p)
}

// policyBundleRunner receives PolicyPollLoop results. Rejections emit
// R-205 once per rejection state — a bad bundle served unchanged for
// hours is ONE event, a different bad bundle (new version or new
// failure mode) is the next (the R-204 once-per-drift-state
// precedent); a daemon restart re-emits once, which is the desired
// "still broken" heartbeat.
type policyBundleRunner struct {
	st      *store.Store
	logger  *slog.Logger
	orgURL  string
	acquire func(context.Context) *guard.Guard
	// onGuardReload, when set, runs after a successful live org-layer
	// reload (start.go wires the hook-posture re-publish here).
	onGuardReload func(*guard.Guard)
	// cachePath is the bundle cache the poll writes (named in a repair's
	// tamper event); posture is the writer that owns the bundle tamper
	// incident (nil: the daemon's, daemonGuardPosture).
	cachePath string
	posture   *guardPostureWriter

	mu         sync.Mutex
	lastReject string
}

// newPolicyBundleRunner builds the result handler over the daemon's
// shared guard (acquired lazily — only a rejection needs it). orgURL
// is audit metadata for the R-205 finding target.
func newPolicyBundleRunner(cfg config.Config, st *store.Store, logger *slog.Logger, orgURL string) *policyBundleRunner {
	return &policyBundleRunner{
		st: st, logger: logger, orgURL: orgURL,
		acquire: func(ctx context.Context) *guard.Guard {
			return acquireProcessGuard(ctx, cfg, st, logger)
		},
		cachePath: orgBundleCachePath(cfg),
		posture:   daemonGuardPosture,
	}
}

// noteCacheRepair records the tamper an Applied poll repaired (a cache that
// no longer verified, was deleted, or was displaced; T-869 and D-704) as one
// org_bundle_tamper event, unless the posture check already recorded the
// same incident (bundleIncidentTable). It runs before the live reload so the
// repair reaches the incident record as soon after the write as it can.
func (r *policyBundleRunner) noteCacheRepair(res orgclient.PolicyResult) {
	if res.RepairedCache == orgclient.CacheRepairNone && res.DisplacedTo == "" {
		return
	}
	var gd *guard.Guard
	if r.acquire != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		gd = r.acquire(ctx)
		cancel()
	}
	detail, ok := bundleRepairDetail(bundleRepair{res: res, cachePath: r.cachePath, deletionIsTamper: deletionIsTamper(gd)})
	if !ok {
		return
	}
	w := r.posture
	if w == nil {
		w = daemonGuardPosture
	}
	w.noteBundleRepair(detail)
}

// onResult is the PolicyPollLoop callback. A rejection emits R-205
// (deduped per rejection state); an ACCEPTED poll hot-reloads the live
// guard org layer in-process (P0-7 §2.3) so the accepted version
// becomes effective without a daemon restart; an UNCHANGED poll
// reloads only when the live running version has diverged from the
// cache (SF7 cold recovery), never in steady state.
func (r *policyBundleRunner) onResult(res orgclient.PolicyResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch res.Status {
	case orgclient.PolicyRejected:
		r.handleRejection(res)
	case orgclient.PolicyApplied:
		// A healthy outcome re-arms the dedup so a LATER rejection emits
		// again even if it textually matches an old one.
		r.lastReject = ""
		r.noteCacheRepair(res)
		r.reloadGuardLayer(res, false)
	case orgclient.PolicyUnchanged:
		r.lastReject = ""
		r.reloadGuardLayer(res, true)
	default:
		// PolicyNone (404) or any other healthy outcome: nothing to
		// reload; just re-arm the rejection dedup.
		r.lastReject = ""
	}
}

// handleRejection emits the once-per-rejection-state R-205 guard event
// through the real engine (the mcpsecRunner precedent).
func (r *policyBundleRunner) handleRejection(res orgclient.PolicyResult) {
	key := fmt.Sprintf("%d|%s", res.Version, res.Detail)
	if key == r.lastReject {
		return
	}
	r.lastReject = key

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gd := r.acquire(ctx)
	if gd == nil {
		// Guard off mid-flight (config raced) — the rejection still
		// protected the cache; it is just not auditable as an event.
		r.logger.Warn("org policy: bundle rejected (guard unavailable, no R-205 recorded)",
			"version", res.Version, "detail", res.Detail)
		return
	}
	// The finding carries the channel subject: Client "org" (the org
	// server, not an AI client) and the bundle endpoint as target. The
	// bundle URL travels INSIDE the finding per the R-204 pinned
	// discovery — never as Event.Target.
	verdicts := gd.EvaluatePostureFindings([]policy.PostureFinding{{
		Kind:   policy.PostureFindingBundleSignature,
		Client: "org",
		Target: r.orgURL + "/api/v1/policy-bundle",
		Detail: res.Detail,
	}}, time.Now().UTC())
	if len(verdicts) == 0 {
		return // R-205 disabled via [guard.rules].disable — operator's call
	}
	if _, err := r.st.PersistGuardVerdicts(ctx, verdicts); err != nil {
		r.logger.Warn("org policy: R-205 persist failed", "err", err)
	}
	for i := range verdicts {
		gd.MaybeAlert(verdicts[i])
	}
	r.logger.Warn("org policy: bundle REJECTED - running on previous policy",
		"version", res.Version, "detail", res.Detail, "rule", "R-205")
}

// reloadGuardLayer applies an accepted org policy to the LIVE guard
// engine in-process (P0-7 §2.3). It is the ONE owner of the guard
// acquire for the convergence path. divergenceOnly gates the SF7
// cold-recovery arm: on an Unchanged poll the reload runs only when the
// live running org version differs from the cache file's version
// (res.CachedVersion) — steady-state (running==cached) skips it to
// avoid re-verify churn. A failed reload is fail-safe: the live policy
// is unchanged and P0-6 keeps honestly reporting pending_restart until
// the next restart.
func (r *policyBundleRunner) reloadGuardLayer(res orgclient.PolicyResult, divergenceOnly bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gd := r.acquire(ctx)
	if gd == nil {
		// Guard off mid-flight (config raced): the cache still advanced,
		// so a later start picks it up; it is just not live now.
		r.logger.Warn("org policy: accepted bundle not applied to live engine (guard unavailable)",
			"version", res.Version)
		return
	}
	if divergenceOnly {
		running := orgRunningVersion(gd)
		if res.CachedVersion == 0 || running == res.CachedVersion {
			return // steady state — nothing to converge
		}
		r.logger.Info("org policy: cold-recovery reload (running behind cache)",
			"running", running, "cached", res.CachedVersion)
	}
	if err := gd.ReloadOrgLayer(ctx); err != nil {
		r.logger.Warn("org policy: live reload failed - running on previous policy until restart",
			"version", res.Version, "err", err)
		return
	}
	r.logger.Info("org policy: applied to live engine (no restart)", "version", res.Version)
	if r.onGuardReload != nil {
		r.onGuardReload(gd)
	}
}

// orgRunningVersion returns the guard's live org-layer version as an
// int64 (0 when no org layer is loaded or the version string does not
// parse). It reads the "org" descriptor off the guard's live snapshot
// (PolicyStates) — the exact pair the P0-6 reader consults.
func orgRunningVersion(gd *guard.Guard) int64 {
	for _, st := range gd.PolicyStates() {
		if st.Layer == "org" { // guard's org-layer descriptor
			v, err := strconv.ParseInt(st.Version, 10, 64)
			if err != nil {
				return 0
			}
			return v
		}
	}
	return 0
}
