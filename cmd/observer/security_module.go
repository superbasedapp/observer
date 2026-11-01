//go:build !sbo_omit_security

package main

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/postureop"
	"github.com/marmutapp/superbased-observer/internal/secipc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_module.go is the daemon wiring of the security pillar's module
// root (component `security`; security pillar plan sections 4.2, 4.3 and
// 4.8, Phase A). Both loops are moduleGates rows (components_gate.go), so
// they start only while the module is active under ModuleActive; with
// sbo_omit_security this file is replaced by security_module_omit.go and
// none of the pillar's packages is linked.

// securityRetentionEvery is how often the retention pass runs.
const securityRetentionEvery = 24 * time.Hour

// securityPackRules composes the pillar's rule pack for guard
// (guard.Options.PackRules; security pillar plan section 4.7 item 1).
// active is the optional-module predicate; a pack that fails validation is
// dropped with a log line and guard runs without it.
func securityPackRules(active func(string) bool, logger *slog.Logger) []policy.Rule {
	c, err := secrules.Compose(active)
	if err != nil {
		if logger != nil {
			logger.Warn("security: rule pack refused", "err", err)
		}
		return nil
	}
	return c.Rules
}

// startSecurityModule starts the module's two loops on ng: security.posture
// (the one writer of the signed per-project posture files, plus the daily
// retention pass) and security.quickscan (the owner-only quick-scan
// endpoint the hook asks at a commit, served by security Phase C's scanner,
// security_phasec.go), then Phase C's security.postwrite loop.
func startSecurityModule(ctx context.Context, ng *gatedGroup, configPath string, snap componentstate.Snapshot) {
	ng.Go("security.posture", func() error {
		securityPostureLoop(ctx, configPath, snap)
		return nil
	})
	ng.Go("security.quickscan", func() error {
		resolved, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			return nil
		}
		layout := secposture.LayoutFor(resolved)
		ln, _, err := secipc.Listen(layout.Dir)
		if err != nil {
			slog.Default().Warn("security: quick-scan endpoint not started", "err", err)
			return nil
		}
		// Phase C's scanner (security_phasec.go): the posture says the
		// service is available only while it serves.
		securityRT.scanReady.Store(true)
		defer securityRT.scanReady.Store(false)
		securityRT.notify()
		_ = secipc.ServeWith(ctx, ln, securityQuickScanner(layout, newSecurityQuickScanEngine(securityIdentify(resolved))),
			secipc.Options{AllowRoot: securityAllowRoot, Feedback: securityFeedbackAnswerer(ctx, configPath, snap), Nudge: newProvenanceNudger(ctx)})
		return nil
	})
	startSecurityPhaseC(ctx, ng, configPath, snap.ModuleActive("security.code"))
	// Package checks (security.deps, Phase D1): the ask endpoint and the
	// index refresh, their own moduleGates row.
	startSecurityDeps(ctx, ng, configPath, snap)
	// Local finding exceptions (lane sec-c3, security_exceptions.go).
	startSecurityExceptions(ctx, ng, configPath)
	// Dependency scanners (security.scan.scalibr and security.scan.osv,
	// Phase D2): one loop per driver, their own moduleGates rows.
	startSecurityScan(ctx, ng, configPath, snap)
	// Custom scanners' scheduled runs (security.scan.custom, lane
	// sec-custom2, security_custom_schedule.go): its own moduleGates row,
	// off until [security.custom] schedule_hours is set.
	startCustomScanSchedule(ctx, ng, configPath, snap)
	// Code rules (security.scan.opengrep, lane sec-g2,
	// security_opengrep_daemon.go): post-write, commit-diff and scheduled
	// scans and the content refresh, its own moduleGates row.
	startOpengrepDaemon(ctx, ng, configPath, snap)
	// IaC checks (security.scan.trivy, security.scan.kics, lane GATES-SEC,
	// security_iac_daemon.go): post-write and scheduled scans, one loop per
	// selected engine, their own moduleGates rows.
	startIaCDaemon(ctx, ng, configPath, snap)
	// Inferences, fix observations and unverified_fix (security.code
	// selected by a [components] block, lane sec-g5, security_fixobs.go).
	startSecurityFixObs(ctx, ng, configPath, snap)
	// AI change records (security.provenance, lane sec-f2a,
	// security_provenance.go): opt-in, its own moduleGates row.
	startSecurityProvenance(ctx, ng, configPath, snap)
}

// securityRetryFirst and securityRetryMax bound the posture loop's back-off
// after a config, database or service start failure.
const (
	securityRetryFirst = 5 * time.Second
	securityRetryMax   = 5 * time.Minute
)

// securityPostureLoop runs the posture writer until ctx ends. A failure to
// load the config, open the database or start the writer is logged and
// retried with a doubling back-off, never dropped in silence (audit P-002
// finding 8): while it lasts the hook reads every project as unknown.
func securityPostureLoop(ctx context.Context, configPath string, snap componentstate.Snapshot) {
	wait := securityRetryFirst
	for {
		err := runSecurityPosture(ctx, configPath, snap)
		if ctx.Err() != nil {
			return
		}
		slog.Default().Warn("security: posture writer stopped; retrying", "err", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, securityRetryMax)
	}
}

// runSecurityPosture is one run of the posture writer: it returns nil only
// when ctx ended, and an error when it could not start.
func runSecurityPosture(ctx context.Context, configPath string, snap componentstate.Snapshot) error {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	logger := newLogger(cfg.Observer.LogLevel)
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return err
	}
	st := store.New(database)
	svc, err := secsvc.New(ctx, secsvc.Options{
		Layout: secposture.LayoutFor(resolved), Store: st, Projects: st.SecActiveProjectRoots,
		Packs:              func() []string { return securityActivePacks(snap) },
		QuickScanAvailable: securityRT.scanReady.Load,
		Baseline:           &secsvc.BaselineRescanner{Store: st, Drivers: securityBaselineDrivers(snap.ModuleActive("security.code")), PackVersion: secrules.PackVersion},
		OnError:            func(err error) { logger.Warn("security: posture pass failed", "err", err) },
		PushDefault:        securityPushDefaults.get,
		// The org commit gate and launch trust floors per project (lane
		// SEC-P4 decision 9), signed into each project's posture.
		Floors: securityPostureFloors(cfg.Security),
		// [security.scanning] per project (lane LEFT-SEC): the quick-scan
		// budget and scan staleness signed into each posture, and the least
		// blocking severity.
		Scanning: securityPostureScanning(cfg.Security),
		// The project audience match (lane sec-p): the core match record,
		// copied into the reserved posture fields.
		ProjectMatch: projectMatchForPosture(orgBundleCachePath(cfg)),
	})
	if err != nil {
		return err
	}
	// The quick-scan service (security_phasec.go) reads the writer to
	// record its runs and wake a pass (lane SEC-C2).
	securityRT.svc.Store(svc)
	defer securityRT.svc.Store(nil)
	projects := st.ProjectRoots
	securityRT.projects.Store(&projects)
	defer securityRT.projects.Store(nil)
	// [security.scanning].history_scan_on_enrol (lane LEFT-SEC,
	// security_scanning_settings.go): off by default; then one bounded
	// local history scan.
	go securityHistoryOnEnrolLoop(ctx, resolved, cfg.Security, st, logger)
	go securityRetentionLoop(ctx, st, func(ctx context.Context) securityRetentionPlan {
		return securityRetentionPlanFor(ctx, cfg.Security, st.ProjectRoots)
	}, logger)
	return svc.Run(ctx, 0)
}

// securityBaselineDrivers are the drivers the lazy baseline rescan asks to
// read a baseline commit's tree (section 4.5.2 item 2): the native
// workflow rules while security.code is active (lane sec-c3,
// security_exceptions.go). Secrets are never pre_existing, so they need
// none; the code and dependency drivers (phases D2 and G) join here.
func securityBaselineDrivers(codeActive bool) []secscan.Driver {
	return securityBaselineDriverSet(codeActive)
}

// securityRetentionPlan is one retention pass: the node-wide days
// ([security.retention].days raised by the org-wide floor) and the projects
// whose own floor keeps findings longer (lane SEC-P4 decision 10), each
// pruned at its own days and left out of the node-wide prune.
type securityRetentionPlan struct {
	Node     int
	Projects map[string]int
}

// securityRetentionPlanMax bounds the projects one plan reads.
const securityRetentionPlanMax = 4096

// securityRetentionPlanFor reads the plan: every project root through the
// project seam (securityFloorsAppliedAt; a linked worktree's project is its
// main repository, P-041), kept when its value is stricter than the node's
// (postureop.RetentionCmp: longer, and 0 is keep forever). A root list that
// cannot be read gives the node-wide plan alone, which never prunes a
// floored project earlier than before this lane did.
func securityRetentionPlanFor(ctx context.Context, sc config.SecurityConfig, roots func(context.Context) ([]string, error)) securityRetentionPlan {
	plan := securityRetentionPlan{Node: securityRetentionDaysNow(sc.Retention.Days)}
	if roots == nil {
		return plan
	}
	list, err := roots(ctx)
	if err != nil {
		return plan
	}
	for i, root := range list {
		if i == securityRetentionPlanMax {
			break
		}
		d := securityFloorsAppliedAt(sc, root).Retention.Days
		if postureop.RetentionCmp(int64(d), int64(plan.Node)) > 0 {
			if plan.Projects == nil {
				plan.Projects = map[string]int{}
			}
			plan.Projects[secposture.ProjectRootHash(root)] = d
		}
	}
	return plan
}

// securityRetentionLoop prunes closed and suppressed findings past the
// retention, once at start and then daily: the node-wide days over every
// project but those whose own floor keeps them longer, and each of those at
// its own days (0 keeps forever). The plan is re-read on every pass, so a
// floor accepted later applies at the next pass.
func securityRetentionLoop(ctx context.Context, st *store.Store, plan func(context.Context) securityRetentionPlan, logger *slog.Logger) {
	t := time.NewTicker(securityRetentionEvery)
	defer t.Stop()
	for {
		securityRetentionPass(ctx, st, plan(ctx), time.Now(), logger)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// securityRetentionPass runs one plan.
func securityRetentionPass(ctx context.Context, st *store.Store, p securityRetentionPlan, now time.Time, logger *slog.Logger) {
	except := make([]string, 0, len(p.Projects))
	for h := range p.Projects {
		except = append(except, h)
	}
	sort.Strings(except)
	prune := func(days int, scope store.SecPruneScope) {
		if days <= 0 {
			return // keep forever: nothing to prune
		}
		if n, err := st.PruneSecFindingsScoped(ctx, now.AddDate(0, 0, -days), scope); err != nil {
			logger.Warn("security: retention pass failed", "err", err)
		} else if n > 0 {
			logger.Info("security: retention pass", "findings_removed", n)
		}
	}
	prune(p.Node, store.SecPruneScope{Except: except})
	for _, h := range except {
		prune(p.Projects[h], store.SecPruneScope{Only: []string{h}})
	}
}
