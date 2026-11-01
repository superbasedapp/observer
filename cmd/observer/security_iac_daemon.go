//go:build !sbo_omit_security

package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/powerstate"
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_iac_daemon.go is the IaC engines' daemon loop, one per selected
// engine (moduleGates rows security.scan.trivy and security.scan.kics,
// components_gate.go; lane GATES-SEC decision 4). Background only, never in
// a hook and never in the commit gate's quick scan. Each pass:
//
//   - post-write: reads the recorded agent writes (store.PostWritesAfter,
//     from the daemon's start) and, for a write to a file in an IaC path
//     class (seciac.ClassOf), scans that project once its writes went quiet
//     (seciac.Debouncer), only while [security.scan.<engine>] post_write
//     is on (default off);
//   - the schedule: a scan of each project active in the last week once
//     per schedule_hours (default 0, off), held on battery unless
//     run_on_battery.
//
// Nothing runs while the engine is not installed (no process starts), and
// runs go one at a time across both engines (the iac-scan lease).

const (
	iacLoopTick       = 15 * time.Second
	iacScheduleFirst  = 10 * time.Minute
	iacActiveWindow   = 7 * 24 * time.Hour
	iacSchedulePerRun = 10
	iacWritesBatch    = 256
)

// iacTriggerConfig is one engine's trigger keys.
type iacTriggerConfig struct {
	postWrite     bool
	scheduleHours int
	runOnBattery  bool
}

func iacTriggers(cfg config.Config, id seciac.EngineID) iacTriggerConfig {
	if id == seciac.KICS {
		k := cfg.Security.Scan.Kics
		return iacTriggerConfig{k.PostWrite, k.ScheduleHours, k.RunOnBattery}
	}
	t := cfg.Security.Scan.Trivy
	return iacTriggerConfig{t.PostWrite, t.ScheduleHours, t.RunOnBattery}
}

// startIaCDaemon starts one loop per compiled, selected engine.
func startIaCDaemon(ctx context.Context, ng *gatedGroup, configPath string, snap componentstate.Snapshot) {
	if iacSelected(snap, seciac.Trivy) {
		// The loop names are literals so TestEveryDaemonLoopIsClassified can
		// match them against the moduleGates rows.
		ng.Go("security.scan.trivy", func() error { runIaCLoop(ctx, configPath, seciac.Trivy); return nil })
	}
	if iacSelected(snap, seciac.KICS) {
		ng.Go("security.scan.kics", func() error { runIaCLoop(ctx, configPath, seciac.KICS); return nil })
	}
}

// iacLoop owns one engine loop's state.
type iacLoop struct {
	id         seciac.EngineID
	configPath string
	db         *sql.DB
	st         *store.Store
	cursor     int64
	deb        seciac.Debouncer
	started    time.Time
	logger     *slog.Logger
	// The seams a test swaps.
	scan      func(ctx context.Context, e *iacEnv, t secscan.Target) error
	power     func() powerstate.State
	installed func(ctx context.Context, e *iacEnv) bool
	stat      func(string) (os.FileInfo, error)
}

func runIaCLoop(ctx context.Context, configPath string, id seciac.EngineID) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		slog.Default().Warn("security: IaC loop not started", "engine", id, "err", err)
		return
	}
	defer cleanup()
	l := newIaCLoop(id, configPath, database, newLogger(cfg.Observer.LogLevel))
	if l.cursor, err = l.st.MaxActionID(ctx); err != nil {
		return
	}
	t := time.NewTicker(iacLoopTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		l.pass(ctx, time.Now())
	}
}

func newIaCLoop(id seciac.EngineID, configPath string, database *sql.DB, logger *slog.Logger) *iacLoop {
	return &iacLoop{
		id: id, configPath: configPath, db: database, st: store.New(database), started: time.Now(), logger: logger,
		scan: iacLoopScan, power: powerstate.Read, installed: iacEngineInstalled, stat: os.Stat,
	}
}

// iacEnvFor opens an engine env over an already open database, nil when
// the engine is not selected.
func iacEnvFor(configPath string, database *sql.DB, id seciac.EngineID) (*iacEnv, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return nil, err
	}
	snap := componentSnapshotForConfig(cfg)
	if !iacSelected(snap, id) {
		return nil, nil
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return nil, err
	}
	e := &iacEnv{id: id, cfg: cfg, resolved: resolved, secDir: secposture.LayoutFor(resolved).Dir, snap: snap, configPath: configPath, cleanup: func() {}}
	if database != nil {
		e.st = store.New(database)
		if lk := managedTenancyLookup(e.st); lk != nil {
			e.managed = lk()
		}
	}
	e.manifest = loadIaCManifest(iacContentStore(resolved), iacTrust(), id)
	return e, nil
}

func iacLoopScan(ctx context.Context, e *iacEnv, t secscan.Target) error {
	_, err := runIaCScan(ctx, e, t)
	return err
}

// iacEngineInstalled reports whether the driver finds an engine (no
// process starts).
func iacEngineInstalled(ctx context.Context, e *iacEnv) bool {
	d := e.inspector()
	return d != nil && d.Probe(ctx).Installed
}

// pass is one pass over the two triggers.
func (l *iacLoop) pass(ctx context.Context, now time.Time) {
	e, err := iacEnvFor(l.configPath, l.db, l.id)
	if err != nil || e == nil {
		return
	}
	tc := iacTriggers(e.cfg, l.id)
	installed := l.installed(ctx, e)
	l.readWrites(ctx, now, tc.postWrite && installed)
	if !installed {
		return
	}
	for _, root := range l.deb.Due(now) {
		err := l.scan(ctx, e, secscan.Target{ProjectRoot: root, Scope: policy.FindingScopePostWrite})
		switch {
		case errors.Is(err, errIaCScanBusy):
			l.deb.Requeue(root, now)
		case err != nil:
			l.logger.Warn("security: IaC post-write scan failed", "engine", l.id, "err", err)
		}
	}
	if tc.scheduleHours > 0 && now.Sub(l.started) >= iacScheduleFirst {
		l.runSchedule(ctx, e, tc, now)
	}
}

// readWrites drains the stored writes; they are queued only while keep.
func (l *iacLoop) readWrites(ctx context.Context, now time.Time, keep bool) {
	for {
		writes, next, err := l.st.PostWritesAfter(ctx, l.cursor, iacWritesBatch)
		if err != nil {
			return
		}
		l.cursor = next
		if keep {
			for _, w := range writes {
				l.deb.Add(w.ProjectRoot, w.Path, now)
			}
		}
		if len(writes) < iacWritesBatch {
			return
		}
	}
}

// runSchedule runs the due scheduled scans, held on battery.
func (l *iacLoop) runSchedule(ctx context.Context, e *iacEnv, tc iacTriggerConfig, now time.Time) {
	if !tc.runOnBattery && l.power() != powerstate.AC {
		return
	}
	roots, err := l.st.SecActiveProjectRoots(ctx, now.Add(-iacActiveWindow))
	if err != nil {
		return
	}
	every := time.Duration(tc.scheduleHours) * time.Hour
	n := 0
	for _, root := range roots {
		if ctx.Err() != nil || n >= iacSchedulePerRun {
			return
		}
		// A root that is not rooted on this host is never statted or
		// scanned relative to the working directory (audit finding 1 on
		// the w14 hand-back).
		if !git.HostRooted(root) {
			continue
		}
		if fi, err := l.stat(root); err != nil || !fi.IsDir() {
			continue
		}
		last, err := l.st.SecLastDriverRun(ctx, secposture.ProjectRootHash(root), string(l.id), policy.FindingScopeScheduled)
		if err != nil || (!last.IsZero() && now.Sub(last) < every) {
			continue
		}
		n++
		err = l.scan(ctx, e, secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeScheduled})
		if errors.Is(err, errIaCScanBusy) {
			return
		}
		if err != nil {
			l.logger.Warn("security: IaC scheduled scan failed", "engine", l.id, "err", err)
		}
	}
}
