//go:build !sbo_omit_security && !sbo_omit_security_scan_custom

package main

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/powerstate"
	"github.com/marmutapp/superbased-observer/internal/seccustomsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_custom_schedule.go is the scheduled-run loop of the custom
// scanners (security pillar plan section 4.4; component
// security.scan.custom, its moduleGates row in components_gate.go). Off by
// default: [security.custom] schedule_hours = 0. While it is on, every
// accepted scanner runs over each project active in the last week once per
// interval, one run at a time, and the pass is held while the machine runs
// on battery or its power state cannot be read, unless pause_on_battery is
// turned off.

const (
	// customScheduleFirst is the delay before the first pass, so a daemon
	// start never begins with a scan.
	customScheduleFirst = 10 * time.Minute
	// customScheduleTick is how often the loop re-reads the settings and
	// the power state; the interval itself is the setting.
	customScheduleTick = 15 * time.Minute
	// customScheduleActiveDays and customScheduleMaxProjects bound which
	// projects a pass scans: the most recently active ten of the last week.
	customScheduleActiveDays  = 7
	customScheduleMaxProjects = 10
)

// startCustomScanSchedule starts the loop when the component is selected
// (the opt-in rule of security_optin.go applies).
func startCustomScanSchedule(ctx context.Context, ng *gatedGroup, configPath string, snap componentstate.Snapshot) {
	if !customScanSelected(snap) {
		return
	}
	ng.Go("security.custom.schedule", func() error {
		l := &customScheduleLoop{configPath: configPath, snap: snap}
		defer l.close()
		l.run(ctx, customScheduleFirst, customScheduleTick)
		return nil
	})
}

// customScheduleLoop owns the loop's database handle and service, opened
// on the first pass the schedule is on.
type customScheduleLoop struct {
	configPath string
	snap       componentstate.Snapshot
	db         *sql.DB
	cleanup    func()
	svc        *seccustomsvc.Service
}

func (l *customScheduleLoop) close() {
	if l.cleanup != nil {
		l.cleanup()
	}
}

// run waits first, then runs a pass every tick until ctx ends.
func (l *customScheduleLoop) run(ctx context.Context, first, tick time.Duration) {
	wait := first
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = tick
		l.pass(ctx)
	}
}

// pass re-reads [security.custom] and, when the schedule is on, runs the
// due pairs.
func (l *customScheduleLoop) pass(ctx context.Context) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: l.configPath})
	if err != nil || cfg.Security.Custom.ScheduleHours <= 0 {
		return
	}
	if l.svc == nil {
		_, database, cleanup, err := loadConfigAndDB(ctx, l.configPath)
		if err != nil {
			slog.Default().Warn("security: custom scanner schedule could not open the database", "err", err)
			return
		}
		svc, err := customScannerService(ctx, l.snap, l.configPath, store.New(database))
		if err != nil || svc == nil {
			cleanup()
			return
		}
		l.db, l.cleanup, l.svc = database, cleanup, svc
	}
	// The cap keeps the most recently active projects (latest session
	// first), not the oldest ids.
	roots, err := store.New(l.db).RecentActiveProjectRoots(ctx, customScheduleActiveDays, customScheduleMaxProjects)
	if err != nil {
		slog.Default().Warn("security: custom scanner schedule could not list projects", "err", err)
		return
	}
	projects := make([]string, 0, len(roots))
	for _, r := range roots {
		projects = append(projects, r.RootPath)
	}
	rep := l.svc.RunScheduled(ctx, seccustomsvc.ScheduleInput{
		Every:          time.Duration(cfg.Security.Custom.ScheduleHours) * time.Hour,
		PauseOnBattery: cfg.Security.Custom.PauseOnBattery,
		Power:          string(powerstate.Read()),
		Projects:       projects,
	})
	if rep.Ran > 0 || rep.Failed > 0 {
		slog.Default().Info("security: custom scanner schedule pass", "ran", rep.Ran, "failed", rep.Failed, "held", rep.Held)
	}
}
