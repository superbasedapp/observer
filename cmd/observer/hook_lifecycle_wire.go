package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hookspool"
	"github.com/marmutapp/superbased-observer/internal/intelligence/compaction"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// hookLifecycleInterval is how often the daemon drains the lifecycle hook
// spool (and runs the other hook-health checks that share this loop).
const hookLifecycleInterval = 5 * time.Second

// lifecycleIngester is the store seam the drain writes through.
type lifecycleIngester interface {
	Ingest(ctx context.Context, events []models.ToolEvent, tokens []models.TokenEvent, opts store.IngestOptions) (store.IngestResult, error)
}

// lifecycleSessions is the store seam a held record is checked against
// (T-320): whether its session exists yet, and the session's project root
// for a row the hook could not give one.
type lifecycleSessions interface {
	SessionExists(ctx context.Context, id string) (bool, error)
	ProjectRootForSession(ctx context.Context, sessionID string) (string, error)
}

// lifecycleDrainStore is everything the drain reads and writes.
type lifecycleDrainStore interface {
	lifecycleIngester
	lifecycleSessions
}

// lifecycleDrainDeps is the drain's injected I/O.
type lifecycleDrainDeps struct {
	st lifecycleDrainStore
	// compaction lands one compaction record (applyCompactionRecord over the
	// daemon's database in production).
	compaction func(ctx context.Context, r hookspool.Record) error
	// hold re-appends a held record to the live spool (hookspool.Append).
	hold func(path string, r hookspool.Record) error
	// activity lands one aside file's hook liveness records (the ONE writer,
	// store.UpsertHookActivity, in production). nil drops them.
	activity func(ctx context.Context, rows []store.HookActivityRow) error
}

// drainHookLifecycleSpool processes every aside spool file that is ready and
// then sets the live spool aside for the next pass (internal/hookspool's
// two-phase protocol). Each record is decided by hookspool.Decide: applied
// now, held (re-appended with Attempts+1) until its session exists, or
// expired past the hold bounds. An aside file is removed only after its
// tool-event rows were ingested; on an ingest failure it stays for the next
// pass with no side effect taken (at-least-once; the rows' deterministic
// source event ids make a repeat an upsert). Returns the number of records
// landed.
func drainHookLifecycleSpool(ctx context.Context, spoolPath string, d lifecycleDrainDeps, now time.Time, logger *slog.Logger) int {
	if spoolPath == "" || d.st == nil {
		return 0
	}
	if d.hold == nil {
		d.hold = hookspool.Append
	}
	ready, err := hookspool.Ready(spoolPath, now)
	if err != nil {
		logger.Warn("hook lifecycle spool: list", "err", err)
	}
	known := map[string]bool{}
	held := 0
	total := 0
	for _, a := range ready {
		if a.Dropped > 0 {
			logger.Warn("hook lifecycle spool: unreadable lines", "file", a.Path, "dropped", a.Dropped)
		}
		plan := planLifecycleAside(ctx, d.st, a.Records, known, &held, now, logger)
		if len(plan.events) > 0 {
			if _, err := d.st.Ingest(ctx, plan.events, nil, store.IngestOptions{}); err != nil {
				logger.Warn("hook lifecycle spool: ingest", "err", err, "records", len(plan.events))
				// No side effect was taken for this file: it is retried whole.
				held -= len(plan.holds)
				continue
			}
			total += len(plan.events)
		}
		if len(plan.activity) > 0 && d.activity != nil {
			// Best effort, after the file's events landed: a failed upsert is
			// a lost liveness count, never a re-ingested event.
			if err := d.activity(ctx, plan.activity); err != nil {
				logger.Warn("hook lifecycle spool: hook activity", "err", err, "records", len(plan.activity))
			}
		}
		for _, r := range plan.compactions {
			if d.compaction == nil {
				continue
			}
			if err := d.compaction(ctx, r); err != nil {
				logger.Warn("hook lifecycle spool: compaction", "err", err, "session_id", r.SessionID, "phase", r.Phase)
				continue
			}
			total++
		}
		for _, r := range plan.holds {
			r.Attempts++
			if err := d.hold(spoolPath, r); err != nil {
				logger.Warn("hook lifecycle spool: hold", "err", err, "session_id", r.SessionID)
			}
		}
		if plan.expired > 0 {
			logger.Warn("hook lifecycle spool: records expired waiting for their session", "file", a.Path, "expired", plan.expired)
		}
		if err := hookspool.Done(a); err != nil {
			logger.Warn("hook lifecycle spool: remove", "err", err)
		}
	}
	if _, err := hookspool.SetAside(spoolPath, now); err != nil {
		logger.Warn("hook lifecycle spool: set aside", "err", err)
	}
	// Activity records the hooks skipped while the spool was past its cap
	// (nothing drained it): the live spool is empty again, so say so once and
	// clear the count (R-188 F5; the doctor's hooks.spool row reads it while
	// the daemon is down).
	if n, err := hookspool.TakeSkippedActivity(spoolPath, now); err != nil {
		logger.Warn("hook lifecycle spool: skipped activity count", "err", err)
	} else if n > 0 {
		logger.Warn("hook lifecycle spool: hook activity records were skipped while the spool was past its cap", "skipped", n, "cap_bytes", hookspool.MaxActivitySpoolBytes)
	}
	return total
}

// lifecycleAsidePlan is one aside file's records sorted by disposition, in
// file order within each list.
type lifecycleAsidePlan struct {
	events      []models.ToolEvent
	compactions []hookspool.Record
	holds       []hookspool.Record
	activity    []store.HookActivityRow
	expired     int
}

// planLifecycleAside decides every record of one aside file. known caches
// session existence for the pass; held counts the records this pass holds,
// against hookspool.MaxHeldPerPass. A lookup error holds the record (the
// next pass retries), bounded like any other hold.
func planLifecycleAside(ctx context.Context, st lifecycleSessions, records []hookspool.Record, known map[string]bool, held *int, now time.Time, logger *slog.Logger) lifecycleAsidePlan {
	var p lifecycleAsidePlan
	for _, r := range records {
		if r.Kind == hookspool.KindActivity {
			p.activity = append(p.activity, hookActivityRow(r))
			continue
		}
		exists := false
		if r.NeedsSession() {
			v, cached := known[r.SessionID]
			if !cached {
				var err error
				v, err = st.SessionExists(ctx, r.SessionID)
				if err != nil {
					logger.Warn("hook lifecycle spool: session lookup", "err", err, "session_id", r.SessionID)
				} else {
					known[r.SessionID] = v
				}
			}
			exists = v
		}
		switch hookspool.Decide(r, exists, now) {
		case hookspool.Apply:
			if r.Kind == hookspool.KindCompaction {
				p.compactions = append(p.compactions, r)
				continue
			}
			ev := r.Event()
			if ev.ProjectRoot == "" {
				// The hook had no cwd; the session the watcher created has
				// the root. Without one Ingest would skip the row.
				root, err := st.ProjectRootForSession(ctx, r.SessionID)
				if err != nil || root == "" {
					p.expired++
					continue
				}
				ev.ProjectRoot = root
			}
			p.events = append(p.events, ev)
		case hookspool.Hold:
			if *held >= hookspool.MaxHeldPerPass {
				p.expired++
				continue
			}
			*held++
			p.holds = append(p.holds, r)
		default:
			p.expired++
		}
	}
	return p
}

// hookActivityRow is one spooled activity record as the writer's row.
func hookActivityRow(r hookspool.Record) store.HookActivityRow {
	return store.HookActivityRow{
		Tool: r.Tool, Event: r.HookEvent, SessionID: r.SessionID, Count: 1,
		FirstAt: r.Timestamp, LastAt: r.Timestamp, EnvClasses: r.Env,
	}
}

// hookActivityPruneInterval is how often the loop drops hook_activity rows
// past store.HookActivityRetention.
const hookActivityPruneInterval = time.Hour

// hookLifecycleLoop is the daemon's ONE drainer of the lifecycle hook spool
// (hook-parity Lane C1) and its ONE watcher of vendor hook-disable switches
// (T-046). P1 like every sibling loop: it never propagates an
// error and never cancels proxy / watcher / dashboard.
func hookLifecycleLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	logger := newLogger(cfg.Observer.LogLevel)
	st := hookIngestStore(database)
	resolved, _ := config.ResolveGlobalPath(configPath)
	spool := hookspool.Path(resolved)
	recorder := compaction.New(database)
	drain := lifecycleDrainDeps{
		st: st,
		compaction: func(ctx context.Context, r hookspool.Record) error {
			return applyCompactionRecord(ctx, recorder, r)
		},
		hold:     hookspool.Append,
		activity: st.UpsertHookActivity,
	}
	var lastPrune time.Time
	// T-046: the same loop watches the vendor switches that turn every hook
	// off, and persists a guard event (reaching the org) when one turns on;
	// T-910 adds the switches in the projects the store knows.
	disabled := newHookDisableWatch(st)
	tick := func() {
		now := time.Now()
		if n := drainHookLifecycleSpool(ctx, spool, drain, now, logger); n > 0 {
			logger.Info("hook lifecycle spool: ingested lifecycle rows", "count", n)
		}
		disabled.check(ctx, st, now, logger)
		if now.Sub(lastPrune) >= hookActivityPruneInterval {
			lastPrune = now
			if _, err := st.PruneHookActivity(ctx, now.Add(-store.HookActivityRetention)); err != nil {
				logger.Warn("hook activity: prune", "err", err)
			}
		}
	}
	tick()
	t := time.NewTicker(hookLifecycleInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
