package main

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/captureprogress"
	"github.com/marmutapp/superbased-observer/internal/firstrunstate"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// The first-run capture view's daemon side (T-922). Two small wirings, both
// fail-open (the view is a convenience; nothing here may stop the daemon):
//
//   - wireCaptureProgress gives the watcher the one progress model its
//     initial scan reports into and returns the read seam the dashboard
//     takes (dashapi.Options.CaptureProgress).
//   - recordFirstRunInstall records ONCE, before the watcher's initial scan,
//     whether this install was fresh (an empty database), which is what lets
//     the dashboard open the view by itself on a new install and never on an
//     upgrade.

// wireCaptureProgress installs a fresh progress model on w and returns its
// snapshot reader. A nil watcher yields a nil reader (the dashboard then
// reports the watcher as not running in this process).
func wireCaptureProgress(w *watcher.Watcher) func() captureprogress.Snapshot {
	if w == nil {
		return nil
	}
	t := captureprogress.New(nil)
	w.SetCaptureProgress(t)
	return t.Snapshot
}

// recordFirstRunInstall records the install kind beside the database at
// dbPath, unless one is already recorded. Failures are logged, never fatal.
func recordFirstRunInstall(ctx context.Context, database *sql.DB, dbPath string, log *slog.Logger) {
	if database == nil || dbPath == "" {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	fs := firstrunstate.New(firstrunstate.Path(dbPath))
	if fs.Load().Install != firstrunstate.InstallUnknown {
		return
	}
	has, err := store.New(database).HasSessions(ctx)
	if err != nil {
		log.Warn("first-run view: could not read the session count; install kind not recorded", "err", err)
		return
	}
	if _, err := fs.RecordInstall(!has, time.Now()); err != nil {
		log.Warn("first-run view: could not record the install kind", "err", err)
	}
}
