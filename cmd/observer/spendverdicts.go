package main

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/spendverdict"
)

// spendVerdictInterval is how often the daemon re-derives the sessions whose
// rows changed. A windowed read (the cost engine, the guard's budget windows,
// the predictor's prior) refreshes before reading anyway; the ticker keeps
// the queue short so that refresh is normally one empty probe, and it works
// off the one-time backfill after an upgrade in the background.
const spendVerdictInterval = 5 * time.Second

// spendVerdictLoop keeps the node's stored sessionmsg dedup verdicts (agent
// migration 143, internal/spendverdict) current for the daemon's lifetime.
// P1 fail-soft like every sibling loop: a failed pass is logged and retried
// on the next tick, never cancels the daemon.
func spendVerdictLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	logger := newLogger(cfg.Observer.LogLevel)
	pass := func() {
		start := time.Now()
		n, err := spendverdict.Refresh(ctx, database, spendverdict.Options{MaxDuration: 30 * time.Second})
		if err != nil && ctx.Err() == nil {
			logger.Warn("spend verdicts: refresh failed", "err", err)
			return
		}
		if n > 100 {
			logger.Info("spend verdicts: re-derived sessions", "sessions", n, "took", time.Since(start).Round(time.Millisecond))
		}
	}
	pass()
	ticker := time.NewTicker(spendVerdictInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pass()
		}
	}
}
