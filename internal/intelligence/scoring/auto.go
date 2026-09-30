package scoring

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// AutoOptions parameterizes the daemon-lifetime AutoScorer. Zero values fall
// back to the Default* constants, so a caller that only wants "on" passes an
// empty struct.
type AutoOptions struct {
	// Interval is the pause between ticks.
	Interval time.Duration
	// Idle is how long a session must have had no new action before it is
	// scored. Spec §15.2 says "computed when session ends"; most adapters
	// never record an explicit end, so a quiet period stands in for it.
	Idle time.Duration
	// MaxPerTick bounds the sessions scored in one tick (the backlog pass
	// and the re-score pass share the budget). One capped batch per tick,
	// never loop-until-done: a first start on a large unscored corpus works
	// the backlog off over several ticks.
	MaxPerTick int
	// Lookback is how far before the first tick's idle cutoff the re-score
	// window reaches on daemon start, so a session that was resumed while the
	// daemon was down still gets its stale score refreshed.
	Lookback time.Duration
	// StartDelay postpones the first tick so a daemon start is not competing
	// with the startup ingest / integrity pass.
	StartDelay time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
	// Logger receives one line per tick that did work. Nil = slog.Default().
	Logger *slog.Logger
}

// Defaults for AutoOptions (mirrored by config.IntelligenceScoringConfig).
const (
	DefaultAutoInterval   = 5 * time.Minute
	DefaultAutoIdle       = 30 * time.Minute
	DefaultAutoMaxPerTick = 200
	DefaultAutoLookback   = 24 * time.Hour
	DefaultAutoStartDelay = 2 * time.Minute
)

// AutoScorer keeps session quality scores current without anyone running
// `observer score`: each tick it (1) re-scores sessions that saw new actions
// since the previous tick and have since gone idle, then (2) spends what is
// left of the per-tick budget on the never-scored backlog, newest first.
//
// The one piece of in-memory state is the re-score watermark (the previous
// tick's idle cutoff). It is not persisted: on a restart the first window
// reaches back Lookback, and anything older is still covered by the backlog
// pass whenever it has never been scored.
type AutoScorer struct {
	scorer    *Scorer
	opts      AutoOptions
	watermark time.Time
}

// TickResult summarizes one AutoScorer tick.
type TickResult struct {
	Rescored BatchResult
	Backlog  BatchResult
}

// NewAuto builds an AutoScorer over s, filling zero options with defaults.
func NewAuto(s *Scorer, opts AutoOptions) *AutoScorer {
	if opts.Interval <= 0 {
		opts.Interval = DefaultAutoInterval
	}
	if opts.Idle <= 0 {
		opts.Idle = DefaultAutoIdle
	}
	if opts.MaxPerTick <= 0 {
		opts.MaxPerTick = DefaultAutoMaxPerTick
	}
	if opts.Lookback < 0 {
		opts.Lookback = 0
	}
	if opts.StartDelay < 0 {
		opts.StartDelay = 0
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &AutoScorer{scorer: s, opts: opts}
}

// Tick runs one scoring pass. Errors scoring an individual session are
// counted in the result, never returned; an error is returned only when a
// candidate listing query fails.
func (a *AutoScorer) Tick(ctx context.Context) (TickResult, error) {
	var out TickResult
	now := a.opts.Now()
	cutoff := now.Add(-a.opts.Idle)
	from := a.watermark
	if from.IsZero() {
		from = cutoff.Add(-a.opts.Lookback)
	}
	// Overlap the window by a minute: action timestamps are compared as TEXT,
	// and a sub-second formatting difference must not drop a boundary row.
	from = from.Add(-time.Minute)

	budget := a.opts.MaxPerTick
	idleNow := func() time.Time { return now }

	ids, err := a.scorer.SessionsActiveBetween(ctx, from, cutoff)
	if err != nil {
		return out, err
	}
	if len(ids) > 0 {
		res, err := a.scorer.BatchScore(ctx, BatchOptions{
			IDs:         ids,
			IdleAtLeast: a.opts.Idle,
			Now:         idleNow,
			Limit:       budget,
		})
		if err != nil {
			return out, fmt.Errorf("scoring: auto rescore: %w", err)
		}
		out.Rescored = res
		budget -= res.Scored + res.Errors
	}
	// The watermark advances only after the re-score listing succeeded. A
	// session the budget cut off this tick is not lost: if it was never
	// scored, the backlog pass picks it up; if it was, its next action moves
	// it into a later window.
	a.watermark = cutoff

	if budget > 0 {
		res, err := a.scorer.BatchScore(ctx, BatchOptions{
			OnlyUnscored: true,
			IdleAtLeast:  a.opts.Idle,
			Now:          idleNow,
			Limit:        budget,
		})
		if err != nil {
			return out, fmt.Errorf("scoring: auto backlog: %w", err)
		}
		out.Backlog = res
	}
	return out, nil
}

// Run ticks until ctx is cancelled. It never returns an error: a failed tick
// is logged and retried on the next interval (fail-soft, like every other
// daemon loop).
func (a *AutoScorer) Run(ctx context.Context) {
	if a.opts.StartDelay > 0 {
		t := time.NewTimer(a.opts.StartDelay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	ticker := time.NewTicker(a.opts.Interval)
	defer ticker.Stop()
	for {
		res, err := a.Tick(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			a.opts.Logger.Warn("session scoring tick failed", "err", err)
		case res.Rescored.Scored+res.Backlog.Scored+res.Rescored.Errors+res.Backlog.Errors > 0:
			a.opts.Logger.Info("session scoring tick",
				"rescored", res.Rescored.Scored,
				"backlog_scored", res.Backlog.Scored,
				"errors", res.Rescored.Errors+res.Backlog.Errors,
				"duration_ms", res.Rescored.DurationMs+res.Backlog.DurationMs)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
