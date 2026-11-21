package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/codequalitysvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// codeQualityLoop is the daemon-lifetime driver of the Projects page's
// quality trend (internal/codequalitysvc, docs/projects-page.md "Quality
// metrics"): one pass a minute after start, then one every 30 minutes,
// each recording a daily point for every active project whose last point
// is from an earlier day or older than six hours. It reads coverage report
// files and the codeintel index only: no git, no test run, no network.
// Self-gating on [projects].quality_metrics; P1 fail-soft like every
// sibling loop (a failing project is logged and skipped).
func codeQualityLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	if !cfg.Projects.QualityMetrics {
		return
	}
	logger := newLogger(cfg.Observer.LogLevel)
	codequalitysvc.New(store.New(database), codequalitysvc.ConfigFrom(cfg), codequalitysvc.WithLogger(logger)).
		Run(ctx, codequalitysvc.DefaultTick)
}
