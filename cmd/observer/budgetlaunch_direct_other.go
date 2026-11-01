//go:build !linux

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// nodeProcessCutoffCoverage reports why no process cutoff covers a launch on
// this operating system.
func nodeProcessCutoffCoverage(context.Context, config.Config, *store.Store, string, budgetLaunchEvidence) (bool, string) {
	return false, "the node's process controller runs only on Linux"
}

// nodeProcessCutoffCoverageNow is the picker preflight's form.
func nodeProcessCutoffCoverageNow(ctx context.Context, cfg config.Config, st *store.Store, tool string, evidence budgetLaunchEvidence) (bool, string) {
	return nodeProcessCutoffCoverage(ctx, cfg, st, tool, evidence)
}
