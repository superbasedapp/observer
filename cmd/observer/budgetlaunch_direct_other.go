//go:build !linux

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func nodeProcessCutoffCoversLaunch(context.Context, config.Config, *store.Store, string, budgetLaunchEvidence) bool {
	return false
}
