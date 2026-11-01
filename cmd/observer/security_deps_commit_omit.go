//go:build !sbo_omit_security && sbo_omit_security_deps

package main

import (
	"context"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdiffobs"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// depsRetainPath retains nothing: security.deps is not in this build.
func depsRetainPath(string) bool { return false }

// recordDepsManifests records nothing: security.deps is not in this build.
func recordDepsManifests(context.Context, *store.Store, string, string, policy.FindingScope, []secdiffobs.FileDiff, *slog.Logger) {
}
