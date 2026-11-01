//go:build !sbo_omit_benchmark

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/arena"
)

// arenaAdmissionTarget reads the launch target internal/arena carries on
// the admission callback's context (arena.LaunchTargetFrom): where the
// process starts, the run's source repository, and a func that adds
// environment entries to the process. ok is false on a context with none.
// It lives behind the benchmark build tag so a build without the module
// never links internal/arena (arena_budget_target_omit.go).
func arenaAdmissionTarget(ctx context.Context) (dir, source string, addEnv func([]string), ok bool) {
	t, ok := arena.LaunchTargetFrom(ctx)
	if !ok {
		return "", "", nil, false
	}
	return t.Dir, t.SourceRoot, func(env []string) { t.ChildEnv = append(t.ChildEnv, env...) }, true
}

// arenaAdmissionProjectRoot is the run's project root on the admission
// context (arena.LaunchTarget.ProjectRoot), "" when none is carried.
func arenaAdmissionProjectRoot(ctx context.Context) string {
	t, ok := arena.LaunchTargetFrom(ctx)
	if !ok {
		return ""
	}
	return t.ProjectRoot
}
