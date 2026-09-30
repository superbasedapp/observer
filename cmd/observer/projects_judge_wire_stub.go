//go:build no_obs

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
)

// projects_judge_wire_stub.go is the no_obs-build stub for the §3.6 "J"
// alignment-grading tier: alignmentJudgeFor (cmd/observer/
// alignment_wire.go) is itself !no_obs-only (it reuses
// chatCompletionsJudge, compiled out under no_obs), so this build
// reports the tier honestly unavailable rather than failing to compile.
func projectsJudgeGradeSeam(cfg *config.Config) (func(context.Context, alignment.Input) (alignment.Result, string, error), string) {
	return nil, "the judge tier is not available in this build (no_obs)"
}
