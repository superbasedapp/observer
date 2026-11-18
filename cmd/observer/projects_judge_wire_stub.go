//go:build sbo_omit_judge_client

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
)

// projects_judge_wire_stub.go is the sbo_omit_judge_client-build stub for
// the §3.6 "J" alignment-grading tier: alignmentJudgeFor
// (cmd/observer/alignment_wire.go) needs the judge client (judge_wire.go),
// which that tag compiles out, so this build reports the tier honestly
// unavailable rather than failing to compile. The public tree keeps the
// judge wiring (operator ruling D-438 on T-665), so a plain public build
// uses projects_judge_wire.go, not this stub.
// judgeClientInBuild is false: this build has no judge client to turn on.
const judgeClientInBuild = false

func projectsJudgeGradeSeam(cfg *config.Config) (func(context.Context, alignment.Input) (alignment.Result, string, error), string) {
	return nil, "the judge tier is not available in this build (judge client compiled out)"
}
