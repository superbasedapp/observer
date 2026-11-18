//go:build !sbo_omit_judge_client

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
)

// projects_judge_wire.go adapts alignmentJudgeFor (W5a,
// cmd/observer/alignment_wire.go) into the dashapi.Options.JudgeGrade
// shape. Build-tag-split from projects_wire.go because alignmentJudgeFor
// uses the judge client component (judge_wire.go, internal/judgeclient),
// which a `-tags sbo_omit_judge_client` build compiles out; see
// projects_judge_wire_stub.go for that side. It no longer depends on obs
// (phase PB moved the judge client out of obs_wire.go, D-408 / D-424).

// judgeClientInBuild is true: the judge tier exists and its settings turn
// it on.
const judgeClientInBuild = true

// projectsJudgeGradeSeam returns a closure that grades one prompt's
// alignment.Input through the configured judge, or nil with the honest
// reason alignmentJudgeFor gave (disabled config / no model configured)
// when the tier cannot run.
func projectsJudgeGradeSeam(cfg *config.Config) (func(context.Context, alignment.Input) (alignment.Result, string, error), string) {
	judge, model, _, reason := alignmentJudgeFor(cfg)
	if judge == nil {
		return nil, reason
	}
	return func(ctx context.Context, in alignment.Input) (alignment.Result, string, error) {
		result, err := alignment.Grade(ctx, judge, in)
		return result, model, err
	}, ""
}
