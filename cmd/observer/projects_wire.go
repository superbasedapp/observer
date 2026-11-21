package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
)

// projects_wire.go wires the Projects-page ROI + commit-alignment arc's
// (docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md
// section 4 W3) remaining cmd/observer seams:
//
//  1. gradeCommitLoader (cloud_gradecommit.go's package var, W5b) gets
//     its real implementation in projects_cloudgrade.go, which builds a
//     cloudevidence.CommitAlignmentInput and so belongs to
//     cloud.intelligence (lane MP-L1I, T-715): a build with -tags
//     sbo_omit_cloud_intelligence has neither file and builds no envelope.
//  2. projectsDashboardOptions resolves the two dashapi.Options
//     fields start.go's and dashboard.go's dashboard.New call sites
//     both need: CloudGradeAvailability (always
//     CommitAlignmentAvailability itself, so the dashboard and the CLI
//     never disagree about why cloud grading is unavailable) and
//     JudgeGrade/JudgeGradeReason (build-tag-split, see
//     projects_judge_wire.go / projects_judge_wire_stub.go, because the
//     underlying [projects].alignment_judge tier reuses the obs-gated
//     chatCompletionsJudge client).

// projectsDashboardOptions resolves the dashapi.Options.JudgeGrade /
// JudgeGradeReason pair (build-tag-split, see projects_judge_wire.go /
// projects_judge_wire_stub.go) for both dashboard.New call sites
// (start.go, cmd/observer/dashboard.go). Options.CloudGradeAvailability
// is wired directly to CommitAlignmentAvailability at each call site:
// no wrapper needed, the signatures already match.
func projectsDashboardOptions(cfg *config.Config) (judgeGrade func(context.Context, alignment.Input) (alignment.Result, string, error), judgeGradeReason string) {
	return projectsJudgeGradeSeam(cfg)
}

// projectsJudgeGradePlace is where the person turns the "J" grading tier on
// when it is unavailable: the alignment_judge switch (Settings >
// Intelligence) while it is off, else the judge's model (Settings >
// Observability). Empty when the tier runs, or when this build has no judge
// client (no setting changes that).
func projectsJudgeGradePlace(cfg *config.Config, available bool) settingslink.Place {
	switch {
	case available || !judgeClientInBuild || cfg == nil:
		return ""
	case cfg.Projects.AlignmentJudge != "obs_judge":
		return settingslink.IntelligenceSettings
	default:
		return settingslink.ObservabilitySettings
	}
}
