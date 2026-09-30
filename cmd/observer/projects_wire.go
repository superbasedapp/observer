package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// projects_wire.go wires the Projects-page ROI + commit-alignment arc's
// (docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md
// §4 W3) remaining cmd/observer seams:
//
//  1. gradeCommitLoader (cloud_gradecommit.go's package var, W5b) gets
//     its real implementation — composing internal/store's W3 loaders
//     (LoadPromptChainInput, ProjectIDForAction) plus the existing
//     cloud-pseudonym/authority/purpose-set helpers cloud.go's own
//     envelope builder uses — into a cloudevidence.CommitAlignmentInput.
//  2. projectsDashboardOptions resolves the two dashboard.Options
//     fields start.go's and dashboard.go's dashboard.New call sites
//     both need: CloudGradeAvailability (always
//     CommitAlignmentAvailability itself, so the dashboard and the CLI
//     never disagree about why cloud grading is unavailable) and
//     JudgeGrade/JudgeGradeReason (build-tag-split — see
//     projects_judge_wire.go / projects_judge_wire_stub.go, because the
//     underlying [projects].alignment_judge tier reuses the obs-gated
//     chatCompletionsJudge client).

func init() {
	// gradeCommitLoader defaults (cloud_gradecommit.go) to a stub that
	// always fails honestly ("no commit-alignment loader is wired
	// yet"). This is the ONE reassignment to the real implementation,
	// done once at process start (before any command can run) so every
	// caller of the package var — today only `observer cloud
	// grade-commit`'s RunE — sees the real loader. Kept as a package
	// init rather than a call threaded through newCloudCmd() so this
	// wave's cmd-side footprint stays entirely inside this file.
	gradeCommitLoader = realGradeCommitLoader
}

// realGradeCommitLoader loads one prompt's attribution facts
// (internal/store.LoadPromptChainInput, W3) and converts them into a
// cloudevidence.CommitAlignmentInput. It opens its own config + DB — the
// same "no --config flag, resolve the default location" shape
// newCloudGradeCommitCmd's RunE uses (mirroring every other bare
// `observer cloud <verb>` subcommand's loadConfigAndDB(ctx, "") call) —
// because the grade-commit command carries no pre-opened store to
// inject through.
func realGradeCommitLoader(ctx context.Context, actionID int64) (cloudevidence.CommitAlignmentInput, error) {
	_, database, cleanup, err := loadConfigAndDB(ctx, "")
	if err != nil {
		return cloudevidence.CommitAlignmentInput{}, fmt.Errorf("observer cloud grade-commit: %w", err)
	}
	defer cleanup()
	st := store.New(database)

	projectID, err := st.ProjectIDForAction(ctx, actionID)
	if err != nil {
		return cloudevidence.CommitAlignmentInput{}, fmt.Errorf("observer cloud grade-commit: %w", err)
	}
	_, facts, err := st.LoadPromptChainInput(ctx, projectID, actionID)
	if err != nil {
		return cloudevidence.CommitAlignmentInput{}, fmt.Errorf("observer cloud grade-commit: %w", err)
	}

	auth, ok, err := st.SessionAuthority(ctx, facts.SessionID)
	if err != nil {
		return cloudevidence.CommitAlignmentInput{}, fmt.Errorf("observer cloud grade-commit: read session authority: %w", err)
	}
	if !ok {
		return cloudevidence.CommitAlignmentInput{}, fmt.Errorf("observer cloud grade-commit: session %q not found, or its data-authority is unknown", facts.SessionID)
	}

	cloudSession, err := st.GetOrCreateCloudSessionPseudonym(ctx, facts.SessionID)
	if err != nil {
		return cloudevidence.CommitAlignmentInput{}, fmt.Errorf("observer cloud grade-commit: session pseudonym: %w", err)
	}
	cloudProject, err := st.GetOrCreateCloudProjectPseudonym(ctx, strconv.FormatInt(projectID, 10))
	if err != nil {
		return cloudevidence.CommitAlignmentInput{}, fmt.Errorf("observer cloud grade-commit: project pseudonym: %w", err)
	}
	purposes, err := cloudPurposeSet(cloudcontract.PurposeExtendedEvidence)
	if err != nil {
		return cloudevidence.CommitAlignmentInput{}, fmt.Errorf("observer cloud grade-commit: %w", err)
	}

	files := make([]cloudevidence.CommitAlignmentFileInput, 0, len(facts.CommitFiles))
	for _, f := range facts.CommitFiles {
		files = append(files, cloudevidence.CommitAlignmentFileInput{PathHash: f.PathHash, Added: f.Added, Deleted: f.Deleted})
	}
	hunks := make([]cloudevidence.CommitAlignmentHunkInput, 0, len(facts.Hunks))
	for _, h := range facts.Hunks {
		hunks = append(hunks, cloudevidence.CommitAlignmentHunkInput{PathHash: h.PathHash, Excerpt: h.Excerpt})
	}

	return cloudevidence.CommitAlignmentInput{
		CloudProjectID:  cloudProject,
		CloudSessionID:  cloudSession,
		PromptExcerpt:   facts.PromptText,
		CommitSubject:   facts.CommitSubject,
		CommitFiles:     files,
		EditHunks:       hunks,
		LinkStatus:      facts.LinkStatus,
		WindowDays:      facts.WindowDays,
		Authority:       auth,
		GrantedPurposes: purposes,
		Scrubber:        scrub.New(),
		ScrubberVersion: cloudScrubberVersion,
	}, nil
}

// projectsDashboardOptions resolves the dashboard.Options.JudgeGrade /
// JudgeGradeReason pair (build-tag-split — see projects_judge_wire.go /
// projects_judge_wire_stub.go) for both dashboard.New call sites
// (start.go, cmd/observer/dashboard.go). Options.CloudGradeAvailability
// is wired directly to CommitAlignmentAvailability at each call site —
// no wrapper needed, the signatures already match.
func projectsDashboardOptions(cfg *config.Config) (judgeGrade func(context.Context, alignment.Input) (alignment.Result, string, error), judgeGradeReason string) {
	return projectsJudgeGradeSeam(cfg)
}
