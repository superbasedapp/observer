package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
)

// cloud_gradecommit.go is the NODE side of the "commit alignment" grade
// (projects-page plan docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md
// §2 R6 / §3.6 tier C, wave W5b): whether a developer's prompt was DELIVERED
// or MISSED by the commit(s) it linked to, judged by the hosted Cloud
// Intelligence plane under the existing PurposeExtendedEvidence purpose.
//
// This wave ships the contract (internal/cloudcontract), the builder
// (internal/cloudevidence), and this CLI verb — honestly, as NOT YET
// AVAILABLE: the hosted commit-alignment job kind does not exist (wave W5c,
// "the hosted executor", is dropped from this arc — see the plan's F21
// review finding). `observer cloud grade-commit` therefore builds and shows
// the exact two-digest preview a future send would upload, then reports
// `not_available: hosted kind not deployed` and exits 0 WITHOUT ever making a
// network call. This is the same manual-only, zero-egress-until-consent
// posture every other `observer cloud` verb follows (see cloud.go's package
// comment) — the difference here is that even a consenting developer cannot
// send yet, because there is nothing on the other end to send to.

// GradeCommitLoader loads the prompt text and its linked-commit facts needed
// to build commit-alignment evidence for one prompt, identified by its
// actions.id. It is a func type, not an interface, so a later wave's real
// implementation (composing internal/store + internal/projectroi) can be
// wired in with a single assignment to gradeCommitLoader below — one seam,
// no type leakage past it (CLAUDE.md §2).
type GradeCommitLoader func(ctx context.Context, actionID int64) (cloudevidence.CommitAlignmentInput, error)

// ErrGradeCommitLoaderNotWired is returned by the default GradeCommitLoader.
// Wave W5b ships the contract, the builder, and this CLI verb; the real
// loader — reading the prompt and its linked commit through internal/store +
// internal/projectroi (waves W1b/W2/W3) — is wired in later. Until then,
// `observer cloud grade-commit` fails honestly here rather than building
// evidence out of nothing.
var ErrGradeCommitLoaderNotWired = errors.New("observer cloud grade-commit: no commit-alignment loader is wired yet")

// gradeCommitLoader is the ONE seam newCloudGradeCommitCmd calls through. A
// later wave reassigns this package variable to a real implementation (in
// another cmd/observer file); until then it always returns
// ErrGradeCommitLoaderNotWired.
var gradeCommitLoader GradeCommitLoader = func(context.Context, int64) (cloudevidence.CommitAlignmentInput, error) {
	return cloudevidence.CommitAlignmentInput{}, ErrGradeCommitLoaderNotWired
}

// hostedCommitAlignmentAvailable is false because no hosted kind exists yet
// to grade against: the plan's wave W5c ("hosted executor") was dropped from
// this arc (review finding F21 — "the session_title trap is precisely
// 'contract without dispatch'"). Flip this to true, and wire the actual
// network call through internal/cloudgateway.FeatureSend (mirroring the
// session-enrichment send path), only once a hosted
// commit-alignment-result.v1-candidate executor is built and deployed.
const hostedCommitAlignmentAvailable = false

// CommitAlignmentAvailability reports whether the Cloud Intelligence commit-
// alignment grading job is available, and the honest reason when it is not.
// It is exported so a dashboard handler (wave W3's `POST
// /api/project/{id}/prompts/{action_id}/grade`) reports the EXACT SAME
// reason the CLI prints here — one owner for the not-available copy, never
// two surfaces independently deciding how to phrase the same fact.
func CommitAlignmentAvailability() (available bool, reason string) {
	if !hostedCommitAlignmentAvailable {
		return false, "hosted kind not deployed"
	}
	return true, ""
}

// newCloudGradeCommitCmd assembles `observer cloud grade-commit`.
func newCloudGradeCommitCmd() *cobra.Command {
	var (
		promptID  int64
		projectID string
		preview   bool
		yes       bool
	)
	cmd := &cobra.Command{
		Use:   "grade-commit",
		Short: "Grade one prompt's delivered-vs-missed alignment with its linked commit (Cloud Intelligence)",
		Long: "Builds commit-alignment evidence for one prompt (--prompt is the prompt's local\n" +
			"action id) under the extended_evidence_deep_review purpose, and shows the exact\n" +
			"literal bytes and two digests a future send would upload — what you see is what\n" +
			"would upload, exactly like `observer cloud preview`.\n\n" +
			"No network call is ever made by this command today: the hosted commit-alignment\n" +
			"job kind does not exist yet, so it always ends by printing an honest\n" +
			"`not_available: hosted kind not deployed` and exiting 0.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if promptID == 0 {
				return errors.New("--prompt is required (a local prompt action id)")
			}
			in, err := gradeCommitLoader(cmd.Context(), promptID)
			if err != nil {
				return fmt.Errorf("load prompt %d: %w", promptID, err)
			}

			ev, err := cloudevidence.BuildCommitAlignment(in)
			if err != nil {
				return fmt.Errorf("build commit-alignment evidence: %w", err)
			}
			final, digests, err := cloudevidence.SerializeCommitAlignment(&ev)
			if err != nil {
				return fmt.Errorf("serialize commit-alignment evidence: %w", err)
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s\n", final)
			fmt.Fprintln(w, "----")
			fmt.Fprintf(w, "purpose:                 %s\n", cloudcontract.PurposeExtendedEvidence)
			fmt.Fprintf(w, "evidence-content digest:  %s\n", digests.EvidenceContent)
			fmt.Fprintf(w, "upload digest:            %s\n", digests.Upload)
			fmt.Fprintf(w, "commit files:             %d\n", len(ev.CommitFiles))
			fmt.Fprintf(w, "edit hunks:               %d\n", len(ev.EditHunks))
			fmt.Fprintf(w, "link status:              %s\n", ev.LinkStatus)
			fmt.Fprintf(w, "upload size:              %d bytes\n", len(final))

			available, reason := CommitAlignmentAvailability()
			if !available {
				fmt.Fprintf(w, "not_available: %s\n", reason)
				return nil
			}
			// Unreachable in this arc: hostedCommitAlignmentAvailable is a
			// compile-time false until the hosted executor (plan §4 W5c)
			// ships. When it does, this branch sends via
			// internal/cloudgateway.FeatureSend under the SAME consent gate
			// every other `observer cloud` send uses — never a raw HTTP call
			// from this file.
			fmt.Fprintln(w, "grading is available but no send path is wired in this build")
			return nil
		},
	}
	cmd.Flags().Int64Var(&promptID, "prompt", 0, "Prompt action id to grade (required)")
	cmd.Flags().StringVar(&projectID, "project", "", "Local project id (currently advisory; the loader resolves the project from the prompt's own session)")
	cmd.Flags().BoolVar(&preview, "preview", false, "Preview only — accepted for symmetry with 'observer cloud preview'; this command never sends regardless")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the interactive confirmation — accepted for forward compatibility; unused today because no network call is ever made")
	return cmd
}
