package cloudevidence

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// commitalignment.go is the NODE-SIDE builder + serializer for the "commit
// alignment" grade (projects-page plan §2 R6 / §3.6 tier C, W5b): whether a
// developer's prompt was DELIVERED or MISSED by the commit(s) it linked to,
// judged by the hosted Cloud Intelligence plane. It follows the exact same
// discipline as builder.go/serialize.go for the session envelope: pure,
// consent-gated, scrub-everything, one Build function and one Serialize
// function so preview bytes always equal upload bytes.

// CommitAlignmentInput is the normalized commit-alignment evidence a caller
// assembles from store rows (prompt text, the linked commit's numstat, and
// the AI-edited hunks that reached it) and hands to BuildCommitAlignment. It
// carries raw, node-local, pre-scrub values; the builder turns them into the
// privacy-preserving evidence object. The builder reads it but never mutates
// it.
type CommitAlignmentInput struct {
	// CloudProjectID and CloudSessionID are caller-supplied RANDOM
	// pseudonyms — never a DB primary key or filesystem path, same rule as
	// SessionInput.
	CloudProjectID string
	CloudSessionID string

	// PromptExcerpt is the raw (pre-scrub) prompt text the grade judges
	// delivery against.
	PromptExcerpt string
	// CommitSubject is the raw (pre-scrub) subject line of the linked commit.
	CommitSubject string
	// CommitFiles is the linked commit's file list (join-key hash plus
	// added/deleted counts — never a path).
	CommitFiles []CommitAlignmentFileInput
	// EditHunks is the raw (pre-scrub) list of AI-edited hunks that reached
	// this commit.
	EditHunks []CommitAlignmentHunkInput
	// LinkStatus is the prompt-to-commit attribution status
	// (internal/projectroi's PromptChain status).
	LinkStatus string
	// WindowDays is the commit-link window (days) the attribution used.
	WindowDays int

	// Authority is the data-authority classification for the session the
	// prompt belongs to. The builder REFUSES to build unless it is eligible
	// for personal enrichment (org/unknown are refused — same INV-1 rule
	// BuildEnvelope applies).
	Authority dataauthority.Classification

	// GrantedPurposes are the consent purposes authorizing this evidence.
	// MUST include cloudcontract.PurposeExtendedEvidence — this evidence
	// kind ships under no other purpose — or the build is refused.
	GrantedPurposes []cloudcontract.Purpose
	// Scrubber is applied to the prompt excerpt, the commit subject, and
	// every edit-hunk excerpt. Required.
	Scrubber *scrub.Scrubber
	// ScrubberVersion is recorded on the evidence. Required.
	ScrubberVersion string
}

// CommitAlignmentFileInput is one file the linked commit touched.
type CommitAlignmentFileInput struct {
	PathHash       string
	Added, Deleted int
}

// CommitAlignmentHunkInput is one raw (pre-scrub) edit-hunk excerpt tied to a
// file the linked commit touched.
type CommitAlignmentHunkInput struct {
	PathHash string
	Excerpt  string
}

// BuildCommitAlignment constructs a schema-valid
// cloudcontract.CommitAlignmentEvidence from in, applying the same privacy
// rules BuildEnvelope applies to the session envelope:
//
//   - the session's data-authority MUST be eligible for the personal plane
//     (INV-1) — org/unknown authority refuses the build outright;
//   - cloud IDs must be random pseudonyms — path-like or PK-like values are
//     rejected;
//   - the granted purposes MUST include PurposeExtendedEvidence — this
//     evidence kind ships under no other purpose (the closed seven-purpose
//     vocabulary is never extended for it);
//   - the prompt excerpt, the commit subject, and every edit-hunk excerpt are
//     scrubbed and bounded before they reach the evidence object;
//   - the commit-files and edit-hunks arrays are capped at
//     MaxCommitAlignmentFiles / MaxCommitAlignmentHunks.
//
// The returned evidence has empty digest fields — digests are a
// serialization concern owned by SerializeCommitAlignment.
func BuildCommitAlignment(in CommitAlignmentInput) (cloudcontract.CommitAlignmentEvidence, error) {
	if !eligibleForPlane(cloudcontract.PlanePersonal, in.Authority) {
		return cloudcontract.CommitAlignmentEvidence{}, fmt.Errorf("cloudevidence.BuildCommitAlignment: authority %q (v%d) is ineligible for the personal plane (INV-1)", in.Authority.Authority, in.Authority.Version)
	}
	if in.ScrubberVersion == "" {
		return cloudcontract.CommitAlignmentEvidence{}, fmt.Errorf("cloudevidence.BuildCommitAlignment: ScrubberVersion is required")
	}
	if in.Scrubber == nil {
		return cloudcontract.CommitAlignmentEvidence{}, fmt.Errorf("cloudevidence.BuildCommitAlignment: Scrubber is required")
	}
	if !purposesInclude(in.GrantedPurposes, cloudcontract.PurposeExtendedEvidence) {
		return cloudcontract.CommitAlignmentEvidence{}, fmt.Errorf("cloudevidence.BuildCommitAlignment: granted purposes must include %q — commit-alignment evidence ships under no other purpose", cloudcontract.PurposeExtendedEvidence)
	}
	if err := validateCloudID("cloud_project_id", in.CloudProjectID); err != nil {
		return cloudcontract.CommitAlignmentEvidence{}, fmt.Errorf("cloudevidence.BuildCommitAlignment: %w", err)
	}
	if err := validateCloudID("cloud_session_id", in.CloudSessionID); err != nil {
		return cloudcontract.CommitAlignmentEvidence{}, fmt.Errorf("cloudevidence.BuildCommitAlignment: %w", err)
	}

	promptExcerpt := scrub.TruncateN(in.Scrubber.String(in.PromptExcerpt), cloudcontract.MaxExcerptBytes)
	commitSubject := scrub.TruncateN(in.Scrubber.String(in.CommitSubject), cloudcontract.MaxCommitAlignmentSubjectBytes)

	ev := cloudcontract.CommitAlignmentEvidence{
		SchemaVersion:      cloudcontract.CommitAlignmentEvidenceSchema,
		CloudProjectID:     in.CloudProjectID,
		CloudSessionID:     in.CloudSessionID,
		PromptExcerpt:      promptExcerpt,
		CommitSubject:      commitSubject,
		CommitFiles:        boundCommitFiles(in.CommitFiles),
		EditHunks:          boundEditHunks(in.EditHunks, in.Scrubber),
		LinkStatus:         in.LinkStatus,
		WindowDays:         in.WindowDays,
		DisclosurePurposes: sortedUniquePurposes(in.GrantedPurposes),
		ScrubberVersion:    in.ScrubberVersion,
		Authority:          in.Authority,
	}

	if err := ev.Validate(); err != nil {
		return cloudcontract.CommitAlignmentEvidence{}, fmt.Errorf("cloudevidence.BuildCommitAlignment: built an invalid evidence: %w", err)
	}
	return ev, nil
}

// boundCommitFiles caps the commit-files list at MaxCommitAlignmentFiles.
// Over-cap lists are truncated (head-first: git numstat is already ordered by
// the commit itself, unlike the session action stream boundActions samples).
func boundCommitFiles(in []CommitAlignmentFileInput) []cloudcontract.CommitAlignmentFile {
	if len(in) > cloudcontract.MaxCommitAlignmentFiles {
		in = in[:cloudcontract.MaxCommitAlignmentFiles]
	}
	out := make([]cloudcontract.CommitAlignmentFile, 0, len(in))
	for _, f := range in {
		out = append(out, cloudcontract.CommitAlignmentFile{
			PathHash: f.PathHash,
			Added:    f.Added,
			Deleted:  f.Deleted,
		})
	}
	return out
}

// boundEditHunks caps the edit-hunks list at MaxCommitAlignmentHunks,
// scrubbing and length-capping each excerpt.
func boundEditHunks(in []CommitAlignmentHunkInput, sc *scrub.Scrubber) []cloudcontract.CommitAlignmentHunk {
	if len(in) > cloudcontract.MaxCommitAlignmentHunks {
		in = in[:cloudcontract.MaxCommitAlignmentHunks]
	}
	out := make([]cloudcontract.CommitAlignmentHunk, 0, len(in))
	for _, h := range in {
		excerpt := scrub.TruncateN(sc.String(h.Excerpt), cloudcontract.MaxCommitAlignmentHunkExcerptBytes)
		out = append(out, cloudcontract.CommitAlignmentHunk{
			PathHash: h.PathHash,
			Excerpt:  excerpt,
		})
	}
	return out
}

// purposesInclude reports whether want is a member of purposes.
func purposesInclude(purposes []cloudcontract.Purpose, want cloudcontract.Purpose) bool {
	for _, p := range purposes {
		if p == want {
			return true
		}
	}
	return false
}

// SerializeCommitAlignment is THE ONE function that produces both the
// literal preview bytes and the upload bytes for a CommitAlignmentEvidence —
// the commit-alignment sibling of Serialize. It works on a copy of e (so the
// caller's evidence is never mutated), validates before serializing, and
// computes the same two-digest protocol: the evidence-content digest over
// the canonical preimage (both digest fields absent), stamped into the
// returned bytes, then the upload digest over those final bytes.
func SerializeCommitAlignment(e *cloudcontract.CommitAlignmentEvidence) ([]byte, cloudcontract.Digests, error) {
	if e == nil {
		return nil, cloudcontract.Digests{}, fmt.Errorf("cloudevidence.SerializeCommitAlignment: nil evidence")
	}
	ev := *e // copy; never mutate the caller's evidence

	if err := ev.Validate(); err != nil {
		return nil, cloudcontract.Digests{}, fmt.Errorf("cloudevidence.SerializeCommitAlignment: %w", err)
	}

	evidenceDigest, err := cloudcontract.CommitAlignmentEvidenceContentDigest(ev)
	if err != nil {
		return nil, cloudcontract.Digests{}, fmt.Errorf("cloudevidence.SerializeCommitAlignment: %w", err)
	}
	ev.EvidenceContentDigest = evidenceDigest

	final, err := cloudcontract.CommitAlignmentUploadBytes(ev)
	if err != nil {
		return nil, cloudcontract.Digests{}, fmt.Errorf("cloudevidence.SerializeCommitAlignment: %w", err)
	}
	uploadDigest := cloudcontract.UploadDigest(final)

	return final, cloudcontract.Digests{EvidenceContent: evidenceDigest, Upload: uploadDigest}, nil
}
