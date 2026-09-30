package cloudcontract

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// commitalignment.go is the NODE-SIDE contract for the "commit alignment"
// grade (W5b, projects-page plan §2 R6 / §3.6 tier C): whether a developer's
// prompt (feature ask, bug fix) was DELIVERED or MISSED by the commit(s) it
// linked to, judged by the hosted Cloud Intelligence plane under the SAME
// closed purpose the rest of this package already vends —
// PurposeExtendedEvidence ("extended_evidence_deep_review", "explicitly
// previewed evidence fields a paid job needs"). It adds no new purpose: the
// seven-purpose vocabulary in consent.go is closed by design.
//
// It follows the session-evidence envelope's exact two-digest discipline
// (digest.go): EvidenceContentDigest is set by the serializer and omitted
// from its own preimage; UploadDigest is carried as data but never
// serialized (json:"-"), so it can never cover itself. The primitives that
// make this possible — marshalCanonical (already generic: it takes `any`)
// and digest (already generic: it takes `[]byte`) — are reused verbatim from
// digest.go; this file adds sibling EvidencePreimage/EvidenceContentDigest/
// UploadBytes functions typed to CommitAlignmentEvidence rather than
// generalizing the existing Envelope-typed ones, so the session envelope's
// digest functions and their goldens are untouched byte-for-byte.
//
// Field declaration order on CommitAlignmentEvidence IS the canonical
// serialization order, exactly as documented on Envelope: do not reorder
// without regenerating goldens.
const (
	// CommitAlignmentEvidenceSchema identifies the commit-alignment evidence
	// schema a node builds and uploads for one grading job.
	CommitAlignmentEvidenceSchema = "commit-alignment-evidence.v1-candidate"
	// CommitAlignmentResultSchema identifies the commit-alignment RESULT
	// schema a grading job returns.
	CommitAlignmentResultSchema = "commit-alignment-result.v1-candidate"
)

// Commit-alignment evidence bounds. Same discipline as limits.go: one place
// per bound, read by both Validate and the builder (internal/cloudevidence).
const (
	// MaxCommitAlignmentSubjectBytes bounds the (scrubbed) commit subject line.
	MaxCommitAlignmentSubjectBytes = 256
	// MaxCommitAlignmentPathHashBytes bounds one file_path_hash join-key value
	// (internal/loc.PathHash today emits a 64-hex sha256 digest; this cap is
	// generous headroom, not a format check — this evidence kind does not
	// require the "sha256:" prefix the envelope's salted correlation hashes
	// use, because file_path_hash is an unsalted join key already used
	// throughout the store, not a privacy-gated correlation id).
	MaxCommitAlignmentPathHashBytes = 128
	// MaxCommitAlignmentFiles caps the commit's file list.
	MaxCommitAlignmentFiles = 200
	// MaxCommitAlignmentHunks caps the linked-edit-hunk excerpt list.
	MaxCommitAlignmentHunks = 20
	// MaxCommitAlignmentHunkExcerptBytes bounds one edit-hunk excerpt.
	MaxCommitAlignmentHunkExcerptBytes = 2048

	// MaxCommitAlignmentResultItems caps EACH of the three result lists
	// (delivered, missed, extra). Reuses the narrative-list shape already
	// established by Result (work_done/plans_implemented/...): a readable
	// handful, never an exhaustive log.
	MaxCommitAlignmentResultItems = MaxNarrativeItems
	// MaxCommitAlignmentResultItemBytes bounds one delivered/missed/extra
	// item — the same size as a Result narrative item.
	MaxCommitAlignmentResultItemBytes = MaxNarrativeItemBytes
	// MaxCommitAlignmentNotesBytes bounds the free-text notes field.
	MaxCommitAlignmentNotesBytes = 400
)

// commitAlignmentLinkStatuses is the CLOSED vocabulary for
// CommitAlignmentEvidence.LinkStatus — the projectroi.PromptChain status
// values from plan §3.3/R4.5, walked as a table rather than a shape check
// (CLAUDE.md §5).
var commitAlignmentLinkStatuses = map[string]bool{
	"committed":   true,
	"partial":     true,
	"uncommitted": true,
	"superseded":  true,
	"no_edits":    true,
	"orphan":      true,
}

// CommitAlignmentEvidence is the "commit-alignment-evidence.v1-candidate"
// schema: everything a node builds locally and uploads for one commit-
// alignment grading job. It is constructed only by
// internal/cloudevidence.BuildCommitAlignment and serialized only by
// internal/cloudevidence.SerializeCommitAlignment — the same one-builder/
// one-serializer discipline as the session envelope.
type CommitAlignmentEvidence struct {
	// SchemaVersion is always CommitAlignmentEvidenceSchema.
	SchemaVersion string `json:"schema_version"`
	// CloudProjectID is a random node-minted pseudonym — never a DB primary
	// key or filesystem path (same rule as Envelope.CloudProjectID).
	CloudProjectID string `json:"cloud_project_id"`
	// CloudSessionID is a random node-minted pseudonym, same rules.
	CloudSessionID string `json:"cloud_session_id"`
	// PromptExcerpt is the post-scrub, bounded (<=4KiB) prompt text the
	// grade is judging delivery against.
	PromptExcerpt string `json:"prompt_excerpt"`
	// CommitSubject is the (scrubbed, bounded) subject line of the linked
	// commit.
	CommitSubject string `json:"commit_subject"`
	// CommitFiles is the bounded (<=200) file list the linked commit
	// touched: join-key hash plus added/deleted line counts, never a path.
	CommitFiles []CommitAlignmentFile `json:"commit_files"`
	// EditHunks is the bounded (<=20), post-scrub list of the AI-edited
	// hunks that reached this commit — the evidence the grade actually
	// reads to decide delivered vs. missed.
	EditHunks []CommitAlignmentHunk `json:"edit_hunks"`
	// LinkStatus is the prompt-to-commit attribution status (projectroi §R4),
	// a member of commitAlignmentLinkStatuses.
	LinkStatus string `json:"link_status"`
	// WindowDays is the commit-link window (days) the attribution used.
	WindowDays int `json:"window_days"`
	// DisclosurePurposes records the consent purposes that authorized this
	// evidence's contents (sorted, deduped by the builder). Always includes
	// PurposeExtendedEvidence — the only purpose this evidence kind may ship
	// under.
	DisclosurePurposes []Purpose `json:"disclosure_purposes"`
	// ScrubberVersion identifies the scrubber applied to every excerpt.
	ScrubberVersion string `json:"scrubber_version"`
	// Authority is the data-authority classification (with its classifier
	// version) copied from the input — same field, same rule as Envelope.
	Authority dataauthority.Classification `json:"authority"`
	// EvidenceContentDigest is set by the serializer; omitted from the
	// evidence preimage (its own digest input).
	EvidenceContentDigest string `json:"evidence_content_digest,omitempty"`
	// UploadDigest is carried as data but NEVER serialized (json:"-") so the
	// upload digest can never cover itself.
	UploadDigest string `json:"-"`
}

// CommitAlignmentFile is one file the linked commit touched.
type CommitAlignmentFile struct {
	// PathHash is the file_path_hash join key (internal/loc.PathHash) —
	// never a path.
	PathHash string `json:"path_hash"`
	// Added / Deleted are the commit's numstat line counts for this file.
	Added   int `json:"added"`
	Deleted int `json:"deleted"`
}

// CommitAlignmentHunk is one bounded, post-scrub edit-hunk excerpt tied to a
// file the linked commit touched.
type CommitAlignmentHunk struct {
	// PathHash is the same join key as CommitAlignmentFile.PathHash.
	PathHash string `json:"path_hash"`
	// Excerpt is the post-scrub, capped (<=2KiB) hunk text.
	Excerpt string `json:"excerpt"`
}

// Validate enforces every CommitAlignmentEvidence bound: identity, the
// bounded collections, and the consent/authority trailer — the same three-
// part shape as Envelope.Validate.
func (e CommitAlignmentEvidence) Validate() error {
	if e.SchemaVersion != CommitAlignmentEvidenceSchema {
		return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: schema_version %q, want %q", e.SchemaVersion, CommitAlignmentEvidenceSchema)
	}
	if err := validateBounded("cloud_project_id", e.CloudProjectID, MaxCloudIDBytes, true); err != nil {
		return err
	}
	if err := validateBounded("cloud_session_id", e.CloudSessionID, MaxCloudIDBytes, true); err != nil {
		return err
	}
	if err := validateBounded("prompt_excerpt", e.PromptExcerpt, MaxExcerptBytes, false); err != nil {
		return err
	}
	if err := validateBounded("commit_subject", e.CommitSubject, MaxCommitAlignmentSubjectBytes, false); err != nil {
		return err
	}
	if err := e.validateCommitFiles(); err != nil {
		return err
	}
	if err := e.validateEditHunks(); err != nil {
		return err
	}
	if !commitAlignmentLinkStatuses[e.LinkStatus] {
		return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: unknown link_status %q", e.LinkStatus)
	}
	if e.WindowDays < 0 {
		return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: window_days %d is negative", e.WindowDays)
	}
	return e.validateDisclosure()
}

func (e CommitAlignmentEvidence) validateCommitFiles() error {
	if len(e.CommitFiles) > MaxCommitAlignmentFiles {
		return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: %d commit_files exceeds max %d", len(e.CommitFiles), MaxCommitAlignmentFiles)
	}
	for i, f := range e.CommitFiles {
		if err := validateBounded(fmt.Sprintf("commit_files[%d].path_hash", i), f.PathHash, MaxCommitAlignmentPathHashBytes, true); err != nil {
			return err
		}
		if f.Added < 0 || f.Deleted < 0 {
			return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: commit_files[%d] has a negative added/deleted count", i)
		}
	}
	return nil
}

func (e CommitAlignmentEvidence) validateEditHunks() error {
	if len(e.EditHunks) > MaxCommitAlignmentHunks {
		return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: %d edit_hunks exceeds max %d", len(e.EditHunks), MaxCommitAlignmentHunks)
	}
	for i, h := range e.EditHunks {
		if err := validateBounded(fmt.Sprintf("edit_hunks[%d].path_hash", i), h.PathHash, MaxCommitAlignmentPathHashBytes, true); err != nil {
			return err
		}
		if err := validateBounded(fmt.Sprintf("edit_hunks[%d].excerpt", i), h.Excerpt, MaxCommitAlignmentHunkExcerptBytes, false); err != nil {
			return err
		}
	}
	return nil
}

// validateDisclosure checks the consent/authority trailer, mirroring
// Envelope.validateDisclosure, plus the ONE rule specific to this evidence
// kind: it may only ever ship under PurposeExtendedEvidence, so an evidence
// object missing that purpose is invalid regardless of what else it
// discloses.
func (e CommitAlignmentEvidence) validateDisclosure() error {
	if len(e.DisclosurePurposes) > MaxDisclosurePurposes {
		return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: %d disclosure purposes exceeds max %d", len(e.DisclosurePurposes), MaxDisclosurePurposes)
	}
	seen := make(map[Purpose]bool, len(e.DisclosurePurposes))
	hasExtendedEvidence := false
	for _, p := range e.DisclosurePurposes {
		if !p.Valid() {
			return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: unknown disclosure purpose %q", p)
		}
		if seen[p] {
			return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: duplicate disclosure purpose %q", p)
		}
		seen[p] = true
		if p == PurposeExtendedEvidence {
			hasExtendedEvidence = true
		}
	}
	if !hasExtendedEvidence {
		return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: disclosure_purposes must include %q — this evidence kind ships under no other purpose", PurposeExtendedEvidence)
	}
	if e.ScrubberVersion == "" {
		return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: scrubber_version is empty")
	}
	if e.Authority.Version <= 0 {
		return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: authority classifier version %d is not positive", e.Authority.Version)
	}
	switch e.Authority.Authority {
	case dataauthority.AuthorityPersonal, dataauthority.AuthorityOrg:
	default:
		return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: unknown authority %q", e.Authority.Authority)
	}
	if e.EvidenceContentDigest != "" && !hasDigestPrefix(e.EvidenceContentDigest) {
		return fmt.Errorf("cloudcontract.CommitAlignmentEvidence.Validate: evidence_content_digest %q missing %q prefix", e.EvidenceContentDigest, digestPrefix)
	}
	return nil
}

// CommitAlignmentEvidencePreimage returns the canonical preimage the
// evidence's EvidenceContentDigest is computed over: e marshaled with both
// digest fields absent. Sibling of EvidencePreimage, typed to
// CommitAlignmentEvidence; built on the same marshalCanonical primitive.
func CommitAlignmentEvidencePreimage(e CommitAlignmentEvidence) ([]byte, error) {
	e.EvidenceContentDigest = ""
	e.UploadDigest = ""
	b, err := marshalCanonical(e)
	if err != nil {
		return nil, fmt.Errorf("cloudcontract.CommitAlignmentEvidencePreimage: %w", err)
	}
	return b, nil
}

// CommitAlignmentEvidenceContentDigest returns the "sha256:<hex>" digest over
// CommitAlignmentEvidencePreimage(e).
func CommitAlignmentEvidenceContentDigest(e CommitAlignmentEvidence) (string, error) {
	pre, err := CommitAlignmentEvidencePreimage(e)
	if err != nil {
		return "", fmt.Errorf("cloudcontract.CommitAlignmentEvidenceContentDigest: %w", err)
	}
	return digest(pre), nil
}

// CommitAlignmentUploadBytes returns the final exact serialized bytes for e:
// the canonical serialization with EvidenceContentDigest as currently set on
// e and UploadDigest excluded. Pair with the existing, already-generic
// UploadDigest([]byte) for the second half of the protocol — it takes no
// Envelope-specific type, so it is reused as-is.
func CommitAlignmentUploadBytes(e CommitAlignmentEvidence) ([]byte, error) {
	e.UploadDigest = ""
	b, err := marshalCanonical(e)
	if err != nil {
		return nil, fmt.Errorf("cloudcontract.CommitAlignmentUploadBytes: %w", err)
	}
	return b, nil
}

// CommitAlignmentResult is the "commit-alignment-result.v1-candidate" schema:
// the strict object a commit-alignment grading job returns. Model output is
// untrusted data — Normalize enforces bounds and counts, mirroring
// Result.Normalize / DigestResult.Normalize.
type CommitAlignmentResult struct {
	// Delivered lists what the prompt asked for that the linked commit(s)
	// actually shipped.
	Delivered []string `json:"delivered"`
	// Missed lists what the prompt asked for that the linked commit(s) did
	// not ship.
	Missed []string `json:"missed"`
	// Extra lists what the linked commit(s) shipped beyond what the prompt
	// asked for.
	Extra []string `json:"extra"`
	// Confidence is a 0-1 self-reported confidence.
	Confidence float64 `json:"confidence"`
	// Notes is one short free-text explanation.
	Notes string `json:"notes"`
	// SchemaVersion is always CommitAlignmentResultSchema.
	SchemaVersion string `json:"schema_version"`
}

// NormalizedCommitAlignmentResult is the VALIDATED, normalized
// representation of a CommitAlignmentResult (same opaque-SafeText discipline
// as NormalizedResult / NormalizedDigestResult).
type NormalizedCommitAlignmentResult struct {
	Delivered     []SafeText `json:"delivered"`
	Missed        []SafeText `json:"missed"`
	Extra         []SafeText `json:"extra"`
	Confidence    float64    `json:"confidence"`
	Notes         SafeText   `json:"notes"`
	SchemaVersion string     `json:"schema_version"`
}

// Normalize enforces every CommitAlignmentResult bound and NFC-normalizes
// every text field, mirroring Result.Normalize / DigestResult.Normalize. It
// does NOT perform output scrubbing — that is the executor's separate
// downstream contract.
func (r CommitAlignmentResult) Normalize() (NormalizedCommitAlignmentResult, error) {
	var out NormalizedCommitAlignmentResult
	if r.SchemaVersion != CommitAlignmentResultSchema {
		return out, fmt.Errorf("cloudcontract.CommitAlignmentResult.Normalize: schema_version %q, want %q", r.SchemaVersion, CommitAlignmentResultSchema)
	}
	out.SchemaVersion = r.SchemaVersion
	var err error
	if out.Delivered, err = normalizeStringList("delivered", r.Delivered, MaxCommitAlignmentResultItems, MaxCommitAlignmentResultItemBytes); err != nil {
		return NormalizedCommitAlignmentResult{}, err
	}
	if out.Missed, err = normalizeStringList("missed", r.Missed, MaxCommitAlignmentResultItems, MaxCommitAlignmentResultItemBytes); err != nil {
		return NormalizedCommitAlignmentResult{}, err
	}
	if out.Extra, err = normalizeStringList("extra", r.Extra, MaxCommitAlignmentResultItems, MaxCommitAlignmentResultItemBytes); err != nil {
		return NormalizedCommitAlignmentResult{}, err
	}
	if r.Confidence < 0 || r.Confidence > 1 {
		return NormalizedCommitAlignmentResult{}, fmt.Errorf("cloudcontract.CommitAlignmentResult.Normalize: confidence %v out of [0,1]", r.Confidence)
	}
	out.Confidence = r.Confidence
	if out.Notes, err = NormalizeText("notes", r.Notes, MaxCommitAlignmentNotesBytes, false); err != nil {
		return NormalizedCommitAlignmentResult{}, err
	}
	return out, nil
}

// Validate is Normalize with the normalized value discarded.
func (r CommitAlignmentResult) Validate() error {
	_, err := r.Normalize()
	return err
}
