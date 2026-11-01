package secfinding

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// The closed vocabularies, owned by internal/policy (section 4.3).
type (
	// Category is the closed finding category vocabulary.
	Category = policy.FindingCategory
	// Severity is the closed finding severity vocabulary.
	Severity = policy.FindingSeverity
	// Confidence is the closed confidence vocabulary.
	Confidence = policy.FindingConfidence
	// Scope is where a finding was produced.
	Scope = policy.FindingScope
	// Baseline is the baseline judgement (section 4.5.2).
	Baseline = policy.FindingBaseline
	// Status is the lifecycle status.
	Status = policy.FindingStatus
	// Attribution is the inferred attribution class.
	Attribution = policy.FindingAttribution
)

// Caps on finding strings (sections 4.5 and 4.5.3).
const (
	// MaxEvidence is the most characters of redacted evidence a finding
	// keeps around a match.
	MaxEvidence = 240
	// MaxPath is the most bytes of a project-relative path.
	MaxPath = 512
	// MaxRuleID is the most bytes of a rule id.
	MaxRuleID = 128
	// MaxMessage is the most bytes of a rendered message or fix hint.
	MaxMessage = 1024
	// MaxPathAliases is the most rename aliases a location keeps.
	MaxPathAliases = 8
)

// Location is where a finding sits (section 4.5). It is display and
// navigation data, never identity: moves and nearby edits keep the
// finding's LocalKey.
type Location struct {
	// RelPath is project-relative, inside the project root, no "..", at
	// most MaxPath bytes.
	RelPath   string
	StartLine int
	EndLine   int
	// PathAliases are earlier paths of the same file from detected renames
	// (section 4.5.1), at most MaxPathAliases.
	PathAliases []string
}

// Rule names the rule that fired (section 4.5). An engine rule id such as
// an Opengrep rule is a finding rule id, never a guard rule id.
type Rule struct {
	ID          string
	Version     string
	Pack        string
	PackVersion string
}

// Engine names the engine, binary and advisory data a finding came from.
type Engine struct {
	Driver        string
	DriverVersion string
	// EngineDigest is the sha256 of the binary or module that ran.
	EngineDigest string
	// DatabaseEpoch is the advisory database epoch, "" when none.
	DatabaseEpoch string
}

// References are optional reference ids from a closed mapping.
type References struct {
	CWE   []string
	OWASP []string
	ATLAS []string
}

// Project identifies the project a finding belongs to (sections 4.5 and
// 7.11).
type Project struct {
	// RootHash is the per-node project root hash.
	RootHash string
	// IdentityHash is the project identity resolver v2 hash.
	IdentityHash string
	// OrgProjectID is the org project the signed mapping resolved, "" when
	// none (filled by Phase P).
	OrgProjectID string
}

// BaselineRef is the baseline a finding was judged against (section
// 4.5.2): an approved commit or a signed CI result, with the versions in
// force.
type BaselineRef struct {
	// Kind is "commit" or "ci_result".
	Kind string
	// Ref is the commit sha or the CI result id.
	Ref           string
	PackVersion   string
	PolicyVersion string
}

// InferredAttribution is the attribution inference (section 4.5).
type InferredAttribution struct {
	Class Attribution
	// Method names the inference, for example "projectroi.link.v1".
	Method     string
	Confidence Confidence
}

// Lineage ties a finding to the session, the tool call associated with
// the write and the prompt before it, and to the agent and model.
type Lineage struct {
	SessionID      string
	ActionID       string
	PromptActionID string
	Tool           string
	ToolVersion    string
	Model          string
	Surface        string
	// RunID is the sandbox run whose box made the change a commit-scope
	// finding was found in (a commit the sandbox return step brought back,
	// or one walked on a box ref; security plan 4.8 "Copy workspaces", M7);
	// "" otherwise. UnknownRunID when the box work's run could not be
	// confirmed against the host's run records. Node-local: no org row
	// carries it.
	RunID string
}

// UnknownRunID is the Lineage.RunID of box work whose run the host could
// not confirm (a run id read from a ref name the box can write that no
// host run record owns; lane sec-box audit finding 5). It is never a real
// run id (those are 22-character base64url ids) and still marks the
// finding as box work.
const UnknownRunID = "unknown"

// TaintAtWrite records whether the session was tainted when the write
// happened (section 4.5).
type TaintAtWrite struct {
	Tainted bool
	// OriginClass is the taint source class (the policy TaintSource
	// classes), never content.
	OriginClass string
	// OriginDetail is a bounded description; it ships only under
	// shipsRawContent().
	OriginDetail string
}

// Commit records the commit a finding's change landed in (section 4.5).
type Commit struct {
	SHA string
	// PatchFP is internal/commitlog.PatchFingerprint of the change.
	PatchFP string
	// Landed comes from the landing tracker.
	Landed bool
}

// FixObservations are facts only (section 5.11), never a claim that tests
// passed in an environment Observer did not run.
type FixObservations struct {
	// RuleNoLongerFires: the rule no longer fires at the location.
	RuleNoLongerFires bool
	// NoNewFindingInRegion: no new finding in the changed region.
	NoNewFindingInRegion bool
	// TestCommandObserved: a test command ran in the session after the
	// last edit; TestExitCode is its exit code; TestFilesEdited says
	// whether test files were edited.
	TestCommandObserved bool
	TestExitCode        int
	TestFilesEdited     bool
}

// Finding is one normalized finding (section 4.5). Drivers build it through
// their semantic adapter; nothing else crosses the seam. Field comments say
// what ships to the org (section 7.4) only where it differs from "yes".
type Finding struct {
	// ID is a node-local ULID. Never shipped.
	ID string
	// LocalKey is the location-free lifecycle key (section 4.5.1). Never
	// shipped.
	LocalKey string
	// OrgKey is the org dedupe key, present only when the node holds the
	// org's dedupe key; never built from the node-keyed HMAC.
	OrgKey string
	// Location ships only under shipsRawContent().
	Location Location

	Rule       Rule
	Engine     Engine
	Category   Category
	Severity   Severity
	Confidence Confidence
	References References
	Scope      Scope
	Project    Project

	// EvidenceRedacted is at most MaxEvidence characters around the match,
	// passed through the scrubber; a secret's value is replaced by its
	// detector type. Ships only under shipsRawContent(); a secret value
	// never, in any mode.
	EvidenceRedacted string
	// EvidenceHash is the hash of EvidenceRedacted.
	EvidenceHash string
	// Message and FixHint are rendered from the rule pack's templates,
	// never from repository or engine text (section 9 T8).
	Message string
	FixHint string

	Baseline    Baseline
	BaselineRef BaselineRef
	Attribution InferredAttribution
	// Lineage ids ship as metadata, subject to the section 7.12
	// drill-down controls.
	Lineage Lineage
	// TaintAtWrite: the class ships; the origin detail only under
	// shipsRawContent().
	TaintAtWrite TaintAtWrite
	// Commit: the sha and patch fingerprint ship only under
	// shipsRawContent(); the landed flag always.
	Commit Commit

	Status    Status
	FirstSeen time.Time
	LastSeen  time.Time
	// ClosedAt is zero while the finding is open.
	ClosedAt time.Time

	Fix FixObservations
	// ExceptionID is the approval or grant that suppressed the finding.
	ExceptionID string
	// VerdictIDs are the guard events that referenced this finding.
	VerdictIDs []string
}
