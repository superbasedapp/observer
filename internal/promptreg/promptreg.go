package promptreg

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// APIVersion is the api_version every response body carries (the SDK control
// API's version, internal/orgserver/sdkapi.APIVersion).
const APIVersion = "v1"

// The two labels (contract section 1). A label points at one version or is
// unset.
const (
	LabelProduction = "production"
	LabelStaging    = "staging"
)

// DefaultLabel is the label a fetch with neither label nor version resolves.
const DefaultLabel = LabelProduction

// Labels returns the label vocabulary in display order.
func Labels() []string { return []string{LabelProduction, LabelStaging} }

// ValidLabel reports whether l is in the vocabulary.
func ValidLabel(l string) bool { return l == LabelProduction || l == LabelStaging }

// Type is a prompt's body shape. A prompt's type is fixed by its first
// version.
type Type string

// The prompt types.
const (
	TypeText Type = "text"
	TypeChat Type = "chat"
)

// Limits (contract section 1).
const (
	MaxNameBytes          = 128
	MaxBodyBytes          = 64 << 10
	MaxMessages           = 100
	MaxConfigBytes        = 16 << 10
	MaxCommitMessageBytes = 500
)

// chatRoles is the closed set of chat message roles.
var chatRoles = map[string]bool{"system": true, "user": true, "assistant": true, "tool": true, "developer": true}

// ChatRoles returns the chat message roles, sorted.
func ChatRoles() []string { return []string{"assistant", "developer", "system", "tool", "user"} }

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidName reports whether name follows the name rule.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// Message is one chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Version is one immutable prompt version, in canonical form.
type Version struct {
	Name    string
	Version int
	Type    Type
	// Prompt is the canonical JSON body: a string for text, a message array
	// for chat.
	Prompt []byte
	// Config is the canonical (compacted) JSON object, "{}" when absent.
	Config        []byte
	CommitMessage string
	CreatedBy     string
	CreatedAt     time.Time
	// Digest is ContentDigest of the version, "sha256:<hex>".
	Digest string
}

// LabelState is the current label -> version map of one prompt. An unset
// label is absent.
type LabelState map[string]int

// On returns the labels pointing at version v, in vocabulary order.
func (s LabelState) On(v int) []string {
	out := []string{}
	for _, l := range Labels() {
		if s[l] == v && v > 0 {
			out = append(out, l)
		}
	}
	return out
}

// Move is one recorded label move.
type Move struct {
	Label string
	// From is the version the label held before the move, 0 when unset.
	From int
	// To is the version the move set.
	To int
	// Rollback marks a move made by PlanRollback.
	Rollback bool
	// Rollout marks a rollout step (contract section 9.1): the base (From ==
	// To) is unchanged and only the label's rollout changed. A rollout step
	// is never a promotion, so PlanRollback never walks back to it.
	Rollout bool
	// RolloutVersion and RolloutPercent are the label's rollout AFTER the
	// move: the candidate and its percent, both 0 when the label has none
	// (every move that is not a rollout step ends a rollout).
	RolloutVersion int
	RolloutPercent int
	Actor          string
	At             time.Time
}

// The error vocabulary. Every refusal a store or a handler returns wraps one
// of these, so ErrorStatus maps it once for the org and the machine.
var (
	ErrBadRequest        = errors.New("bad request")
	ErrPromptNotFound    = errors.New("no prompt has that name")
	ErrVersionNotFound   = errors.New("that version does not exist")
	ErrLabelNotSet       = errors.New("that label points at no version")
	ErrNothingToRollBack = errors.New("nothing to roll back to")
	ErrNoChange          = errors.New("nothing would change")
	ErrTypeMismatch      = errors.New("a prompt keeps the type of its first version")
	// W5-3 (contract section 9.6): approval of production changes.
	ErrApprovalRequired = errors.New("this organization requires approval before production changes: propose it, and a different member approves")
	ErrSelfApproval     = errors.New("a proposal is approved by a different member than the one who proposed it")
	ErrProposalNotFound = errors.New("no proposal has that id")
	ErrProposalClosed   = errors.New("that proposal is no longer pending")
	ErrProposalStale    = errors.New("the label changed since the proposal; it is now stale and nothing moved: propose again")
	// ErrSuperAdminRequired refuses turning production approval OFF to a
	// member who is not the org's super admin (ruling D28, review R-C01):
	// the members the rule constrains cannot lift it.
	ErrSuperAdminRequired = errors.New("turning off production prompt approval needs the org's super admin")
)

// badRequest wraps ErrBadRequest with a message.
func badRequest(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadRequest, fmt.Sprintf(format, args...))
}

// errorRow is one row of the error table.
type errorRow struct {
	err    error
	status int
	code   string
}

// errorRows is the error table, walked top-down (one test case per row).
// Statuses are plain integers so the package needs no net/http.
func errorRows() []errorRow {
	return []errorRow{
		{ErrBadRequest, 400, "bad_request"},
		{ErrPromptNotFound, 404, "prompt_not_found"},
		{ErrVersionNotFound, 404, "version_not_found"},
		{ErrLabelNotSet, 404, "label_not_set"},
		{ErrNothingToRollBack, 409, "nothing_to_roll_back"},
		{ErrNoChange, 409, "no_change"},
		{ErrTypeMismatch, 409, "type_mismatch"},
		{ErrApprovalRequired, 409, "approval_required"},
		{ErrSelfApproval, 403, "self_approval"},
		{ErrProposalNotFound, 404, "proposal_not_found"},
		{ErrProposalClosed, 409, "proposal_closed"},
		{ErrProposalStale, 409, "proposal_stale"},
		{ErrSuperAdminRequired, 403, "super_admin_required"},
	}
}

// ErrorStatus maps err to its HTTP status and wire code. An error outside the
// vocabulary is 500 internal (ok false), and its text must not be shown.
func ErrorStatus(err error) (status int, code string, ok bool) {
	for _, r := range errorRows() {
		if errors.Is(err, r.err) {
			return r.status, r.code, true
		}
	}
	return 500, "internal", false
}
