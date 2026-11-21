package settingsgate

import (
	"fmt"
	"strconv"
	"time"
)

// ProposalMaxAge is how long a filed proposal may still be approved (review
// E-50). An agent's request belongs to the session that asked; after this
// age it is refused at approval and the agent asks again. Rejecting an old
// proposal is always allowed.
const ProposalMaxAge = 14 * 24 * time.Hour

// ProposalFacts is what the approval check needs about one pending
// proposal: when it was filed, the value in force then (PrevValue, in the
// `config set` spelling, "" when unknown or hidden) and the value in force
// now (Current, the same spelling).
type ProposalFacts struct {
	CreatedAt time.Time
	PrevValue string
	Current   string
}

// ApprovalCheck is the answer for one proposal. Code is "" when it may be
// approved, else one of the ApprovalCode* values.
type ApprovalCheck struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// OK reports whether the proposal may be approved.
func (c ApprovalCheck) OK() bool { return c.Code == "" }

// The approval refusal codes.
const (
	// ApprovalCodeExpired: the proposal is older than ProposalMaxAge.
	ApprovalCodeExpired = "expired"
	// ApprovalCodeChanged: the setting changed after the proposal was filed,
	// so approving would overwrite a newer choice made by hand.
	ApprovalCodeChanged = "changed_since_filed"
)

// approvalRule is one row of the approval table, walked top-down.
type approvalRule struct {
	code  string
	match func(ProposalFacts, time.Time) bool
	msg   func(ProposalFacts) string
}

// approvalRules is the ordered approval table (CLAUDE.md #5).
var approvalRules = []approvalRule{
	{
		code: ApprovalCodeExpired,
		match: func(f ProposalFacts, now time.Time) bool {
			return !f.CreatedAt.IsZero() && now.Sub(f.CreatedAt) > ProposalMaxAge
		},
		msg: func(ProposalFacts) string {
			return fmt.Sprintf("this proposal is older than %d days; reject it and let the agent ask again", int(ProposalMaxAge/(24*time.Hour)))
		},
	},
	{
		code:  ApprovalCodeChanged,
		match: func(f ProposalFacts, _ time.Time) bool { return f.Current != f.PrevValue },
		msg: func(f ProposalFacts) string {
			return "the setting changed after the agent asked (it was " + strconv.Quote(f.PrevValue) +
				", it is now " + strconv.Quote(f.Current) + "); approving would overwrite that; reject it and let the agent ask again"
		},
	},
}

// CheckApproval decides whether a pending proposal may still be approved at
// now (review E-50). Pure.
func CheckApproval(f ProposalFacts, now time.Time) ApprovalCheck {
	for _, r := range approvalRules {
		if r.match(f, now) {
			return ApprovalCheck{Code: r.code, Message: r.msg(f)}
		}
	}
	return ApprovalCheck{}
}
