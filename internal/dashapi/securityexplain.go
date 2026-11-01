package dashapi

import (
	"context"
	"errors"
)

// SecurityExplanation is the answer to "Explain" on a Code security finding
// (security pillar plan section 5.11 (b), lane sec-h): the configured
// judge's advisory explanation, or, when none could be produced, the honest
// reason (no judge configured, a judge endpoint the finding's data may not
// reach, the judge failed). It never carries a verdict or a status: the
// explain flow changes nothing.
type SecurityExplanation struct {
	// Available reports that Text holds an explanation.
	Available bool `json:"available"`
	// Text is the cleaned explanation.
	Text string `json:"text,omitempty"`
	// Advisory is always true for an explanation.
	Advisory bool `json:"advisory"`
	// Label is the advisory sentence shown beside the text.
	Label string `json:"label,omitempty"`
	// Reason says why there is no explanation (no call was made unless it
	// says the judge failed).
	Reason string `json:"reason,omitempty"`
	// Model and Hosting name the judge (hosting: local, aggregator,
	// provider, private).
	Model   string `json:"model,omitempty"`
	Hosting string `json:"hosting,omitempty"`
}

// ErrExplainNotSelected reports that component security.feedback, which
// owns the explain flow, is not selected on this node.
var ErrExplainNotSelected = errors.New("explain needs component security.feedback, which is not selected (add it under [components])")

// ErrExplainUnknownFinding reports an unknown finding id.
var ErrExplainUnknownFinding = errors.New("no finding with that id")

// SecurityExplain explains one finding by its id; wired from
// cmd/observer/security_feedback_explain.go. Nil answers 404.
type SecurityExplain func(ctx context.Context, findingID string) (SecurityExplanation, error)
