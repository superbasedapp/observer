package cloudevidence

import (
	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// SessionInput is the normalized session a caller assembles from store rows
// and hands to BuildEnvelope. It carries raw, node-local values (real paths,
// pre-scrub excerpt text); the builder is responsible for turning them into
// the privacy-preserving envelope. The builder reads it but never mutates it.
type SessionInput struct {
	// CloudSessionID and CloudProjectID are caller-supplied RANDOM pseudonyms
	// — never a DB primary key or filesystem path. The builder rejects
	// path-like or purely-numeric (PK-like) values defensively.
	CloudSessionID string
	CloudProjectID string

	// Tool and ModelFamily identify the capturing tool and coarse model.
	Tool        string
	ModelFamily string

	// StartedAtBucket is a coarse RFC3339 start-time bucket.
	StartedAtBucket string
	// DurationSeconds is the session duration in whole seconds.
	DurationSeconds int

	// Metrics carries structural + deterministic-score metrics.
	Metrics MetricsInput
	// Actions is the ordered action list; the builder bounds it and summarizes
	// overflow as a count. It may itself already be a SAMPLE of a longer
	// session — see ActionsTotal.
	Actions []ActionInput
	// ActionsTotal is the size of the WHOLE-SESSION population Actions was drawn
	// from. Zero means "Actions IS the population" (the un-sampled caller).
	//
	// It exists because the store now strides across the whole session in SQL
	// and hands over ~MaxActions rows: without a declared population the builder
	// would compute `len(Actions) - MaxActions` and report ZERO omissions for a
	// 30,000-action session. The count that ships must describe the session, not
	// the slice. A value below len(Actions) is ignored (never a negative count).
	ActionsTotal int
	// Milestones is the full ordered milestone list; bounded like Actions.
	Milestones []MilestoneInput
	// Outcomes carries test/build outcomes.
	Outcomes OutcomesInput
	// ActivityMix is the WHOLE-SESSION action-kind histogram (every action, not
	// just the ones that survive the Actions sample). The builder normalizes,
	// merges, sorts and bounds it. Optional: an empty mix omits the field.
	ActivityMix []ActivityMixInput

	// UserFeedback is optional; included only when BuildOptions.IncludeUserFeedback.
	UserFeedback *UserFeedbackInput
	// Excerpts are optional raw (pre-scrub) context excerpts; included only
	// under the bounded-context-enrichment purpose.
	Excerpts []ExcerptInput

	// Authority is the data-authority classification for the session. The
	// builder REFUSES to build unless it is eligible for personal enrichment.
	Authority dataauthority.Classification
}

// MetricsInput mirrors cloudcontract.MetricsBlock.
type MetricsInput struct {
	TokensIn              int
	TokensOut             int
	CacheReadTokens       int
	CostUSD               float64
	DeterministicScore    float64
	RedundancyRatio       float64
	ErrorRate             float64
	ExplorationEfficiency float64
	ContinuityScore       float64
}

// ActionInput is one normalized action. Path is the raw local path; the
// builder derives Category from it (extension) when Category is empty, and
// emits a salted PathHash only under the path-correlation grant. The raw Path
// itself never leaves the machine.
type ActionInput struct {
	Ref      string
	Kind     string
	Status   string
	Path     string
	Category string // optional explicit override; else derived from Path
}

// MilestoneInput is one normalized milestone.
type MilestoneInput struct {
	Ref            string
	Kind           string
	ElapsedSeconds int
}

// OutcomesInput mirrors cloudcontract.Outcomes. TestsUnknown / BuildsUnknown
// carry the runs whose outcome the recorded exit status cannot honestly speak
// for — see cloudcontract.Outcomes and SegmentStatus.
type OutcomesInput struct {
	TestsRun      int
	TestsPassed   int
	Build         string
	TestsUnknown  int
	BuildsUnknown int
}

// UserFeedbackInput is optional user feedback (rating, note). Note is scrubbed
// and capped by the builder.
type UserFeedbackInput struct {
	Rating *int
	Note   string
}

// ExcerptInput is one raw (pre-scrub) context excerpt. CapBytes is an optional
// per-excerpt byte cap; when 0 the builder uses cloudcontract.MaxExcerptBytes.
// A cap larger than MaxExcerptBytes is clamped down.
type ExcerptInput struct {
	Source   string
	Text     string
	CapBytes int
}

// BuildOptions carries the consent-derived gating and the injected scrubber.
// The caller sets the flags from the granted consent purposes / receipt; the
// builder never reads config or consent state itself.
type BuildOptions struct {
	// Scrubber is applied to every optional excerpt and the feedback note.
	// Required whenever excerpts or a feedback note are to be included.
	Scrubber *scrub.Scrubber
	// ScrubberVersion is recorded on the envelope (bound by the consent
	// receipt). Required.
	ScrubberVersion string
	// GrantedPurposes are the consent purposes authorizing this envelope; they
	// gate content and are recorded (sorted, deduped) as the envelope's
	// disclosure purposes.
	GrantedPurposes []cloudcontract.Purpose
	// PathCorrelation, with a non-empty PathSalt, enables per-account salted
	// path hashes on actions. Off ⇒ paths default to extension/category only.
	PathCorrelation bool
	// PathSalt is the per-account salt for path hashes (used only when
	// PathCorrelation is set).
	PathSalt []byte
	// IncludeUserFeedback includes SessionInput.UserFeedback when the receipt
	// names it.
	IncludeUserFeedback bool
	// GrantedFieldClasses are the field classes the consent receipt binds.
	// They matter for exactly one decision today: under the STRUCTURAL purpose
	// alone, a receipt that binds FieldClassFirstUserPrompt lets the envelope
	// carry the single first_user_prompt excerpt (the "Title only" level's own
	// disclosure); without it a structural envelope carries no context at
	// all. Nil (a caller that predates the class) means "none granted".
	GrantedFieldClasses []cloudcontract.FieldClass
}

// hasFieldClass reports whether c is in the granted field-class set.
func (o BuildOptions) hasFieldClass(c cloudcontract.FieldClass) bool {
	for _, g := range o.GrantedFieldClasses {
		if g == c {
			return true
		}
	}
	return false
}

// hasPurpose reports whether p is in the granted set.
func (o BuildOptions) hasPurpose(p cloudcontract.Purpose) bool {
	for _, g := range o.GrantedPurposes {
		if g == p {
			return true
		}
	}
	return false
}
