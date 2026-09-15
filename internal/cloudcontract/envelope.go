package cloudcontract

import (
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// Envelope is the "session-evidence.v1-candidate" schema: everything a node
// builds locally and uploads for one enrichment job. It is constructed only
// by internal/cloudevidence.BuildEnvelope (which scrubs, bounds, and gates by
// consent) and serialized only by internal/cloudevidence.Serialize.
//
// Field declaration order IS the canonical serialization order (see
// digest.go). Do not reorder fields without regenerating goldens: the order
// is load-bearing for the two-digest protocol.
type Envelope struct {
	// SchemaVersion is always EnvelopeSchemaVersion.
	SchemaVersion string `json:"schema_version"`
	// CloudSessionID is a random node-minted pseudonym — never a DB primary
	// key or filesystem path (the builder rejects path-like/PK-like values).
	CloudSessionID string `json:"cloud_session_id"`
	// CloudProjectID is a random node-minted pseudonym, same rules as
	// CloudSessionID.
	CloudProjectID string `json:"cloud_project_id"`
	// Tool is the capturing tool identifier (e.g. "codex").
	Tool string `json:"tool"`
	// ModelFamily is the coarse model family (e.g. "gpt-5.6").
	ModelFamily string `json:"model_family"`
	// StartedAtBucket is a coarse RFC3339 start-time bucket, not a precise
	// timestamp.
	StartedAtBucket string `json:"started_at_bucket"`
	// DurationSeconds is the session duration in whole seconds.
	DurationSeconds int `json:"duration_seconds"`
	// Metrics carries the structural + deterministic-score metric block.
	Metrics MetricsBlock `json:"metrics"`
	// Actions is the bounded, ordered action list (overflow summarized in
	// Overflow, never sent as content).
	Actions []Action `json:"actions"`
	// Milestones is the bounded, ordered milestone list.
	Milestones []Milestone `json:"milestones"`
	// Outcomes carries test/build outcomes.
	Outcomes Outcomes `json:"outcomes"`
	// ActivityMix is the WHOLE-SESSION action-kind histogram: one entry per
	// normalized action kind with its count across every action in the session,
	// not just the ones that survived the bounded Actions sample. It is the
	// cheapest honest answer to "what shape of work was this?" — a 1718-action
	// session that ships 256 sampled actions still declares that it ran 339
	// commands and 80 edits.
	//
	// It is an ADDITIVE field (omitempty): an envelope built without it
	// serializes exactly as before, so the schema stays v1-candidate. It reuses
	// StructuralMixEntry — a SORTED SLICE, never a Go map — because canonical
	// serialization requires deterministic ordering (see digest.go). Keys are
	// category slugs run through NormalizeMixKey, so a path or free text cannot
	// be spelled as one.
	ActivityMix []StructuralMixEntry `json:"activity_mix,omitempty"`
	// UserFeedback is present only when the receipt names it.
	UserFeedback *UserFeedback `json:"user_feedback,omitempty"`
	// Context is the optional bounded, post-scrub excerpt list (present only
	// under the bounded-context-enrichment purpose).
	Context []ContextExcerpt `json:"context,omitempty"`
	// Overflow records how many items were locally summarized out of the
	// bounded arrays. Present only when something was omitted.
	Overflow *Overflow `json:"overflow,omitempty"`
	// DisclosurePurposes records the consent purposes that authorized this
	// envelope's contents (sorted, deduped by the builder).
	DisclosurePurposes []Purpose `json:"disclosure_purposes"`
	// ScrubberVersion identifies the scrubber applied to every excerpt.
	ScrubberVersion string `json:"scrubber_version"`
	// Authority is the data-authority classification (with its classifier
	// version) copied from the input. The server rejects org/unknown as
	// defense-in-depth (Sol SC9); the builder refuses to build them at all.
	Authority dataauthority.Classification `json:"authority"`
	// EvidenceContentDigest is set by the serializer; omitted from the
	// evidence preimage (its own digest input). See digest.go.
	EvidenceContentDigest string `json:"evidence_content_digest,omitempty"`
	// UploadDigest is carried as data but NEVER serialized (json:"-") so the
	// upload digest can never cover itself.
	UploadDigest string `json:"-"`
}

// MetricsBlock is the structural + deterministic-score metric block.
type MetricsBlock struct {
	// TokensIn is net input tokens.
	TokensIn int `json:"tokens_in"`
	// TokensOut is output tokens.
	TokensOut int `json:"tokens_out"`
	// CacheReadTokens is cache-read tokens.
	CacheReadTokens int `json:"cache_read_tokens"`
	// CostUSD is the estimated cost in USD.
	CostUSD float64 `json:"cost_usd"`
	// DeterministicScore is the 0–100 process-efficiency score.
	DeterministicScore float64 `json:"deterministic_score"`
	// RedundancyRatio is a 0–1 ratio.
	RedundancyRatio float64 `json:"redundancy_ratio"`
	// ErrorRate is a 0–1 ratio.
	ErrorRate float64 `json:"error_rate"`
	// ExplorationEfficiency is a 0–1 ratio.
	ExplorationEfficiency float64 `json:"exploration_efficiency"`
	// ContinuityScore is a 0–1 ratio.
	ContinuityScore float64 `json:"continuity_score"`
}

// Action is one bounded normalized action: a category, not a path.
type Action struct {
	// Ref is a stable in-envelope reference (e.g. "a1").
	Ref string `json:"ref"`
	// Kind is the normalized action kind (e.g. "read", "edit").
	Kind string `json:"kind"`
	// Category is the extension/category default (e.g. "go") — never a path.
	Category string `json:"category"`
	// Status is the normalized outcome (e.g. "ok", "error").
	Status string `json:"status"`
	// PathHash is an optional per-account salted hash of the normalized
	// project-relative path, present ONLY under the path-correlation grant.
	PathHash string `json:"path_hash,omitempty"`
}

// Milestone is one bounded normalized milestone.
type Milestone struct {
	// Ref is a stable in-envelope reference (e.g. "m1").
	Ref string `json:"ref"`
	// Kind is the milestone kind (e.g. "first_edit").
	Kind string `json:"kind"`
	// ElapsedSeconds is elapsed time from session start in whole seconds.
	ElapsedSeconds int `json:"elapsed_seconds"`
}

// Outcomes carries test/build outcomes.
//
// TestsRun/TestsPassed and Build describe only the commands whose outcome is
// KNOWABLE from what was recorded. A shell line's recorded exit status belongs
// to ONE segment of it, and which one depends on how the segments were joined:
// `go test ./... || true` exits 0 whether or not the suite passed, and a test
// piped into `tail` reports `tail`'s status, not the suite's. Those runs are
// counted in TestsUnknown / BuildsUnknown instead of being credited to an
// outcome the evidence cannot support (A3).
type Outcomes struct {
	// TestsRun is the number of test runs whose outcome was knowable.
	TestsRun int `json:"tests_run"`
	// TestsPassed is how many of TestsRun passed.
	TestsPassed int `json:"tests_passed"`
	// Build is the coarse outcome of the LAST build whose outcome was knowable
	// ("passed", "failed", or "" when no such build was observed).
	Build string `json:"build"`
	// TestsUnknown is how many observed test runs had an UNKNOWABLE outcome
	// (the recorded exit status belonged to a different segment of the same
	// command line). Additive: absent when zero.
	TestsUnknown int `json:"tests_unknown,omitempty"`
	// BuildsUnknown is the same count for build commands. Additive: absent
	// when zero.
	BuildsUnknown int `json:"builds_unknown,omitempty"`
}

// UserFeedback is optional user-supplied feedback, present only when the
// receipt names it.
type UserFeedback struct {
	// Rating is a 1–10 overall rating, or nil if none.
	Rating *int `json:"rating,omitempty"`
	// Note is a bounded, post-scrub free-text note.
	Note string `json:"note,omitempty"`
}

// ContextExcerpt is one bounded, post-scrub excerpt with its own source label
// and length cap.
type ContextExcerpt struct {
	// Source labels the excerpt's origin (e.g. "task_excerpt").
	Source string `json:"source"`
	// Text is the post-scrub, capped excerpt content.
	Text string `json:"text"`
	// LengthCapBytes is the per-excerpt byte cap that was applied.
	LengthCapBytes int `json:"length_cap_bytes"`
}

// ContextIsFirstPromptOnly reports whether the envelope's context is EXACTLY
// the title-only set: one excerpt whose source is ExcerptSourceFirstUserPrompt
// and nothing else. That set is what the narrowed first_user_prompt_excerpt
// field class authorizes under the structural purpose alone (the "Title only"
// level's own disclosure: "a structural summary and your first prompt,
// nothing else"); any other context needs bounded_context_enrichment. Both
// the node builder and the hosted out-of-purpose gate dispatch on this one
// predicate so they can never disagree about which purpose a context needs.
func (e Envelope) ContextIsFirstPromptOnly() bool {
	return len(e.Context) == 1 && e.Context[0].Source == ExcerptSourceFirstUserPrompt
}

// Overflow records counts of items summarized out of the bounded arrays. Only
// counts leave the machine — never the omitted content itself.
type Overflow struct {
	// ActionsOmitted is how many actions exceeded MaxActions.
	ActionsOmitted int `json:"actions_omitted,omitempty"`
	// MilestonesOmitted is how many milestones exceeded MaxMilestones.
	MilestonesOmitted int `json:"milestones_omitted,omitempty"`
	// ContextOmitted is how many excerpts exceeded MaxContextExcerpts.
	ContextOmitted int `json:"context_omitted,omitempty"`
}

// Validate enforces every schema bound. It is pure schema validation: it
// accepts either authority (personal or org) as schema-valid — the refusal to
// BUILD an org/unknown envelope lives in the builder, and the server rejects
// org/unknown as defense-in-depth.
func (e Envelope) Validate() error {
	if err := e.validateIdentity(); err != nil {
		return err
	}
	if err := e.validateCollections(); err != nil {
		return err
	}
	return e.validateDisclosure()
}

// validateIdentity checks the envelope header: schema version, the bounded
// identifiers, the start bucket, duration, and the metrics block.
func (e Envelope) validateIdentity() error {
	if e.SchemaVersion != EnvelopeSchemaVersion {
		return fmt.Errorf("cloudcontract.Envelope.Validate: schema_version %q, want %q", e.SchemaVersion, EnvelopeSchemaVersion)
	}
	if err := validateBounded("cloud_session_id", e.CloudSessionID, MaxCloudIDBytes, true); err != nil {
		return err
	}
	if err := validateBounded("cloud_project_id", e.CloudProjectID, MaxCloudIDBytes, true); err != nil {
		return err
	}
	if err := validateBounded("tool", e.Tool, MaxToolBytes, true); err != nil {
		return err
	}
	if err := validateBounded("model_family", e.ModelFamily, MaxModelFamilyBytes, true); err != nil {
		return err
	}
	if e.StartedAtBucket == "" {
		return fmt.Errorf("cloudcontract.Envelope.Validate: started_at_bucket is empty")
	}
	if _, err := time.Parse(time.RFC3339, e.StartedAtBucket); err != nil {
		return fmt.Errorf("cloudcontract.Envelope.Validate: started_at_bucket %q not RFC3339: %w", e.StartedAtBucket, err)
	}
	if e.DurationSeconds < 0 {
		return fmt.Errorf("cloudcontract.Envelope.Validate: duration_seconds %d is negative", e.DurationSeconds)
	}
	return e.Metrics.validate()
}

// validateCollections checks the bounded collections and their items: actions,
// milestones, outcomes, user feedback, and context excerpts.
func (e Envelope) validateCollections() error {
	if len(e.Actions) > MaxActions {
		return fmt.Errorf("cloudcontract.Envelope.Validate: %d actions exceeds MaxActions %d", len(e.Actions), MaxActions)
	}
	for i, a := range e.Actions {
		if err := a.validate(i); err != nil {
			return err
		}
	}
	if len(e.Milestones) > MaxMilestones {
		return fmt.Errorf("cloudcontract.Envelope.Validate: %d milestones exceeds MaxMilestones %d", len(e.Milestones), MaxMilestones)
	}
	for i, m := range e.Milestones {
		if err := m.validate(i); err != nil {
			return err
		}
	}
	if err := validateBounded("outcomes.build", e.Outcomes.Build, MaxShortLabelBytes, false); err != nil {
		return err
	}
	if e.Outcomes.TestsRun < 0 || e.Outcomes.TestsPassed < 0 ||
		e.Outcomes.TestsUnknown < 0 || e.Outcomes.BuildsUnknown < 0 {
		return fmt.Errorf("cloudcontract.Envelope.Validate: negative outcome counts")
	}
	if e.Outcomes.TestsPassed > e.Outcomes.TestsRun {
		return fmt.Errorf("cloudcontract.Envelope.Validate: tests_passed %d exceeds tests_run %d", e.Outcomes.TestsPassed, e.Outcomes.TestsRun)
	}
	// The activity mix is validated by the SAME rule the structural snapshot's
	// mixes use — bounded, normalized keys, strictly key-ascending, positive
	// counts — so a mix key can never be a path or free text on either schema.
	if err := validateMix("cloudcontract.Envelope.Validate", "activity_mix", e.ActivityMix); err != nil {
		return err
	}
	if e.UserFeedback != nil {
		if err := e.UserFeedback.validate(); err != nil {
			return err
		}
	}
	if len(e.Context) > MaxContextExcerpts {
		return fmt.Errorf("cloudcontract.Envelope.Validate: %d context excerpts exceeds MaxContextExcerpts %d", len(e.Context), MaxContextExcerpts)
	}
	for i, c := range e.Context {
		if err := c.validate(i); err != nil {
			return err
		}
	}
	return nil
}

// validateDisclosure checks the consent/authority trailer: the disclosure
// purposes (closed vocabulary, no duplicates), scrubber version, authority
// classification, and the evidence digest prefix.
func (e Envelope) validateDisclosure() error {
	if len(e.DisclosurePurposes) > MaxDisclosurePurposes {
		return fmt.Errorf("cloudcontract.Envelope.Validate: %d disclosure purposes exceeds max %d", len(e.DisclosurePurposes), MaxDisclosurePurposes)
	}
	seen := make(map[Purpose]bool, len(e.DisclosurePurposes))
	for _, p := range e.DisclosurePurposes {
		if !p.Valid() {
			return fmt.Errorf("cloudcontract.Envelope.Validate: unknown disclosure purpose %q", p)
		}
		if seen[p] {
			return fmt.Errorf("cloudcontract.Envelope.Validate: duplicate disclosure purpose %q", p)
		}
		seen[p] = true
	}
	if e.ScrubberVersion == "" {
		return fmt.Errorf("cloudcontract.Envelope.Validate: scrubber_version is empty")
	}
	if e.Authority.Version <= 0 {
		return fmt.Errorf("cloudcontract.Envelope.Validate: authority classifier version %d is not positive", e.Authority.Version)
	}
	switch e.Authority.Authority {
	case dataauthority.AuthorityPersonal, dataauthority.AuthorityOrg:
	default:
		return fmt.Errorf("cloudcontract.Envelope.Validate: unknown authority %q", e.Authority.Authority)
	}
	if e.EvidenceContentDigest != "" && !hasDigestPrefix(e.EvidenceContentDigest) {
		return fmt.Errorf("cloudcontract.Envelope.Validate: evidence_content_digest %q missing %q prefix", e.EvidenceContentDigest, digestPrefix)
	}
	return nil
}

func (m MetricsBlock) validate() error {
	if m.TokensIn < 0 || m.TokensOut < 0 || m.CacheReadTokens < 0 {
		return fmt.Errorf("cloudcontract.MetricsBlock: negative token count")
	}
	if m.CostUSD < 0 {
		return fmt.Errorf("cloudcontract.MetricsBlock: negative cost_usd")
	}
	if m.DeterministicScore < 0 || m.DeterministicScore > 100 {
		return fmt.Errorf("cloudcontract.MetricsBlock: deterministic_score %v out of [0,100]", m.DeterministicScore)
	}
	for name, r := range map[string]float64{
		"redundancy_ratio":       m.RedundancyRatio,
		"error_rate":             m.ErrorRate,
		"exploration_efficiency": m.ExplorationEfficiency,
		"continuity_score":       m.ContinuityScore,
	} {
		if r < 0 || r > 1 {
			return fmt.Errorf("cloudcontract.MetricsBlock: %s %v out of [0,1]", name, r)
		}
	}
	return nil
}

func (a Action) validate(i int) error {
	if err := validateBounded(fmt.Sprintf("actions[%d].ref", i), a.Ref, MaxRefBytes, true); err != nil {
		return err
	}
	if err := validateBounded(fmt.Sprintf("actions[%d].kind", i), a.Kind, MaxShortLabelBytes, true); err != nil {
		return err
	}
	if err := validateBounded(fmt.Sprintf("actions[%d].category", i), a.Category, MaxShortLabelBytes, true); err != nil {
		return err
	}
	if err := validateBounded(fmt.Sprintf("actions[%d].status", i), a.Status, MaxShortLabelBytes, false); err != nil {
		return err
	}
	if a.PathHash != "" && !hasDigestPrefix(a.PathHash) {
		return fmt.Errorf("cloudcontract: actions[%d].path_hash %q missing %q prefix", i, a.PathHash, digestPrefix)
	}
	return nil
}

func (m Milestone) validate(i int) error {
	if err := validateBounded(fmt.Sprintf("milestones[%d].ref", i), m.Ref, MaxRefBytes, true); err != nil {
		return err
	}
	if err := validateBounded(fmt.Sprintf("milestones[%d].kind", i), m.Kind, MaxShortLabelBytes, true); err != nil {
		return err
	}
	if m.ElapsedSeconds < 0 {
		return fmt.Errorf("cloudcontract: milestones[%d].elapsed_seconds %d is negative", i, m.ElapsedSeconds)
	}
	return nil
}

func (u UserFeedback) validate() error {
	if u.Rating != nil && (*u.Rating < 1 || *u.Rating > 10) {
		return fmt.Errorf("cloudcontract.UserFeedback: rating %d out of [1,10]", *u.Rating)
	}
	if err := validateBounded("user_feedback.note", u.Note, MaxExcerptBytes, false); err != nil {
		return err
	}
	return nil
}

func (c ContextExcerpt) validate(i int) error {
	if err := validateBounded(fmt.Sprintf("context[%d].source", i), c.Source, MaxSourceLabelBytes, true); err != nil {
		return err
	}
	if c.LengthCapBytes <= 0 || c.LengthCapBytes > MaxExcerptBytes {
		return fmt.Errorf("cloudcontract: context[%d].length_cap_bytes %d out of (0,%d]", i, c.LengthCapBytes, MaxExcerptBytes)
	}
	if len(c.Text) > c.LengthCapBytes {
		return fmt.Errorf("cloudcontract: context[%d].text %d bytes exceeds its cap %d", i, len(c.Text), c.LengthCapBytes)
	}
	return nil
}

// validateBounded checks a string's byte length against max and, when
// required, that it is non-empty.
func validateBounded(field, v string, max int, required bool) error {
	if required && v == "" {
		return fmt.Errorf("cloudcontract: %s is empty", field)
	}
	if len(v) > max {
		return fmt.Errorf("cloudcontract: %s is %d bytes, exceeds max %d", field, len(v), max)
	}
	return nil
}

func hasDigestPrefix(s string) bool {
	return len(s) > len(digestPrefix) && s[:len(digestPrefix)] == digestPrefix
}
