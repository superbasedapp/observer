package cloudcontract

// Schema-version identifiers. Both are ".v#-candidate" pre-launch (plan
// §4(a)) — versioned and mutable until the A0-exit freeze.
const (
	// EnvelopeSchemaVersion identifies the session-evidence envelope schema.
	EnvelopeSchemaVersion = "session-evidence.v1-candidate"
	// ResultSchemaVersion identifies the enrichment-result schema.
	ResultSchemaVersion = "session_enrichment.v2-candidate"
)

// Structural-insights snapshot bounds (structural.go). Same discipline as the
// envelope bounds below: one place per bound, read by both Validate and the
// pure builder.
const (
	// MaxStructuralMixEntries caps each categorical mix (tool, model family).
	// There are ~37 adapters and a handful of model families, so this is
	// generous headroom that still refuses an unbounded array.
	MaxStructuralMixEntries = 64
	// MaxStructuralMixKeyBytes bounds one categorical mix key.
	MaxStructuralMixKeyBytes = 64
	// MaxDeclaredTimezoneBytes bounds the declared IANA timezone name.
	MaxDeclaredTimezoneBytes = 64
)

// Size and count limits. Every bounded field on the envelope and the result
// is validated against one of these. They are candidate-schema values
// (mutable pre-launch): keep them here so a bound is changed in exactly one
// place and both Validate and the builder read the same number.
const (
	// MaxCloudIDBytes bounds the random cloud session/project pseudonyms.
	MaxCloudIDBytes = 128
	// MaxToolBytes bounds the tool identifier (e.g. "codex").
	MaxToolBytes = 64
	// MaxModelFamilyBytes bounds the model-family identifier.
	MaxModelFamilyBytes = 64
	// MaxRefBytes bounds an action/milestone ref token.
	MaxRefBytes = 64
	// MaxShortLabelBytes bounds short structural labels (kind, category,
	// status, build).
	MaxShortLabelBytes = 64
	// MaxSourceLabelBytes bounds a context-excerpt source label
	// (e.g. "task_excerpt").
	MaxSourceLabelBytes = 64

	// MaxActions caps the bounded actions array; overflow is summarized as a
	// count, never sent as content.
	MaxActions = 256
	// MaxMilestones caps the bounded milestones array.
	MaxMilestones = 64
	// MaxContextExcerpts caps the bounded optional context-excerpt array.
	//
	// Raised 12 -> 20 on 2026-09-16 so the selector can carry a wider spread of
	// the developer's OWN prompts (they are short and they are the direction
	// of the session; see cloudevidence.SelectExcerpts). The hosted validator
	// and the node builder share this constant, so the hosted service must
	// roll first: an older server refuses an envelope above its own cap, an
	// older node simply sends fewer.
	MaxContextExcerpts = 20
	// MaxExcerptBytes is the default per-excerpt byte cap (each excerpt may
	// declare a tighter cap of its own, never a looser one).
	MaxExcerptBytes = 4096

	// MaxDisclosurePurposes caps the disclosure-purpose set (there are only
	// seven purposes in the vocabulary).
	MaxDisclosurePurposes = 7

	// MaxTitleBytes bounds a result title.
	MaxTitleBytes = 200
	// MaxDescriptionBytes bounds a result description.
	MaxDescriptionBytes = 1200
	// MaxTaxonomyTags caps the taxonomy-tag list.
	MaxTaxonomyTags = 16
	// MaxSuggestedTags caps the suggested-tag list.
	MaxSuggestedTags = 12
	// MaxTagBytes bounds a single tag.
	MaxTagBytes = 64
	// MaxEvidenceRefs caps the evidence-reference list.
	MaxEvidenceRefs = 32
	// MaxEvidenceRefBytes bounds a single evidence reference.
	MaxEvidenceRefBytes = 64
	// MaxLimitations caps the limitations list.
	MaxLimitations = 16
	// MaxLimitationBytes bounds a single limitation string.
	MaxLimitationBytes = 240

	// MaxNarrativeItems caps EACH of the five narrative result lists
	// (work_done, plans_implemented, issues_found, failures, next_steps).
	// They are the reader-facing half of the result, so the bound is a
	// readable handful rather than an exhaustive log.
	MaxNarrativeItems = 8
	// MaxNarrativeItemBytes bounds one narrative item. Same size as a
	// limitation: a single plain sentence, never a paragraph.
	MaxNarrativeItemBytes = 240
)
