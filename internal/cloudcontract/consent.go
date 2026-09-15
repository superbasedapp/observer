package cloudcontract

// Purpose is a consent purpose from the amendment §4.1 matrix. Sign-in alone
// grants only account/device operations; every session-derived byte requires
// a distinct purpose grant. The vocabulary is closed: a value outside these
// seven constants is invalid.
type Purpose string

const (
	// PurposeAccountDeviceOps covers identity link, device, session, and
	// security events — active after sign-in; enables authentication and
	// account security. It authorizes no session-derived upload.
	PurposeAccountDeviceOps Purpose = "account_device_operations"

	// PurposeStructuralInsights covers agent/model, bucketed time, durations,
	// token/cost counts, and action/outcome categories — the structural core
	// of the envelope. Off by default; enables the personal dashboard
	// aggregates and basic labels.
	PurposeStructuralInsights Purpose = "structural_activity_insights"

	// PurposeContextEnrichment covers post-scrub bounded task and
	// final-summary excerpts. Off by default; enables a better title, tags,
	// description, and alignment context.
	PurposeContextEnrichment Purpose = "bounded_context_enrichment"

	// PurposeExtendedEvidence covers explicitly previewed evidence fields a
	// paid job needs. Off, just-in-time; enables process/deep review and
	// richer reports. (No paid job kind ships in arc 2.)
	PurposeExtendedEvidence Purpose = "extended_evidence_deep_review"

	// PurposeCohortBenchmarking covers a derived structural contribution
	// compared against a minimum-size cohort. Off by default; enables a
	// private percentile/band. (Deferred out of arc 2.)
	PurposeCohortBenchmarking Purpose = "community_cohort_benchmarking"

	// PurposePublicProfile covers an eligible cohort contribution plus a
	// chosen public handle. Off by default; enables a public listing.
	// (Deferred out of arc 2.)
	PurposePublicProfile Purpose = "public_community_profile"

	// PurposeResearch covers a separately described future research corpus.
	// Off and separate; enables nothing required to serve the user. Serving a
	// requested result never implies this grant.
	PurposeResearch Purpose = "research_model_improvement"
)

// allPurposes is the canonical ordered vocabulary.
var allPurposes = []Purpose{
	PurposeAccountDeviceOps,
	PurposeStructuralInsights,
	PurposeContextEnrichment,
	PurposeExtendedEvidence,
	PurposeCohortBenchmarking,
	PurposePublicProfile,
	PurposeResearch,
}

// AllPurposes returns a copy of the seven-purpose vocabulary in canonical
// order.
func AllPurposes() []Purpose {
	out := make([]Purpose, len(allPurposes))
	copy(out, allPurposes)
	return out
}

// Valid reports whether p is one of the seven known purposes.
func (p Purpose) Valid() bool {
	for _, known := range allPurposes {
		if p == known {
			return true
		}
	}
	return false
}

// FieldClass labels the preview grouping a field belongs to (§5.2 preview UX
// and §4.2 consent-receipt "field classes"). The literal preview groups the
// payload by these classes so a developer sees exactly what leaves the
// machine before enabling a lane.
type FieldClass string

const (
	// FieldClassIdentityLinkage groups identity/linkage fields (cloud
	// session/project pseudonyms, tool, model family).
	FieldClassIdentityLinkage FieldClass = "identity_linkage"
	// FieldClassStructuralMetrics groups structural metrics, actions,
	// milestones, and outcomes.
	FieldClassStructuralMetrics FieldClass = "structural_metrics"
	// FieldClassPaths groups path/project identifiers (extension/category
	// defaults and any per-account salted path hashes).
	FieldClassPaths FieldClass = "paths_project_identifiers"
	// FieldClassUserFeedback groups user feedback (rating, note) — present
	// only when the receipt names it.
	FieldClassUserFeedback FieldClass = "user_feedback"
	// FieldClassContentExcerpts groups post-scrub bounded context excerpts.
	FieldClassContentExcerpts FieldClass = "content_excerpts"
	// FieldClassFirstUserPrompt groups the SINGLE post-scrub excerpt of the
	// session's first user prompt — the narrowed field class the R8 ruling
	// (divergence-remediation plan rev 4.1 §2 R8; W3b F12) carves for the
	// title feature. It is a strict SUBSET of FieldClassContentExcerpts: the
	// most-wanted feature (a session title, the way most chat products derive
	// one) needs the smallest possible disclosure — one prompt, not the whole
	// bounded excerpt set. A grant for this class authorizes ONLY the
	// title-only enrichment job kind; tags and description render locked until
	// the developer additionally shares bounded excerpts.
	FieldClassFirstUserPrompt FieldClass = "first_user_prompt_excerpt"
)

// allFieldClasses is the canonical ordered set of preview groupings.
var allFieldClasses = []FieldClass{
	FieldClassIdentityLinkage,
	FieldClassStructuralMetrics,
	FieldClassPaths,
	FieldClassUserFeedback,
	FieldClassContentExcerpts,
	FieldClassFirstUserPrompt,
}

// AllFieldClasses returns a copy of the preview field-class labels in
// canonical order.
func AllFieldClasses() []FieldClass {
	out := make([]FieldClass, len(allFieldClasses))
	copy(out, allFieldClasses)
	return out
}

// Valid reports whether f is one of the known preview field classes.
func (f FieldClass) Valid() bool {
	for _, known := range allFieldClasses {
		if f == known {
			return true
		}
	}
	return false
}
