package cloudcontract

import "fmt"

// Confidence is the enrichment result's self-reported confidence enum.
type Confidence string

const (
	// ConfidenceLow marks a low-confidence result.
	ConfidenceLow Confidence = "low"
	// ConfidenceMedium marks a medium-confidence result.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceHigh marks a high-confidence result (only when tests, build,
	// explicit completion, and/or user feedback support it).
	ConfidenceHigh Confidence = "high"
)

// Valid reports whether c is a known confidence level.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}

// Result is the "session_enrichment.v2-candidate" schema: the strict object a
// Luna enrichment call returns and the node stores. Model output is untrusted
// data — Validate enforces enums, lengths, and counts; callers still apply
// output scrubbing and per-sink escaping (Sol SC7) on top.
type Result struct {
	// Title is the AI-suggested session title.
	Title string `json:"title"`
	// TaxonomyTags is the controlled-vocabulary tag list.
	TaxonomyTags []string `json:"taxonomy_tags"`
	// SuggestedTags is the free-form suggested-tag list.
	SuggestedTags []string `json:"suggested_tags"`
	// Description is a short AI-generated description.
	Description string `json:"description"`
	// WorkDone lists what the session actually DID, in plain sentences.
	//
	// WorkDone, PlansImplemented, IssuesFound, Failures and NextSteps are the
	// NARRATIVE half of the result: the five things a developer reading their
	// own session wants back (what happened, whether the plan landed, what is
	// broken, what failed, what to do next). They are OPTIONAL by construction
	// so a result stored before they existed still normalizes; a new completion
	// is asked for all five (the strict output schema requires them) but an
	// empty list is always a legitimate answer.
	WorkDone []string `json:"work_done,omitempty"`
	// PlansImplemented says which stated plans or tasks were carried through
	// and which were left, or says plainly that the evidence cannot show it.
	PlansImplemented []string `json:"plans_implemented,omitempty"`
	// IssuesFound lists bugs or problems the session identified.
	IssuesFound []string `json:"issues_found,omitempty"`
	// Failures lists what failed or is unresolved (failing tests, failed
	// builds, errors), including honestly-unknown outcomes.
	Failures []string `json:"failures,omitempty"`
	// NextSteps lists concrete actions for the developer, never generic advice.
	NextSteps []string `json:"next_steps,omitempty"`
	// Confidence is one of ConfidenceLow/Medium/High.
	Confidence Confidence `json:"confidence"`
	// EvidenceRefs are identifiers into the evidence envelope the result cites.
	EvidenceRefs []string `json:"evidence_refs"`
	// Limitations enumerates what was not observed.
	Limitations []string `json:"limitations"`
	// SchemaVersion is always ResultSchemaVersion.
	SchemaVersion string `json:"schema_version"`
}

// NormalizedResult is the VALIDATED, normalized representation of a Result
// (FE1). Every text field is an opaque SafeText — so once a Result has been
// normalized, no downstream holder can substitute un-normalized bytes, and each
// field carries its per-sink escaping contract. It marshals wire-identically to
// Result (SafeText.MarshalJSON emits a plain JSON string), so storing/serving a
// NormalizedResult yields the same JSON as before while routing the value
// through the SafeText JSON sink.
type NormalizedResult struct {
	Title         SafeText   `json:"title"`
	TaxonomyTags  []SafeText `json:"taxonomy_tags"`
	SuggestedTags []SafeText `json:"suggested_tags"`
	Description   SafeText   `json:"description"`
	// The narrative half (see Result): optional lists, each bounded by
	// MaxNarrativeItems / MaxNarrativeItemBytes.
	WorkDone         []SafeText `json:"work_done,omitempty"`
	PlansImplemented []SafeText `json:"plans_implemented,omitempty"`
	IssuesFound      []SafeText `json:"issues_found,omitempty"`
	Failures         []SafeText `json:"failures,omitempty"`
	NextSteps        []SafeText `json:"next_steps,omitempty"`
	Confidence       Confidence `json:"confidence"`
	EvidenceRefs     []SafeText `json:"evidence_refs"`
	Limitations      []SafeText `json:"limitations"`
	SchemaVersion    string     `json:"schema_version"`
}

// NarrativeFields names the five narrative result lists in render order. It is
// the ONE place the set is enumerated, so a caller that must walk all five
// (the executor's scrub pass, the prompt's ref-id purity check, a store seam)
// never hand-restates the list and drifts.
var NarrativeFields = []string{"work_done", "plans_implemented", "issues_found", "failures", "next_steps"}

// Normalize enforces every result bound (enum, lengths, tag/ref/limitation
// counts) AND runs every text field through NormalizeText (Sol SC7 / FE1): the
// result-text value type rejects C0/C1/ANSI/OSC controls, bidi controls, and
// invalid UTF-8, and enforces NFC-normalized byte/rune bounds. It RETURNS the
// normalized result (opaque SafeText fields) rather than only an error, so the
// caller stores/serves the validated value, not the raw one. It does not
// perform output SCRUBBING (secret masking) — that is a separate downstream
// contract the executor applies before storage, since NormalizeText is pure and
// scrub lives outside this pure package.
func (r Result) Normalize() (NormalizedResult, error) {
	var out NormalizedResult
	if r.SchemaVersion != ResultSchemaVersion {
		return out, fmt.Errorf("cloudcontract.Result.Normalize: schema_version %q, want %q", r.SchemaVersion, ResultSchemaVersion)
	}
	out.SchemaVersion = r.SchemaVersion
	var err error
	if out.Title, err = NormalizeText("title", r.Title, MaxTitleBytes, true); err != nil {
		return NormalizedResult{}, err
	}
	if out.Description, err = NormalizeText("description", r.Description, MaxDescriptionBytes, false); err != nil {
		return NormalizedResult{}, err
	}
	if !r.Confidence.Valid() {
		return NormalizedResult{}, fmt.Errorf("cloudcontract.Result.Normalize: unknown confidence %q", r.Confidence)
	}
	out.Confidence = r.Confidence
	if out.TaxonomyTags, err = normalizeStringList("taxonomy_tags", r.TaxonomyTags, MaxTaxonomyTags, MaxTagBytes); err != nil {
		return NormalizedResult{}, err
	}
	if out.SuggestedTags, err = normalizeStringList("suggested_tags", r.SuggestedTags, MaxSuggestedTags, MaxTagBytes); err != nil {
		return NormalizedResult{}, err
	}
	if out.EvidenceRefs, err = normalizeStringList("evidence_refs", r.EvidenceRefs, MaxEvidenceRefs, MaxEvidenceRefBytes); err != nil {
		return NormalizedResult{}, err
	}
	if out.Limitations, err = normalizeStringList("limitations", r.Limitations, MaxLimitations, MaxLimitationBytes); err != nil {
		return NormalizedResult{}, err
	}
	// The narrative lists follow exactly the same rule as limitations: bounded
	// count, bounded per-item bytes, every item through NormalizeText. They are
	// OPTIONAL — a nil list normalizes to nil — so a result stored before these
	// fields existed still normalizes unchanged (back-compat).
	if out.WorkDone, err = normalizeStringList("work_done", r.WorkDone, MaxNarrativeItems, MaxNarrativeItemBytes); err != nil {
		return NormalizedResult{}, err
	}
	if out.PlansImplemented, err = normalizeStringList("plans_implemented", r.PlansImplemented, MaxNarrativeItems, MaxNarrativeItemBytes); err != nil {
		return NormalizedResult{}, err
	}
	if out.IssuesFound, err = normalizeStringList("issues_found", r.IssuesFound, MaxNarrativeItems, MaxNarrativeItemBytes); err != nil {
		return NormalizedResult{}, err
	}
	if out.Failures, err = normalizeStringList("failures", r.Failures, MaxNarrativeItems, MaxNarrativeItemBytes); err != nil {
		return NormalizedResult{}, err
	}
	if out.NextSteps, err = normalizeStringList("next_steps", r.NextSteps, MaxNarrativeItems, MaxNarrativeItemBytes); err != nil {
		return NormalizedResult{}, err
	}
	return out, nil
}

// Validate reports whether r satisfies every bound and normalization contract.
// It is Normalize with the normalized value discarded — kept for callers that
// only need a yes/no verdict.
func (r Result) Validate() error {
	_, err := r.Normalize()
	return err
}

// normalizeStringList checks a list's element count and runs each element
// through NormalizeText (non-empty, control/bidi-free, NFC-bounded), returning
// the normalized SafeText slice. A nil/empty input returns a nil slice.
func normalizeStringList(field string, list []string, maxCount, maxBytes int) ([]SafeText, error) {
	if len(list) > maxCount {
		return nil, fmt.Errorf("cloudcontract.Result.Normalize: %s has %d entries, exceeds max %d", field, len(list), maxCount)
	}
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]SafeText, 0, len(list))
	for i, v := range list {
		st, err := NormalizeText(fmt.Sprintf("%s[%d]", field, i), v, maxBytes, true)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}
