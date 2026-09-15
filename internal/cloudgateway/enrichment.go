package cloudgateway

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// enrichment.go is the NARROW SESSION-ENRICHMENT JOB-KIND CAPABILITY (W3b,
// divergence-remediation plan rev 4.1 §3 W3b + F12 / operator ruling R8). It is
// pure DATA (CLAUDE.md §5: an ordered rule set is a table, not an if-ladder) and
// makes no network call — a sibling to grant.go's purposeRules table. It answers
// one question the CLI and the node dashboard both ask: given the disclosure a
// developer has consented to, which enrichment RESULT fields may a job produce,
// and which render honestly LOCKED?
//
// # Why a title-only job kind exists
//
// The enrichment result (session_enrichment.v2-candidate) bundles title + tags +
// description. R8 narrows the TITLE feature's minimum disclosure to the
// first-user-prompt-only field class (cloudcontract.FieldClassFirstUserPrompt) —
// "how most chat products title" — so the most-wanted feature needs the smallest
// possible upload. But because the bundle is one object, a first-prompt-only
// grant must NOT ride a full-bundle request: doing so would send a body the
// developer did not authorize. So the grant gets its own job kind — a strict
// SUBSET that produces only the title, with tags and description held back and
// shown LOCKED with honest "unlocks when you share bounded excerpts" copy
// (honest-disabled-copy discipline, per the R2 feature-unlock mapping).
//
// This table describes the capability; it does not itself send anything. The
// egress path is still FeatureSend → UploadSession.Upload, gated by a live
// consent grant. What this adds is the SHAPE: the Feature (job-kind) header a
// job carries, the minimum field class it requires, and which result fields it
// is entitled to — so a caller can render the locked fields honestly and can
// never label a first-prompt-only job as a full-bundle one.

// EnrichmentJobKind is one enrichment job the node can request for a session.
// The vocabulary is CLOSED; a value outside these constants is invalid.
type EnrichmentJobKind string

const (
	// EnrichmentTitleOnly is the narrowed job kind (R8): it produces ONLY a
	// session title, from the first-user-prompt excerpt (the smallest possible
	// content disclosure). Tags and description are locked.
	EnrichmentTitleOnly EnrichmentJobKind = "session_title"
	// EnrichmentFull is the full session-enrichment job: title + tags +
	// description, from the bounded content-excerpt set.
	EnrichmentFull EnrichmentJobKind = "session_enrichment"
)

// EnrichmentField names one result field an enrichment job may produce or lock.
type EnrichmentField string

const (
	// EnrichmentFieldTitle is the session title.
	EnrichmentFieldTitle EnrichmentField = "title"
	// EnrichmentFieldTags is the taxonomy + suggested tag list.
	EnrichmentFieldTags EnrichmentField = "tags"
	// EnrichmentFieldDescription is the short description.
	EnrichmentFieldDescription EnrichmentField = "description"
)

// enrichmentRule is one row of the job-kind table.
type enrichmentRule struct {
	// feature is the wire "feature" (job-kind) header a job of this kind
	// carries on upload — the value passed as UploadRequest.Feature.
	feature string
	// minFieldClass is the SMALLEST cloudcontract field class this job kind may
	// ride. It is what a consent surface checks a grant against.
	minFieldClass cloudcontract.FieldClass
	// purpose is the consent purpose a content-bearing job of this kind uploads
	// under (both content job kinds ride bounded_context_enrichment; the field
	// class is what distinguishes their disclosure, not the purpose).
	purpose cloudcontract.Purpose
	// produces is the set of result fields this kind is entitled to, in the
	// canonical order title→tags→description.
	produces []EnrichmentField
	// lockedReason maps each field this kind does NOT produce to honest copy
	// naming exactly what unlocks it (never "coming soon").
	lockedReason map[EnrichmentField]string
}

// enrichmentRules is the closed table over the two enrichment job kinds.
// TestEnrichmentRulesCoverEveryJobKind pins that it stays exhaustive.
var enrichmentRules = map[EnrichmentJobKind]enrichmentRule{
	EnrichmentTitleOnly: {
		feature:       string(EnrichmentTitleOnly),
		minFieldClass: cloudcontract.FieldClassFirstUserPrompt,
		purpose:       cloudcontract.PurposeContextEnrichment,
		produces:      []EnrichmentField{EnrichmentFieldTitle},
		lockedReason: map[EnrichmentField]string{
			EnrichmentFieldTags:        "unlocks when you share bounded excerpts (`--purpose bounded_context_enrichment`)",
			EnrichmentFieldDescription: "unlocks when you share bounded excerpts (`--purpose bounded_context_enrichment`)",
		},
	},
	EnrichmentFull: {
		feature:       string(EnrichmentFull),
		minFieldClass: cloudcontract.FieldClassContentExcerpts,
		purpose:       cloudcontract.PurposeContextEnrichment,
		produces:      []EnrichmentField{EnrichmentFieldTitle, EnrichmentFieldTags, EnrichmentFieldDescription},
		lockedReason:  nil,
	},
}

// allEnrichmentFields is the canonical result-field order.
var allEnrichmentFields = []EnrichmentField{
	EnrichmentFieldTitle,
	EnrichmentFieldTags,
	EnrichmentFieldDescription,
}

// Valid reports whether k is a known enrichment job kind.
func (k EnrichmentJobKind) Valid() bool {
	_, ok := enrichmentRules[k]
	return ok
}

// Feature returns the wire feature (job-kind) header a job of this kind carries,
// or "" for an unknown kind.
func (k EnrichmentJobKind) Feature() string {
	rule, ok := enrichmentRules[k]
	if !ok {
		return ""
	}
	return rule.feature
}

// MinFieldClass returns the smallest field class this job kind may ride, and
// ok=false for an unknown kind.
func (k EnrichmentJobKind) MinFieldClass() (cloudcontract.FieldClass, bool) {
	rule, ok := enrichmentRules[k]
	if !ok {
		return "", false
	}
	return rule.minFieldClass, true
}

// Purpose returns the consent purpose a content-bearing job of this kind uploads
// under, and ok=false for an unknown kind.
func (k EnrichmentJobKind) Purpose() (cloudcontract.Purpose, bool) {
	rule, ok := enrichmentRules[k]
	if !ok {
		return "", false
	}
	return rule.purpose, true
}

// Produces reports whether this job kind is entitled to a given result field.
func (k EnrichmentJobKind) Produces(f EnrichmentField) bool {
	rule, ok := enrichmentRules[k]
	if !ok {
		return false
	}
	for _, p := range rule.produces {
		if p == f {
			return true
		}
	}
	return false
}

// LockedFields returns the result fields this job kind does NOT produce, each
// with honest copy naming what unlocks it, in canonical field order. Empty for
// EnrichmentFull. Callers render these as visibly locked (honest-disabled copy),
// never hidden.
func (k EnrichmentJobKind) LockedFields() []LockedField {
	rule, ok := enrichmentRules[k]
	if !ok {
		return nil
	}
	var out []LockedField
	for _, f := range allEnrichmentFields {
		if k.Produces(f) {
			continue
		}
		reason := rule.lockedReason[f]
		if reason == "" {
			reason = "not available under the current consent"
		}
		out = append(out, LockedField{Field: f, Reason: reason})
	}
	return out
}

// LockedField is one result field a job kind cannot produce, with the honest
// reason it is locked.
type LockedField struct {
	Field  EnrichmentField
	Reason string
}

// EnrichmentJobKindForFeature maps a wire feature (job-kind) header back to its
// job kind. ok=false for an unrecognized feature.
func EnrichmentJobKindForFeature(feature string) (EnrichmentJobKind, bool) {
	for k, rule := range enrichmentRules {
		if rule.feature == feature {
			return k, true
		}
	}
	return "", false
}

// EnrichmentJobKindForFieldClass returns the enrichment job kind a given field
// class authorizes: the first-user-prompt class authorizes ONLY the title-only
// kind, the full content-excerpt class authorizes the full kind. ok=false for a
// field class that authorizes no content-bearing enrichment job (e.g. structural
// metrics only ⇒ a generic structural title with no content upload).
func EnrichmentJobKindForFieldClass(fc cloudcontract.FieldClass) (EnrichmentJobKind, bool) {
	switch fc {
	case cloudcontract.FieldClassFirstUserPrompt:
		return EnrichmentTitleOnly, true
	case cloudcontract.FieldClassContentExcerpts:
		return EnrichmentFull, true
	default:
		return "", false
	}
}

// AllEnrichmentJobKinds returns the closed job-kind vocabulary, title-only
// first (narrowest disclosure first).
func AllEnrichmentJobKinds() []EnrichmentJobKind {
	return []EnrichmentJobKind{EnrichmentTitleOnly, EnrichmentFull}
}

// describeEnrichment renders a job kind for an honest error/status line.
func describeEnrichment(k EnrichmentJobKind) string {
	if !k.Valid() {
		return fmt.Sprintf("%q (unknown enrichment job kind)", string(k))
	}
	return string(k)
}
