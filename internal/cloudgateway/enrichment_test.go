package cloudgateway

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// TestEnrichmentRulesCoverEveryJobKind pins the job-kind table exhaustive: every
// kind AllEnrichmentJobKinds() lists has a rule, and every rule is a listed kind.
func TestEnrichmentRulesCoverEveryJobKind(t *testing.T) {
	if len(AllEnrichmentJobKinds()) != len(enrichmentRules) {
		t.Fatalf("AllEnrichmentJobKinds has %d, enrichmentRules has %d", len(AllEnrichmentJobKinds()), len(enrichmentRules))
	}
	for _, k := range AllEnrichmentJobKinds() {
		if !k.Valid() {
			t.Errorf("listed job kind %q has no rule", k)
		}
	}
	if EnrichmentJobKind("bogus").Valid() {
		t.Errorf("bogus job kind reported valid")
	}
}

// TestTitleOnlyLocksTagsAndDescription is the core W3b/F12 guarantee: the
// title-only kind produces ONLY the title and locks tags + description with
// honest copy; the full kind produces everything and locks nothing.
func TestTitleOnlyLocksTagsAndDescription(t *testing.T) {
	if !EnrichmentTitleOnly.Produces(EnrichmentFieldTitle) {
		t.Errorf("title-only must produce the title")
	}
	for _, f := range []EnrichmentField{EnrichmentFieldTags, EnrichmentFieldDescription} {
		if EnrichmentTitleOnly.Produces(f) {
			t.Errorf("title-only must NOT produce %q", f)
		}
	}
	locked := EnrichmentTitleOnly.LockedFields()
	if len(locked) != 2 {
		t.Fatalf("title-only locked fields = %d, want 2 (tags, description)", len(locked))
	}
	for _, lf := range locked {
		if lf.Reason == "" {
			t.Errorf("locked field %q has empty reason — honest-disabled copy required", lf.Field)
		}
	}

	for _, f := range allEnrichmentFields {
		if !EnrichmentFull.Produces(f) {
			t.Errorf("full enrichment must produce %q", f)
		}
	}
	if len(EnrichmentFull.LockedFields()) != 0 {
		t.Errorf("full enrichment must lock nothing")
	}
}

// TestEnrichmentFieldClassBinding pins the narrowed-disclosure mapping: the
// first-user-prompt class authorizes ONLY the title-only kind; the full
// content-excerpt class authorizes the full kind; a metadata-only class
// authorizes no content-bearing enrichment job.
func TestEnrichmentFieldClassBinding(t *testing.T) {
	if fc, _ := EnrichmentTitleOnly.MinFieldClass(); fc != cloudcontract.FieldClassFirstUserPrompt {
		t.Errorf("title-only min field class = %q, want first_user_prompt_excerpt", fc)
	}
	if fc, _ := EnrichmentFull.MinFieldClass(); fc != cloudcontract.FieldClassContentExcerpts {
		t.Errorf("full min field class = %q, want content_excerpts", fc)
	}
	if k, ok := EnrichmentJobKindForFieldClass(cloudcontract.FieldClassFirstUserPrompt); !ok || k != EnrichmentTitleOnly {
		t.Errorf("first-user-prompt class → %q,%v, want session_title,true", k, ok)
	}
	if k, ok := EnrichmentJobKindForFieldClass(cloudcontract.FieldClassContentExcerpts); !ok || k != EnrichmentFull {
		t.Errorf("content-excerpts class → %q,%v, want session_enrichment,true", k, ok)
	}
	if _, ok := EnrichmentJobKindForFieldClass(cloudcontract.FieldClassStructuralMetrics); ok {
		t.Errorf("structural-metrics class must authorize no content-bearing enrichment job")
	}
	// Both content job kinds ride the bounded-context-enrichment purpose; the
	// FIELD CLASS is what distinguishes their disclosure.
	if p, _ := EnrichmentTitleOnly.Purpose(); p != cloudcontract.PurposeContextEnrichment {
		t.Errorf("title-only purpose = %q, want bounded_context_enrichment", p)
	}
}

// TestEnrichmentFeatureRoundTrip pins the wire feature (job-kind header) mapping
// in both directions, so a first-prompt-only job can never be mislabeled as a
// full-bundle one on the wire.
func TestEnrichmentFeatureRoundTrip(t *testing.T) {
	if EnrichmentTitleOnly.Feature() != "session_title" {
		t.Errorf("title-only feature = %q, want session_title", EnrichmentTitleOnly.Feature())
	}
	if EnrichmentFull.Feature() != "session_enrichment" {
		t.Errorf("full feature = %q, want session_enrichment", EnrichmentFull.Feature())
	}
	for _, k := range AllEnrichmentJobKinds() {
		got, ok := EnrichmentJobKindForFeature(k.Feature())
		if !ok || got != k {
			t.Errorf("feature %q round-trip = %q,%v, want %q,true", k.Feature(), got, ok, k)
		}
	}
	if _, ok := EnrichmentJobKindForFeature("nope"); ok {
		t.Errorf("unknown feature reported a job kind")
	}
	if describeEnrichment(EnrichmentJobKind("x")) == "session_title" {
		t.Errorf("describeEnrichment must not claim an unknown kind is valid")
	}
}
