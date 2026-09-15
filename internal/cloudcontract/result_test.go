package cloudcontract

import (
	"encoding/json"
	"strings"
	"testing"
)

func validResult() Result {
	return Result{
		Title:         "Add retry-safe device authentication",
		TaxonomyTags:  []string{"auth", "backend", "testing"},
		SuggestedTags: []string{"device-flow"},
		Description:   "Implemented and tested a device-bound token exchange flow.",
		Confidence:    ConfidenceMedium,
		EvidenceRefs:  []string{"task_excerpt", "outcome.tests"},
		Limitations:   []string{"deployment was not observed"},
		SchemaVersion: ResultSchemaVersion,
	}
}

func TestResultValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Result)
		wantErr bool
	}{
		{"valid", func(*Result) {}, false},
		{"bad schema", func(r *Result) { r.SchemaVersion = "session_enrichment.v1" }, true},
		{"empty title", func(r *Result) { r.Title = "" }, true},
		{"long title", func(r *Result) { r.Title = strings.Repeat("x", MaxTitleBytes+1) }, true},
		{"bad confidence", func(r *Result) { r.Confidence = "certain" }, true},
		{"too many taxonomy tags", func(r *Result) {
			r.TaxonomyTags = make([]string, MaxTaxonomyTags+1)
			for i := range r.TaxonomyTags {
				r.TaxonomyTags[i] = "t"
			}
		}, true},
		{"empty tag", func(r *Result) { r.TaxonomyTags = []string{""} }, true},
		{"long tag", func(r *Result) { r.SuggestedTags = []string{strings.Repeat("y", MaxTagBytes+1)} }, true},
		{"too many evidence refs", func(r *Result) {
			r.EvidenceRefs = make([]string, MaxEvidenceRefs+1)
			for i := range r.EvidenceRefs {
				r.EvidenceRefs[i] = "e"
			}
		}, true},
		{"long limitation", func(r *Result) { r.Limitations = []string{strings.Repeat("z", MaxLimitationBytes+1)} }, true},
		{"empty optional lists ok", func(r *Result) {
			r.TaxonomyTags = nil
			r.SuggestedTags = nil
			r.EvidenceRefs = nil
			r.Limitations = nil
		}, false},
		// The five narrative lists follow exactly the limitations rule.
		{"narrative lists ok", func(r *Result) {
			r.WorkDone = []string{"Reworked the token dedup allocator."}
			r.PlansImplemented = []string{"The opening ask landed; the backfill was left."}
			r.IssuesFound = []string{"Two sessions collapsed onto one token row."}
			r.Failures = []string{"Six test runs finished with no recorded result."}
			r.NextSteps = []string{"Re-run the suite without piping it."}
		}, false},
		// BACK-COMPAT: a result stored before the narrative fields existed
		// carries none of them and must still normalize unchanged.
		{"narrative absent still normalizes", func(r *Result) {
			r.WorkDone, r.PlansImplemented, r.IssuesFound, r.Failures, r.NextSteps = nil, nil, nil, nil, nil
		}, false},
		{"too many work_done items", func(r *Result) {
			r.WorkDone = make([]string, MaxNarrativeItems+1)
			for i := range r.WorkDone {
				r.WorkDone[i] = "x"
			}
		}, true},
		{"too many next_steps items", func(r *Result) {
			r.NextSteps = make([]string, MaxNarrativeItems+1)
			for i := range r.NextSteps {
				r.NextSteps[i] = "x"
			}
		}, true},
		{"long failure item", func(r *Result) {
			r.Failures = []string{strings.Repeat("z", MaxNarrativeItemBytes+1)}
		}, true},
		{"empty issue item", func(r *Result) { r.IssuesFound = []string{""} }, true},
		{"control char in plan item", func(r *Result) { r.PlansImplemented = []string{"bad\x00plan"} }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validResult()
			tt.mutate(&r)
			err := r.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestResultNarrativeRoundTrip pins that the narrative lists survive
// Normalize as SafeText and marshal back to the SAME JSON keys, and that an
// ALREADY-STORED v2 result with none of them decodes and normalizes cleanly
// (production has real stored results predating these fields).
func TestResultNarrativeRoundTrip(t *testing.T) {
	r := validResult()
	r.WorkDone = []string{"Edited 14 Go files across the store package."}
	r.NextSteps = []string{"Re-run the suite without piping it."}
	nr, err := r.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(nr.WorkDone) != 1 || nr.WorkDone[0].String() != r.WorkDone[0] {
		t.Fatalf("work_done did not round-trip: %+v", nr.WorkDone)
	}
	if len(nr.NextSteps) != 1 || nr.NextSteps[0].String() != r.NextSteps[0] {
		t.Fatalf("next_steps did not round-trip: %+v", nr.NextSteps)
	}
	b, err := json.Marshal(nr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"work_done"`, `"next_steps"`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("normalized result JSON is missing %s: %s", key, b)
		}
	}
	// A list nobody filled is OMITTED, not emitted as null.
	if strings.Contains(string(b), `"issues_found"`) {
		t.Fatalf("an empty narrative list was emitted: %s", b)
	}

	// Back-compat: the exact stored shape of a pre-narrative v2 result.
	const legacy = `{"title":"t","taxonomy_tags":[],"suggested_tags":[],"description":"d",` +
		`"confidence":"low","evidence_refs":[],"limitations":[],` +
		`"schema_version":"` + ResultSchemaVersion + `"}`
	var old Result
	if err := json.Unmarshal([]byte(legacy), &old); err != nil {
		t.Fatalf("legacy result does not decode: %v", err)
	}
	if _, err := old.Normalize(); err != nil {
		t.Fatalf("a stored v2 result without the narrative fields failed to normalize: %v", err)
	}
}

// TestNarrativeRefLeak pins the purity rule the prompt states: an evidence
// identifier must never appear in prose. It is deliberately CONSERVATIVE -
// over-rejection would fail every job - so ordinary English containing
// "context" or "actions" is not a leak.
func TestNarrativeRefLeak(t *testing.T) {
	leaks := []string{
		"a136",
		"m5",
		"See a12 for the edit that landed.",
		"activity_mix",
		"The activity_mix shows 339 commands.",
		"outcomes",
		"  Context. ",
		"error_class x40 dominated the session.",
		"tests_run was 6 but tests_passed was 0.",
		"outcome.build recorded nothing.",
	}
	for _, s := range leaks {
		if _, ok := NarrativeRefLeak(s); !ok {
			t.Errorf("NarrativeRefLeak(%q) = false, want a leak", s)
		}
	}
	clean := []string{
		"Reworked the per-account token dedup allocator.",
		"Six test runs finished with no recorded result.",
		"No tests ran, so the outcome cannot be verified in this context.",
		"Most actions were reads; the edits landed in the store package.",
		"Added metrics for the edge rate limiter.",
		"Finish the migration the last prompt asked for.",
		"Bumped the M5 build target.",
	}
	for _, s := range clean {
		if tok, ok := NarrativeRefLeak(s); ok {
			t.Errorf("NarrativeRefLeak(%q) reported a leak on %q; ordinary prose must pass", s, tok)
		}
	}
}

func TestConfidenceValid(t *testing.T) {
	for _, c := range []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh} {
		if !c.Valid() {
			t.Errorf("%q reported invalid", c)
		}
	}
	if Confidence("").Valid() || Confidence("high ").Valid() {
		t.Errorf("invalid confidence reported valid")
	}
}
