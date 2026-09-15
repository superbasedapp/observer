package cloudcontract

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// validEnvelope returns a fully-populated, schema-valid envelope for tests.
func validEnvelope() Envelope {
	rating := 8
	return Envelope{
		SchemaVersion:   EnvelopeSchemaVersion,
		CloudSessionID:  "cs-9f2a1c",
		CloudProjectID:  "cp-4b7e88",
		Tool:            "codex",
		ModelFamily:     "gpt-5.6",
		StartedAtBucket: "2026-08-27T10:00:00Z",
		DurationSeconds: 1840,
		Metrics: MetricsBlock{
			TokensIn: 1200, TokensOut: 800, CacheReadTokens: 400,
			CostUSD: 0.031, DeterministicScore: 82.5,
			RedundancyRatio: 0.12, ErrorRate: 0.05,
			ExplorationEfficiency: 0.8, ContinuityScore: 0.9,
		},
		Actions: []Action{
			{Ref: "a1", Kind: "read", Category: "go", Status: "ok"},
			{Ref: "a2", Kind: "edit", Category: "go", Status: "ok"},
		},
		Milestones: []Milestone{
			{Ref: "m1", Kind: "first_edit", ElapsedSeconds: 120},
		},
		Outcomes:           Outcomes{TestsRun: 2, TestsPassed: 2, Build: "passed"},
		UserFeedback:       &UserFeedback{Rating: &rating},
		DisclosurePurposes: []Purpose{PurposeStructuralInsights},
		ScrubberVersion:    "scrub-v1",
		Authority: dataauthority.Classification{
			Authority: dataauthority.AuthorityPersonal,
			Version:   dataauthority.Version,
		},
	}
}

func TestEnvelopeValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Envelope)
		wantErr bool
	}{
		{"valid", func(*Envelope) {}, false},
		{"bad schema", func(e *Envelope) { e.SchemaVersion = "x" }, true},
		{"empty session id", func(e *Envelope) { e.CloudSessionID = "" }, true},
		{"empty project id", func(e *Envelope) { e.CloudProjectID = "" }, true},
		{"empty tool", func(e *Envelope) { e.Tool = "" }, true},
		{"bad bucket", func(e *Envelope) { e.StartedAtBucket = "not-a-time" }, true},
		{"empty bucket", func(e *Envelope) { e.StartedAtBucket = "" }, true},
		{"negative duration", func(e *Envelope) { e.DurationSeconds = -1 }, true},
		{"ratio out of range", func(e *Envelope) { e.Metrics.ErrorRate = 1.5 }, true},
		{"score out of range", func(e *Envelope) { e.Metrics.DeterministicScore = 200 }, true},
		{"too many actions", func(e *Envelope) {
			e.Actions = make([]Action, MaxActions+1)
			for i := range e.Actions {
				e.Actions[i] = Action{Ref: "a", Kind: "read", Category: "go"}
			}
		}, true},
		{"passed exceeds run", func(e *Envelope) { e.Outcomes.TestsPassed = 3; e.Outcomes.TestsRun = 2 }, true},
		{"bad rating", func(e *Envelope) { r := 99; e.UserFeedback = &UserFeedback{Rating: &r} }, true},
		{"unknown disclosure purpose", func(e *Envelope) { e.DisclosurePurposes = []Purpose{"nope"} }, true},
		{"duplicate disclosure purpose", func(e *Envelope) {
			e.DisclosurePurposes = []Purpose{PurposeStructuralInsights, PurposeStructuralInsights}
		}, true},
		{"empty scrubber version", func(e *Envelope) { e.ScrubberVersion = "" }, true},
		{"bad authority", func(e *Envelope) { e.Authority.Authority = "weird" }, true},
		{"zero authority version", func(e *Envelope) { e.Authority.Version = 0 }, true},
		{"org authority is schema-valid", func(e *Envelope) { e.Authority.Authority = dataauthority.AuthorityOrg }, false},
		{"bad context cap", func(e *Envelope) {
			e.Context = []ContextExcerpt{{Source: "task", Text: "hi", LengthCapBytes: 0}}
		}, true},
		{"context over its cap", func(e *Envelope) {
			e.Context = []ContextExcerpt{{Source: "task", Text: "hello", LengthCapBytes: 2}}
		}, true},
		{"bad digest prefix", func(e *Envelope) { e.EvidenceContentDigest = "deadbeef" }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validEnvelope()
			tt.mutate(&e)
			err := e.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPurposeAndFieldClassVocabulary(t *testing.T) {
	if got := len(AllPurposes()); got != 7 {
		t.Fatalf("AllPurposes len = %d, want 7", got)
	}
	for _, p := range AllPurposes() {
		if !p.Valid() {
			t.Errorf("purpose %q reported invalid", p)
		}
	}
	if Purpose("bogus").Valid() {
		t.Errorf("bogus purpose reported valid")
	}
	if got := len(AllFieldClasses()); got != 6 {
		t.Fatalf("AllFieldClasses len = %d, want 6", got)
	}
	for _, f := range AllFieldClasses() {
		if !f.Valid() {
			t.Errorf("field class %q reported invalid", f)
		}
	}
	if FieldClass("bogus").Valid() {
		t.Errorf("bogus field class reported valid")
	}
	// R8 (W3b F12): the first-user-prompt field class is a NEW valid class and
	// a strict subset of the bounded content excerpts — the narrowed disclosure
	// the title-only job kind rides.
	if !FieldClassFirstUserPrompt.Valid() {
		t.Errorf("FieldClassFirstUserPrompt reported invalid")
	}
	if FieldClassFirstUserPrompt == FieldClassContentExcerpts {
		t.Errorf("first-user-prompt class must be distinct from the full content-excerpts class")
	}
}
