package api

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// TestRequiredPurposesTitleOnlyCarveOut pins the out-of-purpose gate's one
// carve-out (2026-09-16): a context that is EXACTLY the single first-prompt
// excerpt needs only the structural purpose (the "Title only" level's
// narrowed first_user_prompt_excerpt class), while any wider context - a
// second excerpt, a differently-sourced lone excerpt, or user feedback -
// still needs bounded_context_enrichment.
func TestRequiredPurposesTitleOnlyCarveOut(t *testing.T) {
	first := cloudcontract.ContextExcerpt{Source: cloudcontract.ExcerptSourceFirstUserPrompt, Text: "fix the login test", LengthCapBytes: 1024}
	later := cloudcontract.ContextExcerpt{Source: cloudcontract.ExcerptSourceUserPrompt, Text: "now the logout one", LengthCapBytes: 1024}
	final := cloudcontract.ContextExcerpt{Source: cloudcontract.ExcerptSourceFinalAssistantMessage, Text: "done", LengthCapBytes: 1024}
	rating := 7
	cases := []struct {
		name        string
		env         cloudcontract.Envelope
		wantContext bool
	}{
		{"no context", cloudcontract.Envelope{}, false},
		{"first prompt only", cloudcontract.Envelope{Context: []cloudcontract.ContextExcerpt{first}}, false},
		{"first prompt plus a later one", cloudcontract.Envelope{Context: []cloudcontract.ContextExcerpt{first, later}}, true},
		{"a lone later prompt", cloudcontract.Envelope{Context: []cloudcontract.ContextExcerpt{later}}, true},
		{"a lone final assistant message", cloudcontract.Envelope{Context: []cloudcontract.ContextExcerpt{final}}, true},
		{"first prompt with user feedback", cloudcontract.Envelope{Context: []cloudcontract.ContextExcerpt{first}, UserFeedback: &cloudcontract.UserFeedback{Rating: &rating}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			need := requiredPurposes(tc.env)
			gotStructural, gotContext := false, false
			for _, p := range need {
				switch p {
				case cloudcontract.PurposeStructuralInsights:
					gotStructural = true
				case cloudcontract.PurposeContextEnrichment:
					gotContext = true
				}
			}
			if !gotStructural {
				t.Fatalf("every envelope requires the structural purpose; got %v", need)
			}
			if gotContext != tc.wantContext {
				t.Fatalf("context purpose required = %v, want %v (purposes %v)", gotContext, tc.wantContext, need)
			}
		})
	}
}
