package admission

import "testing"

// TestLintRefusesUnmatchableTopic pins the org-side lint (FR-M03): a denied
// topic with no letter or digit can never match, so it is a fatal issue; the
// vector matches internal/obs/admission's TestTopicProblem.
func TestLintRefusesUnmatchableTopic(t *testing.T) {
	tests := []struct {
		topic  string
		refuse bool
	}{
		{"competitor", false},
		{"hack*", false},
		{"legal advice", false},
		{"ps5", false},
		{"5", false},
		{"竞争对手", false},
		{"c++", false},
		{"!!!", true},
		{"*", true},
		{"**", true},
		{"--", true},
		{"$ *", true},
	}
	for _, tc := range tests {
		t.Run(tc.topic, func(t *testing.T) {
			issues := Lint(PolicyInput{Criteria: []CriterionInput{{
				ID: "c1", Type: "denied_topics", Decision: "deny", Severity: "high",
				Topics: []string{"fine topic", tc.topic},
			}}})
			fatal := 0
			for _, is := range issues {
				if is.Fatal && is.CriterionID == "c1" {
					fatal++
				}
			}
			if (fatal > 0) != tc.refuse {
				t.Errorf("topic %q: fatal issues = %v (want refused=%v)", tc.topic, issues, tc.refuse)
			}
			if got := TopicProblem(tc.topic); (got != "") != tc.refuse {
				t.Errorf("TopicProblem(%q) = %q, want refused=%v", tc.topic, got, tc.refuse)
			}
		})
	}
}
