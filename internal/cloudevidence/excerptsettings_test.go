package cloudevidence

import "testing"

func TestConfiguredExcerptSelection(t *testing.T) {
	texts := SessionTexts{
		UserPrompts:       []string{"first request", "second request", "third request"},
		AssistantMessages: []string{"opening reply", "middle reply", "final reply"}, Errors: []string{"permission denied"},
	}
	for _, tc := range []struct {
		name      string
		selection ExcerptSelection
		sources   []string
	}{
		{"zero", ExcerptSelection{Bytes: 128}, nil},
		{"first only", ExcerptSelection{UserMessages: 1, Bytes: 128}, []string{SourceFirstUserPrompt}},
		{"latest assistants", ExcerptSelection{AssistantMessages: 2, Bytes: 128}, []string{"assistant_message", SourceFinalAssistantMessage}},
		{"mixed", ExcerptSelection{UserMessages: 2, AssistantMessages: 1, FailureClasses: 1, Bytes: 128}, []string{SourceFirstUserPrompt, SourceUserPrompt, SourceFinalAssistantMessage, SourceErrorClass}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SelectExcerptsWithSettings(texts, tc.selection)
			if len(got) != len(tc.sources) {
				t.Fatalf("selection: %+v", got)
			}
			for i, source := range tc.sources {
				if got[i].Source != source {
					t.Fatalf("source %d: %s", i, got[i].Source)
				}
			}
			if tc.name == "latest assistants" && got[0].Text != "middle reply" {
				t.Fatalf("did not use latest replies: %+v", got)
			}
		})
	}
}
