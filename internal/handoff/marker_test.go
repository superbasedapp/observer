package handoff

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func msg(role models.TranscriptRole, text string, calls ...models.ToolCallRef) models.TranscriptMessage {
	return models.TranscriptMessage{Role: role, Text: text, ToolCalls: calls}
}

func TestContainsMarker(t *testing.T) {
	msgs := []models.TranscriptMessage{
		msg(models.TranscriptUser, "read the file"),
		msg(models.TranscriptAssistant, "ok", models.ToolCallRef{
			Name:          "Read",
			ResultExcerpt: "<!-- superbased-handoff 1a2b3c4d -->\nheader",
		}),
	}
	tests := []struct {
		name    string
		shortID string
		want    bool
	}{
		{"present in tool_result", "1a2b3c4d", true},
		{"absent", "99999999", false},
		{"empty never matches", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsMarker(msgs, tt.shortID); got != tt.want {
				t.Errorf("ContainsMarker(%q) = %v, want %v", tt.shortID, got, tt.want)
			}
		})
	}
	if ContainsMarker(nil, "1a2b3c4d") {
		t.Error("nil transcript must not match")
	}
}
