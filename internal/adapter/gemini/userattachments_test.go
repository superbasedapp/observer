package gemini

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// writeGeminiSession writes a minimal legacy-JSON gemini session carrying the
// given user message content and returns its path.
func writeGeminiSession(t *testing.T, userContent string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".gemini", "tmp", "chats", "session-att.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"sessionId":"att-session","projectHash":"0000","startTime":"2026-05-12T10:00:00.000Z","messages":[` +
		`{"id":"u1","role":"user","timestamp":"2026-05-12T10:00:01.000Z","cwd":"/tmp/g","content":` + userContent + `}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestUserAttachments pins Issue 1 (migration 126) for gemini: a user turn
// carrying `inlineData` image parts populates the user_prompt row's
// UserAttachments (kind image, media_type from inlineData.mimeType — never
// the base64 data) on both an image-only turn (which keeps the back-compat
// "[user sent N image attachment(s)]" marker) and a text+image turn. A
// text-only turn carries none.
func TestUserAttachments(t *testing.T) {
	t.Parallel()

	const img = `{"inlineData":{"mimeType":"image/png","data":"aGVsbG8="}}`

	tests := []struct {
		name          string
		content       string
		wantAttach    bool
		wantMarker    bool
		wantMediaType string
	}{
		{
			name:          "text plus image",
			content:       `[{"type":"text","text":"look at this"},` + img + `]`,
			wantAttach:    true,
			wantMediaType: "image/png",
		},
		{
			name:          "image only keeps marker",
			content:       `[` + img + `]`,
			wantAttach:    true,
			wantMarker:    true,
			wantMediaType: "image/png",
		},
		{
			name:       "text only",
			content:    `[{"type":"text","text":"just text"}]`,
			wantAttach: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := writeGeminiSession(t, tc.content)
			res, err := New().ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			var prompt *models.ToolEvent
			for i := range res.ToolEvents {
				if res.ToolEvents[i].ActionType == models.ActionUserPrompt {
					prompt = &res.ToolEvents[i]
					break
				}
			}
			if prompt == nil {
				t.Fatalf("no user_prompt row parsed: %+v", res.ToolEvents)
			}
			if !tc.wantAttach {
				if len(prompt.UserAttachments) != 0 {
					t.Errorf("attachments = %+v; want none", prompt.UserAttachments)
				}
				return
			}
			if len(prompt.UserAttachments) != 1 {
				t.Fatalf("UserAttachments = %+v; want 1 image", prompt.UserAttachments)
			}
			if prompt.UserAttachments[0].Kind != "image" {
				t.Errorf("Kind = %q; want image", prompt.UserAttachments[0].Kind)
			}
			if prompt.UserAttachments[0].MediaType != tc.wantMediaType {
				t.Errorf("MediaType = %q; want %q", prompt.UserAttachments[0].MediaType, tc.wantMediaType)
			}
			if tc.wantMarker && !strings.Contains(prompt.Target, "image attachment(s)") {
				t.Errorf("Target = %q; want the back-compat image-attachment marker", prompt.Target)
			}
		})
	}
}
