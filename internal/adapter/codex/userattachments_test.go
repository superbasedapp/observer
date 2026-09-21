package codex

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestUserAttachments pins Issue 1 (migration 126) for codex: a role=user
// response_item message carrying `input_image` / `input_file` / `image_url`
// parts resolves into UserAttachments (kind image | file, media_type parsed
// from the data-URI prefix — never the base64 body) and is correlated onto
// the most recent user_prompt event (the event_msg/user_message record
// carries only the text). A text-only turn carries no attachments.
func TestUserAttachments(t *testing.T) {
	t.Parallel()

	meta := `{"timestamp":"2026-06-19T01:50:01.0Z","type":"session_meta","payload":{"id":"thread-att","cwd":"/home/u/proj","model":"gpt-5.4","git_branch":"main"}}`

	tests := []struct {
		name          string
		lines         []string
		wantKinds     []string
		wantMediaType map[string]string
	}{
		{
			name: "input_image data uri",
			lines: []string{
				`{"timestamp":"2026-06-19T01:50:02.0Z","type":"event_msg","payload":{"type":"user_message","message":"look at this screenshot"}}`,
				`{"timestamp":"2026-06-19T01:50:02.1Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"look at this screenshot"},{"type":"input_image","image_url":"data:image/png;base64,aGVsbG8="}]}}`,
			},
			wantKinds:     []string{"image"},
			wantMediaType: map[string]string{"image": "image/png"},
		},
		{
			name: "input_file part",
			lines: []string{
				`{"timestamp":"2026-06-19T01:50:02.0Z","type":"event_msg","payload":{"type":"user_message","message":"read this"}}`,
				`{"timestamp":"2026-06-19T01:50:02.1Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"read this"},{"type":"input_file","filename":"secret-ticket-id.pdf"}]}}`,
			},
			wantKinds:     []string{"file"},
			wantMediaType: map[string]string{"file": ""},
		},
		{
			name: "image_url object form",
			lines: []string{
				`{"timestamp":"2026-06-19T01:50:02.0Z","type":"event_msg","payload":{"type":"user_message","message":"and this"}}`,
				`{"timestamp":"2026-06-19T01:50:02.1Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/jpeg;base64,/9j/"}}]}}`,
			},
			wantKinds:     []string{"image"},
			wantMediaType: map[string]string{"image": "image/jpeg"},
		},
		{
			name: "text only no attachments",
			lines: []string{
				`{"timestamp":"2026-06-19T01:50:02.0Z","type":"event_msg","payload":{"type":"user_message","message":"just a prompt"}}`,
				`{"timestamp":"2026-06-19T01:50:02.1Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"just a prompt"}]}}`,
			},
			wantKinds: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "rollout-2026-06-19T01-20-23-thread-att.jsonl")
			body := meta + "\n" + strings.Join(tc.lines, "\n") + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
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
			got := prompt.UserAttachments
			if len(got) != len(tc.wantKinds) {
				t.Fatalf("attachments = %+v; want kinds %v", got, tc.wantKinds)
			}
			for i, wantKind := range tc.wantKinds {
				if got[i].Kind != wantKind {
					t.Errorf("attachment[%d].Kind = %q; want %q", i, got[i].Kind, wantKind)
				}
				if wantMT, ok := tc.wantMediaType[wantKind]; ok && got[i].MediaType != wantMT {
					t.Errorf("attachment[%d].MediaType = %q; want %q", i, got[i].MediaType, wantMT)
				}
			}
			// PRIVACY: neither the base64 body nor the filename may leak.
			for _, a := range got {
				if strings.Contains(a.MediaType, "aGVsbG8") || strings.Contains(a.MediaType, "secret-ticket-id") {
					t.Errorf("base64/filename leaked into MediaType: %q", a.MediaType)
				}
			}
		})
	}
}
