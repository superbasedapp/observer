package claudecode

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// findUserPrompts filters a parse result's ToolEvents to the user_prompt
// rows, in stream order.
func findUserPrompts(evs []models.ToolEvent) []models.ToolEvent {
	var out []models.ToolEvent
	for _, e := range evs {
		if e.ActionType == models.ActionUserPrompt {
			out = append(out, e)
		}
	}
	return out
}

// TestParseSessionFile_UserAttachments pins Issue 1 (migration 126) for
// claude-code: a user turn carrying an `image` / `document` content block,
// or a type:"attachment" line, resolves into ToolEvent.UserAttachments with
// the coarse kind (image | file) and the media_type read ONLY from
// source.media_type — never the base64 data. An image-ONLY user turn (no
// text) now emits a user_prompt row (it used to be dropped). A text-only
// turn carries no attachments.
func TestParseSessionFile_UserAttachments(t *testing.T) {
	t.Parallel()

	const (
		imgSrc = `{"type":"base64","media_type":"image/png","data":"aGVsbG8="}`
		docSrc = `{"type":"base64","media_type":"application/pdf","data":"JVBERg=="}`
	)

	userLine := func(uuid, content string) string {
		return `{"type":"user","sessionId":"sess-att","cwd":"/tmp/w","uuid":"` + uuid +
			`","timestamp":"2026-09-02T10:00:00Z","entrypoint":"cli",` +
			`"message":{"role":"user","content":` + content + `}}`
	}
	attachmentLine := func(uuid, content string) string {
		return `{"type":"attachment","sessionId":"sess-att","cwd":"/tmp/w","uuid":"` + uuid +
			`","timestamp":"2026-09-02T10:00:01Z","entrypoint":"cli",` +
			`"message":{"role":"user","content":` + content + `}}`
	}

	tests := []struct {
		name          string
		line          string
		wantRow       bool // is a user_prompt row emitted at all?
		wantKinds     []string
		wantMediaType map[string]string // kind -> expected media type (first occurrence)
	}{
		{
			name:      "text plus image block",
			line:      userLine("u-img", `[{"type":"text","text":"look at this"},{"type":"image","source":`+imgSrc+`}]`),
			wantRow:   true,
			wantKinds: []string{"image"},
			wantMediaType: map[string]string{
				"image": "image/png",
			},
		},
		{
			name:      "text plus document block",
			line:      userLine("u-doc", `[{"type":"text","text":"read this file"},{"type":"document","source":`+docSrc+`}]`),
			wantRow:   true,
			wantKinds: []string{"file"},
			wantMediaType: map[string]string{
				"file": "application/pdf",
			},
		},
		{
			name:      "image only turn emits a row",
			line:      userLine("u-imgonly", `[{"type":"image","source":`+imgSrc+`}]`),
			wantRow:   true,
			wantKinds: []string{"image"},
			wantMediaType: map[string]string{
				"image": "image/png",
			},
		},
		{
			name:      "attachment line is a file",
			line:      attachmentLine("u-att", `[{"type":"text","text":"<injected file body>"}]`),
			wantRow:   true,
			wantKinds: []string{"file"},
		},
		{
			name:      "text only no attachments",
			line:      userLine("u-text", `[{"type":"text","text":"just a prompt"}]`),
			wantRow:   true,
			wantKinds: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "session-att.jsonl")
			if err := os.WriteFile(path, []byte(tc.line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := New().ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			prompts := findUserPrompts(res.ToolEvents)
			if !tc.wantRow {
				if len(prompts) != 0 {
					t.Fatalf("expected no user_prompt row, got %d", len(prompts))
				}
				return
			}
			if len(prompts) != 1 {
				t.Fatalf("expected exactly one user_prompt row, got %d: %+v", len(prompts), prompts)
			}
			got := prompts[0].UserAttachments
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
			// PRIVACY: the base64 payload must never appear anywhere on the row.
			for _, a := range got {
				if a.MediaType == "aGVsbG8=" || a.MediaType == "JVBERg==" {
					t.Errorf("base64 data leaked into MediaType: %q", a.MediaType)
				}
			}
		})
	}
}
