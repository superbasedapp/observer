package cline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// writeClineHistory writes a synthetic api_conversation_history.json under a
// task dir and returns its path (mirrors copyFixture without the on-disk
// fixture).
func writeClineHistory(t *testing.T, taskID, body string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tasks", taskID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "api_conversation_history.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestUserAttachments pins Issue 1 (migration 126) for cline: a user message
// with an Anthropic `image` content block yields the standalone image row
// carrying BOTH the back-compat "[image attachment]" marker AND the
// structured UserAttachments (kind image, media_type from source.media_type
// — never the base64 data). A text-only turn carries no attachment row.
func TestUserAttachments(t *testing.T) {
	t.Parallel()

	t.Run("image block", func(t *testing.T) {
		t.Parallel()
		body := `[{"role":"user","content":[` +
			`{"type":"text","text":"<task>describe this</task>"},` +
			`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGVsbG8="}}` +
			`]}]`
		path := writeClineHistory(t, "task-img", body)
		res, err := New().ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("ParseSessionFile: %v", err)
		}
		var img *models.ToolEvent
		for i := range res.ToolEvents {
			if res.ToolEvents[i].Target == "[image attachment]" {
				img = &res.ToolEvents[i]
				break
			}
		}
		if img == nil {
			t.Fatalf("no image row parsed: %+v", res.ToolEvents)
		}
		// Back-compat text marker preserved.
		if img.Target != "[image attachment]" {
			t.Errorf("Target = %q; want the back-compat marker", img.Target)
		}
		// Structured field populated.
		if len(img.UserAttachments) != 1 {
			t.Fatalf("UserAttachments = %+v; want 1 image", img.UserAttachments)
		}
		if img.UserAttachments[0].Kind != "image" {
			t.Errorf("Kind = %q; want image", img.UserAttachments[0].Kind)
		}
		if img.UserAttachments[0].MediaType != "image/png" {
			t.Errorf("MediaType = %q; want image/png", img.UserAttachments[0].MediaType)
		}
	})

	t.Run("text only no attachments", func(t *testing.T) {
		t.Parallel()
		body := `[{"role":"user","content":[{"type":"text","text":"<task>just text</task>"}]}]`
		path := writeClineHistory(t, "task-text", body)
		res, err := New().ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("ParseSessionFile: %v", err)
		}
		for _, e := range res.ToolEvents {
			if len(e.UserAttachments) != 0 {
				t.Errorf("event %q carried attachments %+v; want none", e.RawToolName, e.UserAttachments)
			}
		}
	})
}
