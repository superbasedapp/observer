package cowork

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// writeCoworkSession lays out a minimal cowork capture tree
// (<root>/co/dev/local_<id>/audit.jsonl + the sibling local_<id>.json
// sidecar) and returns (root, auditPath).
func writeCoworkSession(t *testing.T, userRecord string) (string, string) {
	t.Helper()
	const sessID = "11111111-2222-3333-4444-555555555555"
	root := t.TempDir()
	devDir := filepath.Join(root, "co", "dev")
	localDir := filepath.Join(devDir, "local_aaaa-bbbb")
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sidecar := `{"sessionId":"local_aaaa-bbbb","processName":"test","cliSessionId":"` + sessID +
		`","cwd":"/tmp/w","userSelectedFolders":["/tmp/w"],"model":"claude-opus-4-6"}`
	if err := os.WriteFile(filepath.Join(devDir, "local_aaaa-bbbb.json"), []byte(sidecar), 0o600); err != nil {
		t.Fatal(err)
	}
	audit := `{"type":"system","subtype":"init","cwd":"/tmp/w","session_id":"` + sessID +
		`","tools":["Read"],"_audit_timestamp":"2026-05-15T10:00:00.000Z"}` + "\n" + userRecord + "\n"
	auditPath := filepath.Join(localDir, "audit.jsonl")
	if err := os.WriteFile(auditPath, []byte(audit), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, auditPath
}

// TestUserAttachments pins Issue 1 (migration 126) for cowork: a user turn
// with an `image` block populates the user_prompt row's UserAttachments
// (kind image, media_type from source.media_type — never the base64 data),
// on both an image-only turn (which keeps the back-compat marker) and a
// text+image turn. A text-only turn carries none.
func TestUserAttachments(t *testing.T) {
	t.Parallel()

	const sessID = "11111111-2222-3333-4444-555555555555"
	userRec := func(uuid, content string) string {
		return `{"type":"user","uuid":"` + uuid + `","session_id":"` + sessID +
			`","parent_tool_use_id":null,"message":{"role":"user","content":` + content +
			`},"_audit_timestamp":"2026-05-15T10:00:01.000Z"}`
	}
	const imgBlock = `{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGVsbG8="}}`

	tests := []struct {
		name          string
		record        string
		wantAttach    bool
		wantMediaType string
	}{
		{
			name:          "text plus image",
			record:        userRec("u-1", `[{"type":"text","text":"describe this"},`+imgBlock+`]`),
			wantAttach:    true,
			wantMediaType: "image/png",
		},
		{
			name:          "image only",
			record:        userRec("u-2", `[`+imgBlock+`]`),
			wantAttach:    true,
			wantMediaType: "image/png",
		},
		{
			name:       "text only",
			record:     userRec("u-3", `"just a plain prompt"`),
			wantAttach: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root, auditPath := writeCoworkSession(t, tc.record)
			res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), auditPath, 0)
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
		})
	}
}
