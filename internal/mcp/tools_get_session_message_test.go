package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/handoffsvc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func messageReaderStub(got *handoffsvc.MessageRequest, out handoffsvc.MessageResult) MessageReader {
	return func(_ context.Context, req handoffsvc.MessageRequest) (handoffsvc.MessageResult, error) {
		*got = req
		return out, nil
	}
}

func TestGetSessionMessage_ByID(t *testing.T) {
	s, _, _ := testServer(t)
	var got handoffsvc.MessageRequest
	s.Register(newGetSessionMessageTool(messageReaderStub(&got, handoffsvc.MessageResult{
		SessionID:  "sess-1",
		Tool:       "claude-code",
		Found:      true,
		Total:      12,
		FullBodies: true,
		Message: models.TranscriptMessage{
			Index: 4,
			ID:    "uuid-42",
			Role:  models.TranscriptAssistant,
			Text:  "here is the file",
			ToolCalls: []models.ToolCallRef{
				{Name: "Read", InputExcerpt: "big.txt", ResultExcerpt: "FULL BODY", Resolved: true},
			},
		},
	})))

	out := callTool(t, s, "get_session_message", map[string]any{
		"session_id": "sess-1",
		"message_id": "uuid-42",
	})

	if got.SessionID != "sess-1" || got.MessageID != "uuid-42" || got.Index != -1 {
		t.Errorf("request = %+v", got)
	}
	if out["found"] != true || out["full_bodies"] != true || out["id"] != "uuid-42" {
		t.Errorf("out = %+v", out)
	}
	// MHC-1: recalled message content comes back wrapped as untrusted,
	// historical data — the raw body must still survive inside the
	// wrapper (never truncated or dropped), and the sentinel must be
	// present so the calling model can tell reported history from an
	// instruction.
	text, _ := out["text"].(string)
	if !strings.Contains(text, "here is the file") {
		t.Errorf("text = %v", out["text"])
	}
	if !strings.Contains(text, "<untrusted_recalled_output") {
		t.Errorf("text missing untrusted-content sentinel: %v", out["text"])
	}
	calls, ok := out["tool_calls"].([]any)
	if !ok || len(calls) != 1 {
		t.Fatalf("tool_calls = %v", out["tool_calls"])
	}
	c := calls[0].(map[string]any)
	result, _ := c["result"].(string)
	if !strings.Contains(result, "FULL BODY") {
		t.Errorf("full un-excerpted result must survive: %v", c["result"])
	}
	if !strings.Contains(result, "<untrusted_recalled_output") {
		t.Errorf("result missing untrusted-content sentinel: %v", c["result"])
	}
}

func TestGetSessionMessage_ByIndex(t *testing.T) {
	s, _, _ := testServer(t)
	var got handoffsvc.MessageRequest
	s.Register(newGetSessionMessageTool(messageReaderStub(&got, handoffsvc.MessageResult{
		SessionID: "sess-1", Tool: "codex", Found: true, Total: 3,
		Message: models.TranscriptMessage{Index: 0, Role: models.TranscriptUser, Text: "hi"},
	})))

	callTool(t, s, "get_session_message", map[string]any{
		"session_id": "sess-1",
		"index":      0,
	})
	if got.MessageID != "" || got.Index != 0 {
		t.Errorf("index addressing should pass Index=0, MessageID empty: %+v", got)
	}
}

func TestGetSessionMessage_NotFound(t *testing.T) {
	s, _, _ := testServer(t)
	s.Register(newGetSessionMessageTool(messageReaderStub(new(handoffsvc.MessageRequest), handoffsvc.MessageResult{
		SessionID: "sess-1", Tool: "claude-code", Found: false, Total: 5,
	})))

	out := callTool(t, s, "get_session_message", map[string]any{
		"session_id": "sess-1",
		"message_id": "nope",
	})
	if out["found"] != false {
		t.Errorf("found should be false: %+v", out)
	}
	if _, ok := out["note"].(string); !ok {
		t.Errorf("not-found should carry an honest note: %+v", out)
	}
}

func TestGetSessionMessage_Validation(t *testing.T) {
	s, _, _ := testServer(t)
	s.Register(newGetSessionMessageTool(messageReaderStub(new(handoffsvc.MessageRequest), handoffsvc.MessageResult{})))

	// no session_id
	callToolExpectError(t, s, "get_session_message", map[string]any{})
	// session_id but neither message_id nor index
	callToolExpectError(t, s, "get_session_message", map[string]any{"session_id": "s"})
}

func TestGetSessionMessage_DegradesWithoutReader(t *testing.T) {
	s, _, _ := testServer(t)
	s.Register(newGetSessionMessageTool(nil))
	got := callToolExpectError(t, s, "get_session_message", map[string]any{
		"session_id": "s", "message_id": "m",
	})
	if got == "" {
		t.Error("nil reader must degrade with an honest error message")
	}
}
