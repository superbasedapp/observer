package cacheobs

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestMessageBuilders_CanonicalBytes pins the exact bytes of the flattened
// message-level builders. These bytes feed the chain hash (spec R3): a
// change here is a chain-hash change for every adapter that uses them.
func TestMessageBuilders_CanonicalBytes(t *testing.T) {
	cases := []struct {
		name   string
		got    func() ([]byte, bool)
		want   string
		wantOK bool
	}{
		{"text", func() ([]byte, bool) { return MarshalTextBlock("hi") }, `{"type":"text","text":"hi"}`, true},
		{"text html escaped", func() ([]byte, bool) { return MarshalTextBlock("<a & b>") }, `{"type":"text","text":"\u003ca \u0026 b\u003e"}`, true},
		{"text empty", func() ([]byte, bool) { return MarshalTextBlock("") }, ``, false},
		{"tool result", func() ([]byte, bool) { return MarshalToolResultBlock("ok\n") }, `{"type":"tool_result","text":"ok\n"}`, true},
		{"tool result empty", func() ([]byte, bool) { return MarshalToolResultBlock("") }, ``, false},
		{"tool use", func() ([]byte, bool) { return MarshalToolUseBlock("bash", `{"command":"ls"}`) }, `{"type":"tool_use","name":"bash","input":"{\"command\":\"ls\"}"}`, true},
		{"tool use name only", func() ([]byte, bool) { return MarshalToolUseBlock("bash", "") }, `{"type":"tool_use","name":"bash"}`, true},
		{"tool use input only", func() ([]byte, bool) { return MarshalToolUseBlock("", "{}") }, `{"type":"tool_use","input":"{}"}`, true},
		{"tool use empty", func() ([]byte, bool) { return MarshalToolUseBlock("", "") }, ``, false},
		{"tool use args", func() ([]byte, bool) { return MarshalToolUseArgsBlock("bash", `{"command":"ls"}`) }, `{"type":"tool_use","name":"bash","args":"{\"command\":\"ls\"}"}`, true},
		{"tool use args empty", func() ([]byte, bool) { return MarshalToolUseArgsBlock("", "") }, ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.got()
			if ok != tc.wantOK || string(got) != tc.want {
				t.Errorf("got (%s, %v), want (%s, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestContentBuilders_CanonicalBytes pins the Anthropic-shape content
// block builders the same way.
func TestContentBuilders_CanonicalBytes(t *testing.T) {
	cases := []struct {
		name     string
		got      func() ([]byte, string, bool)
		want     string
		wantKind string
	}{
		{"text", func() ([]byte, string, bool) { return ContentText("text", "hello") }, `{"type":"text","text":"hello"}`, "text"},
		{"thinking", func() ([]byte, string, bool) { return ContentText("thinking", "plan") }, `{"type":"thinking","text":"plan"}`, "thinking"},
		{"text empty keeps the block", func() ([]byte, string, bool) { return ContentText("text", "") }, `{"type":"text"}`, "text"},
		{"tool use", func() ([]byte, string, bool) {
			return ContentToolUse("tu_1", "Read", json.RawMessage(`{"path":"a.go"}`))
		}, `{"type":"tool_use","id":"tu_1","name":"Read","input":{"path":"a.go"}}`, "tool_use"},
		{"tool use no input", func() ([]byte, string, bool) { return ContentToolUse("tu_1", "Read", nil) }, `{"type":"tool_use","id":"tu_1","name":"Read"}`, "tool_use"},
		{"tool result", func() ([]byte, string, bool) { return ContentToolResult("tu_1", false, json.RawMessage(`"done"`)) }, `{"type":"tool_result","tool_use_id":"tu_1","content":"done"}`, "tool_result"},
		{"tool result error", func() ([]byte, string, bool) {
			return ContentToolResult("tu_1", true, json.RawMessage(`[{"type":"text","text":"x"}]`))
		}, `{"type":"tool_result","tool_use_id":"tu_1","is_error":true,"content":[{"type":"text","text":"x"}]}`, "tool_result"},
		{"image", ContentImage, `{"type":"image"}`, "text"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, kind, ok := tc.got()
			if !ok || string(got) != tc.want || kind != tc.wantKind {
				t.Errorf("got (%s, %q, %v), want (%s, %q, true)", got, kind, ok, tc.want, tc.wantKind)
			}
		})
	}
}

// TestContentBlocks_OrderRoleAndSkips checks that ContentBlocks keeps input
// order, tags every row with the message level and the given role, drops
// the blocks marshal rejects, and returns nil for an empty array.
func TestContentBlocks_OrderRoleAndSkips(t *testing.T) {
	marshal := func(s string) ([]byte, string, bool) {
		if s == "" {
			return nil, "", false
		}
		return ContentText("text", s)
	}
	if got := ContentBlocks([]string(nil), "user", marshal); got != nil {
		t.Errorf("empty input = %v, want nil", got)
	}
	got := ContentBlocks([]string{"a", "", "b"}, "user", marshal)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	for i, want := range []string{`{"type":"text","text":"a"}`, `{"type":"text","text":"b"}`} {
		m := got[i]
		if string(m.CanonicalBytes) != want || m.LevelLabel != "message" || m.Kind != "text" || m.Role != "user" {
			t.Errorf("row %d = %+v (%s)", i, m, m.CanonicalBytes)
		}
	}
}

// TestObserveHelpers_BlockMeta checks the kind and role each Observe*
// helper stamps and that an empty payload adds nothing.
func TestObserveHelpers_BlockMeta(t *testing.T) {
	a := New(DefaultMaxBlocksPerSession)
	a.ObserveText("", "user")
	a.ObserveToolUse("", "")
	a.ObserveToolUseArgs("", "")
	a.ObserveToolResult("")
	a.ObserveText("q", "user")
	a.ObserveText("r", "assistant")
	a.ObserveToolUse("bash", "ls")
	a.ObserveToolUseArgs("bash", "ls")
	a.ObserveToolResult("out")
	obs := a.Emit("p", "s", "m", "model", time.Time{}, models.CacheUsage{}, false)
	want := []models.CacheBlockMeta{
		{LevelLabel: "message", Kind: "text", Role: "user", CanonicalBytes: []byte(`{"type":"text","text":"q"}`)},
		{LevelLabel: "message", Kind: "text", Role: "assistant", CanonicalBytes: []byte(`{"type":"text","text":"r"}`)},
		{LevelLabel: "message", Kind: "tool_use", Role: "assistant", CanonicalBytes: []byte(`{"type":"tool_use","name":"bash","input":"ls"}`)},
		{LevelLabel: "message", Kind: "tool_use", Role: "assistant", CanonicalBytes: []byte(`{"type":"tool_use","name":"bash","args":"ls"}`)},
		{LevelLabel: "message", Kind: "tool_result", Role: "tool", CanonicalBytes: []byte(`{"type":"tool_result","text":"out"}`)},
	}
	if len(obs.BlockHashes) != len(want) {
		t.Fatalf("blocks = %d, want %d", len(obs.BlockHashes), len(want))
	}
	for i, w := range want {
		g := obs.BlockHashes[i]
		if g.LevelLabel != w.LevelLabel || g.Kind != w.Kind || g.Role != w.Role || string(g.CanonicalBytes) != string(w.CanonicalBytes) {
			t.Errorf("block %d = %+v (%s), want %+v (%s)", i, g, g.CanonicalBytes, w, w.CanonicalBytes)
		}
	}
}

// TestEmitTurn covers the zero-usage carve-out (nil, delta kept), the
// drain, the never-fast stamp and the implicit-cache overlay.
func TestEmitTurn(t *testing.T) {
	ts := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	a := New(DefaultMaxBlocksPerSession)
	a.ObserveText("q", "user")
	if obs := a.EmitTurn("p", "s", "m0", "claude-x", "", ts, models.CacheUsage{}); obs != nil {
		t.Fatalf("zero usage = %+v, want nil", obs)
	}
	usage := models.CacheUsage{NetInputTokens: 10, CacheReadTokens: 5}
	obs := a.EmitTurn("p", "s", "m1", "claude-x", "", ts, usage)
	if obs == nil {
		t.Fatal("non-zero usage returned nil")
	}
	if len(obs.BlockHashes) != 1 || obs.SourceEventID != "cachetrack:m1" || obs.Fast || obs.ImplicitCache ||
		obs.Usage != usage || obs.Model != "claude-x" || obs.SessionID != "s" || obs.MessageID != "m1" || !obs.Timestamp.Equal(ts) {
		t.Errorf("observation = %+v", obs)
	}
	a.ObserveText("r", "user")
	implicit := a.EmitTurn("p", "s", "m2", "gpt-5", "openai", ts, usage)
	if implicit == nil || !implicit.ImplicitCache || implicit.BlockHashes != nil {
		t.Errorf("implicit observation = %+v, want ImplicitCache and nil blocks", implicit)
	}
}
