package conversation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/compression/conversation/types"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

func TestPipelineDisabledIsNoop(t *testing.T) {
	p := NewPipeline(PipelineConfig{Enabled: false}, DefaultRegistry(), scrub.New())
	body := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	got := p.Run("anthropic", body)
	if !got.Skipped {
		t.Error("Skipped should be true when Enabled=false")
	}
	if string(got.Body) != string(body) {
		t.Errorf("body mutated: %q", got.Body)
	}
}

func TestPipelineSkipsUnknownProviders(t *testing.T) {
	p := NewPipeline(PipelineConfig{Enabled: true, TargetRatio: 0.5}, DefaultRegistry(), scrub.New())
	body := []byte(`{"messages":[]}`)
	got := p.Run("bedrock", body)
	if !got.Skipped {
		t.Error("unknown provider should Skip")
	}
	if got.Provider != "bedrock" {
		t.Errorf("Provider = %q, want bedrock", got.Provider)
	}
}

func TestPipelineSkipsEmptyOpenAIMessages(t *testing.T) {
	p := NewPipeline(PipelineConfig{Enabled: true, TargetRatio: 0.5}, DefaultRegistry(), scrub.New())
	got := p.Run("openai", []byte(`{"messages":[]}`))
	if !got.Skipped {
		t.Error("empty messages array should Skip")
	}
}

func TestPipelineSkipsMalformedBody(t *testing.T) {
	p := NewPipeline(PipelineConfig{Enabled: true, TargetRatio: 0.5}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", []byte("not json"))
	if !got.Skipped {
		t.Error("malformed body should Skip")
	}
}

func TestPipelineCompressesToolResultBody(t *testing.T) {
	bigJSON := `{"records":[`
	for i := 0; i < 80; i++ {
		if i > 0 {
			bigJSON += ","
		}
		bigJSON += `{"id":` + itoa(i) + `,"payload":"`
		for j := 0; j < 30; j++ {
			bigJSON += "x"
		}
		bigJSON += `"}`
	}
	bigJSON += `]}`

	body := mustMarshal(t, map[string]any{
		"model": "claude-opus-4-6",
		"messages": []any{
			map[string]any{"role": "user", "content": "please analyze"},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":        "tool_result",
						"tool_use_id": "toolu_01",
						"content":     bigJSON,
					},
				},
			},
		},
	})

	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.9,
		PreserveLastN: 0,
		CompressTypes: []string{"json"},
	}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body)

	if got.Skipped {
		t.Fatalf("pipeline skipped: %+v", got)
	}
	if got.CompressedCount == 0 {
		t.Errorf("expected CompressedCount > 0: %+v", got)
	}
	if got.CompressedBytes >= got.OriginalBytes {
		t.Errorf("CompressedBytes %d should be < OriginalBytes %d", got.CompressedBytes, got.OriginalBytes)
	}

	// Output must still be valid JSON with the right shape.
	var env map[string]any
	if err := json.Unmarshal(got.Body, &env); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	msgs, ok := env["messages"].([]any)
	if !ok || len(msgs) != 2 {
		t.Fatalf("messages malformed: %v", env["messages"])
	}
	// The tool_result message's block content should now be a schema,
	// not the original records.
	second, _ := msgs[1].(map[string]any)
	content, _ := second["content"].([]any)
	block, _ := content[0].(map[string]any)
	result, _ := block["content"].(string)
	if !strings.Contains(result, "<string>") && !strings.Contains(result, "<number>") {
		t.Errorf("tool_result content not compressed: %q", result)
	}
	if got.MessagePrefixHash == "" {
		t.Errorf("expected non-empty message_prefix_hash")
	}
}

// TestBuildAllow_EmptyListReturnsEmptyMap_NotNil pins the V7-19 fix:
// buildAllow MUST return a non-nil empty map for empty input. Pre-
// v1.7.19 returning nil silently inverted every downstream
// `if allow != nil && !allow[ct]` gate into "allow all", which made
// the codex-variant recipe (compress_types = []) trigger MAXIMUM per-
// type compression instead of NONE. Full investigation in
// docs/v4-codex-compression-recipe-and-issues.md V7-19 row.
func TestBuildAllow_EmptyListReturnsEmptyMap_NotNil(t *testing.T) {
	got := buildAllow([]string{})
	if got == nil {
		t.Fatal("buildAllow([]) returned nil — must return non-nil empty map so per-type compression gates `!allow[ct]` correctly return true and skip")
	}
	if len(got) != 0 {
		t.Errorf("buildAllow([]) length = %d, want 0", len(got))
	}
}

// TestBuildAllow_NilInputAlsoReturnsEmptyMap pins symmetry: nil and
// empty slice produce the same empty-map result (both express
// "compress nothing").
func TestBuildAllow_NilInputAlsoReturnsEmptyMap(t *testing.T) {
	got := buildAllow(nil)
	if got == nil {
		t.Fatal("buildAllow(nil) returned nil — must return non-nil empty map (V7-19)")
	}
	if len(got) != 0 {
		t.Errorf("buildAllow(nil) length = %d, want 0", len(got))
	}
}

// TestBuildAllow_NonEmptyListPreservesEntries pins the original
// happy-path behavior — every name in the input becomes a true-keyed
// entry in the returned map.
func TestBuildAllow_NonEmptyListPreservesEntries(t *testing.T) {
	got := buildAllow([]string{"json", "logs", "code"})
	if len(got) != 3 {
		t.Fatalf("buildAllow length = %d, want 3", len(got))
	}
	for _, name := range []string{"json", "logs", "code"} {
		if !got[types.ContentType(name)] {
			t.Errorf("buildAllow missing entry for %q", name)
		}
	}
	if got["text"] {
		t.Error("buildAllow has unwanted entry for \"text\"")
	}
}

// TestPipeline_EmptyCompressTypes_SkipsAllPerTypeCompression pins the
// V7-19 end-to-end fix: when compress_types=[] (codex-variant recipe
// intent), the per-type compressors MUST NOT fire on any content. The
// pre-v1.7.19 bug routed the codex-variant recipe through MAXIMUM
// compression instead of NONE — the text head-tail compressor alone
// stripped 71% of tool output content on real codex sessions,
// triggering the V7-11 re-derivation cascade and an empirically-
// measured +11% cost regression vs no-proxy baseline.
//
// This test asserts the contract: compress_types=[] produces ZERO
// events from the per-type pool (json / logs / code / text / diff /
// html / tools). C16 read-cache substitution is NOT under buildAllow's
// gate and may still emit events — that's validated by its own tests.
// V7-21 extended buildAllow's gate to `tools` (envelope-level tool-
// definition trim) so the codex-variant recipe (compress_types=[])
// now correctly forwards the tools field byte-identically — see
// docs/v1.7.21-tools-defs-gate-plan-2026-06-01.md.
func TestPipeline_EmptyCompressTypes_SkipsAllPerTypeCompression(t *testing.T) {
	// 80+ JSON records would have been heavily compressed by the json
	// compressor under the buggy nil-allow path. Pin that it does NOT
	// fire under compress_types=[].
	bigJSON := `{"records":[`
	for i := 0; i < 80; i++ {
		if i > 0 {
			bigJSON += ","
		}
		bigJSON += `{"id":` + itoa(i) + `,"payload":"xxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`
	}
	bigJSON += `]}`

	body := mustMarshal(t, map[string]any{
		"model": "claude-opus-4-6",
		"messages": []any{
			map[string]any{"role": "user", "content": "analyze"},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":        "tool_result",
						"tool_use_id": "toolu_01",
						"content":     bigJSON,
					},
				},
			},
		},
	})

	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.99,
		PreserveLastN: 50,
		CompressTypes: []string{}, // ← the codex-variant intent
	}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body)

	if got.Skipped {
		// Skipped means the pipeline never ran — that's fine for this
		// test, since the assertion is "no per-type compression fires".
		return
	}

	for _, e := range got.Events {
		switch e.Mechanism {
		case "json", "logs", "code", "text", "diff", "html", "tools":
			t.Errorf(
				"V7-19/V7-21 regression: compress_types=[] produced %q mechanism event "+
					"(original=%d compressed=%d). Recipe author intended ZERO per-type compression.",
				e.Mechanism, e.OriginalBytes, e.CompressedBytes,
			)
		}
	}
}

// TestPipeline_ToolsDefsGated_NotInCompressTypes_NoTrim pins the
// V7-21 contract: when "tools" is NOT in compress_types, the
// envelope-level tool-definitions trim is skipped and the body is
// forwarded byte-identically (fast-path taken). codex-safe (["logs"])
// and codex-variant ([]) omit "tools", as does the master-config
// default; claude-code opted IN at A2 (2026-06-11) — the gate
// contract pinned here is unchanged either way. BC blast radius:
// docs/v1.7.21-tools-defs-gate-plan-2026-06-01.md §4.3.
func TestPipeline_ToolsDefsGated_NotInCompressTypes_NoTrim(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"tools": []any{
			map[string]any{
				"name":        "read_file",
				"description": "Read a file.\n\nReturns full contents.\n\nThis paragraph would be trimmed pre-V7-21.\n\nAnd this one too.",
				"input_schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{
							"type":     "string",
							"examples": []any{"/etc/hosts", "/home/user/x"},
						},
					},
					"required": []any{"path"},
				},
			},
		},
		"messages": []any{
			map[string]any{"role": "user", "content": "do a thing"},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Default-list recipe — pre-V7-21 this still trimmed tools.
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body)
	if got.Skipped {
		t.Fatalf("pipeline skipped: %+v", got)
	}
	for _, e := range got.Events {
		if e.Mechanism == "tools" {
			t.Errorf("V7-21 regression: tools mechanism fired but %q NOT in compress_types — got event=%+v", "tools", e)
		}
	}
	// Strong contract: the body must be forwarded byte-identical to the
	// input. compressToolDefinitions was the only thing rewriting the
	// envelope in this fixture; skipping it should restore the fast-path.
	if string(got.Body) != string(body) {
		t.Errorf("V7-21 regression: body was modified despite skip-gate.\n  want=%s\n  got =%s", string(body), string(got.Body))
	}
	// Sanity: trim-target text MUST still be in the wire body.
	if !strings.Contains(string(got.Body), "This paragraph would be trimmed pre-V7-21") {
		t.Errorf("description tail unexpectedly trimmed: %s", string(got.Body))
	}
	if !strings.Contains(string(got.Body), `"examples"`) {
		t.Errorf("examples unexpectedly stripped: %s", string(got.Body))
	}
}

// TestPipeline_ToolsDefsGated_InCompressTypes_DoesTrim pins the
// V7-21 opt-in path: operators who want tool-defs trim to keep
// applying explicitly add "tools" to their compress_types list.
func TestPipeline_ToolsDefsGated_InCompressTypes_DoesTrim(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"tools": []any{
			map[string]any{
				"name":        "read_file",
				"description": "Read a file.\n\nReturns full contents.\n\nThis paragraph IS trimmed.\n\nAnd this one too.",
				"input_schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{
							"type":     "string",
							"examples": []any{"/etc/hosts"},
						},
					},
					"required": []any{"path"},
				},
			},
		},
		"messages": []any{
			map[string]any{"role": "user", "content": "do a thing"},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		// Opt-in via the "tools" sentinel.
		CompressTypes: []string{"json", "logs", "code", "tools"},
	}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body)
	if got.Skipped {
		t.Fatalf("pipeline skipped: %+v", got)
	}

	saw := false
	for _, e := range got.Events {
		if e.Mechanism == "tools" {
			saw = true
			break
		}
	}
	if !saw {
		t.Errorf("V7-21 contract regression: %q in compress_types but tools mechanism did NOT fire. events=%+v", "tools", got.Events)
	}
	if strings.Contains(string(got.Body), "This paragraph IS trimmed") {
		t.Errorf("tail not trimmed despite opt-in: %s", string(got.Body))
	}
	if strings.Contains(string(got.Body), `"examples"`) {
		t.Errorf("examples not stripped despite opt-in: %s", string(got.Body))
	}
}

func TestPipelineDropsLowestScoredMessages(t *testing.T) {
	// Many oldest tool_result messages, one big user prompt at the end.
	msgs := []any{
		map[string]any{"role": "user", "content": "initial prompt"},
	}
	for i := 0; i < 10; i++ {
		msgs = append(msgs, map[string]any{
			"role": "user",
			"content": []any{
				map[string]any{
					"type":        "tool_result",
					"tool_use_id": "toolu_" + itoa(i),
					"content":     strings.Repeat("A", 500),
				},
			},
		})
	}
	msgs = append(msgs, map[string]any{"role": "user", "content": "final question"})

	body := mustMarshal(t, map[string]any{"model": "claude-opus-4-6", "messages": msgs})

	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.25,
		PreserveLastN: 2,
		CompressTypes: []string{},
	}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body)

	if got.Skipped {
		t.Fatalf("unexpected skip: %+v", got)
	}
	if got.DroppedCount == 0 {
		t.Errorf("expected drops: %+v", got)
	}
	if got.MarkerCount == 0 {
		t.Errorf("expected at least 1 marker: %+v", got)
	}

	var env map[string]any
	if err := json.Unmarshal(got.Body, &env); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	final, _ := env["messages"].([]any)
	lastTwo := final[len(final)-2:]
	last, _ := lastTwo[1].(map[string]any)
	if last["content"] != "final question" {
		t.Errorf("last message not preserved: %v", last)
	}
	// Marker should be present somewhere in the middle.
	markerFound := false
	for _, m := range final {
		mm, _ := m.(map[string]any)
		if c, ok := mm["content"].(string); ok && strings.Contains(c, "messages compressed") {
			markerFound = true
			break
		}
	}
	if !markerFound {
		t.Errorf("marker missing from final messages: %v", final)
	}
}

func TestPipelineScrubsOutput(t *testing.T) {
	body := mustMarshal(t, map[string]any{
		"model": "claude-opus-4-6",
		"messages": []any{
			map[string]any{"role": "user", "content": "here is my token ghp_aabbccddeeff1122334455667788"},
		},
	})
	p := NewPipeline(PipelineConfig{Enabled: true, TargetRatio: 0.9}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body)
	if strings.Contains(string(got.Body), "ghp_aabbccddeeff1122334455667788") {
		t.Errorf("token leaked through pipeline: %s", got.Body)
	}
}

// findBreakpointIndex returns the single index i for which messages[i]
// carries a cache_control annotation on its last block, or -1 when
// none do. Fails the test when more than one index matches (the
// pipeline must set exactly one breakpoint).
func findBreakpointIndex(t *testing.T, body []byte) int {
	t.Helper()
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(env["messages"], &msgs); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	found := -1
	for i, mRaw := range msgs {
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(mRaw, &msg); err != nil {
			continue
		}
		var blocks []map[string]any
		if err := json.Unmarshal(msg["content"], &blocks); err != nil {
			continue
		}
		for _, b := range blocks {
			if _, has := b["cache_control"]; has {
				if found >= 0 && found != i {
					t.Fatalf("more than one message carries cache_control (indices %d and %d)", found, i)
				}
				found = i
			}
		}
	}
	return found
}

// messageContentIsArray reports whether the i-th message's content field
// decodes as an array (vs a bare string).
func messageContentIsArray(t *testing.T, body []byte, i int) bool {
	t.Helper()
	var env map[string]json.RawMessage
	_ = json.Unmarshal(body, &env)
	var msgs []json.RawMessage
	_ = json.Unmarshal(env["messages"], &msgs)
	var msg map[string]json.RawMessage
	_ = json.Unmarshal(msgs[i], &msg)
	var arr []any
	return json.Unmarshal(msg["content"], &arr) == nil
}

func TestPipelineCacheMode_InjectsCacheControlAtPrefixBoundary(t *testing.T) {
	body := mustMarshal(t, map[string]any{
		"model": "claude-opus-4-6",
		"messages": []any{
			map[string]any{"role": "user", "content": "alpha"},
			map[string]any{"role": "assistant", "content": "beta"},
			map[string]any{"role": "user", "content": "gamma"},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:     true,
		Mode:        ModeCache,
		TargetRatio: 1.0,
	}, DefaultRegistry(), nil)
	got := p.Run("anthropic", body)
	if got.Skipped {
		t.Fatalf("want pipeline to engage in cache mode; Body=%s", got.Body)
	}
	idx := findBreakpointIndex(t, got.Body)
	if idx < 0 {
		t.Fatalf("no cache_control in body: %s", got.Body)
	}
	// Whichever message carries the breakpoint, its content must be in
	// array form — injection upgrades bare strings into a one-element
	// text block so the annotation has a valid home.
	if !messageContentIsArray(t, got.Body, idx) {
		t.Errorf("messages[%d] content not array-shaped; body=%s", idx, got.Body)
	}
}

func TestPipelineTokenMode_DoesNotInjectCacheControl(t *testing.T) {
	body := mustMarshal(t, map[string]any{
		"model": "claude-opus-4-6",
		"messages": []any{
			map[string]any{"role": "user", "content": "alpha"},
			map[string]any{"role": "assistant", "content": "beta"},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:     true,
		Mode:        ModeToken,
		TargetRatio: 1.0,
	}, DefaultRegistry(), nil)
	got := p.Run("anthropic", body)
	if got.Skipped {
		t.Fatalf("want pipeline to engage; Body=%s", got.Body)
	}
	if idx := findBreakpointIndex(t, got.Body); idx >= 0 {
		t.Fatalf("token mode injected cache_control on messages[%d]; body=%s", idx, got.Body)
	}
}

func TestPipelineCacheMode_PreservesExistingCacheControl(t *testing.T) {
	// Single-message body: SplitIndex → 1, breakpoint lands on the
	// same message whose only block already carries cache_control.
	// The pipeline must not duplicate the annotation on that block.
	body := mustMarshal(t, map[string]any{
		"model": "claude-opus-4-6",
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":          "text",
						"text":          "alpha",
						"cache_control": map[string]string{"type": "ephemeral"},
					},
				},
			},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:     true,
		Mode:        ModeCache,
		TargetRatio: 1.0,
	}, DefaultRegistry(), nil)
	got := p.Run("anthropic", body)

	// Exactly one cache_control on exactly one block — the original
	// one. No second copy, no overwrite.
	idx := findBreakpointIndex(t, got.Body)
	if idx != 0 {
		t.Fatalf("want breakpoint at 0, got %d; body=%s", idx, got.Body)
	}
	// Drill in: the single block on messages[0] has a single
	// cache_control field.
	var env map[string]json.RawMessage
	_ = json.Unmarshal(got.Body, &env)
	var msgs []json.RawMessage
	_ = json.Unmarshal(env["messages"], &msgs)
	var msg map[string]json.RawMessage
	_ = json.Unmarshal(msgs[0], &msg)
	var blocks []map[string]any
	if err := json.Unmarshal(msg["content"], &blocks); err != nil {
		t.Fatalf("content not array: %v; body=%s", err, got.Body)
	}
	if len(blocks) != 1 {
		t.Fatalf("block count duplicated: got %d want 1; body=%s", len(blocks), got.Body)
	}
}

// buildBigJSON returns a JSON string with `n` small records, suitable
// as a fake tool-output body that the JSON compressor will shrink.
func buildBigJSON(n int) string {
	out := `{"records":[`
	for i := 0; i < n; i++ {
		if i > 0 {
			out += ","
		}
		out += `{"id":` + itoa(i) + `,"payload":"`
		for j := 0; j < 30; j++ {
			out += "x"
		}
		out += `"}`
	}
	out += `]}`
	return out
}

func TestPipelineOpenAI_CompressesToolMessageContent(t *testing.T) {
	// Chat Completions: a tool message carries the function-call output
	// as a bare string in `content`. The pipeline should shrink it
	// via the JSON compressor, rewrite the message, and forward.
	bigJSON := buildBigJSON(80)
	body := mustMarshal(t, map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "system", "content": "helpful"},
			map[string]any{"role": "user", "content": "please analyze"},
			map[string]any{"role": "assistant", "content": "", "tool_calls": []any{
				map[string]any{
					"id":       "call_1",
					"type":     "function",
					"function": map[string]any{"name": "fetch", "arguments": "{}"},
				},
			}},
			map[string]any{
				"role":         "tool",
				"tool_call_id": "call_1",
				"content":      bigJSON,
			},
			map[string]any{"role": "user", "content": "summarize"},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		Mode:          ModeToken,
		TargetRatio:   0.5,
		CompressTypes: []string{"json"},
	}, DefaultRegistry(), nil)
	got := p.Run("openai", body)
	if got.Skipped {
		t.Fatalf("want pipeline to engage; body=%s", got.Body)
	}
	if got.CompressedCount < 1 {
		t.Fatalf("expected >=1 compression, got %d", got.CompressedCount)
	}
	if got.CompressedBytes >= got.OriginalBytes {
		t.Fatalf("compressed not smaller: %d >= %d", got.CompressedBytes, got.OriginalBytes)
	}

	// Round-trip the output and confirm the tool message's content
	// shrunk relative to the original.
	var env map[string]json.RawMessage
	if err := json.Unmarshal(got.Body, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v; body=%s", err, got.Body)
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(env["messages"], &msgs); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	// Find the tool message.
	var toolRaw json.RawMessage
	for _, mRaw := range msgs {
		var hdr struct {
			Role string `json:"role"`
		}
		_ = json.Unmarshal(mRaw, &hdr)
		if hdr.Role == "tool" {
			toolRaw = mRaw
			break
		}
	}
	if toolRaw == nil {
		t.Fatalf("no tool message in output: %s", got.Body)
	}
	if len(toolRaw) >= len(bigJSON) {
		t.Errorf("tool message not compressed: len=%d bigJSON=%d", len(toolRaw), len(bigJSON))
	}
}

func TestPipelineOpenAI_CompressesToolMessageWithPartsArray(t *testing.T) {
	// Variant where the tool content is an array of text parts (newer
	// Chat Completions shape) — the rewrite should preserve the array
	// form with one collapsed text part.
	bigJSON := buildBigJSON(80)
	body := mustMarshal(t, map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "user", "content": "analyze"},
			map[string]any{
				"role":         "tool",
				"tool_call_id": "call_1",
				"content": []any{
					map[string]any{"type": "text", "text": bigJSON},
				},
			},
			map[string]any{"role": "user", "content": "summarize"},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		Mode:          ModeToken,
		TargetRatio:   0.5,
		CompressTypes: []string{"json"},
	}, DefaultRegistry(), nil)
	got := p.Run("openai", body)
	if got.Skipped {
		t.Fatalf("want engage; body=%s", got.Body)
	}
	if got.CompressedCount < 1 {
		t.Fatalf("expected compression; got=%+v", got)
	}
	// Confirm the array shape survived the rewrite.
	var env map[string]json.RawMessage
	_ = json.Unmarshal(got.Body, &env)
	var msgs []json.RawMessage
	_ = json.Unmarshal(env["messages"], &msgs)
	for _, mRaw := range msgs {
		var hdr struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		_ = json.Unmarshal(mRaw, &hdr)
		if hdr.Role != "tool" {
			continue
		}
		var arr []any
		if err := json.Unmarshal(hdr.Content, &arr); err != nil {
			t.Errorf("tool content not array after rewrite: %s", hdr.Content)
		}
	}
}

func TestPipelineOpenAIResponses_CompressesFunctionCallOutput(t *testing.T) {
	bigJSON := buildBigJSON(80)
	body := mustMarshal(t, map[string]any{
		"model": "gpt-5",
		"input": []any{
			map[string]any{
				"type": "message",
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": "please inspect this"},
				},
			},
			map[string]any{
				"type":    "function_call_output",
				"call_id": "call_1",
				"output":  bigJSON,
			},
			map[string]any{
				"type": "message",
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": "summarize"},
				},
			},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		Mode:          ModeToken,
		TargetRatio:   0.5,
		CompressTypes: []string{"json"},
	}, DefaultRegistry(), nil)
	got := p.Run("openai", body)
	if got.Skipped {
		t.Fatalf("want Responses API body to engage; body=%s", got.Body)
	}
	if got.CompressedCount < 1 {
		t.Fatalf("expected compression; got=%+v", got)
	}

	var env map[string]json.RawMessage
	if err := json.Unmarshal(got.Body, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v; body=%s", err, got.Body)
	}
	var input []json.RawMessage
	if err := json.Unmarshal(env["input"], &input); err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}
	var foundOutput string
	for _, raw := range input {
		var item struct {
			Type   string `json:"type"`
			Output string `json:"output"`
		}
		_ = json.Unmarshal(raw, &item)
		if item.Type == "function_call_output" {
			foundOutput = item.Output
			break
		}
	}
	if foundOutput == "" {
		t.Fatalf("function_call_output missing after rewrite: %s", got.Body)
	}
	if len(foundOutput) >= len(bigJSON) {
		t.Errorf("Responses output not compressed: len=%d bigJSON=%d", len(foundOutput), len(bigJSON))
	}
}

func TestPipelineOpenAIResponses_CompressesWrappedFunctionCallOutput(t *testing.T) {
	bigJSON := buildBigJSON(80)
	wrapped := "Exit code: 0\nWall time: 0.3 seconds\nOutput:\n" + bigJSON + "\r\n"
	body := mustMarshal(t, map[string]any{
		"model": "gpt-5",
		"input": []any{
			map[string]any{
				"type": "message",
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": "inspect shell output"},
				},
			},
			map[string]any{
				"type":    "function_call_output",
				"call_id": "call_1",
				"output":  wrapped,
			},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		Mode:          ModeToken,
		TargetRatio:   0.7,
		CompressTypes: []string{"json", "text", "logs"},
	}, DefaultRegistry(), nil)
	got := p.Run("openai", body)
	if got.Skipped {
		t.Fatalf("want Responses API body to engage; body=%s", got.Body)
	}
	if got.CompressedCount < 1 {
		t.Fatalf("expected wrapped output compression; got=%+v", got)
	}

	var env map[string]json.RawMessage
	if err := json.Unmarshal(got.Body, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v; body=%s", err, got.Body)
	}
	var input []json.RawMessage
	if err := json.Unmarshal(env["input"], &input); err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}
	var foundOutput string
	for _, raw := range input {
		var item struct {
			Type   string `json:"type"`
			Output string `json:"output"`
		}
		_ = json.Unmarshal(raw, &item)
		if item.Type == "function_call_output" {
			foundOutput = item.Output
			break
		}
	}
	if !strings.Contains(foundOutput, "Output:\n") {
		t.Fatalf("wrapped output header lost: %q", foundOutput)
	}
	if !strings.Contains(foundOutput, "<string>") {
		t.Fatalf("wrapped JSON payload did not compress into schema: %q", foundOutput)
	}
	if len(foundOutput) >= len(wrapped) {
		t.Fatalf("wrapped output not smaller: len=%d wrapped=%d", len(foundOutput), len(wrapped))
	}
}

func TestPipelineOpenAIResponses_CompressesOutputWithoutRewritingContent(t *testing.T) {
	bigJSON := buildBigJSON(80)
	wrapped := "Exit code: 0\nWall time: 0.3 seconds\nOutput:\n" + bigJSON + "\n"
	body := mustMarshal(t, map[string]any{
		"model": "gpt-5",
		"input": []any{
			map[string]any{
				"type": "message",
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": "inspect shell output"},
				},
			},
			map[string]any{
				"type":    "function_call_output",
				"call_id": "call_1",
				"content": []any{
					map[string]any{"type": "output_text", "text": "shell metadata stays here"},
				},
				"output": wrapped,
			},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		Mode:          ModeToken,
		TargetRatio:   0.7,
		CompressTypes: []string{"json", "text", "logs"},
	}, DefaultRegistry(), nil)
	got := p.Run("openai", body)
	if got.Skipped {
		t.Fatalf("want Responses API body to engage; body=%s", got.Body)
	}
	if got.CompressedCount < 1 {
		t.Fatalf("expected output compression; got=%+v", got)
	}

	var env map[string]json.RawMessage
	if err := json.Unmarshal(got.Body, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v; body=%s", err, got.Body)
	}
	var input []json.RawMessage
	if err := json.Unmarshal(env["input"], &input); err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}
	for _, raw := range input {
		var item struct {
			Type    string              `json:"type"`
			Output  string              `json:"output"`
			Content []openaiContentPart `json:"content"`
		}
		_ = json.Unmarshal(raw, &item)
		if item.Type != "function_call_output" {
			continue
		}
		if item.Output == "" || len(item.Output) >= len(wrapped) {
			t.Fatalf("output not compressed: %q", item.Output)
		}
		if !strings.Contains(item.Output, "<string>") {
			t.Fatalf("wrapped payload did not compress: %q", item.Output)
		}
		if len(item.Content) != 1 || item.Content[0].Text != "shell metadata stays here" {
			t.Fatalf("content changed during output rewrite: %+v", item.Content)
		}
		return
	}
	t.Fatalf("function_call_output missing after rewrite: %s", got.Body)
}

func TestPipelineOpenAIResponses_PreservesFunctionCallProducerForOutput(t *testing.T) {
	bigJSON := buildBigJSON(80)
	body := mustMarshal(t, map[string]any{
		"model": "gpt-5",
		"input": []any{
			map[string]any{
				"type": "message",
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": "please inspect this"},
				},
			},
			map[string]any{
				"type":      "function_call",
				"id":        "call_1",
				"name":      "powershell",
				"arguments": `{"command":"Write-Output 1"}`,
			},
			map[string]any{
				"type":    "function_call_output",
				"call_id": "call_1",
				"output":  bigJSON,
			},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		Mode:          ModeToken,
		TargetRatio:   0.25,
		CompressTypes: []string{"json"},
	}, DefaultRegistry(), nil)
	got := p.Run("openai", body)
	if got.Skipped {
		t.Fatalf("want Responses API body to engage; body=%s", got.Body)
	}

	var env map[string]json.RawMessage
	if err := json.Unmarshal(got.Body, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v; body=%s", err, got.Body)
	}
	var input []json.RawMessage
	if err := json.Unmarshal(env["input"], &input); err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}
	foundCall := false
	foundOutput := false
	for _, raw := range input {
		var item struct {
			Type   string `json:"type"`
			ID     string `json:"id"`
			CallID string `json:"call_id"`
		}
		_ = json.Unmarshal(raw, &item)
		if item.Type == "function_call" && item.ID == "call_1" {
			foundCall = true
		}
		if item.Type == "function_call_output" && item.CallID == "call_1" {
			foundOutput = true
		}
	}
	if !foundCall {
		t.Fatalf("function_call producer missing after compression: %s", got.Body)
	}
	if !foundOutput {
		t.Fatalf("function_call_output missing after compression: %s", got.Body)
	}
}

func TestPipelineOpenAIResponses_PreservesUserTaskMessagesWhenDropping(t *testing.T) {
	body := mustMarshal(t, map[string]any{
		"model": "gpt-5",
		"input": []any{
			map[string]any{
				"type": "message",
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": "Continue the Observer work from the handoff file and focus on ChatGPT auth compression."},
				},
			},
			map[string]any{
				"type": "message",
				"role": "assistant",
				"content": []any{
					map[string]any{"type": "output_text", "text": strings.Repeat("observer progress update ", 120)},
				},
			},
			map[string]any{
				"type": "message",
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": "Now verify whether compression is actually helping or losing task context."},
				},
			},
			map[string]any{
				"type": "message",
				"role": "assistant",
				"content": []any{
					map[string]any{"type": "output_text", "text": strings.Repeat("verbose recovery summary ", 120)},
				},
			},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		Mode:          ModeToken,
		TargetRatio:   0.15,
		CompressTypes: []string{},
	}, DefaultRegistry(), nil)
	got := p.Run("openai", body)
	if got.Skipped {
		t.Fatalf("want Responses API body to engage; body=%s", got.Body)
	}
	if got.DroppedCount == 0 {
		t.Fatalf("expected at least one dropped message; got=%+v", got)
	}

	var env map[string]json.RawMessage
	if err := json.Unmarshal(got.Body, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v; body=%s", err, got.Body)
	}
	var input []json.RawMessage
	if err := json.Unmarshal(env["input"], &input); err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}

	userTexts := map[string]bool{}
	markerFound := false
	for _, raw := range input {
		var item struct {
			Type    string `json:"type"`
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		_ = json.Unmarshal(raw, &item)
		if item.Type == "message" && item.Role == "user" {
			for _, part := range item.Content {
				if part.Text != "" {
					userTexts[part.Text] = true
					if strings.Contains(part.Text, "messages compressed") {
						markerFound = true
					}
				}
			}
		}
	}

	if !userTexts["Continue the Observer work from the handoff file and focus on ChatGPT auth compression."] {
		t.Fatalf("initial user task message was dropped: %s", got.Body)
	}
	if !userTexts["Now verify whether compression is actually helping or losing task context."] {
		t.Fatalf("follow-up user task message was dropped: %s", got.Body)
	}
	if !markerFound {
		t.Fatalf("expected a compression marker after drops: %s", got.Body)
	}
}

func TestPipelineOpenAI_CacheModeDoesNotInjectCacheControl(t *testing.T) {
	// Chat Completions has no standardized cache marker today, so
	// cache mode must NOT annotate any OpenAI message even when the
	// split boundary is computed.
	body := mustMarshal(t, map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "user", "content": "alpha"},
			map[string]any{"role": "assistant", "content": "beta"},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:     true,
		Mode:        ModeCache,
		TargetRatio: 1.0,
	}, DefaultRegistry(), nil)
	got := p.Run("openai", body)
	if got.Skipped {
		t.Fatalf("want engage; body=%s", got.Body)
	}
	// findBreakpointIndex asserts at most one hit AND fails on
	// duplicates; no hits == -1 and passes here.
	if idx := findBreakpointIndex(t, got.Body); idx >= 0 {
		t.Errorf("OpenAI body should not carry cache_control; found at idx=%d body=%s", idx, got.Body)
	}
}

func TestPipelineOpenAI_PreservesToolCallsOnAssistantMessages(t *testing.T) {
	// Assistant messages that carry tool_calls must pass through
	// untouched (no content to compress). The serializer should not
	// mangle them.
	body := mustMarshal(t, map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "user", "content": "run it"},
			map[string]any{
				"role":    "assistant",
				"content": nil,
				"tool_calls": []any{
					map[string]any{
						"id":       "call_xyz",
						"type":     "function",
						"function": map[string]any{"name": "f", "arguments": "{}"},
					},
				},
			},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:     true,
		Mode:        ModeToken,
		TargetRatio: 1.0,
	}, DefaultRegistry(), nil)
	got := p.Run("openai", body)
	if got.Skipped {
		t.Fatalf("want engage; body=%s", got.Body)
	}
	if !strings.Contains(string(got.Body), `"call_xyz"`) {
		t.Errorf("tool_calls id dropped from assistant message: %s", got.Body)
	}
}

func TestPipelineCacheMode_SingleMessageAnnotated(t *testing.T) {
	body := mustMarshal(t, map[string]any{
		"model": "claude-opus-4-6",
		"messages": []any{
			map[string]any{"role": "user", "content": "alpha"},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:     true,
		Mode:        ModeCache,
		TargetRatio: 1.0,
	}, DefaultRegistry(), nil)
	got := p.Run("anthropic", body)
	if got.Skipped {
		t.Fatalf("want engage; body=%s", got.Body)
	}
	idx := findBreakpointIndex(t, got.Body)
	if idx != 0 {
		t.Fatalf("want breakpoint at index 0, got %d; body=%s", idx, got.Body)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}

// fakeSymbolLookup implements SymbolLookup for pipeline tests
// without pulling in internal/codeintel. Each field gates a specific
// behaviour so tests can mix-and-match (available + stale, available
// + fresh + empty, etc.).
type fakeSymbolLookup struct {
	available bool
	stale     bool
	symbols   []CompressorSymbol
	err       error
	// Per-call recording so tests can assert the pipeline made the
	// right call (e.g. didn't query when stale).
	staleCalls   []string
	symbolsCalls []string
}

func (f *fakeSymbolLookup) Available() bool { return f.available }

func (f *fakeSymbolLookup) Stale(absPath string) bool {
	f.staleCalls = append(f.staleCalls, absPath)
	return f.stale
}

func (f *fakeSymbolLookup) SymbolsInFile(_ context.Context, absPath string) ([]CompressorSymbol, error) {
	f.symbolsCalls = append(f.symbolsCalls, absPath)
	return f.symbols, f.err
}

// TestPipeline_HintsForFile_EmptyFilenameReturnsZeroHints pins the
// fast-path: callers with no filename get an empty CompressHints
// without any symbol-lookup round-trips.
func TestPipeline_HintsForFile_EmptyFilenameReturnsZeroHints(t *testing.T) {
	t.Parallel()
	fc := &fakeSymbolLookup{available: true, symbols: []CompressorSymbol{{Name: "X"}}}
	p := &Pipeline{symbolLookup: fc}
	hints := p.hintsForFile(context.Background(), "")
	if hints.Filename != "" || hints.Symbols != nil {
		t.Errorf("empty filename should return zero hints; got %+v", hints)
	}
	if len(fc.staleCalls) != 0 || len(fc.symbolsCalls) != 0 {
		t.Errorf("symbol lookup queried for empty filename: stale=%v symbols=%v", fc.staleCalls, fc.symbolsCalls)
	}
}

// TestPipeline_HintsForFile_NilSymbolLookupFilenameOnly pins the
// no-symbol-lookup-wired path: hints carry filename, no symbols, no
// crash.
func TestPipeline_HintsForFile_NilSymbolLookupFilenameOnly(t *testing.T) {
	t.Parallel()
	p := &Pipeline{} // symbolLookup == nil
	hints := p.hintsForFile(context.Background(), "x.go")
	if hints.Filename != "x.go" {
		t.Errorf("Filename: got %q want %q", hints.Filename, "x.go")
	}
	if hints.Symbols != nil {
		t.Errorf("Symbols should be nil without a symbol lookup; got %v", hints.Symbols)
	}
}

// TestPipeline_HintsForFile_UnavailableSymbolLookupFilenameOnly pins
// the lookup-wired-but-index-not-ready path: same shape as nil.
func TestPipeline_HintsForFile_UnavailableSymbolLookupFilenameOnly(t *testing.T) {
	t.Parallel()
	fc := &fakeSymbolLookup{available: false}
	p := &Pipeline{symbolLookup: fc}
	hints := p.hintsForFile(context.Background(), "x.go")
	if hints.Filename != "x.go" || hints.Symbols != nil {
		t.Errorf("unavailable symbol lookup: got %+v", hints)
	}
	if len(fc.symbolsCalls) != 0 {
		t.Errorf("unavailable client queried for symbols: %v", fc.symbolsCalls)
	}
}

// TestPipeline_HintsForFile_StaleSkipsSymbolFetch pins V7-13 Gap 3
// behaviour: when the index reports the file as newer than the
// index, the pipeline does NOT call SymbolsInFile.
func TestPipeline_HintsForFile_StaleSkipsSymbolFetch(t *testing.T) {
	t.Parallel()
	fc := &fakeSymbolLookup{available: true, stale: true, symbols: []CompressorSymbol{{Name: "X"}}}
	p := &Pipeline{symbolLookup: fc}
	hints := p.hintsForFile(context.Background(), "x.go")
	if hints.Filename != "x.go" || hints.Symbols != nil {
		t.Errorf("stale index: got %+v (must NOT pre-fetch)", hints)
	}
	if len(fc.symbolsCalls) != 0 {
		t.Errorf("Stale should suppress SymbolsInFile; got calls=%v", fc.symbolsCalls)
	}
}

// TestPipeline_HintsForFile_PreFetchPopulatesSymbols pins the happy
// path: lookup Available()+!Stale yields filename + symbols in
// the hint struct.
func TestPipeline_HintsForFile_PreFetchPopulatesSymbols(t *testing.T) {
	t.Parallel()
	want := []CompressorSymbol{
		{Name: "handleClick", Kind: "function", StartLine: 50},
		{Name: "Editor", Kind: "class", StartLine: 120},
	}
	fc := &fakeSymbolLookup{available: true, stale: false, symbols: want}
	p := &Pipeline{symbolLookup: fc}
	hints := p.hintsForFile(context.Background(), "Editor.tsx")
	if hints.Filename != "Editor.tsx" {
		t.Errorf("Filename: got %q want Editor.tsx", hints.Filename)
	}
	if len(hints.Symbols) != len(want) || hints.Symbols[0].Name != "handleClick" {
		t.Errorf("Symbols: got %v want %v", hints.Symbols, want)
	}
}

// TestPipeline_HintsForFile_SymbolFetchErrorDegrades pins that any
// error from SymbolsInFile falls back to filename-only — never
// surfaces upstream.
func TestPipeline_HintsForFile_SymbolFetchErrorDegrades(t *testing.T) {
	t.Parallel()
	fc := &fakeSymbolLookup{available: true, stale: false, err: errSentinel{}}
	p := &Pipeline{symbolLookup: fc}
	hints := p.hintsForFile(context.Background(), "x.go")
	if hints.Filename != "x.go" || hints.Symbols != nil {
		t.Errorf("symbol-fetch error should degrade to filename-only; got %+v", hints)
	}
}

// TestPipeline_WithSymbolLookup_Chainable pins the builder pattern: the
// method returns the same *Pipeline so callers can chain WithStash /
// WithSummarizerFactory / WithSymbolLookup in any order.
func TestPipeline_WithSymbolLookup_Chainable(t *testing.T) {
	t.Parallel()
	p := &Pipeline{}
	got := p.WithSymbolLookup(&fakeSymbolLookup{})
	if got != p {
		t.Errorf("WithSymbolLookup should return same pointer for chaining")
	}
	got2 := p.WithSymbolLookup(nil) // nil-tolerant
	if got2 != p {
		t.Errorf("WithSymbolLookup(nil) should also chain cleanly")
	}
}

// errSentinel is a stand-in error type so tests don't need to import
// errors.New.
type errSentinel struct{}

func (errSentinel) Error() string { return "test sentinel" }
