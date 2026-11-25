package conversation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/stash"
)

// TestCompressToolResults_SkipsMCPToolResults pins the load-bearing
// correctness fix surfaced 2026-05-08 dogfood: an MCP tool_result
// (e.g. mcp__observer__search_past_outputs) returning structured
// JSON whose VALUES are the answer (action_ids, ranks, excerpts)
// must NOT go through JSON compression — replacing the scalars with
// type sentinels (`<number>`, `<string>`) corrupts the response and
// the model sees "placeholders only" rather than real data.
//
// The same logic guards stashLargeBodies — `retrieve_stashed`
// returning content stashed-and-replaced-with-marker would be
// catastrophic; same hazard for any MCP tool whose response IS
// the answer.
func TestCompressToolResults_SkipsMCPToolResults(t *testing.T) {
	// Build an Anthropic envelope where the most-recent user message
	// carries a tool_result for a mcp__observer__search_past_outputs
	// call. The body is a JSON document large enough that
	// JSONCompressor would otherwise fire on it (lots of scalars to
	// replace with type sentinels).
	bigSearchResp := `{"query":"app.set","count":10,"hits":[`
	for i := 0; i < 10; i++ {
		if i > 0 {
			bigSearchResp += ","
		}
		bigSearchResp += `{"action_id":` + itoa(1000+i) +
			`,"tool_name":"Bash","target":"grep app.set","excerpt":"app.set('foo','bar')","rank":-` + itoa(i) + `.5}`
	}
	bigSearchResp += `]}`

	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{
						"type":  "tool_use",
						"id":    "tu_search",
						"name":  "mcp__observer__search_past_outputs",
						"input": map[string]any{"query": "app.set"},
					},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":        "tool_result",
						"tool_use_id": "tu_search",
						"content":     bigSearchResp,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	st, err := stash.New(stash.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("stash.New: %v", err)
	}
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New()).WithStash(st, 1024)

	got := p.Run("anthropic", body)
	for _, ev := range got.Events {
		switch ev.Mechanism {
		case "json", "code", "logs", "stash":
			t.Errorf("MCP tool_result was compressed via %q (would corrupt query data); event=%+v", ev.Mechanism, ev)
		}
	}
	// Verify the original action_id values survive in the output.
	// The tool_result content is a string-encoded JSON nested inside
	// the outer envelope — so the inner JSON is escape-encoded
	// (`\"action_id\":1000`) rather than `"action_id":1000`. Both
	// forms are checked against — the value `1000` must appear; the
	// `<number>` sentinel must NOT.
	bodyStr := string(got.Body)
	if !strings.Contains(bodyStr, `1000`) || !strings.Contains(bodyStr, `1009`) {
		t.Errorf("action_id values stripped from MCP response; output=%s", bodyStr)
	}
	if strings.Contains(bodyStr, `<number>`) {
		t.Errorf("JSON compression scalars leaked into MCP response; output=%s", bodyStr)
	}
	if strings.Contains(bodyStr, `<string>`) {
		t.Errorf("JSON compression scalars leaked into MCP response; output=%s", bodyStr)
	}
}

// TestPipelineCompressesParallelToolResults pins the fix for the
// long-standing bug where a message carrying multiple tool_result
// blocks (Claude Code's parallel-tool-call pattern: Read+Bash+Read in
// one assistant turn produces a single user message with N
// tool_results) had Enforce's flat-text compression silently discarded
// by the serializer. The new per-block pre-compression pass shrinks
// each block independently and the rewriter now iterates.
func TestPipelineCompressesParallelToolResults(t *testing.T) {
	bigJSON := `{"records":[`
	for i := 0; i < 60; i++ {
		if i > 0 {
			bigJSON += ","
		}
		bigJSON += `{"id":` + itoa(i) + `,"name":"user-`
		for j := 0; j < 20; j++ {
			bigJSON += "x"
		}
		bigJSON += `"}`
	}
	bigJSON += `]}`

	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{"role": "user", "content": "kick off the multi-tool turn"},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": bigJSON},
					map[string]any{"type": "tool_result", "tool_use_id": "t2", "content": bigJSON},
					map[string]any{"type": "tool_result", "tool_use_id": "t3", "content": "tiny tail"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json"},
	}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body)

	if got.Skipped {
		t.Fatalf("pipeline skipped: %+v", got)
	}
	// Expect at least 2 compression events (the two large JSON blocks).
	jsonEvents := 0
	for _, ev := range got.Events {
		if ev.Mechanism == "json" {
			jsonEvents++
		}
	}
	if jsonEvents < 2 {
		t.Errorf("want ≥2 json compression events for parallel tool_results, got %d. Events=%+v", jsonEvents, got.Events)
	}
	if got.CompressedBytes >= got.OriginalBytes {
		t.Errorf("CompressedBytes %d should be < OriginalBytes %d", got.CompressedBytes, got.OriginalBytes)
	}

	// All three blocks must remain in the output (no drops in this
	// scenario — target_ratio = 0.95 is loose).
	var env map[string]any
	if err := json.Unmarshal(got.Body, &env); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	msgs, _ := env["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages, got %d", len(msgs))
	}
	second := msgs[1].(map[string]any)
	content, _ := second["content"].([]any)
	if len(content) != 3 {
		t.Fatalf("want 3 tool_result blocks preserved, got %d", len(content))
	}
	// First two blocks should now contain the JSON schema; the third
	// (small) one should be untouched.
	for i := 0; i < 2; i++ {
		blk := content[i].(map[string]any)
		body, _ := blk["content"].(string)
		if !strings.Contains(body, "<string>") && !strings.Contains(body, "<number>") {
			t.Errorf("block[%d] not compressed: %q", i, body)
		}
	}
	tail := content[2].(map[string]any)
	tailBody, _ := tail["content"].(string)
	if tailBody != "tiny tail" {
		t.Errorf("tail block mutated: got %q want %q", tailBody, "tiny tail")
	}
}

// TestResolveToolUseInputs_FilenamePlumbing pins that producing
// tool_use.input.file_path flows through to em.resultFilenames so
// types.Detect gets an extension hint instead of empty filename.
func TestResolveToolUseInputs_FilenamePlumbing(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"messages": []any{
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{
						"type":  "tool_use",
						"id":    "tu_read1",
						"name":  "Read",
						"input": map[string]any{"file_path": "/repo/lib/handler.go"},
					},
					map[string]any{
						"type":  "tool_use",
						"id":    "tu_bash1",
						"name":  "Bash",
						"input": map[string]any{"command": "ls"},
					},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "tu_read1", "content": "package handler"},
					map[string]any{"type": "tool_result", "tool_use_id": "tu_bash1", "content": "file1\nfile2"},
					map[string]any{"type": "tool_result", "tool_use_id": "tu_unknown", "content": "orphan"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, ext, ok := anthropicExtract(body)
	if !ok {
		t.Fatalf("extract failed")
	}
	em := ext[1] // user message with tool_results
	if len(em.resultFilenames) != 3 {
		t.Fatalf("want 3 resultFilenames, got %d", len(em.resultFilenames))
	}
	if em.resultFilenames[0] != "/repo/lib/handler.go" {
		t.Errorf("Read tool_result filename: got %q want /repo/lib/handler.go", em.resultFilenames[0])
	}
	if em.resultFilenames[1] != "" {
		t.Errorf("Bash tool_result filename: got %q want empty", em.resultFilenames[1])
	}
	if em.resultFilenames[2] != "" {
		t.Errorf("orphan tool_result filename: got %q want empty", em.resultFilenames[2])
	}
	if em.resultToolNames[0] != "Read" {
		t.Errorf("Read tool name: got %q", em.resultToolNames[0])
	}
	if em.resultToolNames[1] != "Bash" {
		t.Errorf("Bash tool name: got %q", em.resultToolNames[1])
	}
}

// stripCacheControl walks a parsed Anthropic body and removes
// cache_control fields from every messages-level content block.
// Anthropic's prefix-cache lookup ignores cache_control (proven
// empirically: identical text content with different cache_control
// markers still cache-hits), so cross-turn invariance comparisons must
// strip these before diffing.
func stripCacheControl(env map[string]any) {
	msgs, ok := env["messages"].([]any)
	if !ok {
		return
	}
	for _, mAny := range msgs {
		m, ok := mAny.(map[string]any)
		if !ok {
			continue
		}
		content, ok := m["content"].([]any)
		if !ok {
			continue
		}
		for _, bAny := range content {
			b, ok := bAny.(map[string]any)
			if !ok {
				continue
			}
			delete(b, "cache_control")
		}
	}
}

// TestPipelineCacheAware_Determinism verifies the load-bearing
// invariant for cache-aware compression: running the pipeline twice on
// the same input must produce byte-identical output. If this fails the
// per-type compressors or scrubber have hidden state and cache-aware
// mode cannot deliver cache hits across turns.
func TestPipelineCacheAware_Determinism(t *testing.T) {
	body := buildClaudeCodeShapedBody(t)
	p := newCacheAwarePipeline()
	out1 := p.Run("anthropic", body)
	out2 := p.Run("anthropic", body)
	if out1.Skipped || out2.Skipped {
		t.Fatalf("cache-aware pipeline skipped: out1=%+v out2=%+v", out1, out2)
	}
	if string(out1.Body) != string(out2.Body) {
		t.Fatalf("cache-aware compression is not deterministic — same input produced different bytes\n out1=%s\n out2=%s", out1.Body, out2.Body)
	}
}

// TestPipelineCacheAware_CrossTurnInvariance verifies the actual
// cache-hit predicate: when turn N+1's body extends turn N's body by
// adding messages, the prefix (messages already present in turn N)
// must compress to text-identical bytes (cache_control field allowed
// to differ — Anthropic strips it for cache lookup). This is what
// makes cache_creation tokens DROP turn-over-turn instead of paying
// to re-cache the whole prefix.
func TestPipelineCacheAware_CrossTurnInvariance(t *testing.T) {
	turn1 := buildClaudeCodeShapedBody(t) // marker on messages[1].content[2]
	turn2 := extendBodyOneMoreTurn(t, turn1)
	p := newCacheAwarePipeline()
	out1 := p.Run("anthropic", turn1)
	out2 := p.Run("anthropic", turn2)
	if out1.Skipped || out2.Skipped {
		t.Fatalf("pipeline skipped: out1=%+v out2=%+v", out1, out2)
	}

	var env1, env2 map[string]any
	if err := json.Unmarshal(out1.Body, &env1); err != nil {
		t.Fatalf("unmarshal out1: %v", err)
	}
	if err := json.Unmarshal(out2.Body, &env2); err != nil {
		t.Fatalf("unmarshal out2: %v", err)
	}
	stripCacheControl(env1)
	stripCacheControl(env2)

	msgs1 := env1["messages"].([]any)
	msgs2 := env2["messages"].([]any)
	if len(msgs2) <= len(msgs1) {
		t.Fatalf("turn2 should have more messages than turn1: turn1=%d turn2=%d", len(msgs1), len(msgs2))
	}
	for i := 0; i < len(msgs1); i++ {
		raw1, _ := json.Marshal(msgs1[i])
		raw2, _ := json.Marshal(msgs2[i])
		if string(raw1) != string(raw2) {
			t.Errorf("messages[%d] differs across turns (post-cache-control-strip):\n turn1: %s\n turn2: %s", i, raw1, raw2)
		}
	}
}

// TestPipelineCacheAware_MarkerRollPreservesPriorBytes is the named
// regression pin for the marker-roll cache-break bug. The tool_result
// block that carries the SDK's cache_control marker in turn N loses it in
// turn N+1 (the SDK rolls the marker to the new last block). That block's
// on-the-wire bytes must be identical across the two turns (cache_control
// aside), or Anthropic's prefix-cache lookup misses from that block onward
// and bills cache_creation on the whole tail. Before the fix the block was
// left uncompressed while it held the marker and compressed once it didn't
// — two different byte representations of the same logical message.
func TestPipelineCacheAware_MarkerRollPreservesPriorBytes(t *testing.T) {
	turn1 := buildClaudeCodeShapedBody(t) // marker on messages[1].content[2]
	turn2 := extendBodyOneMoreTurn(t, turn1)
	p := newCacheAwarePipeline()
	out1 := p.Run("anthropic", turn1)
	out2 := p.Run("anthropic", turn2)
	if out1.Skipped || out2.Skipped {
		t.Fatalf("pipeline skipped: out1=%+v out2=%+v", out1, out2)
	}

	var env1, env2 map[string]any
	if err := json.Unmarshal(out1.Body, &env1); err != nil {
		t.Fatalf("unmarshal out1: %v", err)
	}
	if err := json.Unmarshal(out2.Body, &env2); err != nil {
		t.Fatalf("unmarshal out2: %v", err)
	}
	stripCacheControl(env1)
	stripCacheControl(env2)

	block1 := markerBlock(t, env1)
	block2 := markerBlock(t, env2)
	if block1 != block2 {
		t.Errorf("marker block (messages[1].content[2]) bytes differ across turns — Anthropic's prefix cache breaks here:\n turn1: %s\n turn2: %s", block1, block2)
	}
}

// markerBlock returns the JSON serialisation of messages[1].content[2] —
// the tool_result block that carried the cache_control marker in turn 1 of
// buildClaudeCodeShapedBody.
func markerBlock(t *testing.T, env map[string]any) string {
	t.Helper()
	msgs := env["messages"].([]any)
	content := msgs[1].(map[string]any)["content"].([]any)
	raw, err := json.Marshal(content[2])
	if err != nil {
		t.Fatalf("marshal marker block: %v", err)
	}
	return string(raw)
}

// TestPipelineCacheAware_RealClaudeCodeShapes pins the pipeline produces
// stable, deterministic, cross-turn-invariant output on the actual
// shapes Claude Code emits — line-numbered Read tool_result, bare Bash
// output (file listing), and unified diff. Each shape exercises a
// different detection path; if any one is non-deterministic the
// cross-turn cache predicate fails for that shape.
func TestPipelineCacheAware_RealClaudeCodeShapes(t *testing.T) {
	// Line-numbered package.json (Read tool envelope)
	readJSON := "1\t{\n2\t  \"name\": \"express\",\n3\t  \"version\": \"5.2.1\",\n4\t  \"dependencies\": {\n5\t    \"a\": \"1\",\n6\t    \"b\": \"2\",\n7\t    \"c\": \"3\",\n8\t    \"d\": \"4\",\n9\t    \"e\": \"5\"\n10\t  }\n11\t}"
	// Bash ls -la output
	bashOutput := "total 192\ndrwxr-xr-x  6 user group  4096 May  7 11:00 .\ndrwxrwxrwt 33 root root  20480 May  7 12:00 ..\n-rw-r--r--  1 user group   1024 May  7 09:00 file.txt\n-rw-r--r--  1 user group    512 May  7 08:00 other.txt\n-rw-r--r--  1 user group    256 May  7 07:00 third.txt"

	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{"type": "tool_use", "id": "tu_read", "name": "Read", "input": map[string]any{"file_path": "package.json"}},
					map[string]any{"type": "tool_use", "id": "tu_bash", "name": "Bash", "input": map[string]any{"command": "ls -la"}},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "tu_read", "content": readJSON},
					map[string]any{
						"type":          "tool_result",
						"tool_use_id":   "tu_bash",
						"content":       bashOutput,
						"cache_control": map[string]string{"type": "ephemeral"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	p := newCacheAwarePipeline()

	// Determinism: same input twice → byte-identical output.
	out1 := p.Run("anthropic", body)
	out2 := p.Run("anthropic", body)
	if out1.Skipped || out2.Skipped {
		t.Fatalf("pipeline skipped: out1=%+v out2=%+v", out1, out2)
	}
	if string(out1.Body) != string(out2.Body) {
		t.Fatalf("non-deterministic on real Claude Code shapes\nout1: %s\nout2: %s", out1.Body, out2.Body)
	}

	// Compression DID fire on at least one path (proves the new
	// detectors are reaching the compressors).
	if len(out1.Events) == 0 {
		t.Errorf("expected at least one compression event on Claude Code shapes; got none")
	}
	t.Logf("events fired: %d", len(out1.Events))
	for _, ev := range out1.Events {
		t.Logf("  %s: %d → %d (saved %d)", ev.Mechanism, ev.OriginalBytes, ev.CompressedBytes, ev.OriginalBytes-ev.CompressedBytes)
	}
}

// TestPipeline_CodeCompressionFiresOnReadToolResult pins the v1.4.40
// integration property: a Claude-Code-shaped Anthropic body with a
// .go-file Read tool_result must produce at least one `code`
// compression event when "code" is in CompressTypes, the output bytes
// must shrink, and the result must remain valid JSON.
//
// The body intentionally includes trailing whitespace, blank-line
// padding, a multi-line license header, and a run of identical
// generated lines so all four CodeCompressor rules have something to
// fire on.
func TestPipeline_CodeCompressionFiresOnReadToolResult(t *testing.T) {
	var src strings.Builder
	src.WriteString("// Copyright 2026 Foo Bar.   \n")
	src.WriteString("// All rights reserved.\n")
	src.WriteString("//\n")
	src.WriteString("// Licensed under Apache 2.0.\n")
	src.WriteString("// See LICENSE for details.\n")
	src.WriteString("// Banner line six.\n")
	src.WriteString("\n")
	src.WriteString("package main\n")
	src.WriteString("\n")
	src.WriteString("\n")
	src.WriteString("\n")
	src.WriteString("\n")
	src.WriteString("import (\t\t\n")
	src.WriteString("\t\"fmt\"   \n")
	src.WriteString("\t\"net/http\"\n")
	src.WriteString(")\n")
	src.WriteString("\n")
	src.WriteString("var _ = []Foo{\n")
	for i := 0; i < 80; i++ {
		src.WriteString("\t{Name: \"x\"},  \n")
	}
	src.WriteString("}\n")
	src.WriteString("\n")
	src.WriteString("func main() {  \n")
	for i := 0; i < 50; i++ {
		src.WriteString("\tfmt.Println(\"hello\")\n")
	}
	src.WriteString("}\n")
	srcBody := src.String()

	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{
						"type":  "tool_use",
						"id":    "tu_read_go",
						"name":  "Read",
						"input": map[string]any{"file_path": "/repo/cmd/main.go"},
					},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":        "tool_result",
						"tool_use_id": "tu_read_go",
						"content":     srcBody,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body)

	if got.Skipped {
		t.Fatalf("pipeline skipped on a body with a 130+-line .go Read tool_result: %+v", got)
	}
	codeEvents := 0
	for _, ev := range got.Events {
		if ev.Mechanism == "code" {
			codeEvents++
		}
	}
	if codeEvents < 1 {
		t.Errorf("want ≥1 code compression event, got %d. Events=%+v", codeEvents, got.Events)
	}
	if got.CompressedBytes >= got.OriginalBytes {
		t.Errorf("CompressedBytes %d should be < OriginalBytes %d", got.CompressedBytes, got.OriginalBytes)
	}
	var env map[string]any
	if err := json.Unmarshal(got.Body, &env); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

// TestPipeline_CodeCompressionRespectsAllowList is the regression guard
// against accidentally flipping the default. With code excluded from
// CompressTypes (the v1.4.39 conservative default), no `code` events
// should fire even on a Code-shaped body.
func TestPipeline_CodeCompressionRespectsAllowList(t *testing.T) {
	srcBody := strings.Repeat("\tfmt.Println(\"x\")\n", 80) + "func a() {}\nfunc b() {}\n"

	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{
						"type":  "tool_use",
						"id":    "tu_read",
						"name":  "Read",
						"input": map[string]any{"file_path": "/repo/x.go"},
					},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":        "tool_result",
						"tool_use_id": "tu_read",
						"content":     srcBody,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs"}, // explicitly excludes code
	}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body)
	for _, ev := range got.Events {
		if ev.Mechanism == "code" {
			t.Errorf("code event fired despite allow-list excluding it: %+v", ev)
		}
	}
}

// TestCompressToolDefinitions_StripsExamplesAndTrimsDescription pins
// the v1.4.40 sub-feature 2 behaviour: top-level description trims to
// its first 2 paragraphs, deep `examples` removal from input_schema,
// while every other field (name, schema type/properties/required/enum)
// remains bytewise unchanged.
func TestCompressToolDefinitions_StripsExamplesAndTrimsDescription(t *testing.T) {
	envelope := map[string]json.RawMessage{
		"tools": json.RawMessage(`[{"name":"read_file","description":"Read a file from disk.\n\nReturns its full contents.\n\nThis is a third paragraph that should be trimmed.\n\nAnd a fourth.","input_schema":{"type":"object","properties":{"path":{"type":"string","description":"Absolute path to the file.","examples":["/home/user/foo.txt","/etc/hosts"]},"max_bytes":{"type":"integer","examples":[1024,4096]}},"required":["path"],"examples":[{"path":"/etc/hosts"}]}}]`),
	}
	originalSize := len(envelope["tools"])

	events := compressToolDefinitions(envelope)
	if len(events) == 0 {
		t.Fatalf("expected at least one tool-compression event, got 0")
	}
	if events[0].Mechanism != "tools" {
		t.Errorf("event mechanism: got %q, want %q", events[0].Mechanism, "tools")
	}

	var tools []map[string]any
	if err := json.Unmarshal(envelope["tools"], &tools); err != nil {
		t.Fatalf("post-compress tools didn't unmarshal: %v\nbody: %s", err, envelope["tools"])
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	tool := tools[0]

	if tool["name"] != "read_file" {
		t.Errorf("name mutated: got %v", tool["name"])
	}

	desc, _ := tool["description"].(string)
	if strings.Contains(desc, "third paragraph") {
		t.Errorf("third paragraph survived: %q", desc)
	}
	if strings.Contains(desc, "fourth") {
		t.Errorf("fourth paragraph survived: %q", desc)
	}
	if !strings.Contains(desc, "Read a file from disk.") || !strings.Contains(desc, "Returns its full contents.") {
		t.Errorf("first two paragraphs missing: %q", desc)
	}

	schema, _ := tool["input_schema"].(map[string]any)
	if schema == nil {
		t.Fatal("input_schema missing post-compress")
	}
	if _, ok := schema["examples"]; ok {
		t.Errorf("top-level schema examples survived: %+v", schema)
	}
	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		t.Fatal("properties dropped")
	}
	for paramName, raw := range props {
		param, _ := raw.(map[string]any)
		if param == nil {
			t.Errorf("property %q became non-object", paramName)
			continue
		}
		if _, ok := param["examples"]; ok {
			t.Errorf("property %q examples survived: %+v", paramName, param)
		}
		if param["type"] == nil {
			t.Errorf("property %q lost its type", paramName)
		}
	}
	pathParam := props["path"].(map[string]any)
	if pathParam["description"] != "Absolute path to the file." {
		t.Errorf("nested per-property description was mutated (forbidden): %v", pathParam["description"])
	}
	if required, ok := schema["required"].([]any); !ok || len(required) != 1 || required[0] != "path" {
		t.Errorf("required field mutated: %v", schema["required"])
	}

	if len(envelope["tools"]) >= originalSize {
		t.Errorf("compressed tools didn't shrink: original=%d new=%d", originalSize, len(envelope["tools"]))
	}
}

// TestCompressToolDefinitions_Idempotent pins idempotence: running
// compressToolDefinitions twice on the same envelope produces
// byte-identical output the second time (no further mutation).
func TestCompressToolDefinitions_Idempotent(t *testing.T) {
	build := func() map[string]json.RawMessage {
		return map[string]json.RawMessage{
			"tools": json.RawMessage(`[{"name":"x","description":"P1.\n\nP2.\n\nP3.","input_schema":{"type":"object","examples":[1,2]}}]`),
		}
	}
	envelope := build()
	compressToolDefinitions(envelope)
	once := append([]byte(nil), envelope["tools"]...)
	events := compressToolDefinitions(envelope)
	if len(events) != 0 {
		t.Errorf("idempotent run produced events: %+v", events)
	}
	if string(envelope["tools"]) != string(once) {
		t.Errorf("idempotent run mutated bytes:\n once=%s\n twice=%s", once, envelope["tools"])
	}
}

// TestCompressToolDefinitions_BodyHashStableAcrossCalls pins the
// V7-18 fix: the tools-mechanism Event must populate BodyHash so
// CountUniqueCompressions (v1.7.12) deduplicates re-emissions across
// turns. Pre-v1.7.18 the field was empty, inflating per-turn comp
// counts by a factor equal to the conversation length on OpenAI
// sessions (codex re-sends tool schemas every turn).
func TestCompressToolDefinitions_BodyHashStableAcrossCalls(t *testing.T) {
	build := func() map[string]json.RawMessage {
		return map[string]json.RawMessage{
			"tools": json.RawMessage(`[{"name":"read_file","description":"P1.\n\nP2.\n\nP3.","input_schema":{"type":"object","examples":[1,2]}}]`),
		}
	}
	env1 := build()
	ev1 := compressToolDefinitions(env1)
	if len(ev1) != 1 {
		t.Fatalf("first call: expected 1 event, got %d", len(ev1))
	}
	if ev1[0].BodyHash == "" {
		t.Fatalf("first call: BodyHash unset — V7-18 wiring regression")
	}
	env2 := build()
	ev2 := compressToolDefinitions(env2)
	if len(ev2) != 1 {
		t.Fatalf("second call: expected 1 event, got %d", len(ev2))
	}
	if ev1[0].BodyHash != ev2[0].BodyHash {
		t.Errorf("BodyHash drift across identical inputs:\n call1=%s\n call2=%s",
			ev1[0].BodyHash, ev2[0].BodyHash)
	}
}

// TestCompressToolDefinitions_NoOp covers the safe paths: missing
// tools, empty array, malformed JSON, descriptions short enough to
// keep, and schemas without `examples`. Each must be a clean no-op
// with zero events.
func TestCompressToolDefinitions_NoOp(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]json.RawMessage
	}{
		{"missing-tools", map[string]json.RawMessage{}},
		{"empty-array", map[string]json.RawMessage{"tools": json.RawMessage(`[]`)}},
		{"malformed", map[string]json.RawMessage{"tools": json.RawMessage(`{not json`)}},
		{"short-desc-no-examples", map[string]json.RawMessage{"tools": json.RawMessage(`[{"name":"x","description":"only one paragraph","input_schema":{"type":"object","properties":{"a":{"type":"string"}}}}]`)}},
		{"two-paragraph-desc", map[string]json.RawMessage{"tools": json.RawMessage(`[{"name":"x","description":"P1.\n\nP2.","input_schema":{"type":"object"}}]`)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := ""
			if v, ok := tc.env["tools"]; ok {
				before = string(v)
			}
			events := compressToolDefinitions(tc.env)
			if len(events) != 0 {
				t.Errorf("expected no events on no-op input, got %+v", events)
			}
			after := ""
			if v, ok := tc.env["tools"]; ok {
				after = string(v)
			}
			if before != after {
				t.Errorf("envelope mutated on no-op:\n before=%s\n after =%s", before, after)
			}
		})
	}
}

// TestCompressToolDefinitions_NeverTouchesParameterSchemaContract is
// the explicit pin that the `parameters` / `properties` / `required`
// / `enum` / nested descriptions are never mutated. This is the
// load-bearing safety property — touching parameter schemas changes
// the model's tool-use behaviour and re-introduces a regression
// equivalent to v1.4.38's turn-count loss for tool calls.
func TestCompressToolDefinitions_NeverTouchesParameterSchemaContract(t *testing.T) {
	envelope := map[string]json.RawMessage{
		"tools": json.RawMessage(`[{"name":"complex","description":"P1.\n\nP2.\n\nP3.","input_schema":{"type":"object","properties":{"mode":{"type":"string","description":"Mode of operation","enum":["fast","slow"]},"count":{"type":"integer","description":"How many","minimum":1,"maximum":100}},"required":["mode","count"]}}]`),
	}
	compressToolDefinitions(envelope)

	var tools []map[string]any
	if err := json.Unmarshal(envelope["tools"], &tools); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tool := tools[0]
	schema := tool["input_schema"].(map[string]any)
	props := schema["properties"].(map[string]any)

	mode := props["mode"].(map[string]any)
	if mode["type"] != "string" {
		t.Errorf("mode.type mutated: %v", mode["type"])
	}
	if mode["description"] != "Mode of operation" {
		t.Errorf("mode.description mutated: %v", mode["description"])
	}
	enum, _ := mode["enum"].([]any)
	if len(enum) != 2 || enum[0] != "fast" || enum[1] != "slow" {
		t.Errorf("mode.enum mutated: %v", enum)
	}

	count := props["count"].(map[string]any)
	if count["minimum"].(float64) != 1 || count["maximum"].(float64) != 100 {
		t.Errorf("count constraints mutated: %v", count)
	}

	required, _ := schema["required"].([]any)
	if len(required) != 2 || required[0] != "mode" || required[1] != "count" {
		t.Errorf("required mutated: %v", required)
	}
}

// TestPipeline_ReadCache_FiresOnDuplicateRead pins the C16 read-cache
// auto-substitution: when the same Read result for the same file
// appears twice in the same Run call (because the model re-Read it in
// turn N+1, so turn N's history + turn N+1's new Read both appear in
// the request body), the second occurrence is replaced with a
// deterministic marker and the first stays bytewise unchanged.
func TestPipeline_ReadCache_FiresOnDuplicateRead(t *testing.T) {
	src := strings.Repeat("package main\n\nfunc main() { /* hello */ }\n", 5)
	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{"type": "tool_use", "id": "tu_r1", "name": "Read", "input": map[string]any{"file_path": "/repo/main.go"}},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "tu_r1", "content": src},
				},
			},
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{"type": "tool_use", "id": "tu_r2", "name": "Read", "input": map[string]any{"file_path": "/repo/main.go"}},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "tu_r2", "content": src},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New())
	got := p.RunInSession("anthropic", body, "session-abc")
	if got.Skipped {
		t.Fatalf("pipeline skipped: %+v", got)
	}
	readCacheEvents := 0
	for _, ev := range got.Events {
		if ev.Mechanism == "read_cache" {
			readCacheEvents++
		}
	}
	if readCacheEvents != 1 {
		t.Errorf("expected exactly 1 read_cache event (one duplicate), got %d. Events=%+v", readCacheEvents, got.Events)
	}
	if !strings.Contains(string(got.Body), "[file /repo/main.go unchanged since earlier in this turn") {
		t.Errorf("read_cache marker missing: %s", got.Body)
	}
}

// TestPipeline_ReadCache_DifferentHashDoesNotCollapse pins the
// safety property: when the same file path appears twice but the
// content differs (the file was edited between the two Reads), C16
// MUST NOT collapse — the model needs to see both states.
func TestPipeline_ReadCache_DifferentHashDoesNotCollapse(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "tool_use", "id": "tu_r1", "name": "Read", "input": map[string]any{"file_path": "/repo/foo.go"}},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "tu_r1", "content": "package main\nfunc v1() {}\n"},
					map[string]any{"type": "tool_result", "tool_use_id": "tu_r2", "content": "package main\nfunc v2() {}\n"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Need to also wire tu_r2 to /repo/foo.go via tool_use — extend.
	body2, _ := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{"type": "tool_use", "id": "tu_r1", "name": "Read", "input": map[string]any{"file_path": "/repo/foo.go"}},
					map[string]any{"type": "tool_use", "id": "tu_r2", "name": "Read", "input": map[string]any{"file_path": "/repo/foo.go"}},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "tu_r1", "content": "package main\nfunc v1() {}\n"},
					map[string]any{"type": "tool_result", "tool_use_id": "tu_r2", "content": "package main\nfunc v2() {}\n"},
				},
			},
		},
	})
	_ = body
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New())
	got := p.RunInSession("anthropic", body2, "session-abc")
	for _, ev := range got.Events {
		if ev.Mechanism == "read_cache" {
			t.Errorf("read_cache fired despite hash difference: %+v", ev)
		}
	}
}

// TestPipeline_ReadCache_DisabledWithoutSession pins the gate:
// without a session_id (legacy Run() callers, tests that don't pass
// one), C16 never fires.
func TestPipeline_ReadCache_DisabledWithoutSession(t *testing.T) {
	src := "same content\nrepeated\nin two reads\n"
	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{"type": "tool_use", "id": "tu_r1", "name": "Read", "input": map[string]any{"file_path": "/x"}},
					map[string]any{"type": "tool_use", "id": "tu_r2", "name": "Read", "input": map[string]any{"file_path": "/x"}},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "tu_r1", "content": src},
					map[string]any{"type": "tool_result", "tool_use_id": "tu_r2", "content": src},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body) // empty sessionID via Run()
	for _, ev := range got.Events {
		if ev.Mechanism == "read_cache" {
			t.Errorf("read_cache fired without session_id: %+v", ev)
		}
	}
}

// TestPipeline_ReadCache_NotFiredOnNonReadTool pins that C16 only
// applies to Read tool_results — Bash, Grep, etc. with the same
// command output don't get the marker (the tool's output isn't
// content-stable across re-runs).
func TestPipeline_ReadCache_NotFiredOnNonReadTool(t *testing.T) {
	out := "build output\nhello\n"
	body, _ := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{"type": "tool_use", "id": "tu_b1", "name": "Bash", "input": map[string]any{"command": "make build"}},
					map[string]any{"type": "tool_use", "id": "tu_b2", "name": "Bash", "input": map[string]any{"command": "make build"}},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "tu_b1", "content": out},
					map[string]any{"type": "tool_result", "tool_use_id": "tu_b2", "content": out},
				},
			},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New())
	got := p.RunInSession("anthropic", body, "session-xyz")
	for _, ev := range got.Events {
		if ev.Mechanism == "read_cache" {
			t.Errorf("read_cache fired on Bash tool: %+v", ev)
		}
	}
}

// TestPipeline_StashFires pins the v1.4.41 / Tier 1 / G31 (CCR)
// integration property: when a tool_result body is over the stash
// threshold even after per-type compression, it gets written to the
// stash and replaced inline with a deterministic marker. The marker
// must contain the sha and the size hint so the model can decide
// whether to retrieve.
func TestPipeline_StashFires(t *testing.T) {
	st, err := stash.New(stash.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("stash.New: %v", err)
	}

	// 16 KB body of unique-ish content so per-type compression can't
	// shrink it below the 8 KB threshold via dedup.
	var sb strings.Builder
	for i := 0; i < 1024; i++ {
		sb.WriteString(fmt.Sprintf("unique-line-%04d-with-content\n", i))
	}
	bigBody := sb.String()

	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{
						"type":  "tool_use",
						"id":    "tu_bash",
						"name":  "Bash",
						"input": map[string]any{"command": "cat huge.log"},
					},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":        "tool_result",
						"tool_use_id": "tu_bash",
						"content":     bigBody,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New()).WithStash(st, 8192)
	got := p.Run("anthropic", body)

	if got.Skipped {
		t.Fatalf("pipeline skipped on body with > threshold tool_result: %+v", got)
	}
	stashEvents := 0
	for _, ev := range got.Events {
		if ev.Mechanism == "stash" {
			stashEvents++
		}
	}
	if stashEvents != 1 {
		t.Errorf("expected exactly 1 stash event, got %d. Events=%+v", stashEvents, got.Events)
	}
	if !strings.Contains(string(got.Body), "observer://stash/") {
		t.Errorf("stash marker missing from output: %s", string(got.Body))
	}
	if !strings.Contains(string(got.Body), "retrieve_stashed") {
		t.Errorf("retrieve_stashed reference missing from marker: %s", string(got.Body))
	}
	// Verify the directive marker shape (post-2026-05-08 rephrase
	// after dogfood showed the model wasn't calling retrieve_stashed
	// on the prior status-note form).
	bodyStr := string(got.Body)
	if !strings.Contains(bodyStr, "mcp__observer__retrieve_stashed") {
		t.Errorf("directive MCP-tool reference missing from marker: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `sha=\"`) {
		t.Errorf("directive sha=\"...\" arg shape missing from marker: %s", bodyStr)
	}
	// Verify round-trip: marker references a real sha that retrieves the
	// original bytes.
	for _, ev := range got.Events {
		if ev.Mechanism != "stash" {
			continue
		}
		// Marker form (v1.4.43+ directive shape):
		//   `[output NKB stashed at observer://stash/<sha> — to view full content, call mcp__observer__retrieve_stashed with sha="<sha>"]`
		// Parse the URL-form sha (terminated by whitespace).
		idx := strings.Index(bodyStr, "observer://stash/")
		if idx < 0 {
			t.Fatal("marker URL missing")
		}
		rest := bodyStr[idx+len("observer://stash/"):]
		end := strings.IndexAny(rest, " \t\n")
		if end < 0 {
			t.Fatal("marker URL terminator missing")
		}
		sha := rest[:end]
		gotBytes, err := st.Read(sha)
		if err != nil {
			t.Errorf("retrieve sha %q failed: %v", sha, err)
		}
		if string(gotBytes) != bigBody {
			t.Errorf("round-trip body mismatch: got %d bytes, want %d", len(gotBytes), len(bigBody))
		}
	}
}

// TestPipeline_StashSkipsBelowThreshold pins that bodies under
// thresholdBytes pass through unchanged — stash is for *large*
// outputs, not every tool_result.
func TestPipeline_StashSkipsBelowThreshold(t *testing.T) {
	st, _ := stash.New(stash.Options{Dir: t.TempDir()})
	body, _ := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":        "tool_result",
						"tool_use_id": "tu_x",
						"content":     "small body",
					},
				},
			},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New()).WithStash(st, 8192)
	got := p.Run("anthropic", body)
	for _, ev := range got.Events {
		if ev.Mechanism == "stash" {
			t.Errorf("stash event fired below threshold: %+v", ev)
		}
	}
}

// TestPipeline_StashCrossTurnInvariance pins the cache-hit predicate
// for CCR: the same body in two turns produces byte-identical markers
// (because the marker depends only on body bytes, not on call order
// or wall-clock). Without this property, Anthropic's prefix cache
// would miss on every turn that contains a stashed body.
func TestPipeline_StashCrossTurnInvariance(t *testing.T) {
	st, _ := stash.New(stash.Options{Dir: t.TempDir()})

	var sb strings.Builder
	for i := 0; i < 1024; i++ {
		sb.WriteString(fmt.Sprintf("invariance-line-%04d\n", i))
	}
	bigBody := sb.String()

	makeBody := func() []byte {
		body, _ := json.Marshal(map[string]any{
			"model": "claude-opus-4-7",
			"messages": []any{
				map[string]any{
					"role": "user",
					"content": []any{
						map[string]any{
							"type":        "tool_result",
							"tool_use_id": "tu_x",
							"content":     bigBody,
						},
					},
				},
			},
		})
		return body
	}
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New()).WithStash(st, 8192)

	out1 := p.Run("anthropic", makeBody())
	out2 := p.Run("anthropic", makeBody())
	if string(out1.Body) != string(out2.Body) {
		t.Errorf("CCR markers not byte-identical across turns:\n out1=%s\n out2=%s", out1.Body, out2.Body)
	}
}

// TestPipeline_StashDisabledByDefault pins that pipelines created
// without WithStash never produce stash events even on huge bodies —
// CCR is opt-in.
func TestPipeline_StashDisabledByDefault(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 1024; i++ {
		sb.WriteString(fmt.Sprintf("line-%04d-padding\n", i))
	}
	body, _ := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":        "tool_result",
						"tool_use_id": "tu_x",
						"content":     sb.String(),
					},
				},
			},
		},
	})
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 0,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body)
	for _, ev := range got.Events {
		if ev.Mechanism == "stash" {
			t.Errorf("stash event fired without WithStash: %+v", ev)
		}
	}
}

// TestPipeline_ToolSchemaCompressionFires pins the integration
// property: a Claude-Code-shaped Anthropic body with a tools array
// containing examples + multi-paragraph descriptions produces at least
// one `tools` compression event when run through the full pipeline.
func TestPipeline_ToolSchemaCompressionFires(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"tools": []any{
			map[string]any{
				"name":        "read_file",
				"description": "Read a file.\n\nReturns full contents.\n\nThis paragraph is trimmed.\n\nAnd this one too.",
				"input_schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{
							"type":     "string",
							"examples": []any{"/etc/hosts", "/home/user/x"},
						},
					},
					"required": []any{"path"},
					"examples": []any{map[string]any{"path": "/etc/hosts"}},
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
		// V7-21: tool-defs trim is opt-in via the "tools" sentinel.
		CompressTypes: []string{"json", "logs", "code", "tools"},
	}, DefaultRegistry(), scrub.New())
	got := p.Run("anthropic", body)
	if got.Skipped {
		t.Fatalf("pipeline skipped on body with multi-paragraph tool description: %+v", got)
	}
	toolEvents := 0
	for _, ev := range got.Events {
		if ev.Mechanism == "tools" {
			toolEvents++
		}
	}
	if toolEvents == 0 {
		t.Errorf("expected ≥1 tools event, got 0. Events=%+v", got.Events)
	}
	if got.CompressedBytes >= got.OriginalBytes {
		t.Errorf("CompressedBytes %d should be < OriginalBytes %d", got.CompressedBytes, got.OriginalBytes)
	}
	var env map[string]any
	if err := json.Unmarshal(got.Body, &env); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	tools, _ := env["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool in output, got %d", len(tools))
	}
}

func newCacheAwarePipeline() *Pipeline {
	return NewPipeline(PipelineConfig{
		Enabled:       true,
		Mode:          ModeCacheAware,
		TargetRatio:   0.85,
		PreserveLastN: 5,
		CompressTypes: []string{"json", "logs", "text"},
	}, DefaultRegistry(), scrub.New())
}

// buildClaudeCodeShapedBody constructs an Anthropic Messages API body
// shaped like Claude Code SDK 2.1+ emits: system array with
// cache_control on the prompt block, messages array with the marker on
// the LAST block of the LAST message (a multi-tool_result user turn).
func buildClaudeCodeShapedBody(t *testing.T) []byte {
	t.Helper()
	bigJSON := `{"records":[`
	for i := 0; i < 40; i++ {
		if i > 0 {
			bigJSON += ","
		}
		bigJSON += `{"id":` + itoa(i) + `,"name":"x"}`
	}
	bigJSON += `]}`

	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"system": []any{
			map[string]any{
				"type":          "text",
				"text":          "You are a Claude agent.",
				"cache_control": map[string]string{"type": "ephemeral"},
			},
		},
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "text", "text": "kick off"},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": bigJSON},
					map[string]any{"type": "tool_result", "tool_use_id": "t2", "content": bigJSON},
					map[string]any{
						// Same compressible body as its siblings — NOT a tiny
						// "small tail" that would short-circuit compression via
						// len(out) >= len(body). This is what makes the
						// cross-turn tests actually exercise the marker-block
						// compression path (the bug was invisible in CI because
						// the marker block was never compressed).
						"type":          "tool_result",
						"tool_use_id":   "t3",
						"content":       bigJSON,
						"cache_control": map[string]string{"type": "ephemeral"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

// extendBodyOneMoreTurn simulates the SDK's marker-rolling behaviour:
// removes cache_control from the prior turn's last block and adds two
// new messages (assistant tool_use + user tool_result) with the marker
// on the new last block.
func extendBodyOneMoreTurn(t *testing.T, prior []byte) []byte {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(prior, &env); err != nil {
		t.Fatalf("unmarshal prior: %v", err)
	}
	msgs := env["messages"].([]any)
	// Strip cache_control from the prior last message's blocks.
	last := msgs[len(msgs)-1].(map[string]any)
	for _, bAny := range last["content"].([]any) {
		b := bAny.(map[string]any)
		delete(b, "cache_control")
	}
	// Append new assistant tool_use + new user tool_result with marker.
	msgs = append(
		msgs,
		map[string]any{
			"role": "assistant",
			"content": []any{
				map[string]any{"type": "tool_use", "id": "t4", "name": "Bash", "input": map[string]any{"command": "ls"}},
			},
		},
		map[string]any{
			"role": "user",
			"content": []any{
				map[string]any{
					"type":          "tool_result",
					"tool_use_id":   "t4",
					"content":       "file1\nfile2\n",
					"cache_control": map[string]string{"type": "ephemeral"},
				},
			},
		},
	)
	env["messages"] = msgs
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

// rollingMockSummarizer is a deterministic Summarizer used in
// pipeline-level tests for D20 live wire-up.
type rollingMockSummarizer struct {
	summary string
	calls   int
}

func (m *rollingMockSummarizer) Summarize(_ context.Context, _ []Message) (string, error) {
	m.calls++
	return m.summary, nil
}

type rollingMockFactory struct{ s Summarizer }

func (f *rollingMockFactory) For(_ string) Summarizer { return f.s }

// TestPipeline_RollingSummary_FiresOnAnthropic_E2E pins the v1.4.43+ /
// Tier 2 / D20 live wire-up: when a session crosses ThresholdTokens,
// runAnthropic calls summarizeIfThreshold which replaces older
// messages with a synthetic marker, the serializer drops them from
// the request body, and a `rolling_summary` event lands on the
// PipelineResult. Cross-turn invariance is exercised by re-running
// the same body and checking the upstream summariser is NOT called
// again (sticky boundary).
func TestPipeline_RollingSummary_FiresOnAnthropic_E2E(t *testing.T) {
	long := strings.Repeat("aaaa bbbb cccc dddd ", 200) // ~4 KB / message

	// Build 25 alternating user/assistant messages — enough to clear
	// the 100-token threshold + the 6-msg preserve.
	msgs := []any{}
	for i := 0; i < 25; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		msgs = append(msgs, map[string]any{
			"role":    role,
			"content": long,
		})
	}
	body, err := json.Marshal(map[string]any{
		"model":    "claude-opus-4-7",
		"messages": msgs,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	mock := &rollingMockSummarizer{summary: "Tight recap line."}
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		TargetRatio:   0.95,
		PreserveLastN: 6,
		CompressTypes: []string{"json", "logs", "code"},
	}, DefaultRegistry(), scrub.New()).WithSummarizerFactory(&rollingMockFactory{s: mock}, 100)

	got := p.RunInSession("anthropic", body, "rolling-sess")

	if got.Skipped {
		t.Fatalf("pipeline skipped despite long conversation: %+v", got)
	}
	rollingEvents := 0
	for _, ev := range got.Events {
		if ev.Mechanism == "rolling_summary" {
			rollingEvents++
		}
	}
	if rollingEvents != 1 {
		t.Errorf("expected 1 rolling_summary event, got %d. Events=%+v", rollingEvents, got.Events)
	}
	if mock.calls != 1 {
		t.Errorf("expected 1 upstream summary call, got %d", mock.calls)
	}
	if got.CompressedBytes >= got.OriginalBytes {
		t.Errorf("expected body to shrink: orig=%d compressed=%d", got.OriginalBytes, got.CompressedBytes)
	}

	// Re-run the same body — sticky boundary should serve from cache,
	// no new upstream call.
	again := p.RunInSession("anthropic", body, "rolling-sess")
	if again.Skipped {
		t.Errorf("second run unexpectedly skipped: %+v", again)
	}
	if mock.calls != 1 {
		t.Errorf("sticky boundary broken: %d upstream calls after re-run (want 1)", mock.calls)
	}
	// Body bytes should match the first run — cross-turn invariance.
	if string(got.Body) != string(again.Body) {
		t.Errorf("cross-turn invariance broken on identical input")
	}
}

// TestPipeline_RollingSummary_NoOpUnderThreshold pins that short
// conversations don't trigger the upstream summariser even with the
// factory wired.
func TestPipeline_RollingSummary_NoOpUnderThreshold(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-4-7",
		"messages": []any{
			map[string]any{"role": "user", "content": "hi"},
			map[string]any{"role": "assistant", "content": "hello"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mock := &rollingMockSummarizer{summary: "should not fire"}
	p := NewPipeline(PipelineConfig{
		Enabled:       true,
		PreserveLastN: 6,
		CompressTypes: []string{"json"},
	}, DefaultRegistry(), scrub.New()).WithSummarizerFactory(&rollingMockFactory{s: mock}, 1000000)
	_ = p.RunInSession("anthropic", body, "rolling-sess")
	if mock.calls != 0 {
		t.Errorf("upstream summariser called below threshold: %d", mock.calls)
	}
}
