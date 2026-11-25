package claudecode

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// writeJSONLFixture stages a JSONL fixture in t.TempDir() under
// the claude-code project-root convention so resolveProjectRoot
// gives a deterministic root. Returns the absolute path.
func writeJSONLFixture(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "session.jsonl")
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// hashChain hashes a slice of CacheBlockMeta using the same
// preimage shape the cachetrack engine's chain.Push uses
// (level-byte || u32be(len(kind)) || kind || u32be(len(canon))
// || canon, rolling SHA-256). Used only by the R3 determinism
// guard test below — proves that two parses of the same
// fixture produce byte-identical chain hashes.
func hashChain(blocks []models.CacheBlockMeta) string {
	if len(blocks) == 0 {
		return ""
	}
	var state []byte
	for _, b := range blocks {
		h := sha256.New()
		h.Write(state)
		// Map LevelLabel to the engine's BlockLevel byte. Mirrors
		// internal/cachetrack/block.go::BlockLevel and tier.go.
		var levelByte byte
		switch b.LevelLabel {
		case "tools":
			levelByte = 1
		case "system":
			levelByte = 2
		case "message":
			levelByte = 3
		default:
			levelByte = 0
		}
		h.Write([]byte{levelByte})
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b.Kind)))
		h.Write(lenBuf[:])
		h.Write([]byte(b.Kind))
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b.CanonicalBytes)))
		h.Write(lenBuf[:])
		h.Write(b.CanonicalBytes)
		state = h.Sum(nil)
	}
	return hex.EncodeToString(state)
}

// TestAccumulateCacheBlocksTier2_Deterministic_R3Guard is THE
// load-bearing test the operator named as the C7 acceptance
// check: pushing the same turn's blocks through the chain twice
// must produce byte-identical output. The accumulator uses
// ordered arrays (transcript message order + each message's
// content[] order) and STRUCT-based canonical marshaling so
// Go-map iteration randomness can NEVER leak into the chain.
//
// A coverage test would not catch a regression here — the same
// random order might be observed twice in a row by chance. The
// determinism guard is the only test that catches it (run
// many iterations to bring the false-pass odds to zero).
func TestAccumulateCacheBlocksTier2_Deterministic_R3Guard(t *testing.T) {
	t.Parallel()

	// Build a content array that exercises every kind the
	// accumulator handles (text / tool_use / tool_result /
	// thinking / image). Inputs include json.RawMessage fields
	// so we also pin that Input/Content bytes round-trip
	// verbatim.
	blocks := []rawContentBlock{
		{Type: "text", Text: "Plan the migration."},
		{Type: "tool_use", ID: "tu_1", Name: "Read", Input: json.RawMessage(`{"path":"/src/main.go","start":0,"end":200}`)},
		{Type: "tool_result", ToolUseID: "tu_1", Content: json.RawMessage(`"file content here"`), IsError: false},
		{Type: "thinking", Text: "I should examine the error path next."},
		{Type: "image"},
	}

	// Build the chain HUNDREDS of times. If Go-map iteration
	// randomness ever leaks into the accumulator, the hash will
	// drift on at least one iteration with overwhelming
	// probability. (Note: math/rand is deliberately seeded by
	// the Go test runner; the goroutine scheduler also varies.)
	var first string
	const iterations = 250
	for i := 0; i < iterations; i++ {
		out := accumulateCacheBlocksTier2(blocks, "user")
		got := hashChain(out)
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("iter %d: chain hash drift\n got:  %s\n want: %s\n— accumulator leaked map-iteration order; R3 byte-stability broken", i, got, first)
		}
	}
}

// TestAccumulateCacheBlocksTier2_PreservesArrayOrder pins that
// the output slice order matches the input content[] order
// exactly. Critical for attachments interleaved with
// text/tool_result — they must land in chain order at the
// content[] index, never appended at the end.
func TestAccumulateCacheBlocksTier2_PreservesArrayOrder(t *testing.T) {
	t.Parallel()
	blocks := []rawContentBlock{
		{Type: "text", Text: "before attachment"},
		{Type: "attachment", Text: "<injected file body>"},
		{Type: "text", Text: "after attachment"},
		{Type: "tool_result", ToolUseID: "tu_x", Content: json.RawMessage(`"done"`)},
	}
	out := accumulateCacheBlocksTier2(blocks, "user")
	if len(out) != 4 {
		t.Fatalf("len = %d, want 4", len(out))
	}
	wantOrder := []string{"text", "attachment", "text", "tool_result"}
	for i, want := range wantOrder {
		if out[i].Kind != want {
			t.Errorf("position %d: kind = %q, want %q (attachment interleaving broken)", i, out[i].Kind, want)
		}
	}
}

// TestAccumulateCacheBlocksTier2_SkipsBlankKind ensures
// malformed/empty-Type blocks drop silently rather than
// landing in the chain with kind="".
func TestAccumulateCacheBlocksTier2_SkipsBlankKind(t *testing.T) {
	t.Parallel()
	blocks := []rawContentBlock{
		{Type: "text", Text: "ok"},
		{Type: ""},
		{Type: "text", Text: "still ok"},
	}
	out := accumulateCacheBlocksTier2(blocks, "user")
	if len(out) != 2 {
		t.Errorf("len = %d, want 2 (blank-kind block must be skipped)", len(out))
	}
}

// TestTier2Accumulator_CapDropsBlockHashes verifies the
// MaxBlocksPerSession guard as the parse loop drives it: the
// canonical blocks feed cacheobs.Accumulator, and once cumulative
// blocks exceed the cap, Emit produces BlockHashes=nil — the spec §9
// OOM guard.
func TestTier2Accumulator_CapDropsBlockHashes(t *testing.T) {
	t.Parallel()
	acc := cacheobs.New(5)
	for i := 0; i < 3; i++ {
		acc.ObserveBlocks(accumulateCacheBlocksTier2([]rawContentBlock{{Type: "text", Text: "a"}, {Type: "text", Text: "b"}}, "user"))
	}
	// 3 × 2 = 6 blocks; cap=5 → the cap latches.
	obs := acc.Emit("path", "sA", "msg_1", "claude", t0Stub(), models.CacheUsage{}, false)
	if obs.BlockHashes != nil {
		t.Errorf("BlockHashes = %v, want nil after cap exceeded", obs.BlockHashes)
	}
	// The cap stays latched until a compaction.
	acc.ObserveBlocks(accumulateCacheBlocksTier2([]rawContentBlock{{Type: "text", Text: "late"}}, "user"))
	if late := acc.Emit("path", "sA", "msg_1b", "claude", t0Stub(), models.CacheUsage{}, false); late.BlockHashes != nil {
		t.Errorf("BlockHashes = %v, want nil while the cap is latched", late.BlockHashes)
	}

	// ObserveCompaction resets the cap state.
	acc.ObserveCompaction()
	acc.ObserveBlocks(accumulateCacheBlocksTier2([]rawContentBlock{{Type: "text", Text: "fresh"}}, "user"))
	obs2 := acc.Emit("path", "sA", "msg_2", "claude", t0Stub(), models.CacheUsage{}, false)
	if len(obs2.BlockHashes) != 1 {
		t.Errorf("post-compaction BlockHashes len = %d, want 1", len(obs2.BlockHashes))
	}
	if !obs2.CompactionSeen {
		t.Error("post-compaction emit should carry CompactionSeen=true")
	}
}

// TestTier2Accumulator_CompactionSeenFlagsNextEmit verifies the
// flag carries to the NEXT emit only, not subsequent ones.
func TestTier2Accumulator_CompactionSeenFlagsNextEmit(t *testing.T) {
	t.Parallel()
	acc := cacheobs.New(MaxBlocksPerSession)
	acc.ObserveCompaction()
	acc.ObserveBlocks(accumulateCacheBlocksTier2([]rawContentBlock{{Type: "text", Text: "x"}}, "user"))
	first := acc.Emit("p", "sA", "m1", "claude", t0Stub(), models.CacheUsage{}, false)
	if !first.CompactionSeen {
		t.Error("first emit after compaction should flag CompactionSeen=true")
	}
	acc.ObserveBlocks(accumulateCacheBlocksTier2([]rawContentBlock{{Type: "text", Text: "y"}}, "user"))
	second := acc.Emit("p", "sA", "m2", "claude", t0Stub(), models.CacheUsage{}, false)
	if second.CompactionSeen {
		t.Error("second emit should not still carry CompactionSeen=true")
	}
}

// TestParseSessionFile_EmitsObservation_PerAssistantTurn parses
// a minimal 2-turn fixture and asserts: one CacheTurnObservation
// per assistant turn; MessageID = upstream msg_xxx (the C5
// dedup-gate join key); ordering matches input.
func TestParseSessionFile_EmitsObservation_PerAssistantTurn(t *testing.T) {
	t.Parallel()
	path := writeJSONLFixture(
		t,
		jsonlLine("user", "uA", "msg_user_a", "What do you think?", ""),
		jsonlAssistantWithUsage("asst_a", "msg_asst_a", "I think yes.", "claude-opus-4-7", 100, 200, 1000, 0, 0),
		jsonlLine("user", "uB", "msg_user_b", "Please continue.", ""),
		jsonlAssistantWithUsage("asst_b", "msg_asst_b", "Continuing.", "claude-opus-4-7", 50, 100, 1100, 0, 0),
	)

	a := New()
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.CacheObservations) != 2 {
		t.Fatalf("observations = %d, want 2", len(res.CacheObservations))
	}
	if res.CacheObservations[0].MessageID != "msg_asst_a" {
		t.Errorf("first MessageID = %q, want msg_asst_a", res.CacheObservations[0].MessageID)
	}
	if res.CacheObservations[1].MessageID != "msg_asst_b" {
		t.Errorf("second MessageID = %q, want msg_asst_b", res.CacheObservations[1].MessageID)
	}
	// First observation's BlockHashes covers the user turn that
	// preceded the first assistant turn. Second observation's
	// BlockHashes covers the assistant's FIRST response + the
	// second user turn (the delta since first emit).
	if len(res.CacheObservations[0].BlockHashes) == 0 {
		t.Error("first observation should carry blocks from preceding user turn")
	}
	// Usage envelope round-trip.
	if res.CacheObservations[0].Usage.CacheReadTokens != 1000 {
		t.Errorf("CacheReadTokens = %d, want 1000", res.CacheObservations[0].Usage.CacheReadTokens)
	}
	if res.CacheObservations[0].Model != "claude-opus-4-7" {
		t.Errorf("Model = %q", res.CacheObservations[0].Model)
	}
	// SourceEventID is "cachetrack:"+msg_xxx → unique per turn,
	// the (SourceFile, SourceEventID) idempotency key the spec
	// §9 names.
	if res.CacheObservations[0].SourceEventID != "cachetrack:msg_asst_a" {
		t.Errorf("SourceEventID = %q, want cachetrack:msg_asst_a", res.CacheObservations[0].SourceEventID)
	}
}

// TestParseSessionFile_Reparse_IdempotentObservations re-parses
// the same fixture and asserts the observations are byte-identical
// (same SourceFile + SourceEventID + chain bytes). The store's
// dedup gate then de-duplicates them — but the test here
// confirms that the input side is stable so the gate has
// something deterministic to dedup against.
func TestParseSessionFile_Reparse_IdempotentObservations(t *testing.T) {
	t.Parallel()
	path := writeJSONLFixture(
		t,
		jsonlLine("user", "uA", "msg_user_a", "What do you think?", ""),
		jsonlAssistantWithUsage("asst_a", "msg_asst_a", "I think yes.", "claude-opus-4-7", 100, 200, 1000, 0, 0),
	)
	a := New()
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.CacheObservations) != len(second.CacheObservations) {
		t.Fatalf("counts differ: first=%d, second=%d", len(first.CacheObservations), len(second.CacheObservations))
	}
	for i := range first.CacheObservations {
		fh := hashChain(first.CacheObservations[i].BlockHashes)
		sh := hashChain(second.CacheObservations[i].BlockHashes)
		if fh != sh {
			t.Errorf("observation %d: chain hash drift on re-parse\n first:  %s\n second: %s", i, fh, sh)
		}
		if first.CacheObservations[i].SourceEventID != second.CacheObservations[i].SourceEventID {
			t.Errorf("observation %d: SourceEventID drift", i)
		}
	}
}

// TestParseSessionFile_CompactBoundaryEmitsFlag verifies the
// compact_boundary line resets the accumulator AND the next
// assistant emit carries CompactionSeen=true. Models the
// b9bd459d 04-29 06:05 fixture shape — after a long gap +
// compact_boundary, the next assistant turn rebuilds with
// reduced chain.
func TestParseSessionFile_CompactBoundaryEmitsFlag(t *testing.T) {
	t.Parallel()
	compactLine := `{"sessionId":"sA","uuid":"compact_1","timestamp":"2026-04-29T06:00:00.000Z","cwd":"/tmp","type":"system","subtype":"compact_boundary","parentUuid":"asst_a","compactMetadata":{"trigger":"manual","preTokens":120000,"preCompactDiscoveredTools":[]}}`
	path := writeJSONLFixture(
		t,
		jsonlLine("user", "uA", "msg_user_a", "Long context...", ""),
		jsonlAssistantWithUsage("asst_a", "msg_asst_a", "OK.", "claude-opus-4-7", 100, 200, 50000, 0, 0),
		compactLine,
		jsonlLine("user", "uB", "msg_user_b", "Continuing after compact.", ""),
		jsonlAssistantWithUsage("asst_b", "msg_asst_b", "Resumed.", "claude-opus-4-7", 50, 100, 0, 5000, 0),
	)
	a := New()
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.CacheObservations) != 2 {
		t.Fatalf("observations = %d, want 2", len(res.CacheObservations))
	}
	if res.CacheObservations[0].CompactionSeen {
		t.Error("first observation predates compact_boundary; CompactionSeen should be false")
	}
	if !res.CacheObservations[1].CompactionSeen {
		t.Error("second observation follows compact_boundary; CompactionSeen should be true")
	}
}

// TestParseSessionFile_AttachmentInterleavesInChain models the
// R1 finding that attachment lines fold into the chain at their
// in-order position, NOT appended at the end. Builds a fixture
// where attachment sits between two user-content lines and
// asserts the chain order. (Note: this exercises the
// line-level interleaving — attachments as separate JSONL
// lines, which is what R1 captured.)
func TestParseSessionFile_AttachmentInterleavesInChain(t *testing.T) {
	t.Parallel()
	attachmentLine := `{"sessionId":"sA","uuid":"att_1","timestamp":"2026-06-08T12:00:00.500Z","cwd":"/tmp","type":"attachment","message":{"role":"user","content":[{"type":"text","text":"<injected file body>"}]}}`
	path := writeJSONLFixture(
		t,
		jsonlLine("user", "uA", "msg_user_a", "Look at this:", ""),
		attachmentLine,
		jsonlLine("user", "uB", "msg_user_b", "What do you think?", ""),
		jsonlAssistantWithUsage("asst_a", "msg_asst_a", "I see it.", "claude-opus-4-7", 100, 200, 0, 0, 0),
	)
	a := New()
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.CacheObservations) != 1 {
		t.Fatalf("observations = %d, want 1", len(res.CacheObservations))
	}
	// Expect 3 blocks in chain: user A text, attachment text,
	// user B text — in that order. The accumulation order
	// matches the JSONL line order, never appends attachment at
	// the end.
	blocks := res.CacheObservations[0].BlockHashes
	if len(blocks) != 3 {
		t.Fatalf("BlockHashes len = %d, want 3", len(blocks))
	}
	// Each block should be text-typed; the role attribution
	// distinguishes user-line vs attachment-line origins by
	// what's INSIDE the canonical bytes — for this test we just
	// pin ordering.
	for i, b := range blocks {
		if b.Kind != "text" {
			t.Errorf("block %d Kind = %q, want text", i, b.Kind)
		}
		if b.Role != "user" {
			t.Errorf("block %d Role = %q, want user (attachment maps to user role)", i, b.Role)
		}
	}
}

// TestTier2AccumulationRole_Mapping pins the role attribution
// rules: user/assistant pass through, attachment maps to user,
// system/etc. returns empty (skip).
func TestTier2AccumulationRole_Mapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		msgRole, lineType, want string
	}{
		{"user", "", "user"},
		{"assistant", "", "assistant"},
		{"", "attachment", "user"},
		{"user", "attachment", "user"},
		{"", "system", ""},
		{"", "agent-name", ""},
		{"system", "", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		got := tier2AccumulationRole(tt.msgRole, tt.lineType)
		if got != tt.want {
			t.Errorf("tier2AccumulationRole(%q, %q) = %q, want %q", tt.msgRole, tt.lineType, got, tt.want)
		}
	}
}

// --- Test fixture helpers ---

// jsonlLine emits a minimal Claude Code transcript line of the
// given role with single-text content. msgID is the upstream
// Anthropic msg_xxx; uuid is the per-record claudecode uuid.
func jsonlLine(role, uuid, msgID, text, model string) string {
	type rawMsg struct {
		ID      string `json:"id,omitempty"`
		Role    string `json:"role"`
		Model   string `json:"model,omitempty"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	msg := rawMsg{
		ID:    msgID,
		Role:  role,
		Model: model,
	}
	msg.Content = append(msg.Content, struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}{Type: "text", Text: text})
	msgBytes, _ := json.Marshal(msg)
	line := fmt.Sprintf(`{"sessionId":"sA","uuid":%q,"timestamp":"2026-06-08T12:00:00.000Z","cwd":"/tmp","type":%q,"message":%s}`,
		uuid, role, msgBytes)
	return line
}

// jsonlAssistantWithUsage emits an assistant line with a usage
// envelope. The fields are the ones the cachetrack observation
// reads: input/output/cache_read/cache_creation/1h.
func jsonlAssistantWithUsage(uuid, msgID, text, model string, inputTokens, outputTokens, cacheRead, cacheCreation5m, cacheCreation1h int64) string {
	usage := fmt.Sprintf(`{"input_tokens":%d,"output_tokens":%d,"cache_read_input_tokens":%d,"cache_creation_input_tokens":%d,"cache_creation":{"ephemeral_5m_input_tokens":%d,"ephemeral_1h_input_tokens":%d}}`,
		inputTokens, outputTokens, cacheRead, cacheCreation5m+cacheCreation1h, cacheCreation5m, cacheCreation1h)
	contentArr := fmt.Sprintf(`[{"type":"text","text":%q}]`, text)
	msg := fmt.Sprintf(`{"id":%q,"role":"assistant","model":%q,"content":%s,"usage":%s,"stop_reason":"end_turn"}`,
		msgID, model, contentArr, usage)
	line := fmt.Sprintf(`{"sessionId":"sA","uuid":%q,"timestamp":"2026-06-08T12:00:01.000Z","cwd":"/tmp","type":"assistant","message":%s}`,
		uuid, msg)
	return line
}

// t0Stub is a deterministic timestamp for accumulator tests
// that don't exercise the JSONL walk.
func t0Stub() time.Time {
	return time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
}
