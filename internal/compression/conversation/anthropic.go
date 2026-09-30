package conversation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/compression/conversation/types"
)

// anthropicBlock is one entry inside an Anthropic message's `content` array.
// Only the fields conversation compression needs are decoded; unknown fields
// pass through via the RawEnc preserved on the containing message.
type anthropicBlock struct {
	Type         string          `json:"type"`
	Text         string          `json:"text,omitempty"`
	ToolUseID    string          `json:"tool_use_id,omitempty"`
	ID           string          `json:"id,omitempty"`
	Name         string          `json:"name,omitempty"`
	Input        json.RawMessage `json:"input,omitempty"`
	Content      json.RawMessage `json:"content,omitempty"`
	IsError      *bool           `json:"is_error,omitempty"`
	CacheControl json.RawMessage `json:"cache_control,omitempty"`
}

// anthropicMessage is the per-entry shape of the request body's `messages`
// array. Content is either a bare string or an array of anthropicBlock.
type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// extractedMessage carries the parsed per-message detail the pipeline
// needs: the original raw JSON (for round-trip when untouched), the
// role, the compressible text (a tool_result body when present,
// flattened content otherwise), and the block-level metadata needed to
// rewrite the tool_result block when compression actually shrinks it.
type extractedMessage struct {
	raw  json.RawMessage
	role string
	// blocks is the decoded content array; empty when content was a bare
	// string.
	blocks []anthropicBlock
	// stringContent is set when content was a string rather than an
	// array.
	stringContent string
	// resultBlockIdxs lists the block index of every tool_result block
	// in this message (empty when no tool_result is present). Multi-
	// element for parallel tool calls (Claude Code's "Read + LS + LS"
	// pattern); single-element for the common one-tool-per-turn case.
	resultBlockIdxs []int
	// resultTexts is the plain-text body of each tool_result block,
	// parallel to resultBlockIdxs.
	resultTexts []string
	// resultIsStructureds tracks whether each tool_result's `content`
	// was an array of blocks (true) or a bare string (false). Drives
	// how the compressed body is serialized back.
	resultIsStructureds []bool
	// compressedTexts holds the post-compression body for each tool_result
	// block, parallel to resultBlockIdxs. Empty string means "use the
	// original — no compression fired or compression didn't shrink".
	// Populated by [compressToolResults] before scoring.
	compressedTexts []string
	// resultFilenames carries the producing tool_use's file_path argument
	// per tool_result block, parallel to resultBlockIdxs. Empty string
	// when the producing tool wasn't a Read (no file_path) or the
	// tool_use_id couldn't be resolved. Lifts types.Detect's accuracy by
	// giving it an extension hint instead of the empty filename.
	resultFilenames []string
	// resultToolNames carries the producing tool_use's name (e.g. "Read",
	// "Bash", "Grep") per tool_result block, parallel to resultBlockIdxs.
	// Drives tool-aware compression dispatch.
	resultToolNames []string
	// toolUseIDs lists every tool_use_id this message produced. Multi-
	// element when the assistant emitted parallel tool calls (Claude
	// Code's "Read + LS + LS" pattern); single-element for the common
	// one-tool-per-turn case; empty for messages without tool_use.
	toolUseIDs []string
	// referencedIDs collects tool_use_ids from tool_result blocks.
	referencedIDs []string
	// flatText is the text version used for scoring.
	flatText string
}

// anthropicExtract parses an Anthropic Messages API request body. Returns
// the top-level envelope (every field preserved as RawMessage so the
// compressor can round-trip unknown top-level keys) and the extracted
// per-message detail slice. When the body isn't an Anthropic request at
// all (unknown shape, parse error), returns ok=false.
func anthropicExtract(body []byte) (envelope map[string]json.RawMessage, extracted []extractedMessage, ok bool) {
	envelope = make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, nil, false
	}
	raw, found := envelope["messages"]
	if !found {
		return nil, nil, false
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return nil, nil, false
	}
	extracted = make([]extractedMessage, 0, len(msgs))
	for _, m := range msgs {
		var hdr anthropicMessage
		if err := json.Unmarshal(m, &hdr); err != nil {
			// Skip malformed messages but preserve the raw so the proxy
			// forwards the original body on re-serialize.
			extracted = append(extracted, extractedMessage{raw: m})
			continue
		}
		em := extractedMessage{
			raw:  m,
			role: hdr.Role,
		}
		// Try array-of-blocks first; fall back to string.
		var blocks []anthropicBlock
		if err := json.Unmarshal(hdr.Content, &blocks); err == nil {
			em.blocks = blocks
			em.fillFromBlocks()
		} else {
			var s string
			if err := json.Unmarshal(hdr.Content, &s); err == nil {
				em.stringContent = s
				em.flatText = s
			}
		}
		extracted = append(extracted, em)
	}
	resolveToolUseInputs(extracted)
	return envelope, extracted, true
}

// toolUseInputInfo carries the producing tool_use block's contextual
// hints used to drive per-block compression: the tool name (Read, Bash,
// Grep, ...) and the file_path argument when present.
type toolUseInputInfo struct {
	Name     string
	FilePath string
}

// resolveToolUseInputs walks the extracted slice once to build a
// tool_use_id → {Name, FilePath} index from every assistant tool_use
// block, then back-fills resultFilenames + resultToolNames on every
// tool_result-bearing message by tool_use_id. Linear in total blocks —
// request bodies typically have a few dozen.
func resolveToolUseInputs(extracted []extractedMessage) {
	index := make(map[string]toolUseInputInfo)
	for _, em := range extracted {
		for _, b := range em.blocks {
			if b.Type != "tool_use" || b.ID == "" {
				continue
			}
			info := toolUseInputInfo{Name: b.Name}
			if len(b.Input) > 0 {
				var raw struct {
					FilePath string `json:"file_path"`
				}
				_ = json.Unmarshal(b.Input, &raw)
				info.FilePath = raw.FilePath
			}
			index[b.ID] = info
		}
	}
	for i := range extracted {
		em := &extracted[i]
		if len(em.resultBlockIdxs) == 0 {
			continue
		}
		em.resultFilenames = make([]string, len(em.resultBlockIdxs))
		em.resultToolNames = make([]string, len(em.resultBlockIdxs))
		for j, blockIdx := range em.resultBlockIdxs {
			useID := em.blocks[blockIdx].ToolUseID
			if info, ok := index[useID]; ok {
				em.resultFilenames[j] = info.FilePath
				em.resultToolNames[j] = info.Name
			}
		}
	}
}

// fillFromBlocks scans the decoded blocks to populate resultBlockIdxs,
// resultTexts, resultIsStructureds, toolUseIDs, referencedIDs, and
// flatText. Multi-element resultBlockIdxs cover Claude Code's parallel-
// tool-result pattern (a single user message carrying N tool_results
// for N parallel tool_use blocks); the per-block compression pass
// shrinks each independently rather than discarding the join.
func (em *extractedMessage) fillFromBlocks() {
	var textParts []string
	for i, b := range em.blocks {
		switch b.Type {
		case "text":
			textParts = append(textParts, b.Text)
		case "tool_use":
			// Append (don't overwrite) so parallel tool_use blocks all
			// land in the slice. Pre-fix this dropped all but the last
			// id, which made parallel-tool-call messages invisible to
			// the budget enforcer's pair-integrity preservation logic.
			em.toolUseIDs = append(em.toolUseIDs, b.ID)
			textParts = append(textParts, fmt.Sprintf("tool_use %s(%s)", b.Name, string(b.Input)))
		case "tool_result":
			em.referencedIDs = append(em.referencedIDs, b.ToolUseID)
			em.resultBlockIdxs = append(em.resultBlockIdxs, i)
			rt, structured := tool_resultText(b.Content)
			em.resultTexts = append(em.resultTexts, rt)
			em.resultIsStructureds = append(em.resultIsStructureds, structured)
			textParts = append(textParts, rt)
		}
	}
	em.flatText = strings.Join(textParts, "\n")
}

// tool_resultText decodes a tool_result block's `content` field. It can be
// a bare string or an array of `{type:"text", text:"..."}` entries. Returns
// the extracted text and whether the original shape was structured (an
// array).
func tool_resultText(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, false
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err == nil {
		parts := make([]string, 0, len(blocks))
		for _, b := range blocks {
			if b.Type == "text" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "\n"), true
	}
	return "", false
}

// compressToolResults runs per-type compression on every tool_result
// block in the extracted slice, mutating em.compressedTexts in place
// (parallel to em.resultBlockIdxs). Each block is compressed
// independently, fixing the multi-tool_result case where Enforce's
// flat-text compression was discarded by serializeAnthropic. Returns
// the per-block compression events for telemetry.
//
// The per-type compressor is a pure function of input bytes; running
// it per-block (instead of on the joined text) preserves cross-turn
// determinism: the same block's bytes in turn N+1 produce the same
// compressed output as in turn N, regardless of what other blocks
// surround it.
//
// Every tool_result block is compressed uniformly — including the block
// currently carrying the SDK's cache_control marker. That marker rolls
// forward each turn (the SDK pins it to the last block of the latest
// message), so the block that holds it in turn N becomes ordinary
// historical-prefix material in turn N+1. Compressing it identically in
// both turns is exactly what keeps the prefix byte-stable for Anthropic's
// cache; the cache_control annotation rides along as a sibling JSON field
// and is ignored by the cache-key hash. (Previously this block was left
// uncompressed as a "safety net", which made the same logical message go
// on the wire with two different byte representations across consecutive
// turns and broke the prefix cache from that block onward — see
// TestPipelineCacheAware_MarkerRollPreservesPriorBytes.)
// hinter is the per-block compression hint-builder closure supplied
// by the runAnthropic / runOpenAI call sites. It captures the
// pipeline's symbol lookup + current context so the per-type compressor
// can receive filename + symbols via CompressHints. Returns the zero
// CompressHints when filename is empty or the code index is unavailable.
type hinter = func(filename string) CompressHints

// codeCollapser is the optional aggressive code-collapse hook
// (codeintel Phase 2). Given a code-type tool_result body + its
// filename, it returns the body with exact-span symbol bodies collapsed
// to a declaration + retrieval marker (originals stashed), the per-
// collapse events, and whether it fired. nil disables the feature
// (the default — content-preserving). In preview mode it returns
// fired=false with non-empty events. ADR-0002: it performs store
// lookups only, never an inline parse.
type codeCollapser func(filename string, body []byte, msgIndex int) (out []byte, events []Event, fired bool)

func compressToolResults(extracted []extractedMessage, registry *Registry, allow map[types.ContentType]bool, buildHints hinter, collapse codeCollapser) []Event {
	if registry == nil {
		return nil
	}
	var events []Event
	for i := range extracted {
		em := &extracted[i]
		if len(em.resultBlockIdxs) == 0 {
			continue
		}
		if cap(em.compressedTexts) < len(em.resultBlockIdxs) {
			em.compressedTexts = make([]string, len(em.resultBlockIdxs))
		} else {
			em.compressedTexts = em.compressedTexts[:len(em.resultBlockIdxs)]
		}
		for j, body := range em.resultTexts {
			if body == "" {
				continue
			}
			// MCP tool_results carry structured query data where the
			// VALUES are the answer (action_ids, file paths, costs,
			// stashed bytes, etc.). JSON / code / logs compression
			// would replace those scalars with type sentinels and
			// corrupt the response. Skip per-type compression entirely
			// for any tool whose name starts with `mcp__`. Surfaced
			// 2026-05-08 dogfood: search_past_outputs returned 10 hits
			// but the model saw "placeholders only" because the JSON
			// compressor replaced every action_id / rank scalar with
			// `<number>`. Pinned by
			// `TestCompressToolResults_SkipsMCPToolResults`.
			if j < len(em.resultToolNames) && isMCPToolName(em.resultToolNames[j]) {
				continue
			}
			filename := ""
			if j < len(em.resultFilenames) {
				filename = em.resultFilenames[j]
			}
			// Read-tool output arrives line-numbered (cat -n style); the
			// per-type compressors expect raw content, so we strip line
			// numbers before detection AND before compression. The
			// resulting compressed body loses line numbers — model can
			// re-Read for line numbers if Edit needs them, an acceptable
			// trade for unlocking compression on the dominant tool_result
			// shape.
			compressInput := []byte(body)
			if types.IsLineNumbered(compressInput) {
				compressInput = types.StripLineNumbers(compressInput)
			}
			ct := types.Detect(compressInput, filename)
			if ct == types.Unknown {
				continue
			}
			// Aggressive code-collapse (codeintel Phase 2, ADR-0005):
			// opt-in, exact-span-gated. Runs INSTEAD of the content-
			// preserving CodeCompressor when it fires, independent of the
			// compress_types allow-list (it is its own opt-in). Preview
			// mode records events without changing the body.
			if ct == types.Code && collapse != nil && filename != "" {
				out, evs, fired := collapse(filename, compressInput, i)
				if len(evs) > 0 {
					events = append(events, evs...)
				}
				if fired {
					em.compressedTexts[j] = string(out)
					continue
				}
			}
			if !allow[ct] {
				// V7-19: see openai.go comment — nil-map access
				// returns zero-value so `!allow[ct]` correctly skips
				// per-type compression when buildAllow returned the
				// empty map for compress_types=[].
				continue
			}
			c, ok := registry.Get(ct)
			if !ok {
				continue
			}
			// V7-11 / v1.7.7 marker enrichment: when the per-type
			// compressor implements HintedCompressor (today only
			// LogsCompressor), pre-fetch code-index symbols via the
			// hinter closure and forward filename+symbols through
			// CompressHinted. The hinter's nil-safe inside — buildHints
			// returns the zero CompressHints when the code index is
			// unavailable / stale / not configured, and the compressor
			// degrades to the legacy marker form on the zero hint.
			var out []byte
			if hc, ok := c.(HintedCompressor); ok && buildHints != nil {
				out = hc.CompressHinted(compressInput, buildHints(filename))
			} else {
				out = c.Compress(compressInput)
			}
			if len(out) >= len(body) {
				continue
			}
			em.compressedTexts[j] = string(out)
			events = append(events, Event{
				Mechanism:       string(ct),
				OriginalBytes:   len(body),
				CompressedBytes: len(out),
				MsgIndex:        i,
				BodyHash:        bodyHashHex(body),
			})
		}
	}
	return events
}

// substituteRedundantReads is the C16 (read-cache auto-substitution)
// pass. Walks the tool_result blocks in extracted, and for each Read
// tool_result whose (filename, content-hash) tuple was already seen in
// an earlier block in *this same call*, replaces the inline body with
// a deterministic marker:
//
//	[file <path> unchanged since earlier in this turn; same content already returned]
//
// Per-call scoping is the natural shape: Anthropic's request body
// includes the entire conversation history every turn, so when the
// model re-Reads a file in turn N+1, both turn N's and turn N+1's
// Read tool_results appear in this single Run call. The first
// occurrence stays as-is (it was — and stays — part of the cached
// prefix); the duplicate gets the marker.
//
// Gated on sessionID being non-empty so callers without session
// context (legacy [Pipeline.Run], unit tests) get the previous
// behaviour. The hash is taken on the post-line-numbers-strip bytes
// (matching what types.Detect / per-type compressors see) so a
// `Read` followed by a re-`Read` of the same file at the same hash
// — even with different envelope framing — collapses correctly.
func substituteRedundantReads(extracted []extractedMessage, sessionID string) []Event {
	if sessionID == "" {
		return nil
	}
	type fileKey struct{ filename, hash string }
	seen := map[fileKey]bool{}
	var events []Event
	for i := range extracted {
		em := &extracted[i]
		if len(em.resultBlockIdxs) == 0 {
			continue
		}
		if cap(em.compressedTexts) < len(em.resultBlockIdxs) {
			em.compressedTexts = make([]string, len(em.resultBlockIdxs))
		} else {
			em.compressedTexts = em.compressedTexts[:len(em.resultBlockIdxs)]
		}
		for j, body := range em.resultTexts {
			if body == "" {
				continue
			}
			filename := ""
			if j < len(em.resultFilenames) {
				filename = em.resultFilenames[j]
			}
			if filename == "" {
				continue
			}
			toolName := ""
			if j < len(em.resultToolNames) {
				toolName = em.resultToolNames[j]
			}
			if toolName != "Read" {
				continue
			}
			hashInput := []byte(body)
			if types.IsLineNumbered(hashInput) {
				hashInput = types.StripLineNumbers(hashInput)
			}
			h := sha256.Sum256(hashInput)
			hashHex := hex.EncodeToString(h[:])
			key := fileKey{filename: filename, hash: hashHex}
			if seen[key] {
				marker := formatReadCacheMarker(filename)
				if len(marker) >= len(body) {
					continue
				}
				em.compressedTexts[j] = marker
				events = append(events, Event{
					Mechanism:       "read_cache",
					OriginalBytes:   len(body),
					CompressedBytes: len(marker),
					MsgIndex:        i,
					BodyHash:        bodyHashHex(body),
				})
				continue
			}
			seen[key] = true
		}
	}
	return events
}

// formatReadCacheMarker is the canonical C16 marker form. Deterministic
// per (filename, hash) — same path → same marker bytewise → cross-turn
// invariance preserved.
func formatReadCacheMarker(filename string) string {
	return fmt.Sprintf("[file %s unchanged since earlier in this turn; same content already returned]", filename)
}

// stashLargeBodies writes any tool_result body that's still over the
// threshold (after per-type compression in [compressToolResults]) to
// the content-addressed stash and replaces the inline body with a
// deterministic marker. Mutates `em.compressedTexts` in place,
// returning the per-block stash events for telemetry.
//
// Marker form (deterministic for cross-turn invariance — depends only
// on body bytes, not on call ordering or wall-clock):
//
//	[output 47KB stashed at observer://stash/<sha>; use retrieve_stashed]
//
// Same body in turn N and turn N+1 hashes to the same sha and produces
// the same marker bytewise, so Anthropic's prefix cache hits stay
// intact. The block carrying the SDK's cache_control marker is stashed
// like any other (see [compressToolResults] for why uniform treatment is
// what preserves cross-turn byte-stability).
//
// No-op when stash is nil (the CCR feature is opt-in via
// `compression.conversation.stash.enabled`).
func stashLargeBodies(extracted []extractedMessage, store interface {
	Write(body []byte) (string, error)
}, threshold int,
) []Event {
	if store == nil || threshold <= 0 {
		return nil
	}
	var events []Event
	for i := range extracted {
		em := &extracted[i]
		if len(em.resultBlockIdxs) == 0 {
			continue
		}
		if cap(em.compressedTexts) < len(em.resultBlockIdxs) {
			em.compressedTexts = make([]string, len(em.resultBlockIdxs))
		} else {
			em.compressedTexts = em.compressedTexts[:len(em.resultBlockIdxs)]
		}
		for j := range em.resultTexts {
			// Same MCP-tool-result skip as compressToolResults — never
			// stash structured query data. retrieve_stashed itself
			// returning a stash marker would be catastrophic; same
			// hazard exists for any MCP tool whose response is the
			// actual answer.
			if j < len(em.resultToolNames) && isMCPToolName(em.resultToolNames[j]) {
				continue
			}
			body := em.compressedTexts[j]
			if body == "" {
				body = em.resultTexts[j]
			}
			if len(body) <= threshold {
				continue
			}
			sha, err := store.Write([]byte(body))
			if err != nil {
				continue
			}
			marker := formatStashMarker(len(body), sha)
			if len(marker) >= len(body) {
				continue
			}
			em.compressedTexts[j] = marker
			events = append(events, Event{
				Mechanism:       "stash",
				OriginalBytes:   len(body),
				CompressedBytes: len(marker),
				MsgIndex:        i,
				BodyHash:        bodyHashHex(body),
			})
		}
	}
	return events
}

// isMCPToolName reports whether a tool_use.name belongs to an MCP
// server (Anthropic's MCP convention prefixes such names with
// `mcp__<server>__<tool>`). The proxy's per-type compression and
// stash passes use this to leave MCP tool_results untouched —
// those bodies carry structured query data where the values ARE
// the answer (action_ids, file hashes, cost dollars, stashed
// bytes); compressing them with JSON/code/logs replaces scalars
// with type sentinels and corrupts the response.
func isMCPToolName(name string) bool {
	return strings.HasPrefix(name, "mcp__")
}

// formatStashMarker is the canonical marker form. Exported indirectly
// via the events the pipeline emits — kept here so the marker shape is
// defined once and consumed by both the pipeline and the
// `retrieve_stashed` MCP tool's documentation.
//
// Marker phrasing is deliberately directive after dogfood evidence
// showed the model treating `... use retrieve_stashed` as a status
// note rather than an actionable instruction. The current form
// includes the explicit MCP tool name (`mcp__observer__retrieve_stashed`)
// and the `sha=...` argument shape so the model can recognise it as
// a tool-call template. Pinned by `TestPipeline_StashFires` —
// presence of `mcp__observer__retrieve_stashed` is the load-bearing
// substring (the URL form `observer://stash/<sha>` stays as a
// secondary reference grep target).
//
// Cross-turn invariance: the marker is a pure function of (kb, sha).
// Same body bytes → same kb → same sha → byte-identical marker
// across turns. Anthropic's prefix cache hits stay intact.
func formatStashMarker(bodyBytes int, sha string) string {
	kb := bodyBytes / 1024
	if kb == 0 {
		kb = 1
	}
	return fmt.Sprintf(
		"[output %dKB stashed at observer://stash/%s — to view full content, call mcp__observer__retrieve_stashed with sha=\"%s\"]",
		kb, sha, sha,
	)
}

// compressToolDefinitions strips informational fields from the tools
// array carried in `envelope["tools"]`, mutating the envelope in place.
// Returns the per-tool compression events for telemetry. No-op when the
// envelope has no `tools` field, when the field doesn't unmarshal as a
// JSON array, or when the array is empty.
//
// Two transforms are applied per tool, both content-preserving in the
// sense that the model retains full semantic capability over the tool:
//
//  1. **Top-level description trim** — when `description` contains 3+
//     paragraphs (split on `\n\n`), keep only the first 2. Most multi-
//     paragraph tool descriptions repeat usage hints already encoded in
//     `input_schema`; the first 2 paragraphs reliably carry the "what
//     the tool does" + "primary parameters" content.
//
//  2. **Deep `examples` strip from `input_schema`** — `examples` is a
//     JSON-Schema informational keyword; removing it does not change
//     validation behaviour, parameter names, types, or required-ness.
//     The model loses sample values but retains every other signal the
//     parameter schema carries.
//
// Forbidden — never touched:
//   - tool `name`
//   - `input_schema.type` / `input_schema.properties` keys / nested
//     `type` / `description` / `required` / `enum`
//   - any field outside `description` and `input_schema`
//
// Cross-turn invariance: the transform is a pure function of input
// bytes, so the same tools array compresses byte-identically every
// turn. Anthropic's prefix cache treats `tools` as part of the cached
// prefix, so this compression's value is realised on cache-cold turns
// (or after the cache TTL elapses); on warm turns it produces zero net
// savings on the wire (the tools field is cached either way).
func compressToolDefinitions(envelope map[string]json.RawMessage) []Event {
	rawTools, ok := envelope["tools"]
	if !ok || len(rawTools) == 0 {
		return nil
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil || len(tools) == 0 {
		return nil
	}

	var events []Event
	originalTotal := len(rawTools)
	changed := false

	for i, raw := range tools {
		var tool map[string]json.RawMessage
		if err := json.Unmarshal(raw, &tool); err != nil {
			continue
		}
		toolChanged := false
		toolOriginalLen := len(raw)

		if descRaw, ok := tool["description"]; ok {
			var desc string
			if err := json.Unmarshal(descRaw, &desc); err == nil {
				if trimmed, trimmedOK := trimDescriptionTail(desc); trimmedOK {
					encoded, err := json.Marshal(trimmed)
					if err == nil {
						tool["description"] = encoded
						toolChanged = true
					}
				}
			}
		}

		if schemaRaw, ok := tool["input_schema"]; ok && len(schemaRaw) > 0 {
			var schema any
			if err := json.Unmarshal(schemaRaw, &schema); err == nil {
				if schema, didStrip := stripExamplesDeep(schema); didStrip {
					encoded, err := json.Marshal(schema)
					if err == nil {
						tool["input_schema"] = encoded
						toolChanged = true
					}
				}
			}
		}

		if !toolChanged {
			continue
		}
		newRaw, err := marshalEnvelope(tool)
		if err != nil {
			continue
		}
		tools[i] = newRaw
		changed = true
		events = append(events, Event{
			Mechanism:       "tools",
			OriginalBytes:   toolOriginalLen,
			CompressedBytes: len(newRaw),
			MsgIndex:        -1,
			BodyHash:        bodyHashHex(string(raw)),
		})
	}

	if !changed {
		return nil
	}
	newToolsRaw, err := json.Marshal(tools)
	if err != nil {
		return nil
	}
	if len(newToolsRaw) >= originalTotal {
		// Net no-op (or grew). Restore original to honour the standard
		// `len(out) >= len(body)` short-circuit at the envelope-tools
		// scope.
		return nil
	}
	envelope["tools"] = newToolsRaw
	return events
}

// trimDescriptionTail returns the description trimmed to its first two
// paragraphs (split on a blank line, `\n\n`) when the input has three
// or more paragraphs. Returns (input, false) when nothing was trimmed.
func trimDescriptionTail(desc string) (string, bool) {
	paragraphs := strings.Split(desc, "\n\n")
	if len(paragraphs) < 3 {
		return desc, false
	}
	out := strings.Join(paragraphs[:2], "\n\n")
	if out == desc {
		return desc, false
	}
	return out, true
}

// stripExamplesDeep removes every `examples` key from the value tree
// rooted at v, descending through map values and array elements.
// Returns the (possibly mutated) value and a boolean indicating whether
// any `examples` key was actually removed.
func stripExamplesDeep(v any) (any, bool) {
	stripped := false
	switch x := v.(type) {
	case map[string]any:
		if _, ok := x["examples"]; ok {
			delete(x, "examples")
			stripped = true
		}
		for k, child := range x {
			newChild, did := stripExamplesDeep(child)
			if did {
				x[k] = newChild
				stripped = true
			}
		}
		return x, stripped
	case []any:
		for i, child := range x {
			newChild, did := stripExamplesDeep(child)
			if did {
				x[i] = newChild
				stripped = true
			}
		}
		return x, stripped
	default:
		return v, false
	}
}

// findLastCacheBreakpoint returns the position of the latest
// cache_control marker in the messages array. Walks each message's
// blocks (when content is an array) and tracks the last (msgIdx,
// blockIdx) pair carrying a non-empty CacheControl annotation.
//
// Only messages-level markers count — system-prompt cache_control is
// useful to Anthropic but not relevant for the per-turn compression
// boundary the cache-aware pipeline cares about. The Anthropic SDK
// (Claude Code 2.1+) sets a rolling marker on the last block of the
// last message every turn; this helper is the detection signal.
//
// Returns found=false when no marker is present (cache-cold request,
// non-Anthropic-SDK client). Callers should fall back to the
// non-cache-aware behaviour in that case.
func findLastCacheBreakpoint(extracted []extractedMessage) (msgIdx, blockIdx int, found bool) {
	msgIdx, blockIdx = -1, -1
	for i := range extracted {
		for j, b := range extracted[i].blocks {
			if len(b.CacheControl) > 0 {
				msgIdx, blockIdx, found = i, j, true
			}
		}
	}
	return msgIdx, blockIdx, found
}

// toConversationMessages projects extractedMessage → conversation.Message
// so the scorer + budget enforcer can operate on them. When the message
// carries tool_result blocks, Text reflects the post-pre-compression
// bodies (joined by '\n' for multi-block) and ByteLen is adjusted to
// account for the compression delta so the budget pass sees the actual
// post-compression size on the wire (preventing the budget pass from
// dropping a message whose body is already shrunk).
func toConversationMessages(extracted []extractedMessage) []Message {
	msgs := make([]Message, len(extracted))
	for i, em := range extracted {
		text := em.flatText
		byteLen := len(em.raw)
		if len(em.resultBlockIdxs) > 0 {
			parts := make([]string, len(em.resultBlockIdxs))
			delta := 0
			for j := range em.resultBlockIdxs {
				if j < len(em.compressedTexts) && em.compressedTexts[j] != "" {
					parts[j] = em.compressedTexts[j]
					delta += len(em.compressedTexts[j]) - len(em.resultTexts[j])
				} else {
					parts[j] = em.resultTexts[j]
				}
			}
			text = strings.Join(parts, "\n")
			byteLen = len(em.raw) + delta
			if byteLen < 0 {
				byteLen = 0
			}
		}
		// NoCompress: any tool_result in this message coming from an
		// MCP tool (`mcp__*`) opts the WHOLE message out of per-type
		// compression in the budget enforcer. The joined `text` here
		// concatenates all parallel tool_results, so we can't safely
		// compress some-but-not-others — protect conservatively when
		// any block is MCP.
		noCompress := false
		for _, name := range em.resultToolNames {
			if isMCPToolName(name) {
				noCompress = true
				break
			}
		}
		msgs[i] = Message{
			Role:          normalizeAnthropicRole(em.role, len(em.resultBlockIdxs) > 0),
			Text:          text,
			ByteLen:       byteLen,
			RawIndex:      i,
			Raw:           em.raw,
			ToolUseIDs:    em.toolUseIDs,
			ReferencedIDs: em.referencedIDs,
			NoCompress:    noCompress,
		}
	}
	return msgs
}

// normalizeAnthropicRole maps Anthropic's two roles ("user", "assistant")
// onto the scorer's four-role vocabulary. A user message that carries a
// tool_result block is effectively a tool message — the role-weight
// should reflect that it's mechanically compressible.
func normalizeAnthropicRole(role string, carriesToolResult bool) string {
	if carriesToolResult {
		return RoleTool
	}
	switch role {
	case "user":
		return RoleUser
	case "assistant":
		return RoleAssistant
	case "system":
		return RoleSystem
	}
	return role
}

// serializeAnthropic rebuilds a request body from the original envelope
// plus the post-enforcement Message slice. Messages with Raw != nil pass
// through untouched; messages with Text modified relative to the source
// extracted state have their single tool_result block rewritten to
// contain the compressed body; messages with Raw == nil (the drop-run
// markers) are serialized from scratch as user-role prose.
//
// When cacheBreakpointIdx is in range [0, len(final)), the last content
// block of that message is annotated with
// cache_control: {"type":"ephemeral"} to tell Anthropic's Messages API
// to cache everything up through that block (spec §10 Layer 3). A
// breakpoint of -1 disables injection.
func serializeAnthropic(envelope map[string]json.RawMessage, original []extractedMessage, final []Message, cacheBreakpointIdx int) ([]byte, error) {
	msgs := make([]json.RawMessage, 0, len(final))
	for _, m := range final {
		if m.Raw == nil {
			// Marker message — synthesize a minimal user-role content.
			obj, err := json.Marshal(map[string]any{
				"role":    "user",
				"content": m.Text,
			})
			if err != nil {
				return nil, fmt.Errorf("serializeAnthropic: marshal marker: %w", err)
			}
			msgs = append(msgs, obj)
			continue
		}
		// Raw is non-nil. Decide what to write back.
		em := findByRaw(original, m.Raw)
		if em == nil || len(em.resultBlockIdxs) == 0 {
			msgs = append(msgs, m.Raw)
			continue
		}
		// Resolve per-block bodies. For single-tool_result messages we
		// honour m.Text (Enforce.compressMessage may have shrunk it
		// further than the pre-compression pass did); for multi-block
		// messages we always use em.compressedTexts (Enforce operates
		// on the joined text and can't be safely re-split).
		compressed := make([]string, len(em.resultBlockIdxs))
		anyChange := false
		if len(em.resultBlockIdxs) == 1 {
			if m.Text != em.resultTexts[0] {
				compressed[0] = m.Text
				anyChange = true
			}
		} else {
			for j := range em.resultBlockIdxs {
				if j < len(em.compressedTexts) && em.compressedTexts[j] != "" && em.compressedTexts[j] != em.resultTexts[j] {
					compressed[j] = em.compressedTexts[j]
					anyChange = true
				}
			}
		}
		if !anyChange {
			msgs = append(msgs, m.Raw)
			continue
		}
		rewritten, err := rewriteToolResult(em, compressed)
		if err != nil {
			// On failure, fall back to the original raw — better to
			// forward uncompressed than to corrupt the body.
			msgs = append(msgs, m.Raw)
			continue
		}
		msgs = append(msgs, rewritten)
	}
	if cacheBreakpointIdx >= 0 && cacheBreakpointIdx < len(msgs) {
		if annotated, err := injectCacheControl(msgs[cacheBreakpointIdx]); err == nil {
			msgs[cacheBreakpointIdx] = annotated
		}
		// On failure we leave the message as-is. Anthropic will just
		// skip the cache; nothing else is corrupted.
	}
	envelope["messages"], _ = json.Marshal(msgs)
	return marshalEnvelope(envelope)
}

// injectCacheControl annotates the last content block of an Anthropic
// message JSON with cache_control: {"type":"ephemeral"}. When the
// content is a bare string, it is first upgraded to a one-element
// [{"type":"text","text":"..."}] array so the annotation has somewhere
// to land. Existing cache_control on the target block is preserved
// verbatim. Returns the original bytes unchanged when the shape is not
// recognized so callers can forward safely.
func injectCacheControl(raw json.RawMessage) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw, err
	}
	contentRaw, ok := obj["content"]
	if !ok {
		return raw, nil
	}
	// Try array-of-blocks first — preserve unknown block fields by
	// decoding each block as map[string]any.
	var blocks []map[string]any
	if err := json.Unmarshal(contentRaw, &blocks); err == nil && len(blocks) > 0 {
		last := blocks[len(blocks)-1]
		if _, already := last["cache_control"]; !already {
			last["cache_control"] = map[string]string{"type": "ephemeral"}
		}
		newContent, err := json.Marshal(blocks)
		if err != nil {
			return raw, err
		}
		obj["content"] = newContent
		return marshalEnvelope(obj)
	}
	// Fall back to bare string — upgrade to a text-block array so the
	// cache_control annotation has a valid home.
	var s string
	if err := json.Unmarshal(contentRaw, &s); err == nil {
		upgraded := []map[string]any{{
			"type":          "text",
			"text":          s,
			"cache_control": map[string]string{"type": "ephemeral"},
		}}
		newContent, err := json.Marshal(upgraded)
		if err != nil {
			return raw, err
		}
		obj["content"] = newContent
		return marshalEnvelope(obj)
	}
	// Unknown content shape — leave alone.
	return raw, nil
}

// rewriteToolResult returns a new raw JSON object for the given extracted
// message with each tool_result block's content overwritten by the
// matching entry in compressed (parallel to em.resultBlockIdxs). An
// empty entry leaves the original block's content untouched. All
// non-tool_result blocks and the rest of the message's top-level fields
// are preserved by round-tripping through a map decode.
func rewriteToolResult(em *extractedMessage, compressed []string) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(em.raw, &obj); err != nil {
		return nil, err
	}
	// Map block index → which entry of compressed/resultIsStructureds
	// to apply.
	resultPos := make(map[int]int, len(em.resultBlockIdxs))
	for j, idx := range em.resultBlockIdxs {
		resultPos[idx] = j
	}
	blocks := make([]json.RawMessage, len(em.blocks))
	for i, b := range em.blocks {
		if j, isResult := resultPos[i]; isResult && j < len(compressed) && compressed[j] != "" {
			rewritten, err := marshalToolResultBlock(b, compressed[j], em.resultIsStructureds[j])
			if err != nil {
				return nil, err
			}
			blocks[i] = rewritten
			continue
		}
		raw, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		blocks[i] = raw
	}
	contentBytes, err := json.Marshal(blocks)
	if err != nil {
		return nil, err
	}
	obj["content"] = contentBytes
	return marshalEnvelope(obj)
}

// marshalToolResultBlock rebuilds a single tool_result block with the
// supplied compressed body. When the original body was a structured
// array, the rewrite keeps the array shape with a single text entry;
// otherwise it emits a bare string.
func marshalToolResultBlock(b anthropicBlock, compressed string, structured bool) ([]byte, error) {
	out := map[string]any{
		"type":        "tool_result",
		"tool_use_id": b.ToolUseID,
	}
	if b.IsError != nil {
		out["is_error"] = *b.IsError
	}
	if len(b.CacheControl) > 0 {
		out["cache_control"] = b.CacheControl
	}
	if structured {
		out["content"] = []any{
			map[string]string{"type": "text", "text": compressed},
		}
	} else {
		out["content"] = compressed
	}
	return json.Marshal(out)
}

// marshalEnvelope re-emits a map of json.RawMessage as compact JSON in
// insertion-sorted key order (for determinism) with a stable
// `messages` ordering (already ordered by the caller).
//
// Anthropic is insensitive to top-level key order, but deterministic
// output makes the SHA-256 system_prompt_hash / message_prefix_hash
// stable across proxy restarts — valuable for cache-hit analysis.
func marshalEnvelope(obj map[string]json.RawMessage) ([]byte, error) {
	// json.Encoder sorts string-keyed maps for us, so assemble a plain
	// map of the RawMessage values and let it produce deterministic output.
	tmp := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		tmp[k] = v
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(tmp); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// findByRaw returns the extractedMessage whose raw bytes equal target, or
// nil when not found. Linear scan — request bodies rarely carry more than
// a few dozen messages.
func findByRaw(ex []extractedMessage, target json.RawMessage) *extractedMessage {
	for i := range ex {
		if bytes.Equal(ex[i].raw, target) {
			return &ex[i]
		}
	}
	return nil
}
