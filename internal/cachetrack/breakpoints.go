package cachetrack

import (
	"encoding/json"
	"strings"
)

// EnumerateAnthropicBlocks walks an Anthropic Messages API request
// body and returns (a) the ordered flat block list across
// tools → system → messages (the chain order), and (b) the
// breakpoint set (every block carrying an explicit cache_control
// marker, with its TTL tier resolved).
//
// Per R1(a) live capture (2026-06-08): Claude Code 2.1+ uses
// EXPLICIT per-block markers on `system[]` and
// `messages[].content[]` blocks — not a top-level automatic
// `cache_control` key. A typical request carries 3 of 4 max
// breakpoints (2 system + 1 rolling last-message). Tools blocks
// carry zero own markers but are cached under the first system
// breakpoint via the provider's hierarchy.
//
// This function is the shared Tier-1 SEAM for the proxy's
// requestShape — the compression pipeline reads cache_control on
// its own internal types; cachetrack reads them through this
// helper. Both paths consume the same JSON shape; only one of
// them WRITES markers (the compression pipeline). Per Module
// rules 1/2: this is the lift the spec §8 calls for, replacing
// a cachetrack-side scan of the messages array for the last
// marker (which would miss the system markers).
//
// The function deliberately accepts already-extracted top-level
// fields (raw.Tools / raw.System / raw.Messages) rather than the
// whole body, so the proxy's existing single-pass parseRequest
// can call this without re-parsing the envelope.
func EnumerateAnthropicBlocks(toolsRaw []json.RawMessage, systemRaw json.RawMessage, messagesRaw []json.RawMessage) ([]ObserveBlock, []ObserveBreakpoint) {
	var blocks []ObserveBlock
	var breakpoints []ObserveBreakpoint

	// Tools — each tool definition is one block; cache_control
	// at the top level of the tool object marks the breakpoint.
	for _, t := range toolsRaw {
		canon, marker, ttl := canonicalizeAndDetectMarker(t)
		idx := len(blocks)
		blocks = append(blocks, ObserveBlock{
			Level:          LevelTools,
			Kind:           "tool",
			CanonicalBytes: canon,
			RawBytes:       cloneRawBytes(t),
			Role:           "tool",
			MarkerPresent:  marker,
			TTL:            ttl,
		})
		if marker {
			breakpoints = append(breakpoints, ObserveBreakpoint{
				BlockIndex: idx,
				Level:      LevelTools,
				TTL:        ttl,
			})
		}
	}

	// System — either a bare string (one synthetic block) or an
	// array of blocks, each possibly with cache_control.
	//
	// Claude Code 2.1.169+ prepends a per-request telemetry block
	// of the form
	//
	//   {"type":"text","text":"x-anthropic-billing-header: cc_version=...; cc_entrypoint=...; cch=<nonce>;"}
	//
	// whose `cch=<nonce>` segment changes EVERY request. Anthropic
	// excludes it from its prefix-cache identity (proven by the
	// provider hitting cache despite the nonce churn). If we
	// include it in our chain hash, every turn produces a different
	// system-level hash and §7 row 5 fires a spurious
	// system_changed → invalidation_rewrite, mislabeling every
	// healthy warm turn (the 39326aa9 / f81cec3f / 386ff48f soaks
	// all exhibited this; localized via the calibrate-log sidecar
	// in commit b9f0f6c). Skip it here so it never enters a segment
	// or the cumulative chain — same shape as the
	// canonicalize-side cache_control strip: identity-neutral wire
	// content, identity-neutral hash content.
	systemBlocks := decodeSystemBlocks(systemRaw)
	for _, sb := range systemBlocks {
		if isProviderExcludedSystemBlock(sb) {
			continue
		}
		canon, marker, ttl := canonicalizeAndDetectMarker(sb)
		idx := len(blocks)
		kind := extractTypeField(sb)
		if kind == "" {
			kind = "text"
		}
		blocks = append(blocks, ObserveBlock{
			Level:          LevelSystem,
			Kind:           kind,
			CanonicalBytes: canon,
			RawBytes:       cloneRawBytes(sb),
			Role:           "system",
			MarkerPresent:  marker,
			TTL:            ttl,
		})
		if marker {
			breakpoints = append(breakpoints, ObserveBreakpoint{
				BlockIndex: idx,
				Level:      LevelSystem,
				TTL:        ttl,
			})
		}
	}

	// Messages — each message has content[], either a string or
	// an array of blocks. Each block may carry cache_control.
	for _, mraw := range messagesRaw {
		var msg struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(mraw, &msg); err != nil {
			continue
		}
		contentBlocks := decodeMessageContentBlocks(msg.Content)
		for _, cb := range contentBlocks {
			canon, marker, ttl := canonicalizeAndDetectMarker(cb)
			idx := len(blocks)
			kind := extractTypeField(cb)
			if kind == "" {
				kind = "text"
			}
			blocks = append(blocks, ObserveBlock{
				Level:          LevelMessage,
				Kind:           kind,
				CanonicalBytes: canon,
				RawBytes:       cloneRawBytes(cb),
				Role:           msg.Role,
				MarkerPresent:  marker,
				TTL:            ttl,
			})
			if marker {
				breakpoints = append(breakpoints, ObserveBreakpoint{
					BlockIndex: idx,
					Level:      LevelMessage,
					TTL:        ttl,
				})
			}
		}
	}

	return blocks, breakpoints
}

// canonicalizeAndDetectMarker strips cache_control from a single
// block's raw JSON, returns the canonical hash bytes (via
// CanonicalizeAnthropic — the C2 seam) AND reports whether the
// raw carried a marker, plus its TTL tier.
func canonicalizeAndDetectMarker(raw json.RawMessage) (canonical []byte, markerPresent bool, ttl BlockTTL) {
	if len(raw) == 0 {
		return nil, false, TTLUnset
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return raw, false, TTLUnset
	}
	if ccRaw, ok := probe["cache_control"]; ok && len(ccRaw) > 0 && string(ccRaw) != "null" {
		markerPresent = true
		ttl = decodeCacheControlTTL(ccRaw)
	}
	canon, err := CanonicalizeAnthropic(raw)
	if err != nil {
		return raw, markerPresent, ttl
	}
	return canon, markerPresent, ttl
}

// decodeCacheControlTTL reads `{"type":"ephemeral","ttl":"1h"}` and
// returns the TTL tier. Absent/empty ttl field → 5m (the provider
// default for ephemeral); "1h" → 1h. Unrecognized values → 5m.
func decodeCacheControlTTL(cc json.RawMessage) BlockTTL {
	var obj struct {
		Type string `json:"type"`
		TTL  string `json:"ttl"`
	}
	if err := json.Unmarshal(cc, &obj); err != nil {
		return TTL5m
	}
	switch obj.TTL {
	case "1h":
		return TTL1h
	case "5m", "":
		return TTL5m
	}
	return TTL5m
}

// decodeSystemBlocks handles both string and array forms of the
// `system` field. A bare string is treated as one synthesized
// text block whose raw JSON is the string-quoted form.
func decodeSystemBlocks(raw json.RawMessage) []json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	trimmed := skipLeadingWhitespace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil
		}
		return arr
	case '"':
		// A bare string: synthesize a single text block carrying
		// the string verbatim. The synthesized block's canonical
		// bytes embed the string, so hash stability holds even
		// when the request shape evolves.
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil
		}
		synth, _ := json.Marshal(map[string]string{"type": "text", "text": s})
		return []json.RawMessage{synth}
	}
	return nil
}

// decodeMessageContentBlocks handles both string and array forms
// of a message's `content` field, mirroring decodeContent in the
// claudecode adapter but operating on json.RawMessage to keep
// the canonical-bytes round-trip stable.
func decodeMessageContentBlocks(raw json.RawMessage) []json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	trimmed := skipLeadingWhitespace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil
		}
		return arr
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil
		}
		synth, _ := json.Marshal(map[string]string{"type": "text", "text": s})
		return []json.RawMessage{synth}
	}
	return nil
}

// extractTypeField returns the value of the top-level "type" key
// on a block's raw JSON, or "" when absent or unparseable.
func extractTypeField(raw json.RawMessage) string {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return ""
	}
	return probe.Type
}

// billingHeaderTextPrefix names the per-request telemetry block
// Claude Code 2.1.169+ prepends to the system array. The full text
// looks like
//
//	x-anthropic-billing-header: cc_version=2.1.169.715; cc_entrypoint=sdk-cli; cch=<NONCE>;
//
// where `cch=<NONCE>` changes every request. Anthropic's prefix-
// cache identity EXCLUDES this block (proven empirically: warm
// turns hit cache despite the nonce churn), so the chain hash
// must exclude it too. Match on the prefix rather than the whole
// string so changes to cc_version / cc_entrypoint don't bypass
// the filter.
const billingHeaderTextPrefix = "x-anthropic-billing-header:"

// isProviderExcludedSystemBlock reports whether a system-array
// block is identity-neutral on the provider side and must therefore
// be skipped on the hash side. Currently the only known case is
// Claude Code's per-request billing-header text block; the function
// is named generically so additional provider-excluded telemetry
// blocks (Anthropic or otherwise) can be folded in without renaming.
//
// Non-text blocks and parse failures fall through (return false).
// The check uses a small struct probe rather than the full
// canonicalize path so it stays cheap on the hot path.
func isProviderExcludedSystemBlock(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var probe struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	if probe.Type != "text" {
		return false
	}
	return strings.HasPrefix(probe.Text, billingHeaderTextPrefix)
}

// cloneRawBytes returns a defensive copy of a json.RawMessage so
// the caller can store it past the parseRequest scope without
// risking later mutation of the parent body buffer. Cheap
// (per-block sizes are small; tools blocks <5 KB typical) and
// avoids subtle "RawMessage points into a reused buffer" bugs
// when the proxy hands ObserveBlock slices to the engine which
// then hands them to async sinks. Engine consumers must NOT
// mutate b.RawBytes.
func cloneRawBytes(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out
}

// skipLeadingWhitespace returns raw[i:] where i is the first
// non-whitespace byte; protects the first-byte switch against
// pretty-printed input.
func skipLeadingWhitespace(raw json.RawMessage) json.RawMessage {
	for i, b := range raw {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			return raw[i:]
		}
	}
	return nil
}
