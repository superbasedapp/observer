package conversation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/compression/conversation/types"
)

// Gemini generateContent conversation compression.
//
// The Google generateContent wire shape differs from Anthropic/OpenAI in two
// ways that matter here:
//
//   - The conversation lives under `contents[]`, each a {role, parts[]} object
//     (role is "user" | "model"). A single content can mix several parts.
//   - Tool OUTPUTS are `functionResponse` parts ({name, response:{…}}) inside a
//     user-role content — NOT a dedicated role like Anthropic's tool_result
//     block or OpenAI's role:"tool" message. Tool CALLS are `functionCall`
//     parts inside a model-role content.
//
// Scope (valid-JSON-preserving — the floor is "never corrupt the request"):
//   - Compress large STRING VALUES inside `functionResponse.response` (the
//     tool output text — the dominant token cost), gated by compress_types,
//     kept only when the per-type compressor shrinks it. The walk is
//     DEEP-RECURSIVE (v2, 2026-06-27): string leaves at ANY depth of the
//     response value are reached, so nested objects and arrays — the common
//     MCP `response:{content:[{text:…}]}` shape and structured tool outputs —
//     are compressed, not just top-level `{output:…}`. Numbers/bools/null are
//     preserved as raw bytes (no float64 round-trip corruption); only string
//     leaves are ever rewritten, so the result is always valid JSON.
//   - CCR stash (v2): a string leaf still larger than the stash threshold
//     AFTER per-type compression is written to the content-addressed stash and
//     replaced inline with a deterministic marker; the model retrieves the
//     original via the `retrieve_stashed` MCP tool (provider-agnostic — the
//     marker carries the sha, exactly like the OpenAI/Anthropic paths). Gated
//     on a stash being wired (`Pipeline.WithStash`); no-op otherwise.
//   - Trim `tools[].functionDeclarations[]` definitions (description tail +
//     parameters.examples), reusing trimDescriptionTail / stripExamplesDeep.
//   - Plain `text` parts (user/model prose) and `inlineData` parts (base64
//     images) are left verbatim: only functionResponse outputs are reached, so
//     image bytes are never fed to a text compressor.
//   - Byte-stable fast-path: when nothing fires, forward the original body
//     unchanged so Gemini's implicit prefix cache keeps hitting.
//
// Budget drop pass (v3, 2026-06-27 — parity-with-runOpenAI follow-up #1):
// when the post-compression body is still over [BudgetOptions.TargetRatio] of
// the original, the OLDEST complete tool round-trips are dropped, oldest-first,
// down to (best-effort) the target. The drop unit is the Gemini-SAFE one and
// nothing else: an ADJACENT (model-with-only-functionCall-parts,
// user-with-only-functionResponse-parts) pair whose call names exactly match
// the response names (a multiset compare). Dropping that pair is the only shape
// that preserves BOTH of Gemini's hard invariants at once —
//   - PAIRING: every functionCall leaves with its matching functionResponse,
//     so no orphan call (→ "function call … must be followed by a response")
//     and no orphan response (→ "unexpected functionResponse") survives.
//   - ALTERNATION: removing an even-length, opposite-role-endpoint run keeps
//     the surviving user/model sequence strictly alternating. Removing a SINGLE
//     content can never be safe (both its neighbours share the opposite role,
//     so they would collapse into a same-role adjacency → 400), which is why
//     no marker is inserted (a user-role marker would itself break alternation)
//     and single-message drops are never attempted.
// Every other shape (a model turn carrying prose/thinking text, a mismatched
// call/response set, a response split across turns, anything touching the
// preserve-last-N tail or the leading user turn) is KEPT — the pass fails safe
// toward a valid body. A final alternation re-validation is the backstop: if
// the chosen drop set would somehow leave a non-alternating sequence the whole
// pass is abandoned (no drop). See enforceGeminiBudget + docs/compression.md
// §Gemini.
//
// Still deferred (grounded): rolling summarisation. It collapses a PREFIX RANGE
// of contents into one synthetic summary content — an ODD, single-content
// insertion that breaks alternation unless paired with a synthesised model
// turn, and it needs a provider-keyed Summarizer (the factory infra is wired
// for Anthropic/OpenAI auth, not Gemini). The drop pass already reclaims whole-
// round-trip bytes safely without a model call, so rolling-summ stays deferred
// until a Gemini-auth summariser + a paired (summary-user, ack-model)
// insertion are designed. See docs/compression.md §Gemini.

// geminiMinCompressBytes is the floor below which a functionResponse string
// value isn't worth a detect+compress attempt. The per-type compressors
// already short-circuit when they don't shrink, so this only avoids wasted
// work on trivial scalars.
const geminiMinCompressBytes = 64

// geminiPart holds one raw part plus its compressed replacement (nil until a
// pass rewrites it).
type geminiPart struct {
	raw        json.RawMessage
	compressed json.RawMessage
}

// geminiContent is one entry of the request's contents[] array.
type geminiContent struct {
	raw   json.RawMessage
	role  string
	parts []geminiPart
	// dropped marks a content the budget pass removed as part of a
	// complete tool round-trip (see enforceGeminiBudget). serializeGemini
	// skips dropped contents entirely — no marker is emitted because a
	// user-role marker would break Gemini's strict role alternation.
	dropped bool
}

// geminiExtract parses a generateContent request body into its envelope plus
// the decoded contents[]. ok=false when the body isn't a recognizable
// generateContent envelope (no parse, or no contents array) — the caller then
// forwards the body untouched.
func geminiExtract(body []byte) (envelope map[string]json.RawMessage, contents []geminiContent, ok bool) {
	envelope = make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, nil, false
	}
	rawContents, found := envelope["contents"]
	if !found {
		return nil, nil, false
	}
	var items []json.RawMessage
	if err := json.Unmarshal(rawContents, &items); err != nil {
		return nil, nil, false
	}
	contents = make([]geminiContent, 0, len(items))
	for _, item := range items {
		gc := geminiContent{raw: item}
		var obj struct {
			Role  string            `json:"role"`
			Parts []json.RawMessage `json:"parts"`
		}
		if err := json.Unmarshal(item, &obj); err == nil {
			gc.role = obj.Role
			gc.parts = make([]geminiPart, len(obj.Parts))
			for i, p := range obj.Parts {
				gc.parts[i] = geminiPart{raw: p}
			}
		}
		contents = append(contents, gc)
	}
	return envelope, contents, true
}

// geminiStashWriter is the narrow content-addressed sink the response walk
// needs for CCR. *stash.Stash satisfies it. Kept as a local interface so this
// pure-logic file never imports internal/stash directly.
type geminiStashWriter interface {
	Write(body []byte) (string, error)
}

// geminiCompressCtx bundles the per-request dependencies for the recursive
// functionResponse walk so the descent has a clean signature. Copied by value
// into each recursive call; msgIndex is the owning content index, stamped per
// part by compressGeminiFunctionResponses for event attribution.
type geminiCompressCtx struct {
	registry       *Registry
	allow          map[types.ContentType]bool
	buildHints     hinter
	stash          geminiStashWriter // nil disables CCR stash
	stashThreshold int
	msgIndex       int
}

// compressGeminiFunctionResponses deep-compresses the string values inside
// every functionResponse part's `response`, mutating gp.compressed in place.
// Returns the per-leaf events. No-op for parts that aren't functionResponses,
// responses with no compressible string, or when nothing shrinks.
func compressGeminiFunctionResponses(contents []geminiContent, cctx geminiCompressCtx) []Event {
	if cctx.registry == nil {
		return nil
	}
	var events []Event
	for ci := range contents {
		gc := &contents[ci]
		cctx.msgIndex = ci
		for pi := range gc.parts {
			gp := &gc.parts[pi]
			newPart, evs, ok := cctx.compressResponsePart(gp.raw)
			if !ok {
				continue
			}
			gp.compressed = newPart
			events = append(events, evs...)
		}
	}
	return events
}

// compressResponsePart rewrites a single part's functionResponse.response by
// recursively compressing its string leaves. Returns the rewritten part bytes
// + per-leaf events when at least one leaf changed; ok=false otherwise
// (leaving the part untouched). Always returns valid JSON — only string leaves
// are replaced; numbers/bools/null/structure are preserved as raw bytes.
func (cctx geminiCompressCtx) compressResponsePart(raw json.RawMessage) (json.RawMessage, []Event, bool) {
	var part map[string]json.RawMessage
	if err := json.Unmarshal(raw, &part); err != nil {
		return raw, nil, false
	}
	frRaw, isFR := part["functionResponse"]
	if !isFR || len(frRaw) == 0 {
		return raw, nil, false
	}
	var fr map[string]json.RawMessage
	if err := json.Unmarshal(frRaw, &fr); err != nil {
		return raw, nil, false
	}
	respRaw, hasResp := fr["response"]
	if !hasResp || len(respRaw) == 0 {
		return raw, nil, false
	}
	newResp, events, changed := cctx.compressValue(respRaw)
	if !changed {
		return raw, nil, false
	}
	fr["response"] = newResp
	newFR, err := marshalEnvelope(fr)
	if err != nil {
		return raw, nil, false
	}
	part["functionResponse"] = newFR
	newPart, err := marshalEnvelope(part)
	if err != nil {
		return raw, nil, false
	}
	return newPart, events, true
}

// compressValue recursively compresses string leaves of a JSON value. Strings
// are per-type compressed (and CCR-stashed when still oversized); objects and
// arrays are descended; numbers/bools/null are returned as raw bytes (no
// float64 round-trip). The returned bytes are always valid JSON. changed=false
// leaves the input byte-for-byte untouched, so the caller keeps the original.
func (cctx geminiCompressCtx) compressValue(raw json.RawMessage) (json.RawMessage, []Event, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return raw, nil, false
	}
	switch trimmed[0] {
	case '"':
		return cctx.compressStringLeaf(raw)
	case '{':
		return cctx.compressObject(raw)
	case '[':
		return cctx.compressArray(raw)
	default:
		// number / bool / null — preserve raw bytes verbatim.
		return raw, nil, false
	}
}

// compressStringLeaf per-type compresses one string leaf, then CCR-stashes the
// result when it is still over the stash threshold. Emits one event per
// transform (per-type with the detected content type as the mechanism, then
// "stash"). Returns the input unchanged when neither fired.
func (cctx geminiCompressCtx) compressStringLeaf(raw json.RawMessage) (json.RawMessage, []Event, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return raw, nil, false
	}
	if len(s) < geminiMinCompressBytes {
		return raw, nil, false
	}
	out := s
	var events []Event
	if compressed, ct, didShrink := compressGeminiString(s, cctx.registry, cctx.allow, cctx.buildHints); didShrink {
		events = append(events, Event{
			Mechanism:       string(ct),
			OriginalBytes:   len(s),
			CompressedBytes: len(compressed),
			MsgIndex:        cctx.msgIndex,
			BodyHash:        bodyHashHex(s),
		})
		out = compressed
	}
	if cctx.stash != nil && cctx.stashThreshold > 0 && len(out) > cctx.stashThreshold {
		if sha, err := cctx.stash.Write([]byte(out)); err == nil {
			if marker := formatStashMarker(len(out), sha); len(marker) < len(out) {
				events = append(events, Event{
					Mechanism:       "stash",
					OriginalBytes:   len(out),
					CompressedBytes: len(marker),
					MsgIndex:        cctx.msgIndex,
					BodyHash:        bodyHashHex(out),
				})
				out = marker
			}
		}
	}
	if out == s {
		return raw, nil, false
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return raw, nil, false
	}
	return encoded, events, true
}

// compressObject descends into an object value, compressing each field's value
// and rebuilding only when a descendant changed. marshalEnvelope keeps key
// order deterministic + HTML un-escaped.
func (cctx geminiCompressCtx) compressObject(raw json.RawMessage) (json.RawMessage, []Event, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw, nil, false
	}
	var events []Event
	changed := false
	for k, v := range obj {
		nv, evs, ch := cctx.compressValue(v)
		if !ch {
			continue
		}
		obj[k] = nv
		events = append(events, evs...)
		changed = true
	}
	if !changed {
		return raw, nil, false
	}
	newRaw, err := marshalEnvelope(obj)
	if err != nil {
		return raw, nil, false
	}
	return newRaw, events, true
}

// compressArray descends into an array value, compressing each element and
// rebuilding only when a descendant changed.
func (cctx geminiCompressCtx) compressArray(raw json.RawMessage) (json.RawMessage, []Event, bool) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return raw, nil, false
	}
	var events []Event
	changed := false
	for i, v := range arr {
		nv, evs, ch := cctx.compressValue(v)
		if !ch {
			continue
		}
		arr[i] = nv
		events = append(events, evs...)
		changed = true
	}
	if !changed {
		return raw, nil, false
	}
	newRaw, err := marshalGeminiArray(arr)
	if err != nil {
		return raw, nil, false
	}
	return newRaw, events, true
}

// compressGeminiString runs the allow-gated per-type compressor on a single
// string value. Returns the compressed text, the detected content type (for
// event telemetry), and true only when a compressor fired and actually shrank
// the input. Mirrors the detect → strip-line-numbers → compress → shrink-check
// sequence used by the OpenAI path.
func compressGeminiString(s string, registry *Registry, allow map[types.ContentType]bool, buildHints hinter) (string, types.ContentType, bool) {
	input := []byte(s)
	if types.IsLineNumbered(input) {
		input = types.StripLineNumbers(input)
	}
	ct := types.Detect(input, "")
	if ct == types.Unknown || !allow[ct] {
		return "", ct, false
	}
	c, ok := registry.Get(ct)
	if !ok {
		return "", ct, false
	}
	var out []byte
	if hc, ok := c.(HintedCompressor); ok && buildHints != nil {
		out = hc.CompressHinted(input, buildHints(""))
	} else {
		out = c.Compress(input)
	}
	if len(out) >= len(s) {
		return "", ct, false
	}
	return string(out), ct, true
}

// marshalGeminiArray serializes a []json.RawMessage with HTML escaping OFF, so
// untouched sibling elements that contain `<`/`>`/`&` keep their exact bytes
// (the default json.Marshal would rewrite them to < etc.). Mirrors
// marshalEnvelope's encoder for objects, keeping the whole Gemini path
// byte-neutral on the changed turn.
func marshalGeminiArray(arr []json.RawMessage) ([]byte, error) {
	return marshalRawArray(arr)
}

// compressGeminiToolDefinitions trims informational fields from
// tools[].functionDeclarations[], mutating the envelope in place. Returns the
// per-declaration events. Gemini wraps declarations as
// {functionDeclarations:[{name, description, parameters}]} — one level deeper
// than Anthropic's flat tool list. Description-tail trim + deep examples strip
// only; the forbidden list (parameters/properties/required/enum/bounds) is
// never touched. Pure function of input bytes → byte-stable across turns, so
// the tools block stays cache-stable.
func compressGeminiToolDefinitions(envelope map[string]json.RawMessage) []Event {
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
		newRaw, toolEvents, didShrink := compressGeminiToolEntry(raw)
		if didShrink {
			tools[i] = newRaw
			events = append(events, toolEvents...)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	newToolsRaw, err := marshalGeminiArray(tools)
	if err != nil || len(newToolsRaw) >= originalTotal {
		return nil
	}
	envelope["tools"] = newToolsRaw
	return events
}

// compressGeminiToolEntry trims the functionDeclarations of one tools[] entry
// (each carries a functionDeclarations array). Non-declaration entries
// (googleSearch, codeExecution, etc.) pass through unchanged.
func compressGeminiToolEntry(raw json.RawMessage) (json.RawMessage, []Event, bool) {
	var tool map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tool); err != nil {
		return raw, nil, false
	}
	declsRaw, ok := tool["functionDeclarations"]
	if !ok || len(declsRaw) == 0 {
		return raw, nil, false
	}
	var decls []json.RawMessage
	if err := json.Unmarshal(declsRaw, &decls); err != nil || len(decls) == 0 {
		return raw, nil, false
	}
	originalLen := len(raw)
	var events []Event
	changed := false
	for i, dRaw := range decls {
		newDecl, didShrink := compressGeminiDeclaration(dRaw)
		if didShrink {
			decls[i] = newDecl
			changed = true
		}
	}
	if !changed {
		return raw, nil, false
	}
	newDeclsRaw, err := marshalGeminiArray(decls)
	if err != nil {
		return raw, nil, false
	}
	tool["functionDeclarations"] = newDeclsRaw
	newRaw, err := marshalEnvelope(tool)
	if err != nil || len(newRaw) >= originalLen {
		return raw, nil, false
	}
	events = append(events, Event{
		Mechanism:       "tools",
		OriginalBytes:   originalLen,
		CompressedBytes: len(newRaw),
		MsgIndex:        -1,
		BodyHash:        bodyHashHex(string(raw)),
	})
	return newRaw, events, true
}

// compressGeminiDeclaration applies description-tail trim + deep examples
// strip to one functionDeclaration. Returns ok=false when nothing shrank.
func compressGeminiDeclaration(raw json.RawMessage) (json.RawMessage, bool) {
	var decl map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decl); err != nil {
		return raw, false
	}
	originalLen := len(raw)
	changed := false
	if descRaw, ok := decl["description"]; ok {
		var desc string
		if err := json.Unmarshal(descRaw, &desc); err == nil {
			if trimmed, trimmedOK := trimDescriptionTail(desc); trimmedOK {
				if encoded, err := json.Marshal(trimmed); err == nil {
					decl["description"] = encoded
					changed = true
				}
			}
		}
	}
	if paramsRaw, ok := decl["parameters"]; ok && len(paramsRaw) > 0 {
		var params any
		if err := json.Unmarshal(paramsRaw, &params); err == nil {
			if stripped, didStrip := stripExamplesDeep(params); didStrip {
				if encoded, err := json.Marshal(stripped); err == nil {
					decl["parameters"] = encoded
					changed = true
				}
			}
		}
	}
	if !changed {
		return raw, false
	}
	newRaw, err := marshalEnvelope(decl)
	if err != nil || len(newRaw) >= originalLen {
		return raw, false
	}
	return newRaw, true
}

// geminiBudgetOptions carries the size target + tail-preservation knobs the
// Gemini drop pass consults, mirroring the relevant [BudgetOptions] fields.
// Kept as a small value type so enforceGeminiBudget stays a pure transform.
type geminiBudgetOptions struct {
	// TargetRatio caps the post-drop body at this fraction of
	// OriginalBodyBytes. Defaults to 0.85 when outside (0,1), matching
	// Enforce.
	TargetRatio float64
	// PreserveLastN contents are never dropped (the live tail). A value
	// below 1 is clamped to 1 so the final content (the current prompt /
	// latest turn) is always protected.
	PreserveLastN int
	// OriginalBodyBytes is len(body) before any compression — the budget
	// reference. When 0, the sum of content byte-lengths is used instead.
	OriginalBodyBytes int
}

// geminiPartKind classifies one part by its discriminator key and returns the
// inner `name` for functionCall / functionResponse parts. A part is a "call"
// when it carries a functionCall object (a sibling thoughtSignature is
// ignored), a "response" when it carries a functionResponse object, and
// "other" for everything else (text, thought, inlineData, executableCode, …).
func geminiPartKind(raw json.RawMessage) (kind, name string) {
	var part map[string]json.RawMessage
	if err := json.Unmarshal(raw, &part); err != nil {
		return "other", ""
	}
	if fc, ok := part["functionCall"]; ok && len(fc) > 0 {
		return "call", geminiInnerName(fc)
	}
	if fr, ok := part["functionResponse"]; ok && len(fr) > 0 {
		return "response", geminiInnerName(fr)
	}
	return "other", ""
}

// geminiInnerName pulls the `name` field out of a functionCall /
// functionResponse object. Returns "" when absent (still a valid multiset key
// — both sides of a pair are dropped together, so a blank name only ever
// matches a blank name).
func geminiInnerName(raw json.RawMessage) string {
	var obj struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(raw, &obj)
	return obj.Name
}

// geminiCallNames returns the multiset of functionCall names in a model
// content, or nil when the content is NOT a pure tool-call turn: it must be
// role "model", have at least one functionCall part, and have EVERY part be a
// functionCall (a model turn that also carries prose/thinking text or any
// other part is kept — we never drop model output that might be an answer).
func geminiCallNames(gc *geminiContent) map[string]int {
	if gc.role != "model" || len(gc.parts) == 0 {
		return nil
	}
	names := make(map[string]int, len(gc.parts))
	for i := range gc.parts {
		kind, name := geminiPartKind(gc.parts[i].raw)
		if kind != "call" {
			return nil
		}
		names[name]++
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

// geminiResponseNames returns the multiset of functionResponse names in a user
// content, or nil when the content is NOT a pure tool-result turn: it must be
// role "user", have at least one functionResponse part, and have EVERY part be
// a functionResponse (a user turn mixing in prose is kept).
func geminiResponseNames(gc *geminiContent) map[string]int {
	if gc.role != "user" || len(gc.parts) == 0 {
		return nil
	}
	names := make(map[string]int, len(gc.parts))
	for i := range gc.parts {
		kind, name := geminiPartKind(gc.parts[i].raw)
		if kind != "response" {
			return nil
		}
		names[name]++
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

// geminiMultisetEqual reports whether two name→count multisets are identical.
func geminiMultisetEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// geminiIsRoundTrip reports whether (model, user) is a self-contained tool
// round-trip safe to drop as a unit: model is a pure call turn, user is a pure
// response turn, and the call names exactly match the response names. Exact
// (multiset) matching guarantees no functionResponse in `user` pairs with a
// call OUTSIDE `model`, and no call in `model` is answered ELSEWHERE — so
// dropping both leaves zero orphans.
func geminiIsRoundTrip(model, user *geminiContent) bool {
	calls := geminiCallNames(model)
	if calls == nil {
		return false
	}
	resps := geminiResponseNames(user)
	if resps == nil {
		return false
	}
	return geminiMultisetEqual(calls, resps)
}

// geminiContentBytes approximates the serialized byte cost of one content as
// the sum of its (compressed-or-raw) part bytes. Per-content envelope overhead
// (role, braces) is intentionally NOT added: the trigger compares this sum
// against TargetRatio × the FULL request body, so — exactly like Enforce's
// ByteLen convention — the estimate must stay at-or-below true content size,
// otherwise a high ratio (e.g. 0.99) would spuriously read as "over budget".
func geminiContentBytes(gc *geminiContent) int {
	n := 0
	for i := range gc.parts {
		if gc.parts[i].compressed != nil {
			n += len(gc.parts[i].compressed)
		} else {
			n += len(gc.parts[i].raw)
		}
	}
	return n
}

// geminiAlternationValid reports whether the surviving (non-dropped) contents
// form a body Gemini will accept: the first surviving content is role "user"
// and no two consecutive surviving contents share a role. Used as the final
// backstop after the drop selection — pair drops are alternation-safe by
// construction, but a belt-and-braces check means any future edge that breaks
// the sequence aborts the whole pass instead of shipping a 400-bound body.
func geminiAlternationValid(contents []geminiContent) bool {
	prev := ""
	survivors := 0
	for i := range contents {
		if contents[i].dropped {
			continue
		}
		role := contents[i].role
		if survivors == 0 {
			if role != "user" {
				return false
			}
		} else if role == prev {
			return false
		}
		survivors++
		prev = role
	}
	return survivors > 0 // an empty contents[] is itself a 400
}

// enforceGeminiBudget is the Gemini-safe analog of Enforce's drop pass. When
// the post-compression contents exceed the target it drops the OLDEST complete
// tool round-trips (model-call + user-response pairs) oldest-first until under
// target (best-effort), mutating each dropped content's `dropped` flag and
// returning one "drop" event per removed content. It NEVER drops a lone
// content, a tail content (within preserve-last-N), the leading user turn, or
// any non-round-trip shape — and abandons the whole selection if the result
// would not alternate. No-op (nil) when already under target or nothing
// qualifies, so the caller's byte-stable fast-path is preserved.
func enforceGeminiBudget(contents []geminiContent, opts geminiBudgetOptions) []Event {
	if len(contents) < 3 {
		return nil // need at least one round-trip plus a surrounding turn
	}
	ratio := opts.TargetRatio
	if ratio <= 0 || ratio >= 1 {
		ratio = 0.85
	}

	total := 0
	sizes := make([]int, len(contents))
	for i := range contents {
		sizes[i] = geminiContentBytes(&contents[i])
		total += sizes[i]
	}
	budgetRef := total
	if opts.OriginalBodyBytes > 0 {
		budgetRef = opts.OriginalBodyBytes
	}
	target := int(float64(budgetRef) * ratio)
	if total <= target {
		return nil
	}

	preserveN := opts.PreserveLastN
	if preserveN < 1 {
		preserveN = 1 // always protect the final content
	}
	preserveFrom := len(contents) - preserveN

	// Collect droppable round-trip pairs, oldest-first. A pair starts at a
	// model content i and consumes the next content i+1; pairs are disjoint
	// by construction (a model content is never index i+1 of another pair in
	// an alternating sequence), so a simple ascending walk yields a
	// non-overlapping candidate set.
	type pair struct{ model, user int }
	var pairs []pair
	for i := 0; i+1 < len(contents); i++ {
		if i+1 >= preserveFrom {
			break // pair touches the protected tail
		}
		if geminiIsRoundTrip(&contents[i], &contents[i+1]) {
			pairs = append(pairs, pair{model: i, user: i + 1})
		}
	}
	if len(pairs) == 0 {
		return nil
	}
	// oldest (lowest index) first — recency is the dominant value signal.
	sort.SliceStable(pairs, func(a, b int) bool { return pairs[a].model < pairs[b].model })

	var events []Event
	n := float64(len(contents))
	for _, pr := range pairs {
		if total <= target {
			break
		}
		contents[pr.model].dropped = true
		contents[pr.user].dropped = true
		total -= sizes[pr.model] + sizes[pr.user]
		// Recency-style importance: older pairs score lower. Mirrors the
		// Score recency component so the drop event is self-explaining.
		score := float64(pr.model+1) / n
		events = append(
			events,
			Event{Mechanism: "drop", OriginalBytes: sizes[pr.model], CompressedBytes: 0, MsgIndex: pr.model, ImportanceScore: score},
			Event{Mechanism: "drop", OriginalBytes: sizes[pr.user], CompressedBytes: 0, MsgIndex: pr.user, ImportanceScore: score},
		)
	}

	// Backstop: if the surviving sequence somehow doesn't alternate, abandon
	// every drop and report nothing — a valid (larger) body always beats a
	// smaller 400-bound one.
	if !geminiAlternationValid(contents) {
		for i := range contents {
			contents[i].dropped = false
		}
		return nil
	}
	return events
}

// serializeGemini rebuilds the request body from the envelope + contents,
// substituting each part's compressed bytes where a pass produced one. Parts
// and contents that weren't touched keep their exact original bytes (so the
// only byte-level change is the compressed values themselves).
func serializeGemini(envelope map[string]json.RawMessage, contents []geminiContent) ([]byte, error) {
	items := make([]json.RawMessage, 0, len(contents))
	for ci := range contents {
		gc := &contents[ci]
		// Budget pass removed this whole content as half of a tool
		// round-trip — omit it (its paired half is omitted too, so
		// pairing + alternation stay intact).
		if gc.dropped {
			continue
		}
		// Did any part in this content change?
		anyChanged := false
		for pi := range gc.parts {
			if gc.parts[pi].compressed != nil {
				anyChanged = true
				break
			}
		}
		if !anyChanged {
			items = append(items, gc.raw) // untouched — exact original bytes
			continue
		}
		parts := make([]json.RawMessage, len(gc.parts))
		for pi := range gc.parts {
			if gc.parts[pi].compressed != nil {
				parts[pi] = gc.parts[pi].compressed
			} else {
				parts[pi] = gc.parts[pi].raw
			}
		}
		// Rewrite only the parts array on a copy of the content object so
		// sibling fields (role, etc.) are preserved verbatim.
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(gc.raw, &obj); err != nil {
			items = append(items, gc.raw)
			continue
		}
		newParts, err := marshalGeminiArray(parts)
		if err != nil {
			items = append(items, gc.raw)
			continue
		}
		obj["parts"] = newParts
		newContent, err := marshalEnvelope(obj)
		if err != nil {
			items = append(items, gc.raw)
			continue
		}
		items = append(items, newContent)
	}
	newContents, err := marshalGeminiArray(items)
	if err != nil {
		return nil, fmt.Errorf("serializeGemini: marshal contents: %w", err)
	}
	envelope["contents"] = newContents
	return marshalEnvelope(envelope)
}

// geminiBodyValid is a defensive backstop: serializeGemini output must remain
// valid JSON (the ~214KB-class regression guard). Cheap re-validate before the
// pipeline adopts the rewritten body.
func geminiBodyValid(body []byte) bool {
	return json.Valid(bytes.TrimSpace(body))
}
