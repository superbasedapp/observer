package scrub

import (
	"bytes"
	"encoding/json"
)

// forward.go holds the JSON-structure-aware half of the forward-path
// scrub: [Scrubber.ScrubForward] and [Scrubber.ScrubProviderRequest].
//
// Why it exists (lane sr-openai-n2, 2026-11-23): ScrubForward used to run
// [Scrubber.String] over the whole body and accept its output whenever it
// was still valid JSON, falling back to an unmarshal → [Scrubber.JSONValue]
// → re-marshal pass only when String had broken the JSON. Both halves were
// wrong for provider-verified content:
//
//   - The fallback scrubbed every string value IN ISOLATION, so the
//     `"encrypted_content":` key the String shield keys on was no longer in
//     view: an OpenAI Responses reasoning item's Fernet blob was scrubbed
//     like prose, and a urlsafe-base64 run such as `-ak-…` matched the
//     api_key_prefixed row. The upstream then answered every follow-up turn
//     with HTTP 400 "encrypted content could not be verified". The fallback
//     fires whenever ANY string in the body ends in a key=value secret shape
//     (`export GITHUB_TOKEN=x` as the last line of a tool output is enough),
//     because the generic `\S+` rows then run across the closing quote.
//   - The same greedy rows can swallow whole items and still leave valid
//     JSON (`"token: x"},{…reasoning…},{…"hello` collapses into one string),
//     which the old "still valid JSON" check accepted: the reasoning item and
//     the user's next message silently vanished from the forwarded body.
//
// The rule now: String's output is accepted only when it has the SAME JSON
// shape as the input (same tokens in the same order; every delimiter, key
// and literal byte-identical; only ordinary string values may differ; kept
// values byte-identical). Otherwise the body is scrubbed token by token -
// every member NAME and every string value not kept - and only the changed
// tokens are spliced back, so every other byte (key order, escapes, kept
// values) is the client's own.
//
// What is kept byte-exact is deliberately no wider than the scrub it
// replaces (review of fixup/n2-scrub, 2026-11-23):
//
//   - In every mode, a string that is the DIRECT value of a member named
//     literally "encrypted_content" - exactly what String's own shield
//     (shieldFernetEncryptedContent) covers. An array or object under that
//     key, or a key spelled with an escape, is ordinary content.
//   - In provider mode only, the opaque fields in verifiedPositions: a
//     direct string member, by literal name, of an object at one protocol
//     position, never a sibling or a descendant, and never an object inside
//     tool output or tool input (functionResponse, tool_result,
//     tool_use.input are not positions).

// jsonTok kind values.
const (
	tokDelim byte = 'd' // { } [ ]
	tokKey   byte = 'k' // an object member name
	tokStr   byte = 's' // a string value
	tokLit   byte = 'l' // number, true, false, null
)

// jsonTok is one token of a JSON document located by walkJSON.
type jsonTok struct {
	kind byte
	// start/end bound the token in the document; a string's span includes
	// its quotes.
	start, end int
	// parentKey is, for a string value, the nearest enclosing object member
	// name, decoded and inherited through arrays: the key JSONValue's
	// sensitive-key rule consults (a wider match only ever scrubs more).
	parentKey string
	// member is, for a key, its raw (undecoded) name; for a string value
	// that is the DIRECT value of an object member, the raw name of that
	// member. Empty for an array element or a root value.
	member string
	// obj is the index in walkJSON's object list of the object a key or a
	// direct member value belongs to; -1 otherwise.
	obj int
	// keepAlways: a direct string member under the literal
	// alwaysKeptKey. Honoured by both forward scrubs.
	keepAlways bool
	// keepVerified: a direct string member that is an opaque field of a
	// provider-verified object at its protocol position
	// (verifiedPositions). Honoured only by ScrubProviderRequest.
	keepVerified bool
}

// pathStep is one step of a protocol position, from the request's root
// object down: the member to follow, whether its value is an array whose
// DIRECT elements are the objects reached, and the literal "role" such an
// object must carry.
type pathStep struct {
	member string // literal member name in the enclosing object
	array  bool   // the member's value is an array; the object is one of its direct elements
	role   string // required literal "role" string of the object reached; "" = any
}

// verifiedField is one opaque field kept byte-exact at a position.
type verifiedField struct {
	objType string // the object's literal "type" string must equal this; "" = any object at the position
	member  string // the direct string member kept byte-exact
}

// verifiedPosition is one row of the provider-verified table: a protocol
// position where the provider puts content it produced and verifies when
// it is sent back, and the opaque fields there that must reach it
// byte-exact. Scrubbing such a field buys no privacy (the provider wrote
// it and the request is going back to that provider) and changing one byte
// fails the provider's check. Only the named fields are kept; every
// sibling and descendant is scrubbed as usual.
type verifiedPosition struct {
	name   string
	path   []pathStep
	fields []verifiedField
	why    string
}

// verifiedPositions is the table ScrubProviderRequest walks, one row per
// protocol position. Rows are matched by data shape and position, never
// by which tool sent the body. Matching is literal throughout (member
// names, "type" and "role" values compared as raw bytes), so an escaped
// spelling is ordinary content.
var verifiedPositions = []verifiedPosition{
	{
		name:   "openai_responses_input_item",
		path:   []pathStep{{member: "input", array: true}},
		fields: []verifiedField{{member: "encrypted_content"}},
		why:    "OpenAI Responses top-level input[] items (reasoning, compaction, any item carrying encrypted_content): the Fernet blob is decrypted and verified upstream, HTTP 400 \"encrypted content could not be verified\" when one byte differs. The reasoning summary is not verified and is scrubbed.",
	},
	{
		name: "anthropic_assistant_content_block",
		path: []pathStep{{member: "messages", array: true, role: "assistant"}, {member: "content", array: true}},
		fields: []verifiedField{
			{objType: "thinking", member: "thinking"},
			{objType: "thinking", member: "signature"},
			{objType: "redacted_thinking", member: "data"},
		},
		why: "Anthropic thinking blocks in an assistant turn's content[]: the signature covers the thinking text, so both must be byte-exact (\"invalid signature in thinking block\"); redacted_thinking.data is opaque encrypted data.",
	},
	{
		name:   "gemini_model_part",
		path:   []pathStep{{member: "contents", array: true, role: "model"}, {member: "parts", array: true}},
		fields: []verifiedField{{member: "thoughtSignature"}},
		why:    "Gemini native generateContent: a model turn's part carries the thought signature it must be returned with. The part's text and functionCall args are not covered and are scrubbed.",
	},
	{
		name: "gemini_openai_compat_tool_call",
		path: []pathStep{
			{member: "messages", array: true, role: "assistant"},
			{member: "tool_calls", array: true},
			{member: "extra_content"},
			{member: "google"},
		},
		fields: []verifiedField{{member: "thought_signature"}},
		why:    "Gemini through the OpenAI-compatible API: the thought signature rides on an assistant tool call's extra_content.google.",
	},
}

// alwaysKeptKey names the one member whose direct string value
// ScrubForward never rewrites in any mode: the value String already
// shields (shieldFernetEncryptedContent), so both passes agree.
const alwaysKeptKey = "encrypted_content"

// keptKeyNames are the literal member names the splice pass never
// rewrites as a key, so the names a kept value hangs on stay as sent.
// (String cannot change any of them anyway; the set is explicit so a
// future pattern cannot.)
var keptKeyNames = func() map[string]bool {
	m := map[string]bool{alwaysKeptKey: true}
	for _, p := range verifiedPositions {
		for _, f := range p.fields {
			m[f.member] = true
		}
	}
	return m
}()

// verifiedByMember indexes verifiedPositions by kept member name.
var verifiedByMember = func() map[string][]verifiedRef {
	m := make(map[string][]verifiedRef)
	for pi, p := range verifiedPositions {
		for _, f := range p.fields {
			m[f.member] = append(m[f.member], verifiedRef{pos: pi, objType: f.objType})
		}
	}
	return m
}()

type verifiedRef struct {
	pos     int
	objType string
}

// jsonObj is one object of a document as walkJSON saw it: where it hangs
// in the tree and its direct literal "type" / "role" strings.
type jsonObj struct {
	// parent is the enclosing object (through at most one array level), -1
	// for the root object, -2 when the object hangs where no protocol
	// position can (a root array element, an element of a nested array).
	parent int
	// via is the raw name of the parent's member the object hangs under.
	via string
	// inArray: the object is a direct element of the array that is that
	// member's value (false: the object is the member's value itself).
	inArray bool
	// typ and role are the raw bytes of the object's direct string members
	// named literally "type" and "role" ("" when absent).
	typ, role string
}

type jsonFrame struct {
	isObj bool
	// obj: for an object, its index; for an array that is the direct value
	// of an object member, that object's index; else -1.
	obj int
	// key: for an object, its current member name (decoded); for an array,
	// the inherited key (parentKey semantics).
	key string
	// rawKey: for an object, its current member name (raw); for an array
	// that is a direct member value, that member's raw name.
	rawKey    string
	direct    bool // array only: the direct value of an object member
	expectKey bool
}

// walkJSON tokenizes b, which MUST be valid JSON (callers check
// json.Valid first), and marks the kept string values. It allocates one
// token per JSON token.
func walkJSON(b []byte) []jsonTok {
	toks := make([]jsonTok, 0, 64)
	objs := make([]jsonObj, 0, 16)
	stack := make([]jsonFrame, 0, 16)
	inherited := func() string {
		if len(stack) == 0 {
			return ""
		}
		return stack[len(stack)-1].key
	}
	i := 0
	for i < len(b) {
		c := b[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			i++
		case '{':
			toks = append(toks, jsonTok{kind: tokDelim, start: i, end: i + 1, obj: -1})
			o := jsonObj{parent: -2}
			if n := len(stack); n == 0 {
				o.parent = -1
			} else if top := stack[n-1]; top.isObj {
				o.parent, o.via = top.obj, top.rawKey
			} else if top.direct {
				o.parent, o.via, o.inArray = top.obj, top.rawKey, true
			}
			objs = append(objs, o)
			stack = append(stack, jsonFrame{isObj: true, obj: len(objs) - 1, expectKey: true})
			i++
		case '[':
			toks = append(toks, jsonTok{kind: tokDelim, start: i, end: i + 1, obj: -1})
			f := jsonFrame{key: inherited(), obj: -1}
			if n := len(stack); n > 0 && stack[n-1].isObj {
				f.direct, f.obj, f.rawKey = true, stack[n-1].obj, stack[n-1].rawKey
			}
			stack = append(stack, f)
			i++
		case '}', ']':
			toks = append(toks, jsonTok{kind: tokDelim, start: i, end: i + 1, obj: -1})
			if n := len(stack); n > 0 {
				stack = stack[:n-1]
			}
			i++
		case ',':
			if n := len(stack); n > 0 && stack[n-1].isObj {
				stack[n-1].expectKey = true
			}
			i++
		case ':':
			if n := len(stack); n > 0 {
				stack[n-1].expectKey = false
			}
			i++
		case '"':
			end := jsonStringEnd(b, i)
			n := len(stack)
			switch {
			case n > 0 && stack[n-1].isObj && stack[n-1].expectKey:
				raw := string(b[i+1 : end-1])
				stack[n-1].rawKey = raw
				stack[n-1].key = raw
				if bytes.IndexByte(b[i:end], '\\') >= 0 {
					stack[n-1].key = decodeJSONString(b[i:end])
				}
				toks = append(toks, jsonTok{kind: tokKey, start: i, end: end, member: raw, obj: stack[n-1].obj})
			case n > 0 && stack[n-1].isObj:
				f := stack[n-1]
				switch f.rawKey {
				case "type":
					objs[f.obj].typ = string(b[i+1 : end-1])
				case "role":
					objs[f.obj].role = string(b[i+1 : end-1])
				}
				toks = append(toks, jsonTok{kind: tokStr, start: i, end: end, parentKey: f.key, member: f.rawKey, obj: f.obj})
			default:
				toks = append(toks, jsonTok{kind: tokStr, start: i, end: end, parentKey: inherited(), obj: -1})
			}
			i = end
		default:
			j := jsonLiteralEnd(b, i)
			toks = append(toks, jsonTok{kind: tokLit, start: i, end: j, obj: -1})
			i = j
		}
	}
	markKept(toks, objs)
	return toks
}

// markKept sets keepAlways / keepVerified on every direct string member
// value the forward scrub must leave byte-exact.
func markKept(toks []jsonTok, objs []jsonObj) {
	for ti := range toks {
		t := &toks[ti]
		if t.kind != tokStr || t.obj < 0 {
			continue
		}
		if t.member == alwaysKeptKey {
			t.keepAlways = true
		}
		for _, ref := range verifiedByMember[t.member] {
			if ref.objType != "" && objs[t.obj].typ != ref.objType {
				continue
			}
			if atPosition(objs, t.obj, verifiedPositions[ref.pos].path) {
				t.keepVerified = true
				break
			}
		}
	}
}

// atPosition reports whether object o sits exactly at path: walking the
// steps from the last up, each object hangs under the step's member (in
// an array or directly, as the step says) and carries the step's role,
// and the object above the first step is the root.
func atPosition(objs []jsonObj, o int, path []pathStep) bool {
	cur := o
	for k := len(path) - 1; k >= 0; k-- {
		if cur < 0 {
			return false
		}
		step, ob := path[k], objs[cur]
		if ob.via != step.member || ob.inArray != step.array {
			return false
		}
		if step.role != "" && ob.role != step.role {
			return false
		}
		cur = ob.parent
	}
	return cur >= 0 && objs[cur].parent == -1
}

// jsonStringEnd returns the offset just past the closing quote of the
// string whose opening quote is at b[i].
func jsonStringEnd(b []byte, i int) int {
	j := i + 1
	for j < len(b) {
		switch b[j] {
		case '\\':
			j += 2
		case '"':
			return j + 1
		default:
			j++
		}
	}
	return len(b)
}

// jsonLiteralEnd returns the offset just past the number / true / false /
// null literal starting at b[i].
func jsonLiteralEnd(b []byte, i int) int {
	for j := i; j < len(b); j++ {
		switch b[j] {
		case ',', '}', ']', ' ', '\t', '\n', '\r':
			return j
		}
	}
	return len(b)
}

// decodeJSONString decodes a quoted JSON string token.
func decodeJSONString(raw []byte) string {
	if len(raw) >= 2 && bytes.IndexByte(raw, '\\') < 0 {
		return string(raw[1 : len(raw)-1])
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return string(raw)
	}
	return s
}

// encodeJSONString quotes s as a JSON string with HTML escaping off, so a
// rewritten value keeps `<`, `>` and `&` as the client wrote them.
func encodeJSONString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		b, _ := json.Marshal(s)
		return b
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// keepsValue reports whether a string value token must leave the forward
// scrub byte-identical.
func keepsValue(t jsonTok, protectVerified bool) bool {
	return t.keepAlways || (protectVerified && t.keepVerified)
}

// keepsKey reports whether a key token is never rewritten: a literal kept
// member name (keptKeyNames).
func keepsKey(t jsonTok) bool {
	return keptKeyNames[t.member]
}

// sameShape reports whether scrubbed (valid JSON) has the same token
// sequence as raw: every delimiter, key and literal byte-identical, every
// kept value byte-identical; ordinary string values may differ. A body
// whose keys String changed is not the same shape, so it takes the splice
// pass, which scrubs keys itself.
func sameShape(raw, scrubbed []byte, protectVerified bool) bool {
	a := walkJSON(raw)
	b := walkJSON(scrubbed)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.kind != y.kind {
			return false
		}
		if x.kind == tokStr && !keepsValue(x, protectVerified) {
			continue
		}
		if !bytes.Equal(raw[x.start:x.end], scrubbed[y.start:y.end]) {
			return false
		}
	}
	return true
}

// spliceScrub scrubs raw (valid JSON) token by token and splices only the
// changed tokens back. A member name goes through String (a secret used
// as a key is redacted, as String did on the whole body), except a
// literal kept name. A string value not kept follows the
// [Scrubber.JSONValue] rules: under a sensitive key it is redacted whole,
// otherwise it goes through String. Structure and kept values are never
// rewritten.
func (s *Scrubber) spliceScrub(raw []byte, protectVerified bool) []byte {
	toks := walkJSON(raw)
	var out []byte
	last := 0
	for _, t := range toks {
		var next, val string
		switch {
		case t.kind == tokKey && !keepsKey(t):
			val = decodeJSONString(raw[t.start:t.end])
			next = s.String(val)
		case t.kind == tokStr && !keepsValue(t, protectVerified):
			val = decodeJSONString(raw[t.start:t.end])
			if IsSensitiveKey(t.parentKey) {
				next = Redacted
			} else {
				next = s.String(val)
			}
		default:
			continue
		}
		if next == val {
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(raw))
		}
		out = append(out, raw[last:t.start]...)
		out = append(out, encodeJSONString(next)...)
		last = t.end
	}
	if out == nil {
		return raw
	}
	return append(out, raw[last:]...)
}

// scrubForward is the shared body of ScrubForward and
// ScrubProviderRequest.
func (s *Scrubber) scrubForward(raw []byte, protectVerified bool) []byte {
	scrubbed := s.String(string(raw))
	if scrubbed == string(raw) {
		return raw
	}
	if !json.Valid(raw) {
		// Not JSON: best effort, exactly as before.
		return []byte(scrubbed)
	}
	out := []byte(scrubbed)
	if json.Valid(out) && sameShape(raw, out, protectVerified) {
		return out
	}
	return s.spliceScrub(raw, protectVerified)
}

// ScrubProviderRequest is [Scrubber.ScrubForward] for a request body bound
// for an LLM provider, the proxy's forward path: it additionally leaves
// the opaque provider-verified fields byte-exact (verifiedPositions: an
// OpenAI Responses input item's encrypted_content, an assistant turn's
// Anthropic thinking text + signature and redacted_thinking data, a Gemini
// model part's thoughtSignature, an OpenAI-compatible tool call's
// extra_content.google.thought_signature), each only at its protocol
// position and only that field. The provider wrote those fields and the
// request is going back to it, so redacting them protects nothing and
// breaks the provider's verification (OpenAI "encrypted content could not
// be verified", Anthropic "invalid signature in thinking block"). Every
// sibling, every descendant, and every look-alike inside tool output or
// tool input is scrubbed as usual.
//
// Use it only for bodies bound for the provider that produced them. A
// caller that STORES content keeps [Scrubber.ScrubForward], which still
// scrubs thinking text and signatures.
func (s *Scrubber) ScrubProviderRequest(raw []byte) []byte {
	return s.scrubForward(raw, true)
}
