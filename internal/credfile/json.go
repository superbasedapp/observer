package credfile

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"sort"
)

// jsonMember is one member of a JSON object, as byte offsets into the
// source: prevEnd is where the previous value (or the '{') ended, keyStart
// the key's opening quote, valueStart/valueEnd the value.
type jsonMember struct {
	key                                     string
	prevEnd, keyStart, valueStart, valueEnd int
	raw                                     json.RawMessage
}

// scanObject locates every member of the JSON object in b. open is the index
// of the '{'. It refuses anything but a single object.
func scanObject(b []byte) (members []jsonMember, open int, err error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, 0, ErrPatch
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, 0, ErrPatch
	}
	open = int(dec.InputOffset()) - 1
	prev := int(dec.InputOffset())
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, 0, ErrPatch
		}
		key, ok := kt.(string)
		if !ok {
			return nil, 0, ErrPatch
		}
		keyEnd := int(dec.InputOffset())
		q := bytes.IndexByte(b[prev:keyEnd], '"')
		if q < 0 {
			return nil, 0, ErrPatch
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, 0, ErrPatch
		}
		end := int(dec.InputOffset())
		start := end - len(raw)
		if start < keyEnd || !bytes.Equal(b[start:end], raw) {
			return nil, 0, ErrPatch
		}
		members = append(members, jsonMember{key: key, prevEnd: prev, keyStart: prev + q, valueStart: start, valueEnd: end, raw: raw})
		prev = end
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, 0, ErrPatch
	}
	return members, open, nil
}

// SpliceObject rewrites the JSON object orig so its members equal next: an
// unchanged member keeps its exact source bytes and position, a changed one
// has only its value replaced, a removed one is cut out with its separator,
// and a new one is appended after the last member (sorted among the new
// ones). The result is verified to decode to exactly next, or ErrPatch is
// returned. An empty orig is an empty object.
func SpliceObject(orig []byte, next map[string]json.RawMessage) ([]byte, error) {
	if len(bytes.TrimSpace(orig)) == 0 {
		orig = []byte("{}\n")
	}
	members, open, err := scanObject(orig)
	if err != nil {
		return nil, err
	}
	unit := "  "
	if len(members) > 0 {
		lead := orig[members[0].prevEnd:members[0].keyStart]
		if i := bytes.LastIndexByte(lead, '\n'); i >= 0 && len(lead[i+1:]) > 0 {
			unit = string(lead[i+1:])
		}
	}
	// A rendered (changed or added) member follows the file's own line
	// ending, so a CRLF file stays CRLF when one member changes (T-407).
	nl := []byte(LineEnding(orig))
	render := func(v json.RawMessage) []byte {
		var buf bytes.Buffer
		if json.Indent(&buf, v, unit, unit) != nil {
			return v
		}
		return bytes.ReplaceAll(buf.Bytes(), []byte("\n"), nl)
	}

	var out []byte
	out = append(out, orig[:open+1]...)
	written := 0
	seen := map[string]bool{}
	for _, m := range members {
		seen[m.key] = true
		v, keep := next[m.key]
		if !keep {
			continue
		}
		lead := orig[m.prevEnd:m.keyStart]
		if i := bytes.IndexByte(lead, ','); i >= 0 {
			lead = append(append([]byte{}, lead[:i]...), lead[i+1:]...)
		}
		if written > 0 {
			out = append(out, ',')
		}
		out = append(out, lead...)
		out = append(out, orig[m.keyStart:m.valueStart]...)
		// An unchanged value keeps its source bytes even when the caller
		// re-encoded it (key order, spacing): rewriting an unchanged value
		// is still a change to the user's file (T-407).
		if bytes.Equal(m.raw, v) || SameJSON(m.raw, v) {
			out = append(out, m.raw...)
		} else {
			out = append(out, render(v)...)
		}
		written++
	}
	var added []string
	for k := range next {
		if !seen[k] {
			added = append(added, k)
		}
	}
	sort.Strings(added)
	for _, k := range added {
		if written > 0 {
			out = append(out, ',')
		}
		kk, err := json.Marshal(k)
		if err != nil {
			return nil, ErrPatch
		}
		out = append(out, nl...)
		out = append(out, unit...)
		out = append(out, kk...)
		out = append(out, ':', ' ')
		out = append(out, render(next[k])...)
		written++
	}
	tailFrom := open + 1
	if len(members) > 0 {
		tailFrom = members[len(members)-1].valueEnd
	}
	tail := orig[tailFrom:]
	if len(members) == 0 && written > 0 {
		tail = append(append([]byte{}, nl...), bytes.TrimLeft(tail, " \t\r\n")...)
	}
	out = append(out, tail...)

	got := map[string]json.RawMessage{}
	if json.Unmarshal(out, &got) != nil || len(got) != len(next) {
		return nil, ErrPatch
	}
	for k, v := range next {
		if !JSONEqual(got[k], v) {
			return nil, ErrPatch
		}
	}
	return out, nil
}

// SetObjectMember is SpliceObject for one member of the object orig: it sets
// key to value (present) or removes it (!present), keeping every other
// member's bytes. When orig holds the member already and value decodes to
// the same JSON, orig is returned unchanged.
func SetObjectMember(orig []byte, key string, value json.RawMessage, present bool) ([]byte, error) {
	next := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(orig)) > 0 {
		if json.Unmarshal(orig, &next) != nil {
			return nil, ErrPatch
		}
	}
	if present {
		if cur, ok := next[key]; ok && JSONEqual(cur, value) {
			return orig, nil
		}
		next[key] = value
	} else {
		if _, ok := next[key]; !ok {
			return orig, nil
		}
		delete(next, key)
	}
	return SpliceObject(orig, next)
}

// SameJSON reports whether two JSON documents hold the same value: key
// order and whitespace are ignored, numbers compare by their literal text
// (no float64 round-trip, so two large integers that differ never compare
// equal) and arrays by order. A document that does not decode to exactly
// one value is never the same as anything.
func SameJSON(a, b []byte) bool {
	x, okx := decodeExact(a)
	y, oky := decodeExact(b)
	return okx && oky && reflect.DeepEqual(x, y)
}

func decodeExact(b []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}

// LineEnding is the line ending a text file mostly uses: "\r\n" when more
// of its line breaks are CRLF than bare LF, "\n" otherwise (an empty or
// single-line file included).
func LineEnding(b []byte) string {
	crlf := bytes.Count(b, []byte("\r\n"))
	if crlf > 0 && crlf*2 > bytes.Count(b, []byte("\n")) {
		return "\r\n"
	}
	return "\n"
}

// WithLineEnding returns body with every line break written in the line
// ending orig mostly uses, so a rewrite never flips a file between CRLF and
// LF. JSON escapes carriage returns and line feeds inside strings, so for a
// JSON body this only touches whitespace.
func WithLineEnding(orig, body []byte) []byte {
	lf := bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
	if LineEnding(orig) == "\n" {
		return lf
	}
	return bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
}

// JSONEqual compares two JSON values semantically (key order and spacing
// ignored).
func JSONEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}

// ObjectMembers returns only the named top-level members of the JSON object
// orig, as their source bytes (D16 / D9: a member-only read of a
// credential-bearing file). A name the object does not hold is absent from
// the result. Anything but a single object is ErrPatch. The other members are
// scanned for their extent only; none is returned.
func ObjectMembers(orig []byte, keys ...string) (map[string]json.RawMessage, error) {
	members, _, err := scanObject(orig)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	out := map[string]json.RawMessage{}
	for _, m := range members {
		if want[m.key] {
			out[m.key] = m.raw
		}
	}
	return out, nil
}

// ObjectKeys returns the member names of the JSON object orig, in source
// order, and none of their values. Anything but a single object is ErrPatch.
func ObjectKeys(orig []byte) ([]string, error) {
	members, _, err := scanObject(orig)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.key)
	}
	return out, nil
}

// IsObject reports whether raw holds a JSON object (it is not decoded).
func IsObject(raw []byte) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '{'
}

// ObjectPath returns the member at path (object keys, outermost first) and
// whether every step exists. A step that is not an object, or a source that
// is not one, is ErrPatch.
func ObjectPath(orig []byte, path []string) (json.RawMessage, bool, error) {
	cur := json.RawMessage(orig)
	for _, k := range path {
		got, err := ObjectMembers(cur, k)
		if err != nil {
			return nil, false, err
		}
		v, ok := got[k]
		if !ok {
			return nil, false, nil
		}
		cur = v
	}
	return cur, true, nil
}

// SetObjectPath is SetObjectMember for a nested member: it sets the member at
// path (object keys, outermost first) to value (present) or removes it
// (!present). Only the innermost object is spliced; every enclosing object
// keeps its bytes except for the one value that changed, so a sibling at any
// level (another provider's settings, its key) keeps its exact bytes and
// position. A missing intermediate object is created when setting and the
// removal is a no-op when it is absent. The result is verified to decode to
// the original document with only path changed, or ErrPatch is returned.
func SetObjectPath(orig []byte, path []string, value json.RawMessage, present bool) ([]byte, error) {
	if len(path) == 0 {
		return nil, ErrPatch
	}
	out, err := setObjectPath(orig, path, value, present)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(out, orig) {
		return orig, nil
	}
	want, ok := decodeExact(orig)
	if len(bytes.TrimSpace(orig)) == 0 {
		want, ok = map[string]any{}, true
	}
	if !ok {
		return nil, ErrPatch
	}
	var v any
	if present {
		if v, ok = decodeExact(value); !ok {
			return nil, ErrPatch
		}
	}
	if !setDecodedPath(want, path, v, present) {
		return nil, ErrPatch
	}
	got, ok := decodeExact(out)
	if !ok || !reflect.DeepEqual(got, want) {
		return nil, ErrPatch
	}
	return out, nil
}

// setObjectPath does SetObjectPath's splice without the final verification.
func setObjectPath(orig []byte, path []string, value json.RawMessage, present bool) ([]byte, error) {
	if t := bytes.TrimSpace(orig); len(t) > 0 && t[0] != '{' {
		return nil, ErrPatch // a step on the path holds something other than an object
	}
	if len(path) == 1 {
		return SetObjectMember(orig, path[0], value, present)
	}
	if len(bytes.TrimSpace(orig)) == 0 {
		orig = []byte("{}\n")
	}
	members, _, err := scanObject(orig)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		if m.key != path[0] {
			continue
		}
		inner, err := setObjectPath(m.raw, path[1:], value, present)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(inner, m.raw) {
			return orig, nil
		}
		out := append([]byte{}, orig[:m.valueStart]...)
		out = append(out, inner...)
		return append(out, orig[m.valueEnd:]...), nil
	}
	if !present {
		return orig, nil
	}
	// The member is absent: build the missing objects and add the outermost
	// one as a new member.
	nested := value
	for i := len(path) - 1; i >= 1; i-- {
		b, err := json.Marshal(map[string]json.RawMessage{path[i]: nested})
		if err != nil {
			return nil, ErrPatch
		}
		nested = b
	}
	return SetObjectMember(orig, path[0], nested, true)
}

// setDecodedPath applies a SetObjectPath edit to a decoded document, so the
// splice can be checked against it. It reports false when a step on the path
// is not an object.
func setDecodedPath(doc any, path []string, v any, present bool) bool {
	m, ok := doc.(map[string]any)
	if !ok {
		return false
	}
	for _, k := range path[:len(path)-1] {
		next, exists := m[k]
		if !exists {
			if !present {
				return true
			}
			child := map[string]any{}
			m[k] = child
			m = child
			continue
		}
		if m, ok = next.(map[string]any); !ok {
			return false
		}
	}
	last := path[len(path)-1]
	if present {
		m[last] = v
	} else {
		delete(m, last)
	}
	return true
}
