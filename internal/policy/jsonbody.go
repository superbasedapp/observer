package policy

import (
	"encoding/json"
	"errors"
	"strings"
)

// The readable JSON request body of an HTTP client unit (lane sec-gate4
// audit findings 1 and 2). The R-165 route rows that read a body (the
// components apply and teardown routes, the config keys route) judge what
// the server will decode, not the text as typed: a JSON string may spell
// any character as a \u escape, in a value ("minimal") and in a key
// ("reset") alike, and encoding/json matches a key to its field case
// insensitively and keeps the LAST of two equal keys. So the body is
// decoded here, with every member kept (duplicates included, in order),
// and the rows match on the decoded values. A body that is present but
// not exactly one JSON value is undecodable: a row that guards a lowering
// counts it as one that names what it guards (fail closed), and nothing
// that allows (the teardown dry run) ever reads it as allowing.

// jsonKind is the kind of one decoded JSON value.
type jsonKind int

const (
	jsonNull jsonKind = iota
	jsonBool
	jsonNumber
	jsonString
	jsonArray
	jsonObject
)

// jsonNode is one decoded JSON value. An object keeps every member in
// order, duplicate keys included (encoding/json keeps only the last).
type jsonNode struct {
	kind jsonKind
	b    bool
	str  string
	arr  []*jsonNode
	obj  []jsonMember
}

// jsonMember is one object member: the decoded key and its value.
type jsonMember struct {
	key string
	val *jsonNode
}

// maxJSONDepth bounds the nesting the decoder follows; a deeper body is
// undecodable (the server's 64 KiB bodies never need more).
const maxJSONDepth = 64

// errJSONShape is a token stream that is not one well-formed value.
var errJSONShape = errors.New("policy: not one JSON value")

// decodeJSONText decodes text as exactly one JSON value (surrounding
// white space allowed, nothing after it). ok is false for anything else.
func decodeJSONText(text string) (*jsonNode, bool) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	n, err := decodeJSONValue(dec, 0)
	if err != nil {
		return nil, false
	}
	// Nothing but white space may follow the value (the server's decoder
	// reads the first value and ignores the rest).
	if off := dec.InputOffset(); off < 0 || off > int64(len(text)) || strings.TrimSpace(text[off:]) != "" {
		return nil, false
	}
	return n, true
}

// decodeJSONValue reads one value from dec's token stream.
func decodeJSONValue(dec *json.Decoder, depth int) (*jsonNode, error) {
	if depth > maxJSONDepth {
		return nil, errJSONShape
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case nil:
		return &jsonNode{kind: jsonNull}, nil
	case bool:
		return &jsonNode{kind: jsonBool, b: v}, nil
	case json.Number:
		return &jsonNode{kind: jsonNumber, str: v.String()}, nil
	case string:
		return &jsonNode{kind: jsonString, str: v}, nil
	case json.Delim:
		switch v {
		case '[':
			n := &jsonNode{kind: jsonArray}
			for dec.More() {
				e, err := decodeJSONValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				n.arr = append(n.arr, e)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, errJSONShape
			}
			return n, nil
		case '{':
			n := &jsonNode{kind: jsonObject}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errJSONShape
				}
				val, err := decodeJSONValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				n.obj = append(n.obj, jsonMember{key: k, val: val})
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, errJSONShape
			}
			return n, nil
		}
	}
	return nil, errJSONShape
}

// members returns the values of an object's members whose key equals key
// as encoding/json matches a field name (case insensitively), every
// occurrence; nil for a node that is not an object.
func (n *jsonNode) members(key string) []*jsonNode {
	if n == nil || n.kind != jsonObject {
		return nil
	}
	var out []*jsonNode
	for _, m := range n.obj {
		if strings.EqualFold(m.key, key) {
			out = append(out, m.val)
		}
	}
	return out
}

// walkMembers calls fn with the value of every member named key (as
// members matches it) at any depth of n.
func (n *jsonNode) walkMembers(key string, fn func(*jsonNode)) {
	if n == nil {
		return
	}
	switch n.kind {
	case jsonObject:
		for _, m := range n.obj {
			if strings.EqualFold(m.key, key) {
				fn(m.val)
			}
			m.val.walkMembers(key, fn)
		}
	case jsonArray:
		for _, e := range n.arr {
			e.walkMembers(key, fn)
		}
	}
}

// bodyState is what the matcher could read of a request's body.
type bodyState int

const (
	// bodyNone: the unit sends no body the matcher sees.
	bodyNone bodyState = iota
	// bodyDecoded: the body is exactly one JSON value.
	bodyDecoded
	// bodyUndecodable: the body is read from a file, a variable or
	// standard input, is form or item data, is sent in parts, or is not
	// one JSON value.
	bodyUndecodable
)

// curlBodyFlags are curl's options whose value is the request body (a
// leading @ names a file for every one but --data-raw, which
// bodyUnreadable already reports).
var curlBodyFlags = []string{"-d", "--data", "--data-binary", "--data-ascii", "--data-raw", "--json"}

// curlEncodedBodyFlags are curl's body options whose value curl rewrites
// (URL-encoding, multipart): never one JSON value as typed.
var curlEncodedBodyFlags = []string{"--data-urlencode", "-F", "--form", "--form-string"}

// flagValueAt reads option f at args[i]: the separate form (`-d v`), the
// embedded long form (`--data=v`) or an attached short value (`-dv`). n is
// how many words it used, 0 when args[i] is not f.
func flagValueAt(args []string, i int, f string) (string, int) {
	a := args[i]
	switch {
	case a == f:
		if i+1 < len(args) {
			return args[i+1], 2
		}
		return "", 1
	case strings.HasPrefix(f, "--") && strings.HasPrefix(a, f+"="):
		return a[len(f)+1:], 1
	case len(f) == 2 && len(a) > 2 && strings.HasPrefix(a, f):
		return a[2:], 1
	}
	return "", 0
}

// requestBodyTexts returns the body texts an HTTP client unit sends, as
// the lexer left them, and whether some part of the body cannot be read.
func requestBodyTexts(cmd *Command) (texts []string, unreadable bool) {
	if bodyUnreadable(cmd) {
		return nil, true
	}
	args := cmd.Args()
	switch cmd.Base {
	case "curl":
		for i := 0; i < len(args); i++ {
			for _, f := range curlEncodedBodyFlags {
				if _, n := flagValueAt(args, i, f); n > 0 {
					unreadable = true
				}
			}
			for _, f := range curlBodyFlags {
				if v, n := flagValueAt(args, i, f); n > 0 {
					texts = append(texts, v)
					i += n - 1
					break
				}
			}
		}
	case "wget":
		for i := 0; i < len(args); i++ {
			for _, f := range []string{"--post-data", "--body-data"} {
				if v, n := flagValueAt(args, i, f); n > 0 {
					texts = append(texts, v)
					i += n - 1
					break
				}
			}
		}
	case "invoke-webrequest", "invoke-restmethod":
		for i, a := range args {
			name, inline, hasInline := strings.Cut(a, ":")
			if !psParamMatches(name, "body", 2) {
				continue
			}
			if hasInline {
				texts = append(texts, inline)
			} else if i+1 < len(args) {
				texts = append(texts, args[i+1])
			}
		}
	case "http", "https", "xh", "xhs":
		// HTTPie's request items (field=value, field:=json) build a JSON
		// body the matcher does not reassemble; a --raw body is read.
		if v, ok := cmd.FlagValue("--raw"); ok {
			texts = append(texts, v)
		}
		for _, p := range cmd.Positionals() {
			if strings.Contains(p, "=") && !strings.Contains(p, "==") {
				unreadable = true
			}
		}
	}
	return texts, unreadable
}

// requestJSONBody decodes the request body of an HTTP client unit: the
// one helper the body-reading R-165 rows share. Several body texts (curl
// joins repeated -d values with "&") are undecodable.
func requestJSONBody(cmd *Command) (*jsonNode, bodyState) {
	texts, unreadable := requestBodyTexts(cmd)
	if unreadable || len(texts) > 1 {
		return nil, bodyUndecodable
	}
	if len(texts) == 0 {
		return nil, bodyNone
	}
	n, ok := decodeJSONText(texts[0])
	if !ok {
		return nil, bodyUndecodable
	}
	return n, bodyDecoded
}

// bodyMemberLowers reports whether the decoded body of cmd has a member
// named key, at any depth, whose value bad judges as lowering; an
// undecodable body counts. A unit whose body the matcher sees none of
// matches nothing here (the text fallback still reads the command line).
func bodyMemberLowers(cmd *Command, key string, bad func(*jsonNode) bool) bool {
	n, st := requestJSONBody(cmd)
	switch st {
	case bodyUndecodable:
		return true
	case bodyNone:
		return false
	}
	hit := false
	n.walkMembers(key, func(v *jsonNode) {
		if !hit && bad(v) {
			hit = true
		}
	})
	return hit
}

// jsonListNames reports whether v is a list with an entry judge accepts
// (or an entry that is not a string), or is neither a list nor null: the
// server refuses such a body, and a matcher never reads it as harmless.
func jsonListNames(judge func(string) bool) func(*jsonNode) bool {
	return func(v *jsonNode) bool {
		switch v.kind {
		case jsonNull:
			return false
		case jsonArray:
			for _, e := range v.arr {
				if e.kind != jsonString || judge(e.str) {
					return true
				}
			}
			return false
		}
		return true
	}
}

// jsonTrueOrOdd reports a value that is true, or is neither a boolean nor
// null (for a boolean switch such as reset).
func jsonTrueOrOdd(v *jsonNode) bool {
	switch v.kind {
	case jsonNull:
		return false
	case jsonBool:
		return v.b
	}
	return true
}

// jsonStringJudged reports a string value judge accepts, or a value that
// is neither a string nor null.
func jsonStringJudged(judge func(string) bool) func(*jsonNode) bool {
	return func(v *jsonNode) bool {
		switch v.kind {
		case jsonNull:
			return false
		case jsonString:
			return judge(v.str)
		}
		return true
	}
}

// bodyTopLevelTrue reports whether cmd's body decodes to an object whose
// top-level member key (as encoding/json matches it) is present and every
// occurrence of it is the boolean true. Anything else, an undecodable
// body, a duplicate that is not true, the key nested in another field or
// spelled in a header, is false.
func bodyTopLevelTrue(cmd *Command, key string) bool {
	n, st := requestJSONBody(cmd)
	if st != bodyDecoded {
		return false
	}
	vals := n.members(key)
	if len(vals) == 0 {
		return false
	}
	for _, v := range vals {
		if v.kind != jsonBool || !v.b {
			return false
		}
	}
	return true
}
