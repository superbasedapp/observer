package cloudsession

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// jsonedit.go is a small order-preserving JSON tree used to edit a JSON file
// another party owns (the repository's .claude/settings.json) without
// reordering or reformatting what is already there.
//
// The encoder writes the JSON.stringify(value, null, 2) layout that Claude
// Code and most editors write. Before an existing file is edited, the planner
// checks that it ROUND-TRIPS: encode(parse(file)) is byte-identical to the
// file. Only then is an insert followed by a remove guaranteed to give back
// the original bytes; a file in any other layout is refused (or, with
// PlanOptions.Reformat, rewritten in this layout and reported as such).

// jkind is a node kind.
type jkind byte

const (
	jObject jkind = 'o'
	jArray  jkind = 'a'
	jScalar jkind = 's'
)

// jnode is one JSON value. Objects keep their keys in source order.
type jnode struct {
	kind  jkind
	keys  []string // object keys, in order
	vals  []*jnode // object values, parallel to keys
	items []*jnode // array items
	raw   string   // scalar: the encoded literal
}

// errDuplicateKey reports an object with a repeated key, which an
// order-preserving edit cannot represent faithfully.
var errDuplicateKey = errors.New("duplicate object key")

// parseJSON decodes s into an ordered tree. It rejects trailing content.
func parseJSON(s string) (*jnode, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	n, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing content after the JSON value")
	}
	return n, nil
}

func decodeValue(dec *json.Decoder) (*jnode, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			n := &jnode{kind: jObject}
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("object key is %T, not a string", kt)
				}
				if seen[key] {
					return nil, fmt.Errorf("%w %q", errDuplicateKey, key)
				}
				seen[key] = true
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				n.keys = append(n.keys, key)
				n.vals = append(n.vals, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return n, nil
		case '[':
			n := &jnode{kind: jArray}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				n.items = append(n.items, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return n, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %q", t)
	case string:
		return jString(t), nil
	case json.Number:
		return &jnode{kind: jScalar, raw: t.String()}, nil
	case bool:
		if t {
			return &jnode{kind: jScalar, raw: "true"}, nil
		}
		return &jnode{kind: jScalar, raw: "false"}, nil
	case nil:
		return &jnode{kind: jScalar, raw: "null"}, nil
	}
	return nil, fmt.Errorf("unexpected token %T", tok)
}

// jString builds a string scalar, encoded without HTML escaping (as
// JSON.stringify does).
func jString(s string) *jnode {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a Go string always encodes
	return &jnode{kind: jScalar, raw: strings.TrimSuffix(b.String(), "\n")}
}

// jInt builds an integer scalar.
func jInt(v int) *jnode { return &jnode{kind: jScalar, raw: fmt.Sprintf("%d", v)} }

// jObj builds an object from alternating key, value pairs.
func jObj(kv ...any) *jnode {
	n := &jnode{kind: jObject}
	for i := 0; i+1 < len(kv); i += 2 {
		n.keys = append(n.keys, kv[i].(string))
		n.vals = append(n.vals, kv[i+1].(*jnode))
	}
	return n
}

// get returns the value under key (nil when absent or n is not an object).
func (n *jnode) get(key string) *jnode {
	if n == nil || n.kind != jObject {
		return nil
	}
	for i, k := range n.keys {
		if k == key {
			return n.vals[i]
		}
	}
	return nil
}

// set replaces the value under key, appending the key when absent.
func (n *jnode) set(key string, v *jnode) {
	for i, k := range n.keys {
		if k == key {
			n.vals[i] = v
			return
		}
	}
	n.keys = append(n.keys, key)
	n.vals = append(n.vals, v)
}

// del removes key.
func (n *jnode) del(key string) {
	for i, k := range n.keys {
		if k == key {
			n.keys = append(n.keys[:i:i], n.keys[i+1:]...)
			n.vals = append(n.vals[:i:i], n.vals[i+1:]...)
			return
		}
	}
}

// stringValue returns the decoded string of a string scalar.
func (n *jnode) stringValue() (string, bool) {
	if n == nil || n.kind != jScalar || !strings.HasPrefix(n.raw, `"`) {
		return "", false
	}
	var s string
	if err := json.Unmarshal([]byte(n.raw), &s); err != nil {
		return "", false
	}
	return s, true
}

// encode renders n in the JSON.stringify(value, null, 2) layout.
func (n *jnode) encode() string {
	var b strings.Builder
	n.write(&b, "")
	return b.String()
}

func (n *jnode) write(b *strings.Builder, indent string) {
	const step = "  "
	switch n.kind {
	case jObject:
		if len(n.keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range n.keys {
			b.WriteString(indent + step)
			b.WriteString(jString(k).raw)
			b.WriteString(": ")
			n.vals[i].write(b, indent+step)
			if i < len(n.keys)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "}")
	case jArray:
		if len(n.items) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, it := range n.items {
			b.WriteString(indent + step)
			it.write(b, indent+step)
			if i < len(n.items)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "]")
	default:
		b.WriteString(n.raw)
	}
}

// jsonDoc is a parsed file plus what is needed to write it back the way it
// was: whether it ended in a newline, and whether it round-trips at all.
type jsonDoc struct {
	root            *jnode
	trailingNewline bool
	roundTrips      bool
}

// loadJSONDoc parses content as a JSON document.
func loadJSONDoc(content string) (jsonDoc, error) {
	root, err := parseJSON(content)
	if err != nil {
		return jsonDoc{}, err
	}
	d := jsonDoc{root: root, trailingNewline: strings.HasSuffix(content, "\n")}
	d.roundTrips = d.render() == content
	return d, nil
}

// render writes the document back.
func (d jsonDoc) render() string {
	out := d.root.encode()
	if d.trailingNewline {
		out += "\n"
	}
	return out
}
