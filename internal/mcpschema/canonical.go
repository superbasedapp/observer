package mcpschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Options bounds the $ref resolution. The zero value takes the defaults.
type Options struct {
	// MaxRefDepth is the maximum nesting of resolved references (a $ref whose
	// target contains a $ref, and so on). Default 8.
	MaxRefDepth int
	// MaxRefExpansions is the maximum total number of $ref substitutions in
	// one document. Default 256.
	MaxRefExpansions int
}

const (
	defaultMaxRefDepth      = 8
	defaultMaxRefExpansions = 256
)

func (o Options) withDefaults() Options {
	if o.MaxRefDepth <= 0 {
		o.MaxRefDepth = defaultMaxRefDepth
	}
	if o.MaxRefExpansions <= 0 {
		o.MaxRefExpansions = defaultMaxRefExpansions
	}
	return o
}

// Sentinel errors. Callers match with errors.Is.
var (
	// ErrInvalidJSON reports a document that is not valid JSON.
	ErrInvalidJSON = errors.New("mcpschema: invalid JSON")
	// ErrRefCycle reports a $ref that (transitively) references itself.
	ErrRefCycle = errors.New("mcpschema: $ref cycle")
	// ErrRefDepth reports a $ref nesting deeper than Options.MaxRefDepth.
	ErrRefDepth = errors.New("mcpschema: $ref depth exceeded")
	// ErrRefBudget reports more $ref expansions than Options.MaxRefExpansions.
	ErrRefBudget = errors.New("mcpschema: $ref expansion budget exceeded")
	// ErrRefTarget reports a local $ref whose JSON pointer does not resolve.
	ErrRefTarget = errors.New("mcpschema: $ref target not found")
)

// Canonicalize returns the canonical form of one JSON document (doc.go
// "Canonical form"). A nil or empty document canonicalizes to "null".
func Canonicalize(raw []byte, opts Options) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("null"), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidJSON, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the document", ErrInvalidJSON)
	}
	r := &resolver{root: v, opts: opts.withDefaults()}
	resolved, err := r.resolve(v, 0, nil)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, resolved); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// resolver performs the bounded inline substitution of local $ref pointers.
type resolver struct {
	root       any
	opts       Options
	expansions int
}

// resolve walks v; stack holds the pointers currently being expanded (cycle
// detection), depth the current nesting of expansions.
func (r *resolver) resolve(v any, depth int, stack []string) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		if ref, ok := t["$ref"].(string); ok && strings.HasPrefix(ref, "#") {
			return r.expand(t, ref, depth, stack)
		}
		out := make(map[string]any, len(t))
		for k, child := range t {
			c, err := r.resolve(child, depth, stack)
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			c, err := r.resolve(child, depth, stack)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	default:
		return v, nil
	}
}

// expand substitutes one local $ref, merging sibling keywords over the target.
func (r *resolver) expand(obj map[string]any, ref string, depth int, stack []string) (any, error) {
	for _, s := range stack {
		if s == ref {
			return nil, fmt.Errorf("%w: %s", ErrRefCycle, ref)
		}
	}
	if depth+1 > r.opts.MaxRefDepth {
		return nil, fmt.Errorf("%w: %s at depth %d", ErrRefDepth, ref, depth+1)
	}
	r.expansions++
	if r.expansions > r.opts.MaxRefExpansions {
		return nil, fmt.Errorf("%w: more than %d expansions", ErrRefBudget, r.opts.MaxRefExpansions)
	}
	target, ok := lookupPointer(r.root, ref)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrRefTarget, ref)
	}
	resolved, err := r.resolve(target, depth+1, append(stack, ref))
	if err != nil {
		return nil, err
	}
	if len(obj) == 1 {
		return resolved, nil
	}
	// Sibling keywords beside $ref: merge over the resolved target.
	merged, isObj := resolved.(map[string]any)
	if !isObj {
		return resolved, nil
	}
	out := make(map[string]any, len(merged)+len(obj))
	for k, v := range merged {
		out[k] = v
	}
	for k, child := range obj {
		if k == "$ref" {
			continue
		}
		c, err := r.resolve(child, depth, stack)
		if err != nil {
			return nil, err
		}
		out[k] = c
	}
	return out, nil
}

// lookupPointer resolves a "#/a/b/0" JSON pointer (RFC 6901, with the ~0/~1
// escapes) against root. "#" alone is the root.
func lookupPointer(root any, ref string) (any, bool) {
	ptr := strings.TrimPrefix(ref, "#")
	if ptr == "" {
		return root, true
	}
	if !strings.HasPrefix(ptr, "/") {
		return nil, false
	}
	cur := root
	for _, seg := range strings.Split(ptr[1:], "/") {
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		switch t := cur.(type) {
		case map[string]any:
			next, ok := t[seg]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(t) {
				return nil, false
			}
			cur = t[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// writeCanonical serializes v with sorted keys, no whitespace, minimal string
// escaping and normalized numbers.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, t)
	case json.Number:
		buf.WriteString(normalizeNumber(t))
	case float64:
		buf.WriteString(strconv.FormatFloat(t, 'g', -1, 64))
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, child := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, child); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		return fmt.Errorf("mcpschema: unsupported value %T", v)
	}
	return nil
}

// normalizeNumber renders an integer literal verbatim and a float in its
// shortest round-trip form ("1.0" -> "1", "1e2" -> "100"). An unparseable
// literal (cannot happen after a successful decode) is kept verbatim.
func normalizeNumber(n json.Number) string {
	s := n.String()
	if !strings.ContainsAny(s, ".eE") {
		return s
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return s
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// writeString escapes a string per RFC 8259 minimally (quotes, backslash,
// control characters) without HTML escaping.
func writeString(buf *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if c < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[c>>4])
				buf.WriteByte(hexDigits[c&0xF])
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
}
