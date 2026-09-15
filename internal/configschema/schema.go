package configschema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// SchemaVersion is bumped when the Leaf / Table wire shape changes in a
// way a consumer must know about (not when keys are added — those are
// carried by the data itself).
const SchemaVersion = 1

// Descriptor is the serializable whole: what the generator writes to
// schema.gen.json and what GET /api/config/schema serves.
type Descriptor struct {
	SchemaVersion int      `json:"schema_version"`
	Blocks        []string `json:"blocks"`
	Tables        []Table  `json:"tables"`
	Leaves        []Leaf   `json:"leaves"`
}

// Describe builds the runtime Descriptor (no doc text — see web/cfgschema
// for the doc-bearing artifact).
func Describe() Descriptor {
	return Descriptor{
		SchemaVersion: SchemaVersion,
		Blocks:        Blocks(),
		Tables:        Tables(),
		Leaves:        Leaves(),
	}
}

// ErrNotWritable is returned for a leaf the generic route cannot set.
var ErrNotWritable = errors.New("configschema: leaf is not writable through the generic route")

// ParseValue coerces raw — a JSON value as sent on the wire — into the Go
// value of leaf's kind. It accepts the natural JSON type for each kind and,
// for the scalar kinds, the string spelling `observer config set` takes
// ("true", "12", "0.5"), so a form that only knows strings still works.
// KindStringList also accepts a comma-separated string. Every error names
// the key so the form can render it inline (plan §2.2 step 4).
func ParseValue(leaf Leaf, raw json.RawMessage) (any, error) {
	if !leaf.Kind.Writable() {
		return nil, fmt.Errorf("%s: %w", leaf.Path, ErrNotWritable)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("%s: value is not valid JSON: %w", leaf.Path, err)
	}
	parse, ok := parsers[leaf.Kind]
	if !ok {
		return nil, fmt.Errorf("%s: unsupported kind %s", leaf.Path, leaf.Kind)
	}
	out, ok := parse(leaf.Path, v)
	if !ok {
		return nil, fmt.Errorf("%s wants a %s, got %s", leaf.Path, leaf.Kind, jsonTypeName(v))
	}
	if pe, failed := out.(parseErr); failed {
		return nil, pe.err
	}
	return out, nil
}

// kindParser coerces a decoded JSON value into the kind's Go value. It
// returns ok=false for a JSON type the kind does not accept (the caller
// reports "wants a <kind>") and an error for a value of an accepted type
// that does not parse (the error names the key).
type kindParser func(path string, v any) (any, bool)

// parsers is the per-kind coercion table — one row per writable kind, no
// control flow (CLAUDE.md #5).
var parsers = map[Kind]kindParser{
	KindBool:       parseBool,
	KindInt:        parseInt,
	KindFloat:      parseFloat,
	KindString:     parseString,
	KindStringList: parseStringList,
	KindStringMap:  parseStringMap,
}

// parseErr wraps a kind-specific failure so ParseValue can return it
// verbatim: the value HAD the right JSON type but did not parse.
type parseErr struct{ err error }

func (p parseErr) Error() string { return p.err.Error() }

func parseBool(path string, v any) (any, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(t))
		if err != nil {
			return parseErr{fmt.Errorf("%s wants true/false, got %q", path, t)}, true
		}
		return b, true
	}
	return nil, false
}

func parseInt(path string, v any) (any, bool) {
	switch t := v.(type) {
	case float64:
		if t != math.Trunc(t) || math.IsInf(t, 0) {
			return parseErr{fmt.Errorf("%s wants an integer, got %v", path, t)}, true
		}
		return int64(t), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		if err != nil {
			return parseErr{fmt.Errorf("%s wants an integer, got %q", path, t)}, true
		}
		return n, true
	}
	return nil, false
}

func parseFloat(path string, v any) (any, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case string:
		fl, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err != nil || math.IsNaN(fl) || math.IsInf(fl, 0) {
			return parseErr{fmt.Errorf("%s wants a number, got %q", path, t)}, true
		}
		return fl, true
	}
	return nil, false
}

func parseString(_ string, v any) (any, bool) {
	t, ok := v.(string)
	return t, ok
}

func parseStringList(path string, v any) (any, bool) {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for i, it := range t {
			s, ok := it.(string)
			if !ok {
				return parseErr{fmt.Errorf("%s[%d] wants a string, got %T", path, i, it)}, true
			}
			out = append(out, s)
		}
		return out, true
	case string:
		out := []string{}
		for _, it := range strings.Split(t, ",") {
			if s := strings.TrimSpace(it); s != "" {
				out = append(out, s)
			}
		}
		return out, true
	case nil:
		return []string{}, true
	}
	return nil, false
}

func parseStringMap(path string, v any) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]string, len(t))
		for k, it := range t {
			s, ok := it.(string)
			if !ok {
				return parseErr{fmt.Errorf("%s.%s wants a string, got %T", path, k, it)}, true
			}
			out[k] = s
		}
		return out, true
	case nil:
		return map[string]string{}, true
	}
	return nil, false
}

func jsonTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

// ValidateLeaf checks a parsed value (from ParseValue) against the leaf's
// enum and numeric bounds. Kind mismatches are impossible after ParseValue;
// they are reported anyway so the function is safe to call on its own.
func ValidateLeaf(leaf Leaf, v any) error {
	switch leaf.Kind {
	case KindString:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%s wants a string", leaf.Path)
		}
		if len(leaf.Enum) > 0 && !contains(leaf.Enum, s) {
			return fmt.Errorf("%s %q not in {%s}", leaf.Path, s, strings.Join(nonEmpty(leaf.Enum), ", "))
		}
	case KindInt:
		n, ok := v.(int64)
		if !ok {
			return fmt.Errorf("%s wants an integer", leaf.Path)
		}
		return checkBounds(leaf, float64(n))
	case KindFloat:
		fl, ok := v.(float64)
		if !ok {
			return fmt.Errorf("%s wants a number", leaf.Path)
		}
		return checkBounds(leaf, fl)
	}
	return nil
}

func checkBounds(leaf Leaf, v float64) error {
	if leaf.Min != nil && v < *leaf.Min {
		return fmt.Errorf("%s must be >= %v, got %v", leaf.Path, *leaf.Min, v)
	}
	if leaf.Max != nil && v > *leaf.Max {
		return fmt.Errorf("%s must be <= %v, got %v", leaf.Path, *leaf.Max, v)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, it := range list {
		if it == s {
			return true
		}
	}
	return false
}

func nonEmpty(list []string) []string {
	out := make([]string, 0, len(list))
	for _, it := range list {
		if it != "" {
			out = append(out, it)
		}
	}
	return out
}

// Get returns the leaf's current value from cfg.
func Get(cfg *config.Config, leaf Leaf) any {
	return reflect.ValueOf(cfg).Elem().FieldByIndex(leaf.index).Interface()
}

// Set writes a value produced by ParseValue onto cfg at leaf.
func Set(cfg *config.Config, leaf Leaf, v any) error {
	if !leaf.Kind.Writable() {
		return fmt.Errorf("%s: %w", leaf.Path, ErrNotWritable)
	}
	field := reflect.ValueOf(cfg).Elem().FieldByIndex(leaf.index)
	switch leaf.Kind {
	case KindBool:
		b, ok := v.(bool)
		if !ok {
			return fmt.Errorf("%s: Set wants bool, got %T", leaf.Path, v)
		}
		field.SetBool(b)
	case KindInt:
		n, ok := v.(int64)
		if !ok {
			return fmt.Errorf("%s: Set wants int64, got %T", leaf.Path, v)
		}
		if field.OverflowInt(n) {
			return fmt.Errorf("%s: %d overflows %s", leaf.Path, n, field.Type())
		}
		field.SetInt(n)
	case KindFloat:
		fl, ok := v.(float64)
		if !ok {
			return fmt.Errorf("%s: Set wants float64, got %T", leaf.Path, v)
		}
		field.SetFloat(fl)
	case KindString:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%s: Set wants string, got %T", leaf.Path, v)
		}
		field.SetString(s)
	case KindStringList:
		list, ok := v.([]string)
		if !ok {
			return fmt.Errorf("%s: Set wants []string, got %T", leaf.Path, v)
		}
		field.Set(reflect.ValueOf(append([]string(nil), list...)).Convert(field.Type()))
	case KindStringMap:
		m, ok := v.(map[string]string)
		if !ok {
			return fmt.Errorf("%s: Set wants map[string]string, got %T", leaf.Path, v)
		}
		out := reflect.MakeMapWithSize(field.Type(), len(m))
		for k, val := range m {
			out.SetMapIndex(reflect.ValueOf(k), reflect.ValueOf(val))
		}
		field.Set(out)
	}
	return nil
}

// ChangedLeaves returns the dotted paths whose values differ between a and
// b, in schema order. It is how the dashboard derives an HONEST
// restart_required from a section save (plan §3.1) — the restart class of
// each changed key, never a per-section heuristic.
func ChangedLeaves(a, b *config.Config) []string {
	va, vb := reflect.ValueOf(a).Elem(), reflect.ValueOf(b).Elem()
	var out []string
	for _, l := range Leaves() {
		if !reflect.DeepEqual(va.FieldByIndex(l.index).Interface(), vb.FieldByIndex(l.index).Interface()) {
			out = append(out, l.Path)
		}
	}
	return out
}

// TOMLScalar renders a parsed scalar value as a single-line TOML right-hand
// side for the surgical editor. ok is false for non-scalar kinds (the caller
// falls back to a full re-serialize) and for values TOML cannot spell
// (NaN / ±Inf floats).
func TOMLScalar(leaf Leaf, v any) (rhs string, ok bool) {
	switch leaf.Kind {
	case KindBool:
		b, isBool := v.(bool)
		if !isBool {
			return "", false
		}
		return strconv.FormatBool(b), true
	case KindInt:
		n, isInt := v.(int64)
		if !isInt {
			return "", false
		}
		return strconv.FormatInt(n, 10), true
	case KindFloat:
		fl, isFloat := v.(float64)
		if !isFloat || math.IsNaN(fl) || math.IsInf(fl, 0) {
			return "", false
		}
		s := strconv.FormatFloat(fl, 'g', -1, 64)
		// TOML floats need a fraction or exponent; "1" is an integer.
		if !strings.ContainsAny(s, ".eE") {
			s += ".0"
		}
		return s, true
	case KindString:
		s, isString := v.(string)
		if !isString {
			return "", false
		}
		return QuoteTOMLString(s), true
	}
	return "", false
}

// QuoteTOMLString renders s as a TOML basic (double-quoted) string with
// every character TOML requires escaped: quote, backslash, the C0 control
// range, DEL, and invalid UTF-8 (which is replaced). The result is always a
// single line, so the surgical editor can never emit a value that opens a
// multi-line string or hides a comment marker inside an unterminated quote.
func QuoteTOMLString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString(`�`)
			i++
			continue
		}
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
		i += size
	}
	b.WriteByte('"')
	return b.String()
}
