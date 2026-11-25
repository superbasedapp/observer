package cfgfmt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"
)

// jsonDoc is the JSON / JSONC engine: an exact syntactic hujson AST,
// patched member by member. Pack() of an unedited AST is the input byte
// for byte; an edit touches only the edited member's value and the
// whitespace hujson needs around a new member.
type jsonDoc struct {
	format Format
	bom    bool
	root   hujson.Value
	// empty is true while the document has no value (an empty or
	// comments-only file). raw holds its original bytes until the first
	// Set gives it an object root.
	empty bool
	raw   []byte
	unit  string // detected indentation unit
	eol   string // line terminator for inserted lines
	discl []Disclosure
}

var jsonLineCol = regexp.MustCompile(`line (\d+), column (\d+)`)

func parseJSON(f Format, bom bool, body []byte, _ Options) (Doc, error) {
	if err := jsonDepthCheck(body); err != nil {
		return nil, err
	}
	d := &jsonDoc{format: f, bom: bom, unit: detectJSONIndent(body), eol: detectEOL(body)}
	if isJSONEmpty(body) {
		if f == FormatJSON && bytes.Contains(body, []byte("/")) {
			return nil, &ParseError{Format: f, Msg: "comments are not allowed in a strict JSON file"}
		}
		d.empty = true
		d.raw = append([]byte(nil), body...)
		return d, nil
	}
	v, err := hujson.Parse(body)
	if err != nil {
		pe := &ParseError{Format: f, Msg: strings.TrimPrefix(err.Error(), "hujson: ")}
		if m := jsonLineCol.FindStringSubmatch(err.Error()); m != nil {
			pe.Line, _ = strconv.Atoi(m[1])
			pe.Column, _ = strconv.Atoi(m[2])
		}
		return nil, pe
	}
	if f == FormatJSON && !v.IsStandard() {
		return nil, &ParseError{Format: f, Msg: "comments or trailing commas are not allowed in a strict JSON file"}
	}
	if err := jsonDuplicateCheck(&v, nil); err != nil {
		return nil, err
	}
	d.root = v
	return d, nil
}

// isJSONEmpty reports a document holding only whitespace and comments.
func isJSONEmpty(b []byte) bool {
	if len(bytes.TrimSpace(b)) == 0 {
		return true
	}
	probe := append(append([]byte(nil), b...), []byte("\nnull")...)
	v, err := hujson.Parse(probe)
	if err != nil {
		return false
	}
	lit, ok := v.Value.(hujson.Literal)
	return ok && string(lit) == "null"
}

// jsonDepthCheck refuses nesting deeper than MaxDepth before any
// recursive parser sees the input.
func jsonDepthCheck(b []byte) error {
	depth := 0
	inStr, esc := false, false
	inLine, inBlock := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inLine:
			if c == '\n' {
				inLine = false
			}
		case inBlock:
			if c == '*' && i+1 < len(b) && b[i+1] == '/' {
				inBlock = false
				i++
			}
		case inStr:
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
		default:
			switch c {
			case '"':
				inStr = true
			case '/':
				if i+1 < len(b) && b[i+1] == '/' {
					inLine = true
				} else if i+1 < len(b) && b[i+1] == '*' {
					inBlock = true
				}
			case '{', '[':
				depth++
				if depth > MaxDepth {
					return ErrTooDeep
				}
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

func jsonDuplicateCheck(v *hujson.Value, path Path) error {
	switch x := v.Value.(type) {
	case *hujson.Object:
		seen := make(map[string]bool, len(x.Members))
		for i := range x.Members {
			name := memberName(&x.Members[i])
			if seen[name] {
				return fmt.Errorf("%w: %s", ErrDuplicateKey, append(append(Path{}, path...), name))
			}
			seen[name] = true
			if err := jsonDuplicateCheck(&x.Members[i].Value, append(append(Path{}, path...), name)); err != nil {
				return err
			}
		}
	case *hujson.Array:
		for i := range x.Elements {
			if err := jsonDuplicateCheck(&x.Elements[i], path); err != nil {
				return err
			}
		}
	}
	return nil
}

func memberName(m *hujson.ObjectMember) string {
	lit, ok := m.Name.Value.(hujson.Literal)
	if !ok {
		return ""
	}
	return lit.String()
}

var jsonIndentRE = regexp.MustCompile(`\n([ \t]+)"`)

// detectJSONIndent returns the smallest member indentation in the file
// (the indent unit), defaulting to two spaces.
func detectJSONIndent(b []byte) string {
	best := ""
	for _, m := range jsonIndentRE.FindAllSubmatch(b, -1) {
		ws := string(m[1])
		if best == "" || len(ws) < len(best) {
			best = ws
		}
	}
	if best == "" {
		return "  "
	}
	return best
}

func (d *jsonDoc) Format() Format            { return d.format }
func (d *jsonDoc) Disclosures() []Disclosure { return append([]Disclosure(nil), d.discl...) }

func (d *jsonDoc) Bytes() []byte {
	if d.empty {
		return withBOM(d.bom, append([]byte(nil), d.raw...))
	}
	return withBOM(d.bom, d.root.Pack())
}

func (d *jsonDoc) Value() (map[string]any, error) {
	if d.empty {
		return map[string]any{}, nil
	}
	v, err := decodeHuJSON(d.root)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		if v == nil {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("%w: document root is not an object", ErrTypeMismatch)
	}
	return m, nil
}

func decodeHuJSON(v hujson.Value) (any, error) {
	c := v.Clone()
	c.Standardize()
	dec := json.NewDecoder(bytes.NewReader(c.Pack()))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("cfgfmt: json decode: %w", err)
	}
	return NativeNumbers(out), nil
}

// NativeNumbers turns json.Number values (a decoder with UseNumber) into
// int64 when the literal is an integer that fits, else float64, recursively
// through []any and map[string]any, so a value compares and re-encodes the
// way a vendor file holds it (an integer setting is written as an integer).
// Slices and maps are rewritten in place and returned; any other value is
// returned as is. It is the one owner of this walk: the JSON engine, the
// managed-settings generator, the org agent-config catalogue and the
// dashboard's agent-config handlers all use it.
func NativeNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		f, _ := x.Float64()
		return f
	case []any:
		for i := range x {
			x[i] = NativeNumbers(x[i])
		}
		return x
	case map[string]any:
		for k := range x {
			x[k] = NativeNumbers(x[k])
		}
		return x
	}
	return v
}

func (d *jsonDoc) Get(path Path) (any, bool, error) {
	tree, err := d.Value()
	if err != nil {
		return nil, false, err
	}
	return lookup(tree, path)
}

func (d *jsonDoc) Set(path Path, value any) error {
	if err := checkPath(path); err != nil {
		return err
	}
	nv, err := Normalize(value)
	if err != nil {
		return err
	}
	if err := checkJSONValue(nv); err != nil {
		return err
	}
	before, err := d.Value()
	if err != nil {
		return err
	}
	if cur, found, err := lookup(before, path); err != nil {
		return err
	} else if found && Equal(cur, nv) {
		return nil
	}
	expected, err := treeSet(before, path, nv)
	if err != nil {
		return err
	}

	snapshot := d.snapshot()
	if d.empty {
		d.materializeRoot()
	}
	if err := d.setAt(path, nv); err != nil {
		d.restore(snapshot)
		return err
	}
	return d.verify(expected, snapshot)
}

func (d *jsonDoc) Delete(path Path) (bool, error) {
	if err := checkPath(path); err != nil {
		return false, err
	}
	before, err := d.Value()
	if err != nil {
		return false, err
	}
	if _, found, err := lookup(before, path); err != nil || !found {
		return false, err
	}
	expected := treeDelete(before, path)
	snapshot := d.snapshot()
	obj, idx, err := d.findMember(path)
	if err != nil {
		d.restore(snapshot)
		return false, err
	}
	removeMember(obj, idx)
	return true, d.verify(expected, snapshot)
}

type jsonSnapshot struct {
	root  hujson.Value
	empty bool
	raw   []byte
}

func (d *jsonDoc) snapshot() jsonSnapshot {
	s := jsonSnapshot{empty: d.empty, raw: append([]byte(nil), d.raw...)}
	if d.root.Value != nil {
		s.root = d.root.Clone()
	}
	return s
}

func (d *jsonDoc) restore(s jsonSnapshot) {
	d.root, d.empty, d.raw = s.root, s.empty, s.raw
}

func (d *jsonDoc) verify(expected map[string]any, s jsonSnapshot) error {
	out := d.root.Pack()
	re, err := hujson.Parse(out)
	if err != nil {
		d.restore(s)
		return fmt.Errorf("%w: re-parse: %w", ErrVerify, err)
	}
	if d.format == FormatJSON && !re.IsStandard() {
		d.restore(s)
		return fmt.Errorf("%w: edit produced non-standard JSON", ErrVerify)
	}
	got, err := d.Value()
	if err != nil || !Equal(any(got), any(expected)) {
		d.restore(s)
		return fmt.Errorf("%w: result differs from the expected tree", ErrVerify)
	}
	d.root = re
	return nil
}

// materializeRoot turns an empty / comments-only document into one whose
// root is an empty object, keeping the original comments in front of it.
func (d *jsonDoc) materializeRoot() {
	lead := strings.TrimRight(string(d.raw), " \t\r\n")
	before := ""
	if lead != "" {
		before = lead + d.eol
	}
	d.root = hujson.Value{
		BeforeExtra: hujson.Extra(before),
		Value:       &hujson.Object{},
		AfterExtra:  hujson.Extra(d.eol),
	}
	d.empty = false
	d.raw = nil
}

// setAt walks / creates objects along path and sets the leaf.
func (d *jsonDoc) setAt(path Path, v any) error {
	obj, ok := d.root.Value.(*hujson.Object)
	if !ok {
		return fmt.Errorf("%w: document root is not an object", ErrTypeMismatch)
	}
	parentIndent := "" // indentation of the line holding obj's closing brace
	for i, seg := range path {
		idx := -1
		for j := range obj.Members {
			if memberName(&obj.Members[j]) == seg {
				idx = j
				break
			}
		}
		memberIndent := d.memberIndent(obj, parentIndent)
		if idx < 0 {
			// Absent: insert the remaining path as one nested value.
			val := nestValue(path[i:], v)
			appendMember(obj, seg, d.render(val, memberIndent, isInline(obj)), memberIndent, parentIndent, d.eol)
			return nil
		}
		m := &obj.Members[idx]
		if i == len(path)-1 {
			rendered := d.render(v, lineIndentOf(m, memberIndent), isInline(obj))
			m.Value.Value = rendered.Value
			return nil
		}
		next, ok := m.Value.Value.(*hujson.Object)
		if !ok {
			if lit, isLit := m.Value.Value.(hujson.Literal); isLit && string(lit) == "null" {
				rendered := d.render(nestValue(path[i:], v), lineIndentOf(m, memberIndent), isInline(obj))
				m.Value.Value = rendered.Value
				return nil
			}
			return fmt.Errorf("%w: %s", ErrTypeMismatch, path[:i+1])
		}
		parentIndent = lineIndentOf(m, memberIndent)
		obj = next
	}
	return nil
}

// memberIndent returns the indentation for members of obj: the last
// member's own, else the closing-brace indentation plus one unit.
func (d *jsonDoc) memberIndent(obj *hujson.Object, parentIndent string) string {
	if n := len(obj.Members); n > 0 {
		if ind, ok := indentAfterNewline(obj.Members[n-1].Name.BeforeExtra); ok {
			return ind
		}
	}
	return parentIndent + d.unit
}

func lineIndentOf(m *hujson.ObjectMember, fallback string) string {
	if ind, ok := indentAfterNewline(m.Name.BeforeExtra); ok {
		return ind
	}
	return fallback
}

// indentAfterNewline returns the whitespace after the last newline of an
// Extra, when it has one.
func indentAfterNewline(e hujson.Extra) (string, bool) {
	i := bytes.LastIndexByte(e, '\n')
	if i < 0 {
		return "", false
	}
	tail := string(e[i+1:])
	return leadingWS(tail), true
}

// isInline reports an object written on one line (no newline anywhere in
// its own syntax), which a new member keeps on that line.
func isInline(obj *hujson.Object) bool {
	if len(obj.Members) == 0 {
		return false
	}
	v := hujson.Value{Value: obj}
	return !bytes.Contains(v.Pack(), []byte("\n"))
}

// render encodes v as a hujson value: compact when inline, indented with
// the given line indentation otherwise.
func (d *jsonDoc) render(v any, lineIndent string, inline bool) hujson.Value {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if !inline {
		enc.SetIndent(lineIndent, d.unit)
	}
	_ = enc.Encode(jsonable(v)) // values are pre-checked by checkJSONValue
	out := bytes.TrimRight(buf.Bytes(), "\n")
	if d.eol != "\n" {
		out = bytes.ReplaceAll(out, []byte("\n"), []byte(d.eol))
	}
	hv, err := hujson.Parse(out)
	if err != nil {
		return hujson.Value{Value: hujson.Literal("null")}
	}
	hv.BeforeExtra, hv.AfterExtra = nil, nil
	return hv
}

// jsonable maps the normalized value set onto encoding/json input.
func jsonable(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = jsonable(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = jsonable(e)
		}
		return out
	}
	return v
}

// checkJSONValue refuses values JSON cannot carry (NaN, Inf, time).
func checkJSONValue(v any) error {
	switch x := v.(type) {
	case float64:
		if x != x || x > 1.7976931348623157e308 || x < -1.7976931348623157e308 {
			return fmt.Errorf("%w: %v in JSON", ErrValueType, x)
		}
	case []any:
		for _, e := range x {
			if err := checkJSONValue(e); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, e := range x {
			if err := checkJSONValue(e); err != nil {
				return err
			}
		}
	case nil, bool, string, int64:
	default:
		return fmt.Errorf("%w: %T in JSON", ErrValueType, v)
	}
	return nil
}

// appendMember adds name: val at the end of obj, keeping the file's
// layout: a same-line comment after the old last member stays on that
// line, the closing brace keeps its indentation, a trailing-comma object
// keeps its trailing comma.
func appendMember(obj *hujson.Object, name string, val hujson.Value, indent, closeIndent, eol string) {
	nameLit, _ := json.Marshal(name)
	inline := isInline(obj)
	hadTrailing := len(obj.Members) > 0 && obj.Members[len(obj.Members)-1].Value.AfterExtra != nil

	var before string
	switch {
	case inline:
		before = " "
	case len(obj.Members) == 0:
		ae := string(obj.AfterExtra)
		if strings.TrimSpace(ae) == "" {
			// "{}" or "{ }": open it up; the closing brace lands on its
			// own line at the parent's indentation.
			obj.AfterExtra = hujson.Extra(eol + closeIndent)
			before = eol + indent
		} else {
			// Comments inside an empty object stay in front of the member.
			lead := strings.TrimRight(ae, " \t\r\n")
			closeIndent := ""
			if i := strings.LastIndexByte(ae, '\n'); i >= 0 {
				closeIndent = leadingWS(ae[i+1:])
			}
			before = lead + eol + indent
			obj.AfterExtra = hujson.Extra(eol + closeIndent)
		}
	default:
		same := ""
		if head, rest, ok := splitFirstLine(string(obj.AfterExtra)); ok && strings.TrimSpace(head) != "" {
			same = head
			obj.AfterExtra = hujson.Extra(rest)
		}
		before = same + eol + indent
	}
	m := hujson.ObjectMember{
		Name:  hujson.Value{BeforeExtra: hujson.Extra(before), Value: hujson.Literal(nameLit)},
		Value: hujson.Value{BeforeExtra: hujson.Extra(" "), Value: val.Value},
	}
	if hadTrailing {
		m.Value.AfterExtra = hujson.Extra{}
	}
	obj.Members = append(obj.Members, m)
}

// findMember locates the object holding path's leaf and its index.
func (d *jsonDoc) findMember(path Path) (*hujson.Object, int, error) {
	obj, ok := d.root.Value.(*hujson.Object)
	if !ok {
		return nil, -1, fmt.Errorf("%w: document root is not an object", ErrTypeMismatch)
	}
	for i, seg := range path {
		idx := -1
		for j := range obj.Members {
			if memberName(&obj.Members[j]) == seg {
				idx = j
				break
			}
		}
		if idx < 0 {
			return nil, -1, fmt.Errorf("%w: %s not found", ErrVerify, path[:i+1])
		}
		if i == len(path)-1 {
			return obj, idx, nil
		}
		next, ok := obj.Members[idx].Value.Value.(*hujson.Object)
		if !ok {
			return nil, -1, fmt.Errorf("%w: %s", ErrTypeMismatch, path[:i+1])
		}
		obj = next
	}
	return nil, -1, ErrEmptyPath
}

// splitFirstLine splits s at its first line break: head is the text before
// the terminator, rest starts with the terminator ("\r\n" or "\n"). ok is
// false when s has no line break.
func splitFirstLine(s string) (head, rest string, ok bool) {
	j := strings.IndexByte(s, '\n')
	if j < 0 {
		return s, "", false
	}
	if j > 0 && s[j-1] == '\r' {
		j--
	}
	return s[:j], s[j:], true
}

// detectEOL returns "\r\n" when most line breaks in b are CRLF.
func detectEOL(b []byte) string {
	crlf := bytes.Count(b, []byte("\r\n"))
	if lf := bytes.Count(b, []byte("\n")) - crlf; crlf > lf {
		return "\r\n"
	}
	return "\n"
}

// removeMember deletes obj.Members[i] with its leading comments and its
// same-line trailing comment, keeping the previous member's same-line
// comment and the object's trailing-comma style.
func removeMember(obj *hujson.Object, i int) {
	n := len(obj.Members)
	hadTrailing := obj.Members[n-1].Value.AfterExtra != nil
	own := string(obj.Members[i].Name.BeforeExtra)
	// The part of this member's BeforeExtra up to its first newline is the
	// PREVIOUS member's same-line comment: it survives. The rest (this
	// member's own leading comments and indentation) goes with it.
	keep := ""
	if head, _, ok := splitFirstLine(own); ok && strings.TrimSpace(head) != "" {
		keep = head
	}
	// The following Extra starts with THIS member's same-line comment
	// (up to its first line break): that goes with the member too. On a
	// single-line object there is no line break, so the removed member's
	// own spacing is reused.
	tail := func(e string) string {
		if _, rest, ok := splitFirstLine(e); ok {
			return rest
		}
		if strings.TrimSpace(e) == "" {
			return own
		}
		return e
	}
	if i < n-1 {
		obj.Members[i+1].Name.BeforeExtra = hujson.Extra(keep + tail(string(obj.Members[i+1].Name.BeforeExtra)))
	} else {
		ae := string(obj.AfterExtra)
		rest := ae
		if _, r, ok := splitFirstLine(ae); ok {
			rest = r
		}
		obj.AfterExtra = hujson.Extra(keep + rest)
	}
	obj.Members = append(obj.Members[:i], obj.Members[i+1:]...)
	if len(obj.Members) == 0 {
		if strings.TrimSpace(string(obj.AfterExtra)) == "" {
			obj.AfterExtra = nil
		}
		return
	}
	last := &obj.Members[len(obj.Members)-1].Value
	switch {
	case hadTrailing && last.AfterExtra == nil:
		last.AfterExtra = hujson.Extra{}
	case !hadTrailing && last.AfterExtra != nil:
		obj.AfterExtra = append(append(hujson.Extra{}, last.AfterExtra...), obj.AfterExtra...)
		last.AfterExtra = nil
	}
}
