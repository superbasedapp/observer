package cfgfmt

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// tomlDoc is the TOML engine: the file held as physical lines (each with
// its own terminator) plus a structural index rebuilt after every edit.
// Scalars, arrays and inline tables are replaced in place over their exact
// span (multi-line arrays and strings included); a new key is inserted
// after the last direct key of its table, a new table is appended at the
// end of the file. What the line editor cannot express (a path inside an
// array of tables or an inline table) is re-serialized from the decoded
// tree and disclosed.
type tomlDoc struct {
	bom   bool
	lines []line
	opts  Options
	discl []Disclosure
	idx   tomlIndex
}

type tomlEntryKind int

const (
	tomlKeyVal tomlEntryKind = iota
	tomlTable
	tomlArrayTable
)

// tomlEntry is one structural line (or multi-line key/value) of the file.
type tomlEntry struct {
	kind tomlEntryKind
	// path is the table path for headers and the FULL key path (table +
	// dotted key) for key/values.
	path []string
	// first / last are the inclusive line range the entry occupies.
	first, last int
	// value span for key/values: start at (first, valCol), end exclusive
	// at (last, valEnd).
	valCol, valEnd int
	// inArray is true for anything inside an array of tables.
	inArray bool
	// inline is true when the value is an inline table.
	inline bool
}

type tomlIndex struct {
	entries []tomlEntry
}

func parseTOML(bom bool, body []byte, opts Options) (Doc, error) {
	if err := tomlDepthCheck(body); err != nil {
		return nil, err
	}
	if _, err := decodeTOML(string(body)); err != nil {
		return nil, err
	}
	d := &tomlDoc{bom: bom, lines: splitLines(string(body)), opts: opts}
	d.reindex()
	return d, nil
}

// tomlDepthCheck bounds bracket nesting before the recursive decoder runs.
func tomlDepthCheck(b []byte) error {
	depth := 0
	var quote byte
	inComment := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inComment:
			if c == '\n' {
				inComment = false
			}
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			inComment = true
		case c == '[' || c == '{':
			depth++
			if depth > MaxDepth {
				return ErrTooDeep
			}
		case c == ']' || c == '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return nil
}

func decodeTOML(s string) (map[string]any, error) {
	var out map[string]any
	if _, err := toml.Decode(s, &out); err != nil {
		pe := &ParseError{Format: FormatTOML, Msg: err.Error()}
		var tp toml.ParseError
		if errors.As(err, &tp) {
			pe.Line, pe.Column = tp.Position.Line, tp.Position.Col
			pe.Msg = tp.Message
			if strings.Contains(strings.ToLower(tp.Message), "already been defined") ||
				strings.Contains(strings.ToLower(tp.Message), "duplicate") {
				return nil, fmt.Errorf("%w: %s", ErrDuplicateKey, pe.Error())
			}
		}
		return nil, pe
	}
	n, err := normalize(out, 0)
	if err != nil {
		return nil, err
	}
	m, _ := n.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func (d *tomlDoc) Format() Format            { return FormatTOML }
func (d *tomlDoc) Disclosures() []Disclosure { return append([]Disclosure(nil), d.discl...) }
func (d *tomlDoc) Bytes() []byte             { return withBOM(d.bom, []byte(joinLines(d.lines))) }
func (d *tomlDoc) Value() (map[string]any, error) {
	return decodeTOML(joinLines(d.lines))
}

func (d *tomlDoc) Get(path Path) (any, bool, error) {
	tree, err := d.Value()
	if err != nil {
		return nil, false, err
	}
	return lookup(tree, path)
}

// --- indexing ---------------------------------------------------------------

func (d *tomlDoc) reindex() {
	var entries []tomlEntry
	var table []string
	tableInArray := false
	var arrayTables [][]string
	underArray := func(p []string) bool {
		for _, a := range arrayTables {
			if hasPrefix(p, a) {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(d.lines); i++ {
		t := strings.TrimLeft(d.lines[i].text, " \t")
		switch {
		case t == "" || t[0] == '#':
			continue
		case strings.HasPrefix(t, "[["):
			p := parseTOMLKey(strings.TrimSpace(headerInner(t, true)))
			arrayTables = append(arrayTables, p)
			table, tableInArray = p, true
			entries = append(entries, tomlEntry{kind: tomlArrayTable, path: p, first: i, last: i, inArray: true})
		case t[0] == '[':
			p := parseTOMLKey(strings.TrimSpace(headerInner(t, false)))
			table, tableInArray = p, underArray(p)
			entries = append(entries, tomlEntry{kind: tomlTable, path: p, first: i, last: i, inArray: tableInArray})
		default:
			text := d.lines[i].text
			eq := keyEnd(text)
			if eq < 0 {
				continue
			}
			key := parseTOMLKey(strings.TrimSpace(text[:eq]))
			full := append(append([]string{}, table...), key...)
			col := eq + 1
			for col < len(text) && (text[col] == ' ' || text[col] == '\t') {
				col++
			}
			lastLine, endCol := scanTOMLValue(d.lines, i, col)
			inline := col < len(text) && text[col] == '{'
			entries = append(entries, tomlEntry{
				kind: tomlKeyVal, path: full, first: i, last: lastLine,
				valCol: col, valEnd: endCol, inArray: tableInArray, inline: inline,
			})
			i = lastLine
		}
	}
	d.idx = tomlIndex{entries: entries}
}

func headerInner(t string, array bool) string {
	open, closeTok := "[", "]"
	if array {
		open, closeTok = "[[", "]]"
	}
	inner := t[len(open):]
	// Find the closing bracket outside quotes.
	var quote byte
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case strings.HasPrefix(inner[i:], closeTok):
			return inner[:i]
		}
	}
	return inner
}

// keyEnd returns the index of the '=' that ends the key of a key/value
// line (outside quoted key segments), or -1.
func keyEnd(s string) int {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '=':
			return i
		case c == '#':
			return -1
		}
	}
	return -1
}

// parseTOMLKey splits a (dotted, possibly quoted) key into segments,
// decoding quoted segments.
func parseTOMLKey(s string) []string {
	var segs []string
	i := 0
	for i <= len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		var seg string
		switch s[i] {
		case '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j > len(s) {
				j = len(s)
			}
			raw := s[i:min(j+1, len(s))]
			if u, err := strconv.Unquote(raw); err == nil {
				seg = u
			} else {
				seg = strings.Trim(raw, `"`)
			}
			i = j + 1
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				seg, i = s[i+1:], len(s)
			} else {
				seg, i = s[i+1:i+1+j], i+1+j+1
			}
		default:
			j := i
			for j < len(s) && s[j] != '.' && s[j] != ' ' && s[j] != '\t' {
				j++
			}
			seg, i = s[i:j], j
		}
		segs = append(segs, seg)
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i < len(s) && s[i] == '.' {
			i++
			continue
		}
		break
	}
	return segs
}

// scanTOMLValue finds the end of the value starting at (li, col): it
// returns the last line index and the exclusive end column on that line.
// Strings (basic, literal, multi-line), arrays and inline tables may span
// lines; comments inside arrays are skipped.
func scanTOMLValue(ls []line, li, col int) (int, int) {
	text := ls[li].text
	if col >= len(text) {
		return li, col
	}
	switch {
	case strings.HasPrefix(text[col:], `"""`):
		return scanMultiString(ls, li, col+3, `"`, true)
	case strings.HasPrefix(text[col:], `'''`):
		return scanMultiString(ls, li, col+3, `'`, false)
	case text[col] == '"':
		j := col + 1
		for j < len(text) && text[j] != '"' {
			if text[j] == '\\' {
				j++
			}
			j++
		}
		return li, min(j+1, len(text))
	case text[col] == '\'':
		j := strings.IndexByte(text[col+1:], '\'')
		if j < 0 {
			return li, len(text)
		}
		return li, col + 1 + j + 1
	case text[col] == '[' || text[col] == '{':
		return scanBracketed(ls, li, col)
	default:
		end := len(text)
		if h := strings.IndexByte(text[col:], '#'); h >= 0 {
			end = col + h
		}
		return li, col + len(strings.TrimRight(text[col:end], " \t"))
	}
}

func scanMultiString(ls []line, li, col int, q string, escapes bool) (int, int) {
	delim := q + q + q
	for l := li; l < len(ls); l++ {
		text := ls[l].text
		start := 0
		if l == li {
			start = col
		}
		for j := start; j < len(text); j++ {
			if escapes && text[j] == '\\' {
				j++
				continue
			}
			if strings.HasPrefix(text[j:], delim) {
				end := j + 3
				// Up to two extra quotes belong to the content.
				for k := 0; k < 2 && end < len(text) && text[end] == q[0]; k++ {
					end++
				}
				return l, end
			}
		}
	}
	last := len(ls) - 1
	return last, len(ls[last].text)
}

func scanBracketed(ls []line, li, col int) (int, int) {
	depth := 0
	for l := li; l < len(ls); l++ {
		text := ls[l].text
		start := 0
		if l == li {
			start = col
		}
		for j := start; j < len(text); j++ {
			c := text[j]
			switch {
			case c == '#':
				j = len(text) // comment to end of line
			case strings.HasPrefix(text[j:], `"""`):
				el, ec := scanMultiString(ls, l, j+3, `"`, true)
				if el != l {
					l, text = el, ls[el].text
				}
				j = ec - 1
			case strings.HasPrefix(text[j:], `'''`):
				el, ec := scanMultiString(ls, l, j+3, `'`, false)
				if el != l {
					l, text = el, ls[el].text
				}
				j = ec - 1
			case c == '"':
				j++
				for j < len(text) && text[j] != '"' {
					if text[j] == '\\' {
						j++
					}
					j++
				}
			case c == '\'':
				k := strings.IndexByte(text[j+1:], '\'')
				if k < 0 {
					j = len(text)
				} else {
					j += k + 1
				}
			case c == '[' || c == '{':
				depth++
			case c == ']' || c == '}':
				depth--
				if depth == 0 {
					return l, j + 1
				}
			}
		}
	}
	last := len(ls) - 1
	return last, len(ls[last].text)
}

func hasPrefix(p, prefix []string) bool {
	if len(prefix) > len(p) {
		return false
	}
	for i := range prefix {
		if p[i] != prefix[i] {
			return false
		}
	}
	return true
}

func pathEq(a, b []string) bool { return len(a) == len(b) && hasPrefix(a, b) }

// --- editing ------------------------------------------------------------------

func (d *tomlDoc) Set(path Path, value any) error {
	if err := checkPath(path); err != nil {
		return err
	}
	nv, err := Normalize(value)
	if err != nil {
		return err
	}
	if err := checkTOMLValue(nv); err != nil {
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
	for _, lines := range d.surgicalSet(before, path, nv) {
		if d.accept(lines, expected) {
			return nil
		}
	}
	return d.reserialize("set", path, expected)
}

func (d *tomlDoc) Delete(path Path) (bool, error) {
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
	if lines, ok := d.surgicalDelete(path); ok {
		for _, want := range tomlDeleteOutcomes(expected, path) {
			if d.accept(lines, want) {
				return true, nil
			}
		}
	}
	return true, d.reserialize("delete", path, expected)
}

// tomlDeleteOutcomes lists the trees a surgical delete of path may
// faithfully produce: expected itself, then expected with each ancestor
// that the delete left empty pruned, innermost first. TOML cannot spell an
// empty IMPLICIT table (one that exists only as the super-table of
// [a.b.c] headers or dotted keys, with no [a.b] header of its own), so
// removing its last child removes it too: deleting the only
// [hooks.state."k"] table leaves no hooks.state at all, while an explicit
// [hooks.state] header survives the delete and decodes as the exact
// expected tree. Since surgicalDelete drops only lines under path, a
// decode that matches a pruned candidate proves the pruned tables had no
// defining line left, so nothing the user wrote is lost.
func tomlDeleteOutcomes(expected map[string]any, path Path) []map[string]any {
	out := []map[string]any{expected}
	cur := expected
	for k := len(path) - 1; k >= 1; k-- {
		v, found, err := lookup(cur, path[:k])
		if err != nil || !found {
			break
		}
		if m, isMap := v.(map[string]any); !isMap || len(m) > 0 {
			break
		}
		cur = treeDelete(cur, path[:k])
		out = append(out, cur)
	}
	return out
}

// accept installs lines when they decode to exactly expected.
func (d *tomlDoc) accept(lines []line, expected map[string]any) bool {
	got, err := decodeTOML(joinLines(lines))
	if err != nil || !Equal(any(got), any(expected)) {
		return false
	}
	d.lines = lines
	d.reindex()
	return true
}

// reserialize is the disclosed fallback: encode the expected tree.
func (d *tomlDoc) reserialize(op string, path Path, expected map[string]any) error {
	if d.opts.ForbidReserialize {
		return fmt.Errorf("%w: %s %s", ErrNeedsReserialize, op, path)
	}
	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if err := enc.Encode(expected); err != nil {
		return fmt.Errorf("%w: re-encode: %w", ErrValueType, err)
	}
	eol := dominantEOL(d.lines)
	lines := textLines(buf.String(), eol)
	if buf.Len() == 0 {
		lines = nil
	}
	got, err := decodeTOML(joinLines(lines))
	if err != nil || !Equal(any(got), any(expected)) {
		return fmt.Errorf("%w: re-encoded document differs", ErrVerify)
	}
	d.lines = lines
	d.reindex()
	d.discl = append(d.discl, Disclosure{
		Op: op, Path: append(Path(nil), path...),
		Reason: "the edit is inside an array of tables or an inline table, so the whole file was re-serialized: comments, blank lines and key order were not kept",
	})
	return nil
}

// containerOn reports whether some prefix of path (or path itself) is an
// inline table or lives in an array of tables: the line editor refuses
// those and the caller falls back.
func (d *tomlDoc) blocked(path Path) bool {
	for _, e := range d.idx.entries {
		if e.inArray && (hasPrefix(path, e.path) || hasPrefix(e.path, path)) {
			return true
		}
		if e.kind == tomlKeyVal && e.inline && hasPrefix(path, e.path) && len(path) > len(e.path) {
			return true
		}
	}
	return false
}

// surgicalSet returns candidate edited line sets, most idiomatic first.
// The caller installs the first one that decodes to the expected tree, so
// a candidate that TOML's table-definition rules reject costs nothing.
func (d *tomlDoc) surgicalSet(before map[string]any, path Path, v any) [][]line {
	if d.blocked(path) {
		return nil
	}
	eol := dominantEOL(d.lines)
	// 1. An existing key/value at exactly path: replace its value span
	// (a table value is written as an inline table there).
	for _, e := range d.idx.entries {
		if e.kind != tomlKeyVal || !pathEq(e.path, path) {
			continue
		}
		rendered, err := renderTOMLInline(v)
		if err != nil {
			return nil
		}
		first := d.lines[e.first].text[:e.valCol]
		last := d.lines[e.last].text[e.valEnd:]
		repl := []line{{text: first + rendered + last, eol: d.lines[e.last].eol}}
		return [][]line{spliceLines(d.lines, e.first, e.last+1, repl, eol)}
	}
	// 2. path names an existing table: remove it, then insert afresh.
	if cur, found, _ := lookup(before, path); found {
		if _, curIsMap := cur.(map[string]any); curIsMap {
			lines, ok := d.surgicalDelete(path)
			if !ok {
				return nil
			}
			tmp := &tomlDoc{lines: lines, opts: d.opts}
			tmp.reindex()
			return tmp.insertNew(path, v, eol)
		}
	}
	// 3. Absent: insert.
	return d.insertNew(path, v, eol)
}

// insertNew returns candidate insertions of a key that does not exist yet.
func (d *tomlDoc) insertNew(path Path, v any, eol string) [][]line {
	var out [][]line
	parent := path[:len(path)-1]
	leaf := path[len(path)-1]
	if m, isMap := v.(map[string]any); isMap && len(m) > 0 {
		// A table value: a [path] section (with sub-sections) at the end.
		if block, err := renderTOMLTable(path, m); err == nil {
			out = append(out, d.appendBlock(block, eol))
		}
	}
	rendered, err := renderTOMLInline(v)
	if err != nil {
		return out
	}
	// a. After the last direct key of the parent's own [header], or of
	// the deepest ancestor header, as a (dotted) relative key.
	for k := len(parent); k >= 1; k-- {
		for hi, e := range d.idx.entries {
			if e.kind != tomlTable || !pathEq(e.path, parent[:k]) {
				continue
			}
			at, indent := d.afterLastDirectKey(hi)
			ln := line{text: indent + renderTOMLKey(path[k:]) + " = " + rendered, eol: eol}
			out = append(out, spliceLines(d.lines, at, at, []line{ln}, eol))
		}
	}
	if len(parent) > 0 {
		// b. A [parent] section at the end of the file (valid when the
		// parent is absent, or exists only as a super-table of headers).
		block := []string{"[" + renderTOMLKey(parent) + "]", renderTOMLKey([]string{leaf}) + " = " + rendered}
		out = append(out, d.appendBlock(block, eol))
	}
	// c. A (dotted) key among the root keys.
	out = append(out, d.insertRoot(renderTOMLKey(path)+" = "+rendered, eol))
	return out
}

// afterLastDirectKey returns the insertion line after the last key/value
// of the table whose header is entries[hi], and the indentation to use.
func (d *tomlDoc) afterLastDirectKey(hi int) (int, string) {
	h := d.idx.entries[hi]
	at := h.last + 1
	indent := ""
	found := false
	for _, e := range d.idx.entries[hi+1:] {
		if e.kind != tomlKeyVal {
			break
		}
		at = e.last + 1
		indent = leadingWS(d.lines[e.first].text)
		found = true
	}
	if !found && d.indentUnit() != "" {
		indent = leadingWS(d.lines[h.first].text) + d.indentUnit()
	}
	return at, indent
}

// indentUnit is the file's prevailing indentation step ("" when keys sit
// flush left).
func (d *tomlDoc) indentUnit() string {
	best := ""
	for _, e := range d.idx.entries {
		if e.kind != tomlKeyVal || len(e.path) < 2 {
			continue
		}
		ws := leadingWS(d.lines[e.first].text)
		if ws != "" && (best == "" || len(ws) < len(best)) {
			best = ws
		}
	}
	return best
}

// insertRoot puts a root-level key/value after the last root key, or
// before the first table (and the comment block attached to it).
func (d *tomlDoc) insertRoot(text string, eol string) []line {
	at := -1
	for _, e := range d.idx.entries {
		if e.kind != tomlKeyVal {
			break
		}
		at = e.last + 1
	}
	ln := line{text: text, eol: eol}
	if at >= 0 {
		return spliceLines(d.lines, at, at, []line{ln}, eol)
	}
	// No root keys: before the first header.
	first := len(d.lines)
	for _, e := range d.idx.entries {
		first = e.first
		break
	}
	if first == len(d.lines) {
		// No tables at all (only comments / blanks): append.
		return spliceLines(d.lines, len(d.lines), len(d.lines), []line{ln}, eol)
	}
	at = first
	for at > 0 && strings.HasPrefix(strings.TrimSpace(d.lines[at-1].text), "#") {
		at--
	}
	repl := []line{ln, {text: "", eol: eol}}
	return spliceLines(d.lines, at, at, repl, eol)
}

// appendBlock adds a block of lines at the end, separated by one blank
// line from previous content.
func (d *tomlDoc) appendBlock(block []string, eol string) []line {
	var repl []line
	if n := len(d.lines); n > 0 && !isBlank(d.lines[n-1].text) {
		repl = append(repl, line{text: "", eol: eol})
	}
	for _, b := range block {
		repl = append(repl, line{text: b, eol: eol})
	}
	return spliceLines(d.lines, len(d.lines), len(d.lines), repl, eol)
}

// surgicalDelete removes every line that defines path: the key/value at
// path, dotted keys below it, and [path] / [path.*] sections. Comment
// lines directly attached above a removed entry go with it.
func (d *tomlDoc) surgicalDelete(path Path) ([]line, bool) {
	if d.blocked(path) {
		return nil, false
	}
	drop := map[int]bool{}
	entries := d.idx.entries
	for i, e := range entries {
		if !hasPrefix(e.path, path) {
			continue
		}
		switch e.kind {
		case tomlKeyVal:
			for l := e.first; l <= e.last; l++ {
				drop[l] = true
			}
			d.dropAttachedComments(e.first, drop)
		case tomlTable, tomlArrayTable:
			end := e.last
			for _, n := range entries[i+1:] {
				if n.kind != tomlKeyVal {
					break
				}
				end = n.last
			}
			for l := e.first; l <= end; l++ {
				drop[l] = true
			}
			d.dropAttachedComments(e.first, drop)
		}
	}
	if len(drop) == 0 {
		return nil, false
	}
	out := make([]line, 0, len(d.lines))
	for i, l := range d.lines {
		if drop[i] {
			continue
		}
		// Collapse a double blank left behind by the removal.
		if isBlank(l.text) && len(out) > 0 && isBlank(out[len(out)-1].text) && drop[i-1] {
			continue
		}
		out = append(out, l)
	}
	// A removal that reached the end of the file takes the blank lines that
	// only separated it from the content above (appendBlock writes one), so
	// deleting what Set appended restores the file byte for byte.
	if n := len(d.lines); n > 0 && drop[n-1] {
		for len(out) > 0 && isBlank(out[len(out)-1].text) {
			out = out[:len(out)-1]
		}
	}
	// Keep the original "no final newline" state if the old last line was
	// removed.
	if n := len(out); n > 0 && len(d.lines) > 0 && d.lines[len(d.lines)-1].eol == "" && drop[len(d.lines)-1] {
		out[n-1].eol = ""
	}
	return out, true
}

// dropAttachedComments marks the contiguous comment lines directly above
// line first (no blank line between) for removal.
func (d *tomlDoc) dropAttachedComments(first int, drop map[int]bool) {
	for l := first - 1; l >= 0; l-- {
		t := strings.TrimSpace(d.lines[l].text)
		if !strings.HasPrefix(t, "#") {
			return
		}
		drop[l] = true
	}
}

// --- rendering -------------------------------------------------------------

func checkTOMLValue(v any) error {
	switch x := v.(type) {
	case nil:
		return fmt.Errorf("%w: TOML has no null", ErrValueType)
	case []any:
		for _, e := range x {
			if err := checkTOMLValue(e); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, e := range x {
			if err := checkTOMLValue(e); err != nil {
				return err
			}
		}
	}
	return nil
}

var bareTOMLKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func renderTOMLKey(p []string) string {
	parts := make([]string, len(p))
	for i, s := range p {
		if bareTOMLKey.MatchString(s) {
			parts[i] = s
		} else {
			parts[i] = tomlString(s)
		}
	}
	return strings.Join(parts, ".")
}

func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
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
	}
	b.WriteByte('"')
	return b.String()
}

// renderTOMLInline renders a value as an inline TOML value (tables become
// inline tables).
func renderTOMLInline(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return tomlString(x), nil
	case bool:
		return strconv.FormatBool(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		switch {
		case math.IsNaN(x):
			return "nan", nil
		case math.IsInf(x, 1):
			return "inf", nil
		case math.IsInf(x, -1):
			return "-inf", nil
		}
		s := strconv.FormatFloat(x, 'g', -1, 64)
		if !strings.ContainsAny(s, ".eE") {
			s += ".0"
		}
		return s, nil
	case time.Time:
		return x.Format(time.RFC3339Nano), nil
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			s, err := renderTOMLInline(e)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case map[string]any:
		if len(x) == 0 {
			return "{}", nil
		}
		parts := make([]string, 0, len(x))
		for _, k := range sortedKeys(x) {
			s, err := renderTOMLInline(x[k])
			if err != nil {
				return "", err
			}
			parts = append(parts, renderTOMLKey([]string{k})+" = "+s)
		}
		return "{ " + strings.Join(parts, ", ") + " }", nil
	}
	return "", fmt.Errorf("%w: %T in TOML", ErrValueType, v)
}

// renderTOMLTable renders a map as a [path] section: scalar and array
// leaves first, then one sub-section per nested map.
func renderTOMLTable(path Path, m map[string]any) ([]string, error) {
	out := []string{"[" + renderTOMLKey(path) + "]"}
	var subs []string
	for _, k := range sortedKeys(m) {
		if sub, ok := m[k].(map[string]any); ok && len(sub) > 0 {
			subs = append(subs, k)
			continue
		}
		s, err := renderTOMLInline(m[k])
		if err != nil {
			return nil, err
		}
		out = append(out, renderTOMLKey([]string{k})+" = "+s)
	}
	for _, k := range subs {
		block, err := renderTOMLTable(append(append(Path{}, path...), k), m[k].(map[string]any))
		if err != nil {
			return nil, err
		}
		out = append(out, "")
		out = append(out, block...)
	}
	return out, nil
}
