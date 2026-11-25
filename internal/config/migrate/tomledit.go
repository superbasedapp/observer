package migrate

import (
	"strconv"
	"strings"
)

// lineKind classifies a physical line for table-context tracking.
type lineKind int

const (
	kOther  lineKind = iota // blank, comment, or unrecognised
	kHeader                 // [table] or [table.sub]
	kArray                  // [[array.table]]
	kKeyVal                 // key = value  (possibly dotted key)
)

// meta is the analysed view of one physical line. table is set on
// header lines (the table they declare); path + rhs are set on keyval
// lines (path is the FULL dotted path including the enclosing table).
type meta struct {
	kind  lineKind
	table []string
	path  []string
	rhs   string
}

// document is a config.toml held as its physical lines plus the
// analysed metadata aligned index-for-index. lines is the source of
// truth; metas is recomputed via analyze after any structural edit so
// paths never drift from the text.
type document struct {
	lines      []string
	metas      []meta
	trailingNL bool
}

// parseDocument splits text into lines and analyses table context.
func parseDocument(text string) *document {
	lines, trailing := SplitLines(text)
	d := &document{lines: lines, trailingNL: trailing}
	d.metas = analyze(lines)
	return d
}

// render reassembles the document back into text, preserving the
// original trailing-newline state.
func (d *document) render() string {
	return JoinLines(d.lines, d.trailingNL)
}

// SplitLines splits a TOML file's text into its physical lines and
// reports whether it ended in a newline. Empty text yields no lines.
// JoinLines(SplitLines(text)) returns text byte for byte, which is what
// lets every line editor in package config leave an untouched file
// unchanged.
func SplitLines(text string) (lines []string, trailingNL bool) {
	trailingNL = strings.HasSuffix(text, "\n")
	body := text
	if trailingNL {
		body = body[:len(body)-1]
	}
	if body == "" && !trailingNL {
		return nil, trailingNL
	}
	return strings.Split(body, "\n"), trailingNL
}

// JoinLines reassembles lines split by SplitLines, restoring the trailing
// newline when trailingNL is set.
func JoinLines(lines []string, trailingNL bool) string {
	s := strings.Join(lines, "\n")
	if trailingNL {
		s += "\n"
	}
	return s
}

// reanalyze recomputes metadata after a structural mutation.
func (d *document) reanalyze() { d.metas = analyze(d.lines) }

// analyze walks the lines maintaining the current table context and
// returns per-line metadata aligned to lines.
func analyze(lines []string) []meta {
	metas := make([]meta, len(lines))
	var cur []string // current table path (nil = root)
	for i, raw := range lines {
		t := strings.TrimLeft(raw, " \t")
		switch {
		case t == "" || t[0] == '#':
			metas[i] = meta{kind: kOther}
		case strings.HasPrefix(t, "[["):
			cur = HeaderPath(t, true)
			metas[i] = meta{kind: kArray, table: cur}
		case t[0] == '[':
			cur = HeaderPath(t, false)
			metas[i] = meta{kind: kHeader, table: cur}
		default:
			key, rhs, ok := splitKeyVal(raw)
			if !ok {
				metas[i] = meta{kind: kOther}
				continue
			}
			seg := SplitDottedKey(key)
			full := make([]string, 0, len(cur)+len(seg))
			full = append(full, cur...)
			full = append(full, seg...)
			metas[i] = meta{kind: kKeyVal, path: full, rhs: rhs}
		}
	}
	return metas
}

// HeaderPath extracts the dotted table path from a header line (already
// trimmed of leading whitespace). For array tables (`[[a.b]]`) pass
// array=true. Best-effort: an inline
// comment or exotic quoting only risks a MISS (the line won't match a
// migration target), never a wrong edit.
func HeaderPath(trimmed string, array bool) []string {
	open, close := "[", "]"
	if array {
		open, close = "[[", "]]"
	}
	inner := trimmed[len(open):]
	if idx := strings.Index(inner, close); idx >= 0 {
		inner = inner[:idx]
	}
	return SplitDottedKey(inner)
}

// splitKeyVal splits a `key = value` line into its raw left-hand key
// text and raw right-hand value text (both trimmed of surrounding
// spaces). Returns ok=false for lines with no top-level '='.
func splitKeyVal(raw string) (key, rhs string, ok bool) {
	// The key half is everything before the first '='. A quoted key
	// containing '=' is vanishingly rare; a misparse here only causes a
	// missed match, never a wrong edit (Apply acts on exact paths only).
	i := strings.IndexByte(raw, '=')
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(raw[:i])
	rhs = strings.TrimSpace(raw[i+1:])
	if key == "" {
		return "", "", false
	}
	return key, rhs, true
}

// SplitDottedKey splits a dotted TOML key/table path on '.' outside
// quotes and trims quotes/space from each segment. It is the one
// quote-aware dotted-key splitter in package config and its
// subpackages.
func SplitDottedKey(s string) []string {
	var segs []string
	var b strings.Builder
	inBasic, inLiteral := false, false
	flush := func() {
		seg := strings.TrimSpace(b.String())
		seg = strings.Trim(seg, `"'`)
		if seg != "" {
			segs = append(segs, seg)
		}
		b.Reset()
	}
	for _, r := range s {
		switch {
		case inBasic:
			if r == '"' {
				inBasic = false
			}
			b.WriteRune(r)
		case inLiteral:
			if r == '\'' {
				inLiteral = false
			}
			b.WriteRune(r)
		case r == '"':
			inBasic = true
			b.WriteRune(r)
		case r == '\'':
			inLiteral = true
			b.WriteRune(r)
		case r == '.':
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return segs
}

// scalarSafe reports whether rhs is a single-line scalar value the
// editor can move verbatim. Arrays, inline tables, and multiline
// strings are rejected so Apply can Skip rather than mangle them.
func scalarSafe(rhs string) bool {
	if rhs == "" {
		return false
	}
	if rhs[0] == '[' || rhs[0] == '{' {
		return false
	}
	if strings.Contains(rhs, `"""`) || strings.Contains(rhs, "'''") {
		return false
	}
	return true
}

// findKey returns the index of the keyval line at exactly path, or
// -1 if absent.
func (d *document) findKey(path []string) int {
	for i, m := range d.metas {
		if m.kind == kKeyVal && pathEqual(m.path, path) {
			return i
		}
	}
	return -1
}

// findHeader returns the index of the [table] header declaring exactly
// path, or -1 if absent.
func (d *document) findHeader(path []string) int {
	for i, m := range d.metas {
		if m.kind == kHeader && pathEqual(m.table, path) {
			return i
		}
	}
	return -1
}

// removeIndices rebuilds the line slice with the given indices dropped,
// then reanalyzes.
func (d *document) removeIndices(drop map[int]bool) {
	if len(drop) == 0 {
		return
	}
	out := make([]string, 0, len(d.lines))
	for i, l := range d.lines {
		if !drop[i] {
			out = append(out, l)
		}
	}
	d.lines = out
	d.reanalyze()
}

// upsertScalar sets the leaf key of path to rhs. If the key already
// exists its value line is replaced in place (its own indent kept).
// Otherwise the key is inserted after the table's last direct key
// (falling back to just after the header), creating the [table] header
// — and the whole block at EOF — when absent. Inserted lines are
// indented to MATCH the file's prevailing style (a flat file stays
// flat; a 2-space nested / BurntSushi-encoded file gets depth-indented
// keys and headers) so additions don't stick out. rhs is written
// verbatim so an existing value + any trailing inline comment survives.
func (d *document) upsertScalar(path []string, rhs string) {
	leaf := path[len(path)-1]
	table := path[:len(path)-1]

	if idx := d.findKey(path); idx >= 0 {
		indent := leadingWS(d.lines[idx])
		d.lines[idx] = indent + leaf + " = " + rhs
		d.reanalyze()
		return
	}

	newLine := d.keyIndent(len(table)) + leaf + " = " + rhs
	if len(table) == 0 {
		d.lines = append(d.lines, newLine)
		d.reanalyze()
		return
	}
	if hi := d.findHeader(table); hi >= 0 {
		d.lines = insertAt(d.lines, d.lastDirectKeyIndex(hi, table)+1, newLine)
		d.reanalyze()
		return
	}
	// Append a fresh table block at EOF, separated by a blank line, with
	// the header indented by its nesting depth to match the file style.
	header := d.headerIndent(len(table)) + "[" + strings.Join(table, ".") + "]"
	block := []string{"", header, newLine}
	if len(d.lines) == 0 {
		block = block[1:] // no leading blank on an empty file
	}
	d.lines = append(d.lines, block...)
	d.reanalyze()
}

// indentUnit returns the file's prevailing single-level indentation
// (e.g. "  " for a BurntSushi-encoded config), or "" when the file
// keeps keys/headers flush-left. Detected as the smallest positive
// leading-whitespace across key and header lines.
func (d *document) indentUnit() string {
	best := -1
	unit := ""
	for i, m := range d.metas {
		if m.kind != kKeyVal && m.kind != kHeader {
			continue
		}
		ws := leadingWS(d.lines[i])
		if n := len(ws); n > 0 && (best < 0 || n < best) {
			best, unit = n, ws
		}
	}
	return unit
}

// keyIndent returns the indentation for a key whose enclosing table has
// tableDepth segments (unit×depth in nested style, "" when flat).
func (d *document) keyIndent(tableDepth int) string {
	u := d.indentUnit()
	if u == "" || tableDepth <= 0 {
		return ""
	}
	return strings.Repeat(u, tableDepth)
}

// headerIndent returns the indentation for a [table] header of the
// given depth (unit×(depth-1) in nested style — a top-level table is
// flush-left, a sub-table is indented one level, matching BurntSushi).
func (d *document) headerIndent(depth int) string {
	u := d.indentUnit()
	if u == "" || depth <= 1 {
		return ""
	}
	return strings.Repeat(u, depth-1)
}

// lastDirectKeyIndex returns the index of the last DIRECT key line of
// the table headed at headerIdx (a key whose path is exactly table+leaf),
// or headerIdx when the table has no direct keys yet. Scanning stops at
// the next table/array header so sub-table keys aren't counted.
func (d *document) lastDirectKeyIndex(headerIdx int, table []string) int {
	last := headerIdx
	for i := headerIdx + 1; i < len(d.metas); i++ {
		switch d.metas[i].kind {
		case kHeader, kArray:
			return last
		case kKeyVal:
			if len(d.metas[i].path) == len(table)+1 {
				last = i
			}
		}
	}
	return last
}

// readInt returns the integer value of the scalar at path, if present
// and parseable.
func (d *document) readInt(path []string) (int, bool) {
	idx := d.findKey(path)
	if idx < 0 {
		return 0, false
	}
	v := strings.TrimSpace(stripInlineComment(d.metas[idx].rhs))
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

// dropEmptyTable removes a [table] header whose block holds no keyval
// lines (only blanks/comments before the next header or EOF). Used to
// clean up a legacy block left hollow after its keys migrated away.
func (d *document) dropEmptyTable(table []string) {
	hi := d.findHeader(table)
	if hi < 0 {
		return
	}
	for i := hi + 1; i < len(d.metas); i++ {
		switch d.metas[i].kind {
		case kHeader, kArray:
			// reached the next table; block had no keyvals
			d.removeIndices(map[int]bool{hi: true})
			return
		case kKeyVal:
			return // block still has content
		}
	}
	// ran to EOF with no keyvals
	d.removeIndices(map[int]bool{hi: true})
}

func leadingWS(s string) string {
	return s[:len(s)-len(strings.TrimLeft(s, " \t"))]
}

// stripInlineComment removes a trailing `# ...` comment from a scalar
// rhs, respecting basic/literal strings. Used only for reading an int
// value, never for moving a value (moves keep the rhs verbatim).
func stripInlineComment(rhs string) string {
	inBasic, inLiteral := false, false
	for i, r := range rhs {
		switch {
		case inBasic:
			if r == '"' {
				inBasic = false
			}
		case inLiteral:
			if r == '\'' {
				inLiteral = false
			}
		case r == '"':
			inBasic = true
		case r == '\'':
			inLiteral = true
		case r == '#':
			return strings.TrimSpace(rhs[:i])
		}
	}
	return rhs
}

func insertAt(lines []string, at int, v string) []string {
	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:at]...)
	out = append(out, v)
	out = append(out, lines[at:]...)
	return out
}

func pathEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func dottedPath(p []string) string { return strings.Join(p, ".") }
