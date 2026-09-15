package migrate

import (
	"strconv"
	"strings"
)

// ScalarPatch is one leaf edit for PatchScalars: the dotted TOML path as
// segments and the fully-rendered single-line TOML right-hand side (a
// quoted string, a bare number, true/false). Rendering the value is the
// caller's job (internal/configschema.TOMLScalar); this editor moves text.
type ScalarPatch struct {
	Path []string
	RHS  string
}

// PatchResult is the outcome of PatchScalars. Applied and Unsafe are dotted
// paths. The edit is ALL-OR-NOTHING: when Unsafe is non-empty, Text is the
// input unchanged and Applied is nil, so a caller can fall back to a full
// re-serialize for the whole batch rather than half-patch the file.
type PatchResult struct {
	Text    string
	Applied []string
	Unsafe  []string
	Reason  string
}

// PatchScalars applies scalar key edits to config.toml text by line surgery
// (plan §2.3 Tier A), preserving every untouched line byte-for-byte:
//
//   - an existing `key = value` line is rewritten in place, keeping its
//     indentation AND any trailing inline `# comment`;
//   - a missing key is inserted after its table's last direct key (creating
//     the [table] header at EOF in the file's prevailing indent style);
//   - CRLF files stay CRLF.
//
// It refuses — reporting the path in Unsafe and touching nothing — whenever
// the surgery could not be exact: the existing value is an array, an inline
// table or a multi-line string; the new RHS is not a single-line scalar; the
// enclosing table is declared as an inline table or an [[array]] table (an
// inserted [table] header would then redefine it). The "skip rather than
// mangle" property of the migration editor is inherited, not re-invented.
func PatchScalars(text string, patches []ScalarPatch) PatchResult {
	crlf := strings.Contains(text, "\r\n")
	work := text
	if crlf {
		work = strings.ReplaceAll(work, "\r\n", "\n")
	}
	doc := parseDocument(work)
	res := PatchResult{Text: text}

	// Plan every edit against the ORIGINAL document first so a refusal on
	// the third patch cannot leave the first two applied.
	type edit struct {
		p       ScalarPatch
		lineIdx int // -1 ⇒ insert
		rhs     string
	}
	edits := make([]edit, 0, len(patches))
	for _, p := range patches {
		dotted := dottedPath(p.Path)
		if len(p.Path) == 0 || !scalarSafe(p.RHS) || strings.ContainsAny(p.RHS, "\r\n") {
			res.Unsafe = append(res.Unsafe, dotted)
			res.Reason = "new value for " + dotted + " is not a single-line scalar"
			continue
		}
		idx := doc.findKey(p.Path)
		if idx >= 0 {
			value, comment := splitInlineComment(doc.metas[idx].rhs)
			if !scalarSafe(value) {
				res.Unsafe = append(res.Unsafe, dotted)
				res.Reason = "existing value at " + dotted + " is an array, inline table or multi-line string"
				continue
			}
			rhs := p.RHS
			if comment != "" {
				rhs += " " + comment
			}
			edits = append(edits, edit{p: p, lineIdx: idx, rhs: rhs})
			continue
		}
		if reason := doc.insertBlocker(p.Path); reason != "" {
			res.Unsafe = append(res.Unsafe, dotted)
			res.Reason = reason
			continue
		}
		edits = append(edits, edit{p: p, lineIdx: -1, rhs: p.RHS})
	}
	if len(res.Unsafe) > 0 {
		return res
	}

	// In-place rewrites first (indices are stable), then inserts (each
	// reanalyzes, so paths stay aligned with the text).
	for _, e := range edits {
		if e.lineIdx < 0 {
			continue
		}
		indent := leadingWS(doc.lines[e.lineIdx])
		// Keep the key exactly as written (a dotted or quoted key must not
		// be re-spelled); only the value changes.
		key, _, _ := splitKeyVal(doc.lines[e.lineIdx])
		doc.lines[e.lineIdx] = indent + key + " = " + e.rhs
		res.Applied = append(res.Applied, dottedPath(e.p.Path))
	}
	doc.reanalyze()
	for _, e := range edits {
		if e.lineIdx >= 0 {
			continue
		}
		doc.upsertScalar(e.p.Path, e.rhs)
		res.Applied = append(res.Applied, dottedPath(e.p.Path))
	}
	out := doc.render()
	if crlf {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}
	res.Text = out
	return res
}

// insertBlocker reports why a NEW key at path cannot be inserted by line
// surgery: an ancestor is itself a key line (an inline table or scalar the
// analyzer does not descend into), or an ancestor table is declared as an
// [[array]] table. Returns "" when insertion is safe.
func (d *document) insertBlocker(path []string) string {
	for i := 1; i < len(path); i++ {
		anc := path[:i]
		if idx := d.findKey(anc); idx >= 0 {
			return "table " + dottedPath(anc) + " is written as an inline value at line " + strconv.Itoa(idx+1) + " — cannot insert " + dottedPath(path) + " by line surgery"
		}
		for j, m := range d.metas {
			if m.kind == kArray && pathEqual(m.table, anc) {
				return "table " + dottedPath(anc) + " is an [[array]] table at line " + strconv.Itoa(j+1) + " — cannot insert " + dottedPath(path) + " by line surgery"
			}
		}
	}
	return ""
}

// splitInlineComment separates a raw rhs into its value text and any
// trailing `# comment` (returned WITH the '#', "" when absent), respecting
// basic and literal strings so a '#' inside quotes is not a comment.
func splitInlineComment(rhs string) (value, comment string) {
	value = stripInlineComment(rhs)
	if len(value) == len(rhs) {
		return value, ""
	}
	rest := strings.TrimSpace(rhs[len(value):])
	// stripInlineComment trims the value's trailing space, so `rest` starts
	// at the '#' only after that whitespace; find it explicitly.
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		return value, rest[i:]
	}
	return value, ""
}
