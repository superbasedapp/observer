package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// AdoptResult reports what AdoptEnabledAdapters found and (if asked to
// write) changed.
type AdoptResult struct {
	// Missing is the set of default adapter names absent from the
	// operator's explicit enabled_adapters list, in registry order.
	// Empty when there is nothing to adopt (no explicit list, or the
	// explicit list already covers every default).
	Missing []string
	// Changed reports whether newBody differs from the input — true
	// only when len(Missing) > 0 and the array could be edited safely.
	Changed bool
	// Skipped reports that an explicit enabled_adapters key exists but
	// its value could not be edited with confidence (not a literal
	// array of plain strings). newBody is byte-identical to the input.
	Skipped    bool
	SkipReason string
	// HadExplicitList reports whether config.toml carries an explicit
	// [observer.watch] enabled_adapters key at all. When false, the
	// operator already inherits every default via Config.Default() and
	// there is nothing to adopt — Missing/Changed/Skipped are all
	// zero-value regardless of the defaults argument.
	HadExplicitList bool
	// Existing is the operator's current list, as parsed, in file
	// order. Populated whenever HadExplicitList is true and the array
	// was parsed successfully (i.e. not Skipped).
	Existing []string
}

// AdoptEnabledAdapters is the pure, I/O-free core of
// `observer config adopt-defaults` (Invariant #51 drift hardening).
//
// Config.Default() only seeds [observer.watch] enabled_adapters when
// the key is ABSENT from config.toml — BurntSushi TOML decoding only
// overwrites keys present in the file, so an operator with an explicit
// list from a prior release never picks up newly-registered default
// adapters. This function computes (and, via the returned newBody,
// applies) the fix: append every name in defaults that is missing from
// the operator's existing enabled_adapters array, preserving the
// array's existing order, formatting, and comments.
//
// tomlBody is the full text of config.toml. defaults is the current
// registry's adapter names in the order they should be reported/
// appended (callers pass adapterdefaults.Adapters() names — this
// package intentionally does not import the adapter registry, per the
// module-boundary rule that internal/config stays free of the adapter
// package graph).
//
// AdoptEnabledAdapters never corrupts the file: if the enabled_adapters
// value is anything other than a literal array of plain quoted strings
// (a TOML reference, an array containing a non-string, a nested array,
// an inline table, or a value the line-scanner cannot close with
// confidence), it returns Skipped=true and newBody identical to
// tomlBody — mirroring internal/config/migrate.Apply's fail-safe
// posture.
//
// Implementation note: internal/config/migrate's tomledit.go document/
// analyze machinery is intentionally NOT reused here. Its types and
// helpers (document, meta, parseDocument, upsertScalar, …) are
// unexported to that package, and — more fundamentally — upsertScalar
// explicitly refuses to touch array values (scalarSafe rejects any rhs
// starting with '[' or '{'), since it only ever moves a scalar
// verbatim. Editing INSIDE an existing array (appending elements while
// preserving the operator's line breaks / indentation / trailing
// commas / inline comments) is a different, array-shaped problem, so
// this file carries its own small, self-contained, quote-aware line
// scanner scoped to exactly this one key.
func AdoptEnabledAdapters(tomlBody string, defaults []string) (newBody string, res AdoptResult, err error) {
	lines, trailingNL := splitAdoptLines(tomlBody)

	keyLine, eqPos, found := findEnabledAdaptersKey(lines)
	if !found {
		return tomlBody, res, nil
	}
	res.HadExplicitList = true

	startLine, startCol, endLine, endCol, ok := locateArrayBounds(lines, keyLine, eqPos)
	if !ok {
		res.Skipped = true
		res.SkipReason = fmt.Sprintf(
			"line %d: enabled_adapters is not a single literal array I can safely edit (not closed on a plain line, or nests an array/inline table) — add the missing adapters by hand",
			keyLine+1,
		)
		return tomlBody, res, nil
	}

	inner := extractArrayInner(lines, startLine, startCol, endLine, endCol)
	existing, ok := parseArrayElements(inner)
	if !ok {
		res.Skipped = true
		res.SkipReason = fmt.Sprintf(
			"line %d: enabled_adapters contains a value that is not a plain quoted adapter name — add the missing adapters by hand",
			keyLine+1,
		)
		return tomlBody, res, nil
	}
	res.Existing = existing

	have := make(map[string]bool, len(existing))
	for _, n := range existing {
		have[n] = true
	}
	var missing []string
	for _, d := range defaults {
		if !have[d] {
			missing = append(missing, d)
		}
	}
	res.Missing = missing
	if len(missing) == 0 {
		return tomlBody, res, nil
	}

	quoted := make([]string, len(missing))
	for i, m := range missing {
		quoted[i] = strconv.Quote(m)
	}

	newLines := appendToArray(lines, startLine, endLine, endCol, quoted)
	res.Changed = true
	return joinAdoptLines(newLines, trailingNL), res, nil
}

// AdoptEnabledAdaptersFile is the I/O boundary for `observer config
// adopt-defaults --write`: it reads the config.toml at path, runs the
// pure AdoptEnabledAdapters, and — only when a change was actually
// computed and nothing was skipped — writes the result back through
// the shared atomic writer (a path+".bak" backup, then temp-file +
// rename), mirroring MigrateFile exactly.
//
// A missing file, a file with no explicit enabled_adapters key, or a
// list that already covers every default all return a zero-change
// AdoptResult and touch nothing. A file whose enabled_adapters value
// can't be edited safely comes back Skipped=true, again untouched.
//
// path must be the already-resolved global (or project) config path
// (callers use ResolveGlobalPath). defaults is the current adapter
// registry's names, in registry order.
func AdoptEnabledAdaptersFile(path string, defaults []string) (AdoptResult, error) {
	if path == "" {
		return AdoptResult{}, errors.New("config.AdoptEnabledAdaptersFile: empty path")
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return AdoptResult{}, nil
	}
	if err != nil {
		return AdoptResult{}, fmt.Errorf("config.AdoptEnabledAdaptersFile: read %s: %w", path, err)
	}
	newBody, res, err := AdoptEnabledAdapters(string(body), defaults)
	if err != nil {
		return res, fmt.Errorf("config.AdoptEnabledAdaptersFile: apply %s: %w", path, err)
	}
	if res.Changed && !res.Skipped {
		if err := writeBytesAtomic(path, []byte(newBody)); err != nil {
			return res, fmt.Errorf("config.AdoptEnabledAdaptersFile: write %s: %w", path, err)
		}
	}
	return res, nil
}

// splitAdoptLines / joinAdoptLines mirror migrate's tomledit
// parseDocument/render trailing-newline handling (kept in step so
// round-tripping an unchanged file is byte-identical), duplicated
// locally since those helpers are unexported to package migrate.
func splitAdoptLines(text string) (lines []string, trailingNL bool) {
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

func joinAdoptLines(lines []string, trailingNL bool) string {
	s := strings.Join(lines, "\n")
	if trailingNL {
		s += "\n"
	}
	return s
}

// findEnabledAdaptersKey scans lines tracking the current [table]
// context and returns the line/column of the '=' on the
// enabled_adapters key declared under [observer.watch] — either via an
// explicit [observer.watch] header (the common, BurntSushi-encoded
// shape) or an equivalent dotted key at any table depth
// (observer.watch.enabled_adapters = ...). Returns found=false if no
// such key exists.
func findEnabledAdaptersKey(lines []string) (lineIdx, eqPos int, found bool) {
	var curTable []string
	for i, raw := range lines {
		t := strings.TrimLeft(raw, " \t")
		switch {
		case t == "" || strings.HasPrefix(t, "#"):
			continue
		case strings.HasPrefix(t, "[["):
			curTable = adoptDottedKey(adoptHeaderInner(t, true))
		case strings.HasPrefix(t, "["):
			curTable = adoptDottedKey(adoptHeaderInner(t, false))
		default:
			eq := strings.IndexByte(raw, '=')
			if eq < 0 {
				continue
			}
			key := strings.TrimSpace(raw[:eq])
			if key == "" {
				continue
			}
			segs := adoptDottedKey(key)
			if len(segs) == 0 {
				continue
			}
			if segs[len(segs)-1] != "enabled_adapters" {
				continue
			}
			full := make([]string, 0, len(curTable)+len(segs)-1)
			full = append(full, curTable...)
			full = append(full, segs[:len(segs)-1]...)
			if adoptPathEqual(full, []string{"observer", "watch"}) {
				return i, eq, true
			}
		}
	}
	return 0, 0, false
}

// adoptHeaderInner extracts the dotted path text from a [table] or
// [[array.table]] header line (best-effort — same tolerance as
// tomledit's parseHeaderPath: a miss only means the header isn't
// recognised, never a wrong edit).
func adoptHeaderInner(trimmed string, array bool) string {
	open, closeTok := "[", "]"
	if array {
		open, closeTok = "[[", "]]"
	}
	inner := trimmed[len(open):]
	if idx := strings.Index(inner, closeTok); idx >= 0 {
		inner = inner[:idx]
	}
	return inner
}

// adoptDottedKey splits a dotted TOML key/table path on '.' outside
// quotes, trimming quotes/space from each segment.
func adoptDottedKey(s string) []string {
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

func adoptPathEqual(a, b []string) bool {
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

// locateArrayBounds scans forward from (keyLine, eqPos) for a literal
// `[ ... ]` array value, tracking bracket depth and quote state
// (respecting '#' comments outside strings). It returns the position
// just inside the opening bracket (startLine, startCol) and just
// before the matching closing bracket (endLine, endCol). ok is false
// when the value doesn't open with '[' at all, nests a second array or
// an inline table, or never closes — every case where safe editing
// can't be guaranteed.
func locateArrayBounds(lines []string, keyLine, eqPos int) (startLine, startCol, endLine, endCol int, ok bool) {
	li, ci := keyLine, eqPos+1
	depth := 0
	started := false
	inStr := false
	var quote byte
	escaped := false

	for li < len(lines) {
		line := lines[li]
		for ci < len(line) {
			c := line[ci]
			switch {
			case inStr:
				switch {
				case escaped:
					escaped = false
				case quote == '"' && c == '\\':
					escaped = true
				case c == quote:
					inStr = false
				}
			case c == '#':
				ci = len(line)
				continue
			case c == '"' || c == '\'':
				inStr = true
				quote = c
			case c == '[':
				depth++
				if depth > 1 {
					return 0, 0, 0, 0, false
				}
				started = true
				startLine, startCol = li, ci+1
			case c == '{':
				if started {
					return 0, 0, 0, 0, false
				}
			case c == ']':
				if !started {
					return 0, 0, 0, 0, false
				}
				depth--
				if depth == 0 {
					return startLine, startCol, li, ci, true
				}
			}
			ci++
		}
		li++
		ci = 0
	}
	return 0, 0, 0, 0, false
}

// stripAdoptLineComment removes a trailing `# ...` comment from s,
// respecting basic/literal string quoting. Duplicated from (rather
// than importing) migrate's stripInlineComment for the same reason
// documented on AdoptEnabledAdapters: that helper is unexported.
func stripAdoptLineComment(s string) string {
	inStr := false
	var quote byte
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case escaped:
				escaped = false
			case quote == '"' && c == '\\':
				escaped = true
			case c == quote:
				inStr = false
			}
			continue
		}
		switch c {
		case '"', '\'':
			inStr = true
			quote = c
		case '#':
			return s[:i]
		}
	}
	return s
}

// extractArrayInner returns the array's element text (between the
// brackets, across however many lines it spans) with any trailing
// per-line comments stripped, ready for parseArrayElements.
func extractArrayInner(lines []string, startLine, startCol, endLine, endCol int) string {
	var sb strings.Builder
	for li := startLine; li <= endLine; li++ {
		line := lines[li]
		var seg string
		switch {
		case startLine == endLine && li == startLine:
			seg = line[startCol:endCol]
		case li == startLine:
			seg = line[startCol:]
		case li == endLine:
			seg = line[:endCol]
		default:
			seg = line
		}
		sb.WriteString(stripAdoptLineComment(seg))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// parseArrayElements splits comment-stripped array-inner text into its
// quoted string elements, unquoting each. ok is false the moment any
// element is not a plain basic/literal TOML string (a number, bool,
// nested structure, or otherwise malformed value) — the caller treats
// that as unsafe to edit.
func parseArrayElements(inner string) ([]string, bool) {
	var elements []string
	var cur strings.Builder
	inStr := false
	var quote byte
	escaped := false

	flush := func() bool {
		s := strings.TrimSpace(cur.String())
		cur.Reset()
		if s == "" {
			return true
		}
		name, ok := adoptUnquote(s)
		if !ok {
			return false
		}
		elements = append(elements, name)
		return true
	}

	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if inStr {
			cur.WriteByte(c)
			switch {
			case escaped:
				escaped = false
			case quote == '"' && c == '\\':
				escaped = true
			case c == quote:
				inStr = false
			}
			continue
		}
		switch c {
		case '"', '\'':
			inStr = true
			quote = c
			cur.WriteByte(c)
		case ',':
			if !flush() {
				return nil, false
			}
		default:
			cur.WriteByte(c)
		}
	}
	if !flush() {
		return nil, false
	}
	return elements, true
}

// adoptUnquote unwraps a TOML basic ("...") or literal ('...') string
// literal. Any other shape (bare word, number, boolean, unterminated
// quote) is rejected.
func adoptUnquote(s string) (string, bool) {
	if len(s) < 2 {
		return "", false
	}
	switch s[0] {
	case '"':
		if s[len(s)-1] != '"' {
			return "", false
		}
		unq, err := strconv.Unquote(s)
		if err != nil {
			return "", false
		}
		return unq, true
	case '\'':
		if s[len(s)-1] != '\'' {
			return "", false
		}
		return s[1 : len(s)-1], true
	default:
		return "", false
	}
}

// appendToArray returns a copy of lines with quoted appended as new
// elements of the array spanning [startLine, endLine], as far as
// possible in the operator's own style: inline when the whole array
// (or its last element) already lives on one line, as new indented
// lines (mirroring an existing element line's indent, and adding a
// trailing comma to the prior last element if it lacked one) when the
// closing bracket sits alone on its own line.
func appendToArray(lines []string, startLine, endLine, endCol int, quoted []string) []string {
	out := append([]string(nil), lines...)

	beforeClose := out[endLine][:endCol]
	after := out[endLine][endCol:]
	trimmedBeforeClose := strings.TrimRight(beforeClose, " \t")

	if startLine == endLine || trimmedBeforeClose != "" {
		// Single-line array, or a multi-line array whose last element(s)
		// share the closing-bracket line: append inline before ']'.
		out[endLine] = adoptInsertInline(beforeClose, quoted) + after
		return out
	}

	// Closing bracket alone on its own line: insert new element lines
	// just above it, matching an existing element line's indent, and
	// make sure the previous content line ends with a comma.
	indent := adoptElementIndent(out, startLine, endLine)
	prev := endLine - 1
	for prev > startLine && strings.TrimSpace(stripAdoptLineComment(out[prev])) == "" {
		prev--
	}
	if prev >= startLine {
		out[prev] = adoptEnsureTrailingComma(out[prev])
	}

	newElemLines := make([]string, len(quoted))
	for i, q := range quoted {
		newElemLines[i] = indent + q + ","
	}
	merged := make([]string, 0, len(out)+len(newElemLines))
	merged = append(merged, out[:endLine]...)
	merged = append(merged, newElemLines...)
	merged = append(merged, out[endLine:]...)
	return merged
}

// adoptInsertInline appends quoted elements just before an array's
// closing bracket, given the raw text preceding it (which may be
// "...enabled_adapters = [" for an empty array, "...[\"a\"" with no
// trailing comma, or "...[\"a\"," already comma-terminated).
func adoptInsertInline(before string, quoted []string) string {
	trimmed := strings.TrimRight(before, " \t")
	joined := strings.Join(quoted, ", ")
	switch {
	case strings.HasSuffix(trimmed, "["):
		return trimmed + joined
	case strings.HasSuffix(trimmed, ","):
		return trimmed + " " + joined + ","
	default:
		return trimmed + ", " + joined
	}
}

// adoptEnsureTrailingComma appends a comma to a content line's code
// portion if it doesn't already end with one, preserving any trailing
// inline comment.
func adoptEnsureTrailingComma(line string) string {
	code := stripAdoptLineComment(line)
	comment := line[len(code):]
	trimmedCode := strings.TrimRight(code, " \t")
	if trimmedCode == "" || strings.HasSuffix(trimmedCode, ",") {
		return line
	}
	if comment == "" {
		return trimmedCode + ","
	}
	return trimmedCode + ", " + comment
}

// adoptElementIndent returns the indentation to use for new element
// lines: an existing element line's leading whitespace when one is
// present between the opening and closing brackets, else one indent
// level (two spaces) past the key line — a reasonable default for an
// array that was written empty across two lines.
func adoptElementIndent(lines []string, startLine, endLine int) string {
	for i := startLine + 1; i < endLine; i++ {
		if strings.TrimSpace(stripAdoptLineComment(lines[i])) == "" {
			continue
		}
		s := lines[i]
		return s[:len(s)-len(strings.TrimLeft(s, " \t"))]
	}
	s := lines[startLine]
	base := s[:len(s)-len(strings.TrimLeft(s, " \t"))]
	return base + "  "
}
