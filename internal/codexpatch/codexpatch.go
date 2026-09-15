package codexpatch

import (
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ScanLimit bounds a single linear pass over a unified-exec `input`
// blob. Live programs top out in the low hundreds of kilobytes (an
// apply_patch envelope carrying whole new files); the cap only
// guarantees a malformed or hostile blob cannot turn parsing into a long
// stall. It is exported because the Codex adapter's own dispatcher
// scanner must bound its pass by the SAME limit — two different caps
// would let the scanner see a call whose binding the resolver cannot
// reach.
const ScanLimit = 4 << 20

// applyPatchIdent is the inner dispatcher verb whose single argument is
// a raw patch envelope. ExtractPatch looks for a call to it by NAME, so
// it resolves `tools.apply_patch(p)`, `t.apply_patch(p)` and a bare
// `apply_patch(p)` alike — the dispatcher namespace is the adapter's
// concern, not this package's.
const applyPatchIdent = "apply_patch"

// ExtractPatch resolves the decoded `*** Begin Patch …` envelope out of
// a whole unified-exec JavaScript program, or returns "" when the
// program contains no resolvable patch argument.
//
// It walks the program ONCE — string- and comment-aware — looking for an
// `apply_patch( … )` call, then resolves that call's single argument
// through PatchArgument: an inline string literal, a String.raw tagged
// template, or an identifier bound to one earlier in the program. The
// FIRST apply_patch call whose argument resolves wins; a call whose
// argument cannot be resolved (a hoisted array, a join, a value assigned
// only AFTER the call site) is skipped rather than guessed at, and a
// program with no resolvable call yields "".
//
// The returned text is whatever the call's argument decoded to; it is
// not re-validated against the `*** Begin Patch` header, because the
// call site — not the content — is what identifies it as a patch.
//
// It never panics. A truncated, unbalanced or non-JavaScript program
// yields "".
func ExtractPatch(program string) string {
	src := program
	if len(src) > ScanLimit {
		src = src[:ScanLimit]
	}
	for i := 0; i < len(src); {
		switch {
		case IsJSQuote(src[i]):
			i = SkipJSString(src, i)
		case strings.HasPrefix(src[i:], "//"):
			nl := strings.IndexByte(src[i:], '\n')
			if nl < 0 {
				return ""
			}
			i += nl + 1
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return ""
			}
			i += 2 + end + 2
		case isJSIdentStart(src[i]) && (i == 0 || !IsJSIdentByte(src[i-1])):
			name, after := ReadJSIdent(src, i)
			if name != applyPatchIdent {
				i = after
				continue
			}
			open := SkipJSSpace(src, after)
			if open >= len(src) || src[open] != '(' {
				// `apply_patch` mentioned but not called.
				i = after
				continue
			}
			args, end := ReadJSParenGroup(src, open)
			if v := PatchArgument(src, args, i); v != "" {
				return v
			}
			i = end
		default:
			i++
		}
	}
	return ""
}

// StringField returns the decoded value of the first `key: "…"` pair
// in an object-literal source, and whether it was found. Keys appear
// BOTH bare (`cmd:`) and quoted (`"plan":`) in live programs, sometimes
// within one call, so both forms are accepted. Values that are not
// string literals (numbers, arrays, nested objects) are skipped rather
// than stringified. Found-but-empty is reported as ("", true) so the
// caller can distinguish "no such field" from a genuinely empty one.
func StringField(src, key string) (string, bool) {
	for i := 0; i < len(src); {
		var name string
		var after int
		switch {
		case IsJSQuote(src[i]):
			name, after = readJSString(src, i)
		case isJSIdentStart(src[i]):
			name, after = ReadJSIdent(src, i)
		default:
			i++
			continue
		}
		colon := SkipJSSpace(src, after)
		if colon >= len(src) || src[colon] != ':' {
			i = after
			continue
		}
		val := SkipJSSpace(src, colon+1)
		if val >= len(src) || !IsJSQuote(src[val]) {
			i = colon + 1
			continue
		}
		v, end := readJSString(src, val)
		if name == key {
			return v, true
		}
		i = end
	}
	return "", false
}

// PatchArgument resolves apply_patch's single argument to its decoded
// patch envelope. The argument is either an inline string literal or —
// in all 820 live calls — an identifier bound earlier in the same
// program by `const patch = "*** Begin Patch…"`. callAt is the byte
// offset of the call itself, which bounds the binding search.
func PatchArgument(program, args string, callAt int) string {
	trimmed := strings.TrimLeft(args, " \t\r\n")
	if trimmed == "" {
		return ""
	}
	if v, ok := readJSStringExpr(trimmed, 0); ok {
		return v
	}
	if !isJSIdentStart(trimmed[0]) {
		return ""
	}
	ident, _ := ReadJSIdent(trimmed, 0)
	if ident == "" {
		return ""
	}
	return StringBinding(program, ident, callAt)
}

// StringBinding resolves `<ident> = <string literal>` in a program
// and returns the decoded literal. It matches the assignment regardless
// of the declaration keyword (const / let / var / bare), because the
// keyword is read and discarded as just another identifier. `==`, `===`
// and `=>` are excluded so a comparison is never mistaken for a
// binding. A binding to anything that is not a string literal (an
// array, an object, a call) yields "" — see the Codex adapter's
// RESIDUAL CLASS 2.
//
// THREE RULES, all three load-bearing (WP-T6 finding F5):
//
//  1. STRING- AND COMMENT-AWARE, the same scan the call scanner runs.
//     Without it a decoy inside a comment — `// const patch = "…FAKE…"`
//     — or inside an unrelated literal beats the real binding, and the
//     row reports a file the program never touched.
//  2. BEFORE THE CALL. An assignment textually after the call site
//     cannot have supplied its argument; counting one would report a
//     value the call never saw. Past the limit, unresolved.
//  3. LAST ASSIGNMENT WINS. `const p = A; p = B; tools.apply_patch(p)`
//     passes B. Taking the first match reported A. A last assignment to
//     a NON-string expression withdraws any earlier string, because the
//     value at the call site is then not a literal we can decode.
//
// APPROXIMATION, stated honestly: this is textual nearest-dominating
// resolution, not scope- or control-flow-aware evaluation. A binding
// inside a branch, a loop or a nested function that does not execute
// (or executes with a different value) is resolved as if it did. A real
// JavaScript parser is out of scope for an adapter, and the failure
// mode is bounded — the row's ACTION TYPE comes from the call itself
// and is unaffected; only the patch-derived Target can be wrong, with
// the whole program preserved in raw_tool_input as the evidence trail.
// Zero live programs (819 apply_patch calls, 2026-07-31) contain a
// conditional or repeated binding of the patch identifier.
func StringBinding(src, ident string, before int) string {
	if len(src) > ScanLimit {
		src = src[:ScanLimit]
	}
	if before < 0 || before > len(src) {
		before = len(src)
	}
	// last is the value of the newest assignment seen so far; ok
	// records whether that newest assignment was string-valued (a
	// later non-string assignment must invalidate an earlier string).
	var last string
	var ok bool
	for i := 0; i < before; {
		switch {
		case IsJSQuote(src[i]):
			i = SkipJSString(src, i)
		case strings.HasPrefix(src[i:], "//"):
			nl := strings.IndexByte(src[i:], '\n')
			if nl < 0 {
				i = len(src)
				continue
			}
			i += nl + 1
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				i = len(src)
				continue
			}
			i += 2 + end + 2
		case isJSIdentStart(src[i]) && (i == 0 || !IsJSIdentByte(src[i-1])):
			name, after := ReadJSIdent(src, i)
			if name != ident {
				i = after
				continue
			}
			eq := SkipJSSpace(src, after)
			if eq >= len(src) || src[eq] != '=' ||
				(eq+1 < len(src) && (src[eq+1] == '=' || src[eq+1] == '>')) {
				i = after
				continue
			}
			last, ok = readJSStringExpr(src, SkipJSSpace(src, eq+1))
			i = after
		default:
			i++
		}
	}
	if !ok {
		return ""
	}
	return last
}

// jsStringRawPrefix is the tagged-template form live Codex uses to hoist
// a patch envelope that itself contains backslashes: `String.raw` makes
// the literal's escape sequences INERT, so the decoder must not process
// them (6 of the 819 live apply_patch programs use it — every one of
// them patches Go source containing "\t" / "\n" that must survive as
// two characters).
const jsStringRawPrefix = "String.raw"

// readJSStringExpr reads a string-VALUED expression at index i: a plain
// literal, or a String.raw-tagged template whose escapes stay inert.
// Reports whether one was found at all, so callers can distinguish an
// empty string from a non-string expression.
func readJSStringExpr(src string, i int) (string, bool) {
	if i >= len(src) {
		return "", false
	}
	if IsJSQuote(src[i]) {
		v, _ := readJSString(src, i)
		return v, true
	}
	if strings.HasPrefix(src[i:], jsStringRawPrefix) {
		j := SkipJSSpace(src, i+len(jsStringRawPrefix))
		if j < len(src) && src[j] == '`' {
			// The literal's escapes are inert, but `\`` still
			// terminates nothing — step over escape PAIRS while
			// hunting the closing backtick, and keep both bytes.
			var b strings.Builder
			for k := j + 1; k < len(src); k++ {
				if src[k] == '\\' && k+1 < len(src) {
					b.WriteByte(src[k])
					k++
					b.WriteByte(src[k])
					continue
				}
				if src[k] == '`' {
					break
				}
				b.WriteByte(src[k])
			}
			return b.String(), true
		}
	}
	return "", false
}

// ReadJSParenGroup reads a balanced parenthesis group starting at the
// '(' at index open, and returns the RAW inner source plus the index
// just past the closing ')'. String and comment state is tracked so a
// parenthesis inside a literal never closes the group. An unbalanced
// group (truncated program) yields everything to the end of source —
// honest partial data rather than a panic.
func ReadJSParenGroup(src string, open int) (string, int) {
	depth := 0
	for i := open; i < len(src); {
		switch {
		case IsJSQuote(src[i]):
			i = SkipJSString(src, i)
		case strings.HasPrefix(src[i:], "//"):
			nl := strings.IndexByte(src[i:], '\n')
			if nl < 0 {
				return src[open+1:], len(src)
			}
			i += nl + 1
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return src[open+1:], len(src)
			}
			i += 2 + end + 2
		case src[i] == '(':
			depth++
			i++
		case src[i] == ')':
			depth--
			if depth == 0 {
				return src[open+1 : i], i + 1
			}
			i++
		default:
			i++
		}
	}
	return src[open+1:], len(src)
}

// SkipJSString returns the index just past the string literal that
// starts at i. An unterminated literal consumes the rest of the source.
func SkipJSString(src string, i int) int {
	_, end := readJSString(src, i)
	return end
}

// readJSString decodes the JavaScript string literal starting at index
// i (which must be a quote) and returns the decoded value plus the
// index just past the closing quote. Template literals are read as
// plain strings — no live program uses `${}` substitution, and reading
// one literally is strictly better than mis-tokenising the program.
func readJSString(src string, i int) (string, int) {
	quote := src[i]
	var b strings.Builder
	for j := i + 1; j < len(src); j++ {
		c := src[j]
		switch c {
		case quote:
			return b.String(), j + 1
		case '\\':
			if j+1 >= len(src) {
				return b.String(), len(src)
			}
			v, next := decodeJSEscape(src, j+1)
			b.WriteString(v)
			j = next - 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), len(src)
}

// decodeJSEscape decodes the escape sequence whose body starts at index
// i (just past the backslash) and returns the replacement text plus the
// index just past the sequence. Unknown escapes decode to the escaped
// character itself, which is what JavaScript does.
func decodeJSEscape(src string, i int) (string, int) {
	switch c := src[i]; c {
	case 'n':
		return "\n", i + 1
	case 't':
		return "\t", i + 1
	case 'r':
		return "\r", i + 1
	case 'b':
		return "\b", i + 1
	case 'f':
		return "\f", i + 1
	case 'v':
		return "\v", i + 1
	case '0':
		// \0 is NUL only when not followed by another digit.
		if i+1 >= len(src) || src[i+1] < '0' || src[i+1] > '9' {
			return "\x00", i + 1
		}
		return "0", i + 1
	case '\n':
		// Line continuation: the newline is not part of the value.
		return "", i + 1
	case 'x':
		if v, ok := hexValue(src, i+1, 2); ok {
			return string(rune(v)), i + 3
		}
		return "x", i + 1
	case 'u':
		return decodeJSUnicodeEscape(src, i)
	default:
		_, size := utf8.DecodeRuneInString(src[i:])
		return src[i : i+size], i + size
	}
}

// decodeJSUnicodeEscape decodes \uHHHH (including a surrogate pair
// followed by a second \uHHHH) and \u{H…}. i points at the 'u'.
func decodeJSUnicodeEscape(src string, i int) (string, int) {
	if i+1 < len(src) && src[i+1] == '{' {
		end := strings.IndexByte(src[i+2:], '}')
		if end < 0 {
			return "u", i + 1
		}
		if v, ok := hexValue(src, i+2, end); ok && v <= utf8.MaxRune {
			return string(rune(v)), i + 2 + end + 1
		}
		return "u", i + 1
	}
	hi, ok := hexValue(src, i+1, 4)
	if !ok {
		return "u", i + 1
	}
	next := i + 5
	if utf16.IsSurrogate(rune(hi)) && next+5 < len(src) &&
		src[next] == '\\' && src[next+1] == 'u' {
		if lo, ok := hexValue(src, next+2, 4); ok {
			if r := utf16.DecodeRune(rune(hi), rune(lo)); r != utf8.RuneError {
				return string(r), next + 6
			}
		}
	}
	return string(rune(hi)), next
}

// hexValue parses exactly n hex digits starting at i.
func hexValue(src string, i, n int) (int, bool) {
	if n <= 0 || i+n > len(src) {
		return 0, false
	}
	v := 0
	for _, c := range []byte(src[i : i+n]) {
		switch {
		case c >= '0' && c <= '9':
			v = v*16 + int(c-'0')
		case c >= 'a' && c <= 'f':
			v = v*16 + int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = v*16 + int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

// ReadJSIdent reads the identifier starting at index i and returns it
// plus the index just past it. Returns "" when i is not an identifier
// start.
func ReadJSIdent(src string, i int) (string, int) {
	if i >= len(src) || !isJSIdentStart(src[i]) {
		return "", i
	}
	j := i
	for j < len(src) && IsJSIdentByte(src[j]) {
		j++
	}
	return src[i:j], j
}

// SkipJSSpace returns the index of the first non-whitespace byte at or
// after i.
func SkipJSSpace(src string, i int) int {
	for i < len(src) {
		switch src[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}

// IsJSQuote reports whether c opens a JavaScript string literal: a
// double quote, a single quote, or a template-literal backtick.
func IsJSQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

// isJSIdentStart reports whether c may begin a JavaScript identifier.
// ASCII only — every identifier in the live corpus is ASCII, and a
// non-ASCII byte simply fails to start an identifier rather than
// mis-tokenising the program.
func isJSIdentStart(c byte) bool {
	return c == '_' || c == '$' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// IsJSIdentByte reports whether c may appear inside a JavaScript
// identifier. Callers use it for whole-token matching: a candidate
// match is a token only when neither neighbouring byte is one of these.
func IsJSIdentByte(c byte) bool {
	return isJSIdentStart(c) || (c >= '0' && c <= '9')
}
