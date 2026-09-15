package loc

import (
	"sort"
	"strings"
)

// blockPair is one block-comment delimiter pair.
type blockPair struct {
	open  string
	close string
	// anchored requires both tokens to sit at the line's first
	// non-whitespace column (Ruby `=begin`/`=end`, Perl `=pod`/`=cut`,
	// MATLAB `%{`/`%}`).
	anchored bool
	// detectStray enables close-without-open detection for this pair.
	// It is false where the close token also occurs in ordinary code:
	// Lua's `]]` is the tail of `t[x[1]]`, and treating it as a stray
	// close would retroactively unknown the whole fragment.
	detectStray bool
}

// stringDelim is one string-literal delimiter. open and close differ only
// for Lua long strings (`[[` … `]]`).
type stringDelim struct {
	open  string
	close string
	// multiline marks a literal that may span lines (Go raw strings,
	// JS/TS template literals, Python/Scala triple-quoted strings).
	// Single-line literals simply end at the newline, which keeps an
	// apostrophe in prose from swallowing the rest of a fragment.
	multiline bool
	// escape enables backslash escaping while scanning for the close.
	escape bool
	// docstring marks a literal that counts as a COMMENT when it opens a
	// line with no code before it. This implements the cloc convention
	// for Python bare triple-quoted string statements — see
	// ClassifyLines' doc comment, where it is a stated convention rather
	// than an accident of the lexer.
	docstring bool
}

// heredocKind selects the heredoc introducer syntax a language uses.
type heredocKind uint8

// The heredoc syntaxes loc recognises.
const (
	heredocNone  heredocKind = iota
	heredocShell             // <<WORD, <<-WORD, <<~WORD, <<'WORD', <<"WORD"
	heredocPHP               // <<<WORD, <<<'WORD', <<<"WORD"
)

// langTokens is one language's row in the lexer table.
type langTokens struct {
	// lineComments start a comment that runs to end of line.
	lineComments []string
	// anchoredLine are line-comment keywords matched case-insensitively,
	// and only at the line's first non-whitespace column (BASIC `REM`).
	anchoredLine []string
	// blocks are block-comment delimiter pairs.
	blocks []blockPair
	// strings are string-literal delimiters.
	strings []stringDelim
	// heredoc is the heredoc introducer syntax, if any.
	heredoc heredocKind
}

// lexState is the block/string/heredoc state carried between lines of one
// fragment.
type lexState struct {
	blockIdx      int // index into langTokens.blocks, or -1
	blockLine     int // line index the open block comment started on
	strIdx        int // index into langTokens.strings, or -1
	strLine       int // line index the open multi-line string started on
	strDoc        bool
	inHeredoc     bool
	heredocTerm   string
	heredocIndent bool
}

// ClassifyLines classifies each line of a fragment as code, comment,
// blank or unknown, and grades the result.
//
// The input is a FRAGMENT, not a file: an edit's before- or after-image
// may begin in the middle of a block comment and end in the middle of a
// string. Those cases degrade to ClassUnknown and a lower Confidence
// rather than guessing, because guessing "code" is what inflates a
// headline lines-of-code number.
//
// Line splitting: the text is split on "\n" after a single trailing "\n"
// is trimmed, so a fragment ending in a newline does NOT contribute a
// trailing empty line. A trailing "\r" is stripped from each line before
// classification (CRLF fragments classify identically to LF ones) but the
// returned slice still has exactly one entry per split line. Empty text
// returns (nil, ConfidenceHigh).
//
// Classification rules, in the order they resolve:
//
//   - A line carried entirely inside a block comment is ClassComment,
//     blank or not.
//   - A line whose first non-whitespace token opens a line comment, with
//     no code before it, is ClassComment.
//   - A line whose only content is a block comment that opens and closes
//     on the same line is ClassComment.
//   - Code wins over comment on a mixed line (cloc's convention): code
//     followed by a trailing `//`, or code that opens a block comment,
//     is ClassCode.
//   - A line whose trimmed text is empty, in no carried state, is
//     ClassBlank.
//   - Everything else is ClassCode.
//
// Stated conventions:
//
//   - A Python bare triple-quoted string statement — a `"""…"""` that
//     opens a line with no code before it — counts as ClassComment, not
//     ClassCode. This is cloc's convention for docstrings and is applied
//     deliberately, not as a side effect of the string lexer.
//   - Heredoc bodies (shell/Ruby/PHP) are ClassCode: they are literal
//     data embedded in the source, and a `#` inside one does not start a
//     comment.
//   - A `#` never starts a comment in the C family; `#include`,
//     `#define`, `#if` and `#pragma` are ClassCode.
//
// Fragment boundary rules:
//
//   - A block comment opened but never closed makes every line from the
//     opener to the end of the fragment ClassUnknown, and drops
//     Confidence to ConfidenceMedium.
//   - A multi-line string opened but never closed does the same.
//   - A block-comment CLOSE with no matching open retroactively makes
//     every line from the start of the fragment through that line
//     ClassUnknown, and drops Confidence to ConfidenceMedium.
//   - A blank line inside an unresolved region is ClassUnknown, never
//     ClassBlank.
//   - A language with no token table (LangUnknown, and any Lang that has
//     not been given one) classifies blank lines as ClassBlank and every
//     other line as ClassUnknown, at ConfidenceLow. Calling those lines
//     "code" would inflate the headline number for free.
//
// Confidence is ConfidenceHigh only for a known language whose fragment
// resolved with no unterminated or unopened region.
func ClassifyLines(lang Lang, text string) ([]LineClass, Confidence) {
	if text == "" {
		return nil, ConfidenceHigh
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	out := make([]LineClass, len(lines))

	tok, known := lexTable[lang]
	if !known {
		for i, raw := range lines {
			if strings.TrimSpace(strings.TrimSuffix(raw, "\r")) == "" {
				out[i] = ClassBlank
			} else {
				out[i] = ClassUnknown
			}
		}
		return out, ConfidenceLow
	}

	st := lexState{blockIdx: -1, strIdx: -1}
	retroThrough := -1
	for i, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		code, comment, stray := scanLine(line, tok, &st, i)
		if stray && i > retroThrough {
			retroThrough = i
		}
		switch {
		case code:
			out[i] = ClassCode
		case comment:
			out[i] = ClassComment
		case strings.TrimSpace(line) == "":
			out[i] = ClassBlank
		default:
			out[i] = ClassCode
		}
	}

	conf := ConfidenceHigh
	if st.blockIdx >= 0 {
		markUnknown(out, st.blockLine, len(out)-1)
		conf = ConfidenceMedium
	}
	if st.strIdx >= 0 {
		markUnknown(out, st.strLine, len(out)-1)
		conf = ConfidenceMedium
	}
	if retroThrough >= 0 {
		markUnknown(out, 0, retroThrough)
		conf = ConfidenceMedium
	}
	return out, conf
}

// markUnknown overwrites out[from:to] (inclusive) with ClassUnknown.
func markUnknown(out []LineClass, from, to int) {
	if from < 0 {
		from = 0
	}
	for i := from; i <= to && i < len(out); i++ {
		out[i] = ClassUnknown
	}
}

// scanLine walks one line character by character, updating the carried
// lexer state. It reports whether the line contained code, whether it
// contained comment text, and whether it closed a block comment that was
// never opened within the fragment.
//
// Character-by-character scanning is what shields a `#` inside a Python
// string, a `//` inside a JavaScript string or URL, and a `--` inside a
// SQL literal from being read as a comment.
//
// gocyclo: one branch per lexer construct by design (block/line comments,
// anchored variants, stray closes, string/heredoc literals); complexity tracks
// the token-shape count a language-agnostic classifying lexer must recognize,
// not logic depth.
//
//nolint:gocyclo // see the note above
func scanLine(line string, tok langTokens, st *lexState, lineNo int) (code, comment, stray bool) {
	if st.inHeredoc {
		body := line
		if st.heredocIndent {
			body = strings.TrimLeft(body, " \t")
		}
		body = strings.TrimRight(body, " \t")
		if tok.heredoc == heredocPHP {
			body = strings.TrimRight(body, ";,")
		}
		if body == st.heredocTerm {
			st.inHeredoc = false
		}
		return true, false, false
	}

	// An empty line never enters the scan loop below, so the carried
	// state has to be applied here: a blank line inside a block comment
	// is comment, and one inside a multi-line string belongs to the
	// string.
	if len(line) == 0 {
		switch {
		case st.blockIdx >= 0:
			return false, true, false
		case st.strIdx >= 0 && st.strDoc:
			return false, true, false
		case st.strIdx >= 0:
			return true, false, false
		default:
			return false, false, false
		}
	}

	first := -1
	for k := 0; k < len(line); k++ {
		if line[k] != ' ' && line[k] != '\t' {
			first = k
			break
		}
	}

	var (
		pending       bool
		pendingTerm   string
		pendingIndent bool
	)

	i := 0
	for i < len(line) {
		if st.blockIdx >= 0 {
			bp := tok.blocks[st.blockIdx]
			comment = true
			j := indexClose(line, i, bp, first)
			if j < 0 {
				break
			}
			st.blockIdx = -1
			i = j + len(bp.close)
			continue
		}
		if st.strIdx >= 0 {
			sd := tok.strings[st.strIdx]
			if st.strDoc {
				comment = true
			} else {
				code = true
			}
			j, found := scanForClose(line, i, sd)
			if !found {
				break
			}
			st.strIdx = -1
			st.strDoc = false
			i = j + len(sd.close)
			continue
		}

		if line[i] == ' ' || line[i] == '\t' {
			i++
			continue
		}
		rest := line[i:]
		handled := false

		if i == first {
			for k := range tok.blocks {
				bp := tok.blocks[k]
				if !bp.anchored {
					continue
				}
				if bp.detectStray && strings.HasPrefix(rest, bp.close) {
					stray, comment, handled = true, true, true
					break
				}
				if strings.HasPrefix(rest, bp.open) {
					st.blockIdx, st.blockLine = k, lineNo
					comment, handled = true, true
					break
				}
			}
			if handled {
				// The rest of the line is consumed by the anchored block open
				// or stray close just matched; break ends the scan outright.
				break
			}
			for _, tk := range tok.anchoredLine {
				if len(rest) >= len(tk) && strings.EqualFold(rest[:len(tk)], tk) {
					comment, handled = true, true
					break
				}
			}
			if handled {
				// The anchored full-line comment consumes the rest of the
				// line; break ends the scan outright.
				break
			}
		}

		for k := range tok.blocks {
			bp := tok.blocks[k]
			if bp.anchored || !strings.HasPrefix(rest, bp.open) {
				continue
			}
			comment, handled = true, true
			j := indexClose(line, i+len(bp.open), bp, first)
			if j < 0 {
				st.blockIdx, st.blockLine = k, lineNo
				i = len(line)
			} else {
				i = j + len(bp.close)
			}
			break
		}
		if handled {
			continue
		}

		for k := range tok.blocks {
			bp := tok.blocks[k]
			if bp.anchored || !bp.detectStray || !strings.HasPrefix(rest, bp.close) {
				continue
			}
			stray, comment, handled = true, true, true
			i += len(bp.close)
			break
		}
		if handled {
			continue
		}

		for _, tk := range tok.lineComments {
			if strings.HasPrefix(rest, tk) {
				comment, handled = true, true
				break
			}
		}
		if handled {
			// The line comment consumes the rest of the line; break ends the
			// scan outright.
			break
		}

		if tok.heredoc != heredocNone && !pending && strings.HasPrefix(rest, "<<") {
			if term, indent, next, ok := parseHeredoc(line, i, tok.heredoc); ok {
				pending, pendingTerm, pendingIndent = true, term, indent
				code = true
				i = next
				continue
			}
		}

		for k := range tok.strings {
			sd := tok.strings[k]
			if !strings.HasPrefix(rest, sd.open) {
				continue
			}
			handled = true
			isDoc := sd.docstring && !code
			if isDoc {
				comment = true
			} else {
				code = true
			}
			j, found := scanForClose(line, i+len(sd.open), sd)
			switch {
			case found:
				i = j + len(sd.close)
			case sd.multiline:
				st.strIdx, st.strLine, st.strDoc = k, lineNo, isDoc
				i = len(line)
			default:
				// An unterminated single-line literal: the rest of the
				// line is its content, and the literal ends at the
				// newline rather than leaking into the next line.
				code = true
				i = len(line)
			}
			break
		}
		if handled {
			continue
		}

		code = true
		i++
	}

	if pending {
		st.inHeredoc, st.heredocTerm, st.heredocIndent = true, pendingTerm, pendingIndent
	}
	return code, comment, stray
}

// indexClose finds a block pair's close token at or after from, honouring
// the pair's anchoring.
func indexClose(line string, from int, bp blockPair, first int) int {
	if from > len(line) {
		return -1
	}
	if bp.anchored {
		if first >= from && strings.HasPrefix(line[first:], bp.close) {
			return first
		}
		return -1
	}
	j := strings.Index(line[from:], bp.close)
	if j < 0 {
		return -1
	}
	return from + j
}

// scanForClose finds a string literal's close delimiter at or after from,
// skipping escaped characters when the delimiter supports escaping.
func scanForClose(line string, from int, sd stringDelim) (int, bool) {
	for j := from; j < len(line); j++ {
		if sd.escape && line[j] == '\\' {
			j++
			continue
		}
		if strings.HasPrefix(line[j:], sd.close) {
			return j, true
		}
	}
	return 0, false
}

// parseHeredoc recognises a heredoc introducer at position i (which must
// already start with "<<") and returns its terminator word, whether the
// terminator may be indented, and the index just past the introducer.
//
// An UNQUOTED terminator must follow the introducer with no intervening
// whitespace and must be all-uppercase (`[A-Z_][A-Z0-9_]*`). That
// restriction is what stops Ruby's append operator (`arr << item`) and
// shell arithmetic (`$((1 << n))`) from being read as heredocs; the cost
// is that a lowercase `cat << eof` is missed, which degrades to ordinary
// per-line classification rather than to a wrong answer.
func parseHeredoc(line string, i int, kind heredocKind) (term string, indent bool, next int, ok bool) {
	j := i + 2
	if kind == heredocPHP {
		if j >= len(line) || line[j] != '<' {
			return "", false, 0, false
		}
		j++
	} else if j < len(line) && line[j] == '<' {
		return "", false, 0, false // "<<<" is a here-string, not a heredoc
	}
	if j < len(line) && (line[j] == '-' || line[j] == '~') {
		indent = true
		j++
	}
	spaced := false
	for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
		spaced = true
		j++
	}
	if j >= len(line) {
		return "", false, 0, false
	}
	if q := line[j]; q == '\'' || q == '"' {
		k := j + 1
		for k < len(line) && line[k] != q {
			k++
		}
		if k >= len(line) || k == j+1 {
			return "", false, 0, false
		}
		return line[j+1 : k], indent, k + 1, true
	}
	k := j
	for k < len(line) && isWordByte(line[k]) {
		k++
	}
	term = line[j:k]
	if term == "" || spaced || !isUpperWord(term) {
		return "", false, 0, false
	}
	return term, indent, k, true
}

// isWordByte reports whether b may appear in a heredoc terminator.
func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z')
}

// isUpperWord reports whether w matches `[A-Z_][A-Z0-9_]*`.
func isUpperWord(w string) bool {
	if w[0] != '_' && (w[0] < 'A' || w[0] > 'Z') {
		return false
	}
	for k := 0; k < len(w); k++ {
		b := w[k]
		if b == '_' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') {
			continue
		}
		return false
	}
	return true
}

// init sorts every token list longest-first so that a longer token is
// always tried before a prefix of itself: `"""` before `"`, `--[[` before
// `--`, `{/*` before `/*`.
func init() {
	for lang, tok := range lexTable {
		sort.SliceStable(tok.lineComments, func(a, b int) bool {
			return len(tok.lineComments[a]) > len(tok.lineComments[b])
		})
		sort.SliceStable(tok.blocks, func(a, b int) bool {
			return len(tok.blocks[a].open) > len(tok.blocks[b].open)
		})
		sort.SliceStable(tok.strings, func(a, b int) bool {
			return len(tok.strings[a].open) > len(tok.strings[b].open)
		})
		lexTable[lang] = tok
	}
}

// cFamily builds the token set shared by the C-derived languages: `//`
// line comments, `/* */` blocks and escaped `"…"` strings. Note the
// absence of `#`: in this family `#include` and `#pragma` are code.
func cFamily(extra ...stringDelim) langTokens {
	t := langTokens{
		lineComments: []string{"//"},
		blocks:       []blockPair{{open: "/*", close: "*/", detectStray: true}},
		strings:      []stringDelim{{open: `"`, close: `"`, escape: true}},
	}
	t.strings = append(t.strings, extra...)
	return t
}

var (
	dq          = stringDelim{open: `"`, close: `"`, escape: true}
	sq          = stringDelim{open: `'`, close: `'`, escape: true}
	dqRaw       = stringDelim{open: `"`, close: `"`}
	sqRaw       = stringDelim{open: `'`, close: `'`}
	backtick    = stringDelim{open: "`", close: "`", multiline: true}
	tripleDQ    = stringDelim{open: `"""`, close: `"""`, multiline: true, escape: true}
	tripleSQ    = stringDelim{open: `'''`, close: `'''`, multiline: true, escape: true}
	htmlComment = blockPair{open: "<!--", close: "-->", detectStray: true}
	cComment    = blockPair{open: "/*", close: "*/", detectStray: true}
)

// lexTable is the per-language token table the line lexer walks. Every
// Lang constant except LangUnknown has a row; a Lang with no row falls
// back to the conservative unknown-language path in ClassifyLines.
var lexTable = map[Lang]langTokens{
	LangGo:     cFamily(sq, backtick),
	LangC:      cFamily(sq),
	LangCPP:    cFamily(sq),
	LangCSharp: cFamily(sq),
	LangJava:   cFamily(sq),
	LangKotlin: cFamily(tripleDQ),
	LangSwift:  cFamily(tripleDQ),
	// Rust deliberately has no `'` string delimiter: a lifetime (`&'a
	// str`) would open one and swallow the rest of the line.
	LangRust:       cFamily(),
	LangJavaScript: cFamily(sq, backtick),
	LangTypeScript: cFamily(sq, backtick),
	LangJSX: {
		lineComments: []string{"//"},
		blocks:       []blockPair{{open: "{/*", close: "*/}", detectStray: true}, cComment},
		strings:      []stringDelim{dq, sq, backtick},
	},
	LangTSX: {
		lineComments: []string{"//"},
		blocks:       []blockPair{{open: "{/*", close: "*/}", detectStray: true}, cComment},
		strings:      []stringDelim{dq, sq, backtick},
	},
	LangPython: {
		lineComments: []string{"#"},
		strings: []stringDelim{
			{open: `"""`, close: `"""`, multiline: true, escape: true, docstring: true},
			{open: `'''`, close: `'''`, multiline: true, escape: true, docstring: true},
			dq, sq,
		},
	},
	LangRuby: {
		lineComments: []string{"#"},
		blocks:       []blockPair{{open: "=begin", close: "=end", anchored: true, detectStray: true}},
		strings:      []stringDelim{dq, sq},
		heredoc:      heredocShell,
	},
	LangPHP: {
		lineComments: []string{"//", "#"},
		blocks:       []blockPair{cComment},
		strings:      []stringDelim{dq, sq},
		heredoc:      heredocPHP,
	},
	LangPerl: {
		lineComments: []string{"#"},
		blocks:       []blockPair{{open: "=pod", close: "=cut", anchored: true, detectStray: true}},
		strings:      []stringDelim{dq, sq},
		heredoc:      heredocShell,
	},
	LangShell: {
		lineComments: []string{"#"},
		strings:      []stringDelim{dq, sq},
		heredoc:      heredocShell,
	},
	LangPowerShell: {
		lineComments: []string{"#"},
		blocks:       []blockPair{{open: "<#", close: "#>", detectStray: true}},
		strings:      []stringDelim{dq, sq},
	},
	LangLua: {
		lineComments: []string{"--"},
		// detectStray is off: "]]" is the tail of an ordinary nested
		// index expression.
		blocks:  []blockPair{{open: "--[[", close: "]]"}},
		strings: []stringDelim{dq, sq, {open: "[[", close: "]]", multiline: true}},
	},
	LangSQL: {
		lineComments: []string{"--"},
		blocks:       []blockPair{cComment},
		// SQL escapes a quote by doubling it, which balances out under a
		// non-escaping scan, so no escape character is declared.
		strings: []stringDelim{sqRaw, dqRaw},
	},
	LangHTML: {
		blocks:  []blockPair{htmlComment},
		strings: []stringDelim{dqRaw, sqRaw},
	},
	LangXML: {
		blocks:  []blockPair{htmlComment},
		strings: []stringDelim{dqRaw, sqRaw},
	},
	LangCSS: {
		blocks:  []blockPair{cComment},
		strings: []stringDelim{dq, sq},
	},
	LangSCSS: {
		lineComments: []string{"//"},
		blocks:       []blockPair{cComment},
		strings:      []stringDelim{dq, sq},
	},
	LangYAML: {
		lineComments: []string{"#"},
		strings:      []stringDelim{dq, sq},
	},
	// JSON has no comment syntax. `.jsonc`/`.json5` do, but admitting
	// `//` here would misread a plain-JSON value, and the cost of the
	// omission is only that a JSONC comment counts as config code.
	LangJSON: {
		strings: []stringDelim{dq},
	},
	LangTOML: {
		lineComments: []string{"#"},
		strings:      []stringDelim{tripleDQ, tripleSQ, dq, sq},
	},
	LangINI: {
		lineComments: []string{";", "#"},
		strings:      []stringDelim{dq, sq},
	},
	// Markdown's `#` is a heading, not a comment; only the HTML comment
	// form is a comment. Prose lines therefore classify as code, and the
	// docs Category is what keeps them out of the headline number.
	LangMarkdown: {
		blocks: []blockPair{htmlComment},
	},
	LangText:  {},
	LangProto: cFamily(sq),
	LangGraphQL: {
		lineComments: []string{"#"},
		strings:      []stringDelim{tripleDQ, dq},
	},
	LangDockerfile: {
		lineComments: []string{"#"},
		strings:      []stringDelim{dq, sq},
	},
	LangMakefile: {
		lineComments: []string{"#"},
		strings:      []stringDelim{dq, sq},
	},
	LangVue: {
		lineComments: []string{"//"},
		blocks:       []blockPair{htmlComment, cComment},
		strings:      []stringDelim{dq, sq, backtick},
	},
	LangSvelte: {
		lineComments: []string{"//"},
		blocks:       []blockPair{htmlComment, cComment},
		strings:      []stringDelim{dq, sq, backtick},
	},
	LangDart:  cFamily(sq, tripleDQ, tripleSQ),
	LangScala: cFamily(sq, tripleDQ),
	LangElixir: {
		lineComments: []string{"#"},
		strings:      []stringDelim{tripleDQ, dq, sq},
	},
	LangHaskell: {
		lineComments: []string{"--"},
		blocks:       []blockPair{{open: "{-", close: "-}", detectStray: true}},
		strings:      []stringDelim{dq},
	},
	LangR: {
		lineComments: []string{"#"},
		strings:      []stringDelim{dq, sq},
	},
	// Reachable only from a caller that already knows the language: see
	// languageTable's note on the `.m` ambiguity.
	LangMatlab: {
		lineComments: []string{"%"},
		blocks:       []blockPair{{open: "%{", close: "%}", anchored: true, detectStray: true}},
		strings:      []stringDelim{sqRaw, dqRaw},
	},
	LangTerraform: {
		lineComments: []string{"#", "//"},
		blocks:       []blockPair{cComment},
		strings:      []stringDelim{dq},
		heredoc:      heredocShell,
	},
	LangZig: {
		lineComments: []string{"//"},
		strings:      []stringDelim{dq},
	},
	LangNim: {
		lineComments: []string{"#"},
		blocks:       []blockPair{{open: "#[", close: "]#", detectStray: true}},
		strings:      []stringDelim{tripleDQ, dq},
	},
	LangJulia: {
		lineComments: []string{"#"},
		blocks:       []blockPair{{open: "#=", close: "=#", detectStray: true}},
		strings:      []stringDelim{tripleDQ, dq},
	},
	LangClojure: {
		lineComments: []string{";"},
		strings:      []stringDelim{dq},
	},
	LangLisp: {
		lineComments: []string{";"},
		blocks:       []blockPair{{open: "#|", close: "|#", detectStray: true}},
		strings:      []stringDelim{dq},
	},
	LangErlang: {
		lineComments: []string{"%"},
		strings:      []stringDelim{dq},
	},
	LangOCaml: {
		blocks:  []blockPair{{open: "(*", close: "*)", detectStray: true}},
		strings: []stringDelim{dq},
	},
	LangFSharp: {
		lineComments: []string{"//"},
		blocks:       []blockPair{{open: "(*", close: "*)", detectStray: true}},
		strings:      []stringDelim{tripleDQ, dq},
	},
	LangVB: {
		lineComments: []string{"'"},
		anchoredLine: []string{"REM "},
		strings:      []stringDelim{dqRaw},
	},
	LangGroovy: cFamily(sq, tripleDQ, tripleSQ),
	// A notebook is JSON on disk; the cell sources inside it are strings.
	LangNotebook: {
		strings: []stringDelim{dq},
	},
}
