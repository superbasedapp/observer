package migcheck

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// tokKind is the lexical class of one token.
type tokKind int

const (
	tokWord        tokKind = iota // an unquoted identifier or keyword
	tokQuotedIdent                // "..." or U&"..."
	tokString                     // '...', E'...', B'...', X'...', N'...', U&'...'
	tokDollar                     // $tag$ ... $tag$
	tokNumber                     // 42, 4.2, 1e9
	tokParam                      // $1
	tokPunct                      // one punctuation character
)

// token is one lexical token of a statement.
type token struct {
	kind  tokKind
	text  string // the raw source text
	up    string // the upper-cased text, for keyword matching (words only)
	depth int    // parenthesis depth: "(" and ")" carry the depth outside them
	pos   int    // byte offset of the token in the step's SQL
	end   int    // byte offset just past the token
}

// ident returns the identifier a word or quoted identifier names, folded the
// way PostgreSQL folds it: unquoted to lower case, quoted verbatim.
func (t token) ident() string {
	switch t.kind {
	case tokWord:
		return strings.ToLower(t.text)
	case tokQuotedIdent:
		s := t.text
		s = strings.TrimPrefix(strings.TrimPrefix(s, "U&"), "u&")
		if len(s) >= 2 {
			s = s[1 : len(s)-1]
		}
		return strings.ReplaceAll(s, `""`, `"`)
	default:
		return ""
	}
}

// isWord reports whether the token is the unquoted keyword w (upper case).
func (t token) isWord(w string) bool { return t.kind == tokWord && t.up == w }

// isPunct reports whether the token is the punctuation character p.
func (t token) isPunct(p string) bool { return t.kind == tokPunct && t.text == p }

// statement is one SQL statement: its tokens and its span in the source.
type statement struct {
	toks       []token
	start, end int
}

// lexed is the tokenizer's result for one step.
type lexed struct {
	stmts []statement
	// header holds the text after "--" of every line comment that comes
	// before the first statement, in order.
	header []string
}

// lex splits a step's SQL into statements. Semicolons end statements outside
// comments, strings, quoted identifiers and dollar-quoted bodies. It fails
// only on an unterminated comment, string, quoted identifier or dollar quote.
//
//nolint:gocyclo // a hand-written SQL lexer: one branch per token class (comments, quotes, dollar quotes, identifiers) by design.
func lex(src string) (lexed, error) {
	var out lexed
	var cur []token
	depth := 0
	flush := func() {
		if len(cur) > 0 {
			out.stmts = append(out.stmts, statement{toks: cur, start: cur[0].pos, end: cur[len(cur)-1].end})
		}
		cur = nil
		depth = 0
	}
	add := func(kind tokKind, start, end int) {
		t := token{kind: kind, text: src[start:end], depth: depth, pos: start, end: end}
		if kind == tokWord {
			t.up = strings.ToUpper(t.text)
		}
		cur = append(cur, t)
	}
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < len(src) && src[i+1] == '-':
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				j = len(src)
			} else {
				j += i
			}
			if len(out.stmts) == 0 && len(cur) == 0 {
				out.header = append(out.header, strings.TrimRight(src[i+2:j], "\r"))
			}
			i = j
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			j, err := skipBlockComment(src, i)
			if err != nil {
				return lexed{}, err
			}
			i = j
		case c == ';':
			flush()
			i++
		case c == '\'':
			j, err := scanQuoted(src, i, '\'', false)
			if err != nil {
				return lexed{}, err
			}
			add(tokString, i, j)
			i = j
		case c == '"':
			j, err := scanQuoted(src, i, '"', false)
			if err != nil {
				return lexed{}, err
			}
			add(tokQuotedIdent, i, j)
			i = j
		case c == '$':
			j, kind, err := scanDollar(src, i)
			if err != nil {
				return lexed{}, err
			}
			add(kind, i, j)
			i = j
		case isIdentStart(c):
			j := i + 1
			for j < len(src) && isIdentPart(src[j]) {
				j++
			}
			word := src[i:j]
			switch {
			case (word == "E" || word == "e") && j < len(src) && src[j] == '\'':
				k, err := scanQuoted(src, j, '\'', true)
				if err != nil {
					return lexed{}, err
				}
				add(tokString, i, k)
				i = k
			case strings.ContainsAny(word, "BbXxNn") && len(word) == 1 && j < len(src) && src[j] == '\'':
				k, err := scanQuoted(src, j, '\'', false)
				if err != nil {
					return lexed{}, err
				}
				add(tokString, i, k)
				i = k
			case (word == "U" || word == "u") && j+1 < len(src) && src[j] == '&' && (src[j+1] == '\'' || src[j+1] == '"'):
				k, err := scanQuoted(src, j+1, src[j+1], false)
				if err != nil {
					return lexed{}, err
				}
				kind := tokString
				if src[j+1] == '"' {
					kind = tokQuotedIdent
				}
				add(kind, i, k)
				i = k
			default:
				add(tokWord, i, j)
				i = j
			}
		case isDigit(c) || (c == '.' && i+1 < len(src) && isDigit(src[i+1])):
			j := scanNumber(src, i)
			add(tokNumber, i, j)
			i = j
		case c == '(':
			add(tokPunct, i, i+1)
			depth++
			i++
		case c == ')':
			if depth > 0 {
				depth--
			}
			add(tokPunct, i, i+1)
			i++
		default:
			_, size := utf8.DecodeRuneInString(src[i:])
			add(tokPunct, i, i+size)
			i += size
		}
	}
	flush()
	return out, nil
}

// skipBlockComment returns the offset just past the block comment that
// starts at i. PostgreSQL block comments nest.
func skipBlockComment(src string, i int) (int, error) {
	level := 0
	for j := i; j < len(src)-1; {
		switch {
		case src[j] == '/' && src[j+1] == '*':
			level++
			j += 2
		case src[j] == '*' && src[j+1] == '/':
			level--
			j += 2
			if level == 0 {
				return j, nil
			}
		default:
			j++
		}
	}
	return 0, fmt.Errorf("migcheck.lex: unterminated block comment at offset %d", i)
}

// scanQuoted returns the offset just past the quoted string or identifier
// that opens with the quote character at i. A doubled quote is an escaped
// quote; with backslash set (E'...' strings) a backslash escapes the next
// byte.
func scanQuoted(src string, i int, quote byte, backslash bool) (int, error) {
	for j := i + 1; j < len(src); j++ {
		switch {
		case backslash && src[j] == '\\':
			j++
		case src[j] == quote:
			if j+1 < len(src) && src[j+1] == quote {
				j++
				continue
			}
			return j + 1, nil
		}
	}
	what := "string"
	if quote == '"' {
		what = "quoted identifier"
	}
	return 0, fmt.Errorf("migcheck.lex: unterminated %s at offset %d", what, i)
}

// errDollar is the cause of an unterminated dollar quote.
var errDollar = errors.New("unterminated dollar-quoted string")

// scanDollar reads what starts with "$" at i: a positional parameter ($1), a
// dollar-quoted string ($$...$$ or $tag$...$tag$), or a lone "$".
func scanDollar(src string, i int) (int, tokKind, error) {
	j := i + 1
	if j < len(src) && isDigit(src[j]) {
		for j < len(src) && isDigit(src[j]) {
			j++
		}
		return j, tokParam, nil
	}
	if j < len(src) && isIdentStart(src[j]) {
		for j < len(src) && isIdentPart(src[j]) && src[j] != '$' {
			j++
		}
	}
	if j >= len(src) || src[j] != '$' {
		return i + 1, tokPunct, nil
	}
	tag := src[i : j+1]
	k := strings.Index(src[j+1:], tag)
	if k < 0 {
		return 0, 0, fmt.Errorf("migcheck.lex: %w %s at offset %d", errDollar, tag, i)
	}
	return j + 1 + k + len(tag), tokDollar, nil
}

// scanNumber returns the offset just past the numeric literal at i.
func scanNumber(src string, i int) int {
	j := i
	for j < len(src) && (isDigit(src[j]) || src[j] == '.' || src[j] == '_') {
		j++
	}
	if j < len(src) && (src[j] == 'e' || src[j] == 'E') {
		k := j + 1
		if k < len(src) && (src[k] == '+' || src[k] == '-') {
			k++
		}
		if k < len(src) && isDigit(src[k]) {
			j = k
			for j < len(src) && isDigit(src[j]) {
				j++
			}
		}
	}
	return j
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) || c == '$' }

// excerpt is the source text of a span with its whitespace collapsed,
// truncated for a finding.
func excerpt(src string, start, end int) string {
	s := strings.Join(strings.Fields(src[start:end]), " ")
	const limit = 120
	if utf8.RuneCountInString(s) > limit {
		r := []rune(s)
		s = string(r[:limit]) + "..."
	}
	return s
}
