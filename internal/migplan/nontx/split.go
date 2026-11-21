package nontx

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// tokKind is the lexical class of one token.
type tokKind int

const (
	tokWord   tokKind = iota // an unquoted identifier or keyword
	tokQuoted                // a quoted identifier: "..." or U&"..."
	tokOther                 // a string, number, parameter, dollar quote or punctuation
)

// token is one lexical token of a statement.
type token struct {
	kind tokKind
	text string // the raw source text
	up   string // the upper-cased text (words only), for keyword matching
	pos  int    // byte offset in the step's SQL
	end  int    // byte offset just past the token
}

// isWord reports whether the token is the unquoted keyword w (upper case).
func (t token) isWord(w string) bool { return t.kind == tokWord && t.up == w }

// isPunct reports whether the token is the punctuation p.
func (t token) isPunct(p string) bool { return t.kind == tokOther && t.text == p }

// isName reports whether the token can be one part of an object name.
func (t token) isName() bool { return t.kind == tokWord || t.kind == tokQuoted }

// statement is one SQL statement: its source text (comments inside it
// included, leading comments and the terminating semicolon excluded) and its
// tokens.
type statement struct {
	text string
	toks []token
}

// split cuts a step's SQL into statements. Semicolons end statements outside
// comments, strings, quoted identifiers and dollar-quoted bodies. It fails only
// on an unterminated comment, string, quoted identifier or dollar quote.
//
//nolint:gocyclo // a hand-written SQL lexer: one branch per token class by design.
func split(src string) ([]statement, error) {
	var out []statement
	var cur []token
	flush := func() {
		if len(cur) > 0 {
			out = append(out, statement{text: src[cur[0].pos:cur[len(cur)-1].end], toks: cur})
		}
		cur = nil
	}
	add := func(kind tokKind, start, end int) {
		t := token{kind: kind, text: src[start:end], pos: start, end: end}
		if kind == tokWord {
			t.up = strings.ToUpper(t.text)
		}
		cur = append(cur, t)
	}
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < len(src) && src[i+1] == '-':
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				i = len(src)
			} else {
				i += j
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			j, err := skipBlockComment(src, i)
			if err != nil {
				return nil, err
			}
			i = j
		case c == ';':
			flush()
			i++
		case c == '\'':
			j, err := scanQuoted(src, i, '\'', false)
			if err != nil {
				return nil, err
			}
			add(tokOther, i, j)
			i = j
		case c == '"':
			j, err := scanQuoted(src, i, '"', false)
			if err != nil {
				return nil, err
			}
			add(tokQuoted, i, j)
			i = j
		case c == '$':
			j, err := scanDollar(src, i)
			if err != nil {
				return nil, err
			}
			add(tokOther, i, j)
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
					return nil, err
				}
				add(tokOther, i, k)
				i = k
			case len(word) == 1 && strings.ContainsAny(word, "BbXxNn") && j < len(src) && src[j] == '\'':
				k, err := scanQuoted(src, j, '\'', false)
				if err != nil {
					return nil, err
				}
				add(tokOther, i, k)
				i = k
			case (word == "U" || word == "u") && j+1 < len(src) && src[j] == '&' && (src[j+1] == '\'' || src[j+1] == '"'):
				k, err := scanQuoted(src, j+1, src[j+1], false)
				if err != nil {
					return nil, err
				}
				kind := tokOther
				if src[j+1] == '"' {
					kind = tokQuoted
				}
				add(kind, i, k)
				i = k
			default:
				add(tokWord, i, j)
				i = j
			}
		default:
			_, size := utf8.DecodeRuneInString(src[i:])
			add(tokOther, i, i+size)
			i += size
		}
	}
	flush()
	return out, nil
}

// skipBlockComment returns the offset just past the block comment that starts
// at i. PostgreSQL block comments nest.
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
	return 0, fmt.Errorf("nontx.split: unterminated block comment at offset %d", i)
}

// scanQuoted returns the offset just past the quoted string or identifier
// opening with the quote at i. A doubled quote is an escaped quote; with
// backslash set (E'...') a backslash escapes the next byte.
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
	return 0, fmt.Errorf("nontx.split: unterminated %s at offset %d", what, i)
}

// scanDollar reads what starts with "$" at i: a positional parameter ($1), a
// dollar-quoted string ($$...$$ or $tag$...$tag$), or a lone "$".
func scanDollar(src string, i int) (int, error) {
	j := i + 1
	if j < len(src) && isDigit(src[j]) {
		for j < len(src) && isDigit(src[j]) {
			j++
		}
		return j, nil
	}
	if j < len(src) && isIdentStart(src[j]) {
		for j < len(src) && isIdentPart(src[j]) && src[j] != '$' {
			j++
		}
	}
	if j >= len(src) || src[j] != '$' {
		return i + 1, nil
	}
	tag := src[i : j+1]
	k := strings.Index(src[j+1:], tag)
	if k < 0 {
		return 0, fmt.Errorf("nontx.split: unterminated dollar-quoted string %s at offset %d", tag, i)
	}
	return j + 1 + k + len(tag), nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) || c == '$' }
