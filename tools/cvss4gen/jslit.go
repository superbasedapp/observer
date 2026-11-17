package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file is a small parser for the JavaScript object literals FIRST's
// calculator keeps its data in (cvss_lookup.js, max_severity.js,
// max_composed.js, cvss_config.js, and the *_levels literals inside
// cvss_score.js). It understands exactly the subset those files use:
// objects with quoted, single-quoted, bare-identifier or bare-number keys,
// arrays, strings with escapes, numbers, `//` and `/* */` comments and
// trailing commas. Anything else is an error that names the line, so an
// upstream change in shape stops generation instead of producing wrong
// tables. Object keys keep their source order.

type nodeKind int

const (
	kindObject nodeKind = iota
	kindArray
	kindString
	kindNumber
)

// node is one parsed literal.
type node struct {
	kind nodeKind
	// str is the decoded value of a string and the verbatim source text of a
	// number (so a number is emitted exactly as upstream spelled it).
	str  string
	keys []string // object keys, in source order
	vals []*node  // object values (parallel to keys) or array elements
	line int
}

func (n *node) lookup(key string) (*node, bool) {
	if n == nil || n.kind != kindObject {
		return nil, false
	}
	for i, k := range n.keys {
		if k == key {
			return n.vals[i], true
		}
	}
	return nil, false
}

var numberRe = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)

type jsParser struct {
	src  string
	pos  int
	file string
}

func (p *jsParser) fail(format string, args ...any) error {
	line := 1 + strings.Count(p.src[:min(p.pos, len(p.src))], "\n")
	return fmt.Errorf("%s:%d: %s", p.file, line, fmt.Sprintf(format, args...))
}

func (p *jsParser) lineNo() int {
	return 1 + strings.Count(p.src[:min(p.pos, len(p.src))], "\n")
}

// skip moves past whitespace and comments.
func (p *jsParser) skip() error {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			p.pos++
		case strings.HasPrefix(p.src[p.pos:], "//"):
			i := strings.IndexByte(p.src[p.pos:], '\n')
			if i < 0 {
				p.pos = len(p.src)
			} else {
				p.pos += i + 1
			}
		case strings.HasPrefix(p.src[p.pos:], "/*"):
			i := strings.Index(p.src[p.pos+2:], "*/")
			if i < 0 {
				return p.fail("unterminated block comment")
			}
			p.pos += 2 + i + 2
		default:
			return nil
		}
	}
	return nil
}

func (p *jsParser) parseValue() (*node, error) {
	if err := p.skip(); err != nil {
		return nil, err
	}
	if p.pos >= len(p.src) {
		return nil, p.fail("unexpected end of input")
	}
	switch c := p.src[p.pos]; {
	case c == '{':
		return p.parseObject()
	case c == '[':
		return p.parseArray()
	case c == '"' || c == '\'':
		line := p.lineNo()
		s, err := p.parseString()
		if err != nil {
			return nil, err
		}
		return &node{kind: kindString, str: s, line: line}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	}
	return nil, p.fail("unsupported value starting with %q", p.src[p.pos])
}

func (p *jsParser) parseNumber() (*node, error) {
	start, line := p.pos, p.lineNo()
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if (c >= '0' && c <= '9') || c == '.' || c == '-' {
			p.pos++
			continue
		}
		break
	}
	for p.pos < len(p.src) && isIdentByte(p.src[p.pos]) {
		p.pos++ // 1e3, 0x10: not a plain decimal
	}
	raw := p.src[start:p.pos]
	if !numberRe.MatchString(raw) {
		return nil, p.fail("number %q is not a plain decimal", raw)
	}
	return &node{kind: kindNumber, str: raw, line: line}, nil
}

func (p *jsParser) parseString() (string, error) {
	quote := p.src[p.pos]
	p.pos++
	var b strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == quote:
			p.pos++
			return b.String(), nil
		case c == '\n':
			return "", p.fail("newline inside a string")
		case c == '\\':
			if p.pos+1 >= len(p.src) {
				return "", p.fail("dangling escape")
			}
			esc := p.src[p.pos+1]
			if esc >= utf8.RuneSelf {
				// JavaScript: a backslash before a character that has no
				// escape meaning stands for that character (cvss_config.js
				// writes \“ and \”).
				r, size := utf8.DecodeRuneInString(p.src[p.pos+1:])
				if r == utf8.RuneError {
					return "", p.fail("invalid UTF-8 after a backslash")
				}
				b.WriteRune(r)
				p.pos += 1 + size
				continue
			}
			p.pos += 2
			switch esc {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\', '"', '\'', '/':
				b.WriteByte(esc)
			case 'u':
				if p.pos+4 > len(p.src) {
					return "", p.fail("short \\u escape")
				}
				v, err := strconv.ParseUint(p.src[p.pos:p.pos+4], 16, 32)
				if err != nil {
					return "", p.fail("bad \\u escape")
				}
				b.WriteRune(rune(v))
				p.pos += 4
			default:
				return "", p.fail("unsupported escape \\%c", esc)
			}
		default:
			r, size := utf8.DecodeRuneInString(p.src[p.pos:])
			if r == utf8.RuneError && size == 1 {
				return "", p.fail("invalid UTF-8")
			}
			b.WriteString(p.src[p.pos : p.pos+size])
			p.pos += size
		}
	}
	return "", p.fail("unterminated string")
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func (p *jsParser) parseKey() (string, error) {
	if err := p.skip(); err != nil {
		return "", err
	}
	if p.pos >= len(p.src) {
		return "", p.fail("unexpected end of input in object")
	}
	if c := p.src[p.pos]; c == '"' || c == '\'' {
		return p.parseString()
	}
	start := p.pos
	for p.pos < len(p.src) && isIdentByte(p.src[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return "", p.fail("expected an object key, found %q", p.src[p.pos])
	}
	return p.src[start:p.pos], nil
}

func (p *jsParser) parseObject() (*node, error) {
	n := &node{kind: kindObject, line: p.lineNo()}
	p.pos++ // {
	for {
		if err := p.skip(); err != nil {
			return nil, err
		}
		if p.pos >= len(p.src) {
			return nil, p.fail("unterminated object")
		}
		if p.src[p.pos] == '}' {
			p.pos++
			return n, nil
		}
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		for _, k := range n.keys {
			if k == key {
				return nil, p.fail("duplicate key %q", key)
			}
		}
		if err := p.skip(); err != nil {
			return nil, err
		}
		if p.pos >= len(p.src) || p.src[p.pos] != ':' {
			return nil, p.fail("expected ':' after key %q", key)
		}
		p.pos++
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		n.keys = append(n.keys, key)
		n.vals = append(n.vals, v)
		if err := p.skip(); err != nil {
			return nil, err
		}
		if p.pos < len(p.src) && p.src[p.pos] == ',' {
			p.pos++
			continue
		}
		if p.pos >= len(p.src) {
			return nil, p.fail("unterminated object")
		}
		if p.src[p.pos] == '}' {
			continue
		}
		return nil, p.fail("expected ',' or '}' after key %q", key)
	}
}

func (p *jsParser) parseArray() (*node, error) {
	n := &node{kind: kindArray, line: p.lineNo()}
	p.pos++ // [
	for {
		if err := p.skip(); err != nil {
			return nil, err
		}
		if p.pos >= len(p.src) {
			return nil, p.fail("unterminated array")
		}
		if p.src[p.pos] == ']' {
			p.pos++
			return n, nil
		}
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		n.vals = append(n.vals, v)
		if err := p.skip(); err != nil {
			return nil, err
		}
		if p.pos < len(p.src) && p.src[p.pos] == ',' {
			p.pos++
			continue
		}
		if p.pos >= len(p.src) {
			return nil, p.fail("unterminated array")
		}
		if p.src[p.pos] == ']' {
			continue
		}
		return nil, p.fail("expected ',' or ']' in array")
	}
}

// parseAssigned finds the one line-leading `ident = {` in src and parses the
// object literal it assigns. Zero or several such lines are an error.
func parseAssigned(file, src, ident string) (*node, error) {
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(ident) + `[ \t]*=[ \t]*\{`)
	locs := re.FindAllStringIndex(src, -1)
	if len(locs) != 1 {
		return nil, fmt.Errorf("%s: want exactly one `%s = {` assignment, found %d", file, ident, len(locs))
	}
	p := &jsParser{src: src, pos: locs[0][1] - 1, file: file}
	n, err := p.parseObject()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ident, err)
	}
	return n, nil
}
