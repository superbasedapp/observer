package secassess

import (
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// The forms a logged response body is looked at in when a condition is checked
// (row V14, depth plan W5b; added after the first live run, 2026-11-15).
//
// What the helper keeps of a body is text. A JSON response often carries another
// body inside one of its strings: a fetch endpoint that returns what it fetched
// ({"url": "...", "content": "{\"console\": \"internal\"}"}), an error that
// quotes the request, a log line. In the stored text the inner quotes are
// escaped, so a condition written from what the agent saw ("console":
// "internal") is not a substring of it, though the response holds exactly that
// text (live finding F-9). The body is therefore looked at in each form of
// bodyViewRows; a text the condition must contain holds when ANY form contains
// it, and a text it must not contain holds only when NO form contains it, so
// the control request is held to the same forms (the differential rule, row
// E18, is not weakened: the same condition must still fail on the control).
//
// The table is closed and every form is a pure, bounded function of the stored
// text: nothing is fetched, parsed against a schema or guessed, and a form is
// never longer than the text it came from.

// bodyViewRow is one form of the body a condition is checked in.
type bodyViewRow struct {
	// ID is the row's name in this table (B1, B2).
	ID string
	// Form turns the stored body text into this form of it.
	Form func(string) string
}

// bodyViewRows is the table of body forms, in the order they are tried. B1 is
// the stored text as it is (the form before the table existed); B2 is the text
// with its JSON string escapes decoded once, which is the form of a body that
// was carried inside a JSON string.
var bodyViewRows = []bodyViewRow{
	{"B1", func(s string) string { return s }},
	{"B2", jsonUnescape},
}

// bodyForms returns the distinct forms of a stored body, each passed through
// norm (the redactor and the cleaner the condition's own text went through,
// applied to the form: a secret that only shows once the escapes are decoded is
// hidden the way the condition's text hides it). A form equal to an earlier one
// is left out, so a body with no escape is looked at once. norm may be nil.
func bodyForms(raw string, norm func(string) string) []string {
	var out []string
	for _, row := range bodyViewRows {
		form := row.Form(raw)
		if norm != nil {
			form = norm(form)
		}
		dup := false
		for _, have := range out {
			if have == form {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, form)
		}
	}
	return out
}

// anyContains reports whether any form contains the text.
func anyContains(forms []string, text string) bool {
	for _, f := range forms {
		if strings.Contains(f, text) {
			return true
		}
	}
	return false
}

// jsonUnescape decodes the escapes of a JSON string in text, once and in one
// pass: \" \\ \/ \b \f \n \r \t and \uXXXX (a surrogate pair is one character).
// The text need not be JSON (a body excerpt is cut at a kilobyte and may end in
// the middle of a string), so it is read as text and nothing is checked: a
// backslash that does not start one of those escapes, a \u with fewer than four
// hex digits and a lone surrogate stay as they were written, and an escape that
// the first pass produced is not decoded again (a doubly escaped quote becomes
// an escaped quote, not a quote). The result is never longer than the text.
func jsonUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			i++
			continue
		}
		switch n := s[i+1]; n {
		case '"', '\\', '/':
			b.WriteByte(n)
			i += 2
		case 'b':
			b.WriteByte('\b')
			i += 2
		case 'f':
			b.WriteByte('\f')
			i += 2
		case 'n':
			b.WriteByte('\n')
			i += 2
		case 'r':
			b.WriteByte('\r')
			i += 2
		case 't':
			b.WriteByte('\t')
			i += 2
		case 'u':
			if r, size, ok := unicodeEscape(s[i:]); ok {
				b.WriteRune(r)
				i += size
			} else {
				b.WriteByte(c)
				i++
			}
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// unicodeEscape reads \uXXXX (or a surrogate pair of two of them) at the start
// of s and returns the character and how many bytes it took; ok is false for
// anything else, a lone surrogate included.
func unicodeEscape(s string) (r rune, size int, ok bool) {
	hi, hiOK := hex4(s)
	switch {
	case !hiOK:
		return 0, 0, false
	case utf16.IsSurrogate(hi):
		lo, loOK := hex4(s[6:])
		if !loOK || !utf16.IsSurrogate(lo) {
			return 0, 0, false
		}
		if pair := utf16.DecodeRune(hi, lo); pair != utf8.RuneError {
			return pair, 12, true
		}
		return 0, 0, false
	}
	return hi, 6, true
}

// hex4 reads the rune of "\uXXXX" at the start of s; s[6:] of a shorter text is
// handled by the length check.
func hex4(s string) (rune, bool) {
	if len(s) < 6 || s[0] != '\\' || s[1] != 'u' {
		return 0, false
	}
	var r rune
	for _, c := range []byte(s[2:6]) {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}
