package secdepdetail

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// bidiControl reports the Unicode bidirectional embedding, override and
// isolate controls, which can make shown text read differently from what
// it is (the "trojan source" class).
func bidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}

// cleanText strips control characters (and the bidi controls) from
// third-party text and makes it valid UTF-8. keepNewlines keeps '\n' (a
// record's details is multi-paragraph Markdown); every other control,
// '\r' included, is dropped, and a tab becomes a space.
func cleanText(s string, keepNewlines bool) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' && keepNewlines:
			b.WriteRune(r)
		case r == '\t':
			b.WriteByte(' ')
		case r == '\n':
			b.WriteByte(' ')
		case unicode.IsControl(r), bidiControl(r), r == utf8.RuneError:
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// capBytes cuts s to at most max bytes on a rune boundary and reports
// whether it cut anything.
func capBytes(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

// cleanShort is a one-line field: cleaned, newlines folded, trimmed and
// capped.
func cleanShort(s string, max int) string {
	out, _ := capBytes(strings.TrimSpace(cleanText(s, false)), max)
	return out
}
