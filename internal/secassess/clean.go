package secassess

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// invisibleSpaces are blank-looking characters that unicode.IsSpace does not
// cover: the Braille blank and the Hangul fillers render as nothing but are
// not control characters, so a text could hide a line break or a fence in
// them.
var invisibleSpaces = map[rune]bool{
	0x115F: true, 0x1160: true, 0x2800: true, 0x3164: true, 0xFFA0: true,
}

// isDash reports whether r is a hyphen-like character that could stand in for
// '-' in a fence lookalike ("-----").
func isDash(r rune) bool {
	switch {
	case r == '-', r >= 0x2010 && r <= 0x2015, r == 0x2212, r == 0x2E3A, r == 0x2E3B,
		r == 0xFE58, r == 0xFE63, r == 0xFF0D:
		return true
	}
	return false
}

// CleanText returns s cleaned for display and for a prompt: see clean. It is
// the one exported seam to the cleaner, used by the service package and by the
// property test that holds it to the fix-with-an-agent prompt's own cleaner.
func CleanText(s string, max int) string { return clean(s, max) }

// clean returns s on one line, safe to place inside a fenced block of a prompt
// or on a page, cut to at most max runes:
//
//   - control characters, every Unicode space (no-break, ideographic, line and
//     paragraph separators included) and the blank-looking fillers become one
//     space, runs of spaces collapse;
//   - invisible format characters (zero-width space and joiners, byte-order
//     mark, bidirectional controls, soft hyphen) are dropped, so they cannot
//     hide a dash run or reorder what a reader sees;
//   - backticks and invalid UTF-8 are dropped;
//   - a run of dash-like characters (hyphen, the Unicode dashes, the minus
//     sign, the full-width hyphen) shrinks to two, so a fence lookalike such
//     as "----- END FINDINGS" cannot be written.
//
// Every string that came from a repository or an agent goes through it before
// it reaches a prompt or a stored model. The rules mirror the fix prompt's own
// cleaner (internal/secfixtask); a test in secassesssvc holds them to the same
// safety properties on one hostile table.
func clean(s string, max int) string {
	var b strings.Builder
	space, dashes, n := false, 0, 0
	for _, r := range s {
		switch {
		case r == utf8.RuneError, r == '`':
			continue
		case unicode.Is(unicode.Cf, r):
			continue
		case unicode.IsControl(r), unicode.IsSpace(r), unicode.Is(unicode.Zs, r), invisibleSpaces[r]:
			space, dashes = b.Len() > 0, 0
			continue
		}
		if isDash(r) {
			dashes++
			if dashes > 2 {
				continue
			}
		} else {
			dashes = 0
		}
		if space {
			if n >= max {
				break
			}
			b.WriteByte(' ')
			n++
			space = false
		}
		if n >= max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}
