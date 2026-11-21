package secassess

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Escaping for the Markdown export. The report is written by Go from the
// checked model, and the model is the agent's: every string in it is
// untrusted text that a reader's Markdown renderer would otherwise act on (an
// image that phones home, a link with a script address, raw HTML, a heading or
// a list that is not Observer's). One function, mdText, is the only way an
// agent string reaches the output, and the rest of the renderer only writes
// Observer's own literals around its results.
//
// What mdText guarantees, pinned by exportmd_escape_test.go over every ASCII
// byte and a set of Unicode troublemakers:
//
//   - the result is one line of plain text: any run of white space, control
//     characters, format characters (zero width, bidi, soft hyphen, byte
//     order mark), private-use and separator characters, the replacement
//     character and a few blank-looking letters becomes one space, and the
//     ends are trimmed. A string cannot add a block.
//   - "<", ">" and "&" are written as the entities &lt; &gt; &amp;, so no tag,
//     comment, autolink or character reference can start.
//   - every ASCII punctuation character that starts or changes Markdown, inline
//     or block, is written after a backslash (mdBackslashed). CommonMark treats
//     a backslash before ASCII punctuation as that character, literally.
//
// What the escapes do not stop, said plainly: a renderer that finds the bare
// text of an address, a "www." name or an e-mail address after it has merged
// the escaped pieces of a line (some GitHub-style renderers do) can still make
// it a link. That link can only be an http, https, ftp or mailto link whose
// visible text is its own address; it cannot be a script or data address, an
// image, or HTML, which is what the escapes are for.
//
// The same holds for text a host acts on when the file is pasted into an issue,
// a pull request or a comment: an "@name" can notify that account, "#123" can
// link an issue or pull request, and a 7 to 40 digit hex string can link a
// commit. Those filters read the text nodes after the escaping, so a backslash
// does not stop them, and neither does an entity; they are plain text that
// names something, never a script, an image or HTML. A reader who pastes an
// export into such a place pastes the agent's words with it.

// mdBackslashed is the set of ASCII punctuation mdText writes after a
// backslash. Each member, and why:
//
//	\   the escape character itself
//	*   emphasis, bullet lists, thematic breaks
//	_   emphasis, thematic breaks
//	{ } attribute lists and template syntax of some renderers
//	[ ] links, images, reference definitions, footnotes, task boxes
//	( ) link destinations, ordered list markers ("1)")
//	#   headings
//	+   bullet lists
//	-   bullet lists, setext underlines, thematic breaks, table rules
//	!   the image marker (!['alt'](address))
//	|   table cells
//	~   strikethrough and tilde fences
//	:   table alignment, definition lists, emoji codes, a link scheme
//	=   setext underlines
//	.   ordered list markers ("1."), "www." autolinks, a domain's dots
//	$   math spans
//	^   superscript and footnote marks
//	"   attribute and title delimiters
//	`   code spans and fences
//
// "<", ">" and "&" are entity-encoded instead (mdEntities).
const mdBackslashed = "\\*_{}[]()#+-!|~:=.$^\"`"

// mdEntities maps the three characters that are written as entities.
var mdEntities = map[rune]string{'<': "&lt;", '>': "&gt;", '&': "&amp;"}

// mdBlankLookalikes are letters and marks that draw as nothing or as blank
// space but are not white space to Unicode: the braille blank, the Hangul
// fillers and the combining grapheme joiner. They are replaced by a space
// like any other blank.
var mdBlankLookalikes = map[rune]bool{
	0x034F: true, // combining grapheme joiner
	0x115F: true, // Hangul choseong filler
	0x1160: true, // Hangul jungseong filler
	0x2800: true, // braille pattern blank
	0x3164: true, // Hangul filler
	0xFFA0: true, // halfwidth Hangul filler
}

// mdIsBlank reports whether r is one of the characters mdText turns into a
// space: white space of any kind (a no-break space and the line and paragraph
// separators included), control characters, format characters (zero width and
// bidi controls), private-use, surrogate and separator characters, the
// replacement character (an invalid byte decodes to it), and the blank
// lookalikes.
func mdIsBlank(r rune) bool {
	return r == utf8.RuneError || unicode.IsSpace(r) || unicode.IsControl(r) || mdBlankLookalikes[r] ||
		unicode.In(r, unicode.Cf, unicode.Co, unicode.Cs, unicode.Zs, unicode.Zl, unicode.Zp)
}

// mdText makes one agent-originated string safe to put in a Markdown line, a
// heading, a list item or a table cell. See the comment at the top of this
// file for what it guarantees. It is deterministic and not idempotent (an
// escaped string escaped again gains backslashes).
func mdText(s string) string {
	var b strings.Builder
	b.Grow(len(s) + len(s)/8)
	space := false
	for _, r := range s {
		if mdIsBlank(r) {
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		mdWriteRune(&b, r)
	}
	return b.String()
}

// mdWriteRune writes one non-blank rune, escaped.
func mdWriteRune(b *strings.Builder, r rune) {
	if e, ok := mdEntities[r]; ok {
		b.WriteString(e)
		return
	}
	if r < utf8.RuneSelf && strings.IndexByte(mdBackslashed, byte(r)) >= 0 {
		b.WriteByte('\\')
	}
	b.WriteRune(r)
}

// mdWords is mdText over a closed word an agent wrote with underscores
// (end_user, accepted_by_design): the underscores read as spaces, as the page
// does, and the result is still escaped. A value is printed as written, never
// as a lookup, so a word Observer does not know is shown and not lost.
func mdWords(s string) string { return mdText(strings.ReplaceAll(s, "_", " ")) }

// mdInt is a count or a number from the model as text. Numbers are not
// escaped: they hold nothing but digits and a sign.
func mdInt(n int) string { return strconv.Itoa(n) }

// mdWriter builds the document. Every method writes Observer's literals and
// strings already made safe by mdText; none escapes on its own.
type mdWriter struct{ b strings.Builder }

// line writes s and a line break.
func (w *mdWriter) line(s string) {
	w.b.WriteString(s)
	w.b.WriteByte('\n')
}

// blank writes an empty line.
func (w *mdWriter) blank() { w.b.WriteByte('\n') }

// para writes s as a paragraph: the text and an empty line after it.
func (w *mdWriter) para(s string) {
	w.line(s)
	w.blank()
}

// heading writes a heading of the given level (1 to 6) and an empty line.
func (w *mdWriter) heading(level int, s string) {
	w.b.WriteString(strings.Repeat("#", level))
	w.b.WriteByte(' ')
	w.para(s)
}

// bullet writes a list item at the given depth (0 is the outermost).
func (w *mdWriter) bullet(depth int, s string) {
	w.b.WriteString(strings.Repeat("  ", depth))
	w.b.WriteString("- ")
	w.line(s)
}

// table writes a table: the header row, the rule and one line per row. A cell
// is text that is already safe (one line, no raw bar). A row shorter than the
// header is padded with empty cells and a longer one is cut to the header's
// width, so the table never breaks.
func (w *mdWriter) table(header []string, rows [][]string) {
	w.row(header)
	rule := make([]string, len(header))
	for i := range rule {
		rule[i] = "---"
	}
	w.row(rule)
	for _, r := range rows {
		cells := make([]string, len(header))
		copy(cells, r)
		w.row(cells)
	}
	w.blank()
}

// row writes one table row.
func (w *mdWriter) row(cells []string) {
	w.b.WriteByte('|')
	for _, c := range cells {
		w.b.WriteByte(' ')
		w.b.WriteString(c)
		w.b.WriteString(" |")
	}
	w.b.WriteByte('\n')
}

// String is the document so far.
func (w *mdWriter) String() string { return w.b.String() }
