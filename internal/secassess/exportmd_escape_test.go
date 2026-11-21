package secassess

import (
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

// The escaping of the Markdown export is its security core, so it is pinned
// from three sides: a table of exact outputs, a property check that every
// output is one line of plain text with every Markdown character escaped and
// that undoing the escapes gives back the input with its blanks collapsed (so
// nothing is lost and nothing is added), and a small block classifier that
// proves a hostile string cannot start a block.

// mdUnescape undoes mdText's escapes: a backslash before a character stands
// for the character, and the three entities for theirs.
func mdUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			b.WriteByte(s[i+1])
			i += 2
		case strings.HasPrefix(s[i:], "&amp;"):
			b.WriteByte('&')
			i += 5
		case strings.HasPrefix(s[i:], "&lt;"):
			b.WriteByte('<')
			i += 4
		case strings.HasPrefix(s[i:], "&gt;"):
			b.WriteByte('>')
			i += 4
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// mdNormalized is what mdText must give back once its escapes are undone: the
// input with every run of blank characters made one space and the ends
// trimmed. It decodes the input rune by rune, so an invalid byte is a blank
// (it decodes to the replacement character).
func mdNormalized(s string) string {
	var b strings.Builder
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
		b.WriteRune(r)
	}
	return b.String()
}

// mdCheckSafe is the property every output of mdText has. It names the input
// in each failure.
func mdCheckSafe(t *testing.T, in, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Errorf("mdText(%q) = %q is not valid UTF-8", in, out)
	}
	for _, r := range out {
		if r != ' ' && mdIsBlank(r) {
			t.Errorf("mdText(%q) = %q holds the blank character %U", in, out, r)
		}
	}
	if strings.Contains(out, "  ") || out != strings.TrimSpace(out) {
		t.Errorf("mdText(%q) = %q has a run of spaces or untrimmed ends", in, out)
	}
	for i := 0; i < len(out); {
		c := out[i]
		switch {
		case c == '\\':
			if i+1 >= len(out) || strings.IndexByte(mdBackslashed, out[i+1]) < 0 {
				t.Errorf("mdText(%q) = %q: a backslash at %d does not escape a member of the set", in, out, i)
			}
			i += 2
		case strings.HasPrefix(out[i:], "&amp;"):
			i += 5
		case strings.HasPrefix(out[i:], "&lt;"), strings.HasPrefix(out[i:], "&gt;"):
			i += 4
		case c == '<' || c == '>' || c == '&':
			t.Errorf("mdText(%q) = %q has a raw %q at %d", in, out, c, i)
			i++
		case strings.IndexByte(mdBackslashed, c) >= 0:
			t.Errorf("mdText(%q) = %q has an unescaped %q at %d", in, out, c, i)
			i++
		default:
			i++
		}
	}
	if got, want := mdUnescape(out), mdNormalized(in); got != want {
		t.Errorf("mdText(%q) = %q reads back as %q, want %q", in, out, got, want)
	}
}

// mdBlockStart names the Markdown block a line would start, "" when it is a
// paragraph line. It covers the starts a hostile string could use: headings,
// block quotes, bullets, ordered items, thematic breaks and setext underlines,
// fences, raw HTML, table rows, link reference definitions and indented code.
func mdBlockStart(line string) string {
	if strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t") {
		return "indented code"
	}
	s := strings.TrimLeft(line, " ")
	if s == "" {
		return ""
	}
	if k := mdBlockStartByPrefix(s); k != "" {
		return k
	}
	if k := mdBlockStartByShape(s); k != "" {
		return k
	}
	return ""
}

// mdBlockStartByPrefix recognises the starts that are decided by the first
// characters.
func mdBlockStartByPrefix(s string) string {
	switch {
	case s[0] == '>':
		return "block quote"
	case s[0] == '<':
		return "raw html"
	case strings.HasPrefix(s, "```") || strings.HasPrefix(s, "~~~"):
		return "fence"
	case s[0] == '#':
		n := len(s) - len(strings.TrimLeft(s, "#"))
		if n <= 6 && (n == len(s) || s[n] == ' ') {
			return "heading"
		}
	case s[0] == '-' || s[0] == '+' || s[0] == '*':
		if len(s) == 1 || s[1] == ' ' {
			return "bullet"
		}
	}
	return ""
}

// mdBlockStartByShape recognises the starts that are decided by the shape of
// the whole line.
func mdBlockStartByShape(s string) string {
	if strings.Trim(s, "-") == "" && len(s) >= 1 {
		return "thematic break or setext underline"
	}
	if strings.Trim(s, "=") == "" || strings.Trim(s, "*") == "" || strings.Trim(s, "_") == "" {
		return "thematic break or setext underline"
	}
	if i := strings.IndexAny(s, ".)"); i > 0 && i <= 9 && strings.Trim(s[:i], "0123456789") == "" && (i+1 == len(s) || s[i+1] == ' ') {
		return "ordered item"
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '|' && (i == 0 || s[i-1] != '\\') {
			return "table row"
		}
	}
	if strings.HasPrefix(s, "[") && strings.Contains(s, "]:") {
		return "link reference definition"
	}
	return ""
}

// mdHostile is the table of hostile strings the tests use: each is a way an
// agent string could change what the report says.
var mdHostile = []string{
	"<script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"<!-- comment -->",
	"<https://evil.example/a>",
	"![x](http://e/x.png)",
	"[l](javascript:alert(1))",
	"[l](data:text/html;base64,PHNjcmlwdD4=)",
	"[ref]: http://e/",
	"[ref][other]",
	"| a | b |",
	"|---|---|",
	"x\n# Injected\n- [a](http://e)",
	"x\r\n\r\n## Injected\r\n",
	"x\n\n    indented code",
	"x\n```\ncode\n```",
	"x\n~~~\ncode",
	"> quote",
	"1. one\n2) two",
	"- bullet\n+ plus\n* star",
	"***",
	"---",
	"___",
	"===",
	"Title\n=====",
	"Title\n-----",
	"*em* **strong** _u_ __uu__ ~~strike~~",
	"`code` ``a`b``",
	"$x^2$ and $$y$$",
	"{#id .class} {{template}}",
	"www.example.com and http://e.com/a?b=c and ftp://e/f and a@b.com",
	":smile: and ::: fence",
	"&amp; &lt;b&gt; &#60; &#x3c;",
	"a \\ b \\* c \\` d \\\\",
	"\"quoted\" 'single'",
	"[^1]: footnote",
	"- [ ] task",
	"# H1 #\n## H2",
	"<a href=\"javascript:alert(1)\">x</a>",
	"</td></tr></table><h1>x</h1>",
	"```mermaid\ngraph TD\n```",
	"x" + exRunes(0x2028) + "# Injected" + exRunes(0x2029) + "- item",
	"x" + exRunes(0x85) + "# Injected",
	"x" + exRunes(0x202e) + "# Injected" + exRunes(0x202c),
	"x" + exRunes(0x200b, 0x200c, 0x200d, 0xfeff) + "# y",
}

// exRunes builds a string from code points, so this file holds no invisible
// character of its own.
func exRunes(rs ...rune) string { return string(rs) }

// mdTroublemakers are characters that are not ASCII punctuation and still need
// care, with the output each gets.
var mdTroublemakers = []struct{ name, in, want string }{
	{"no-break space", "a" + exRunes(0xa0) + "b", "a b"},
	{"line separator", "a" + exRunes(0x2028) + "b", "a b"},
	{"paragraph separator", "a" + exRunes(0x2029) + "b", "a b"},
	{"next line", "a" + exRunes(0x85) + "b", "a b"},
	{"zero width space", "a" + exRunes(0x200b) + "b", "a b"},
	{"zero width joiner and non-joiner", "a" + exRunes(0x200c, 0x200d) + "b", "a b"},
	{"left and right marks", "a" + exRunes(0x200e, 0x200f) + "b", "a b"},
	{"right to left override", "a" + exRunes(0x202e) + "b" + exRunes(0x202c), "a b"},
	{"isolates", "a" + exRunes(0x2066) + "b" + exRunes(0x2069), "a b"},
	{"byte order mark", exRunes(0xfeff) + "a", "a"},
	{"soft hyphen", "a" + exRunes(0xad) + "b", "a b"},
	{"mongolian vowel separator", "a" + exRunes(0x180e) + "b", "a b"},
	{"ideographic space", "a" + exRunes(0x3000) + "b", "a b"},
	{"tag character", "a" + exRunes(0xe0041) + "b", "a b"},
	{"private use", "a" + exRunes(0xe000) + "b", "a b"},
	{"braille blank", "a" + exRunes(0x2800) + "b", "a b"},
	{"hangul filler", "a" + exRunes(0x3164) + "b", "a b"},
	{"combining grapheme joiner", "a" + exRunes(0x34f) + "b", "a b"},
	{"invalid byte", "a\xffb", "a b"},
	{"encoded surrogate", "a\xed\xa0\x80b", "a b"},
	{"the replacement character", "a" + exRunes(0xfffd) + "b", "a b"},
	{"nul and bell", "a\x00\x07b", "a b"},
	{"delete", "a\x7fb", "a b"},
	{"escape sequence", "a\x1b[31mb", "a " + exBackslash + "[31mb"},
	{"fullwidth brackets are not syntax", exRunes(0xff3b, 0xff3d, 0xff08, 0xff09, 0xff1c, 0xff1e), exRunes(0xff3b, 0xff3d, 0xff08, 0xff09, 0xff1c, 0xff1e)},
	{"right to left text is kept", exRunes(0x5e9, 0x5dc, 0x5d5, 0x5dd), exRunes(0x5e9, 0x5dc, 0x5d5, 0x5dd)},
	{"an emoji is kept", "ok " + exRunes(0x1f600), "ok " + exRunes(0x1f600)},
	{"a combining mark is kept", "e" + exRunes(0x301), "e" + exRunes(0x301)},
}

// TestMDTextExact is the table of exact outputs.
func TestMDTextExact(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain words", "Login has no throttle", "Login has no throttle"},
		{"empty", "", ""},
		{"only blanks", " \t\r\n ", ""},
		{"trimmed", "  a  ", "a"},
		{"runs of blanks", "a \t\r\n b", "a b"},
		{"script tag", "<script>alert(1)</script>", `&lt;script&gt;alert\(1\)&lt;/script&gt;`},
		{"image", "![x](http://e/x.png)", `\!\[x\]\(http\://e/x\.png\)`},
		{"link with a script address", "[l](javascript:alert(1))", `\[l\]\(javascript\:alert\(1\)\)`},
		{"table bars", "| a | b |", `\| a \| b \|`},
		{"newline then heading then list", "x\n# Injected\n- [a](http://e)", `x \# Injected \- \[a\]\(http\://e\)`},
		{"ordered marker", "1. one", `1\. one`},
		{"ordered marker with a bracket", "2) two", `2\) two`},
		{"thematic break", "***", `\*\*\*`},
		{"dashes", "---", `\-\-\-`},
		{"setext equals", "===", `\=\=\=`},
		{"tilde fence", "~~~", `\~\~\~`},
		{"backtick fence", "```", "\\`\\`\\`"},
		{"double quote", `say "hi"`, `say \"hi\"`},
		{"a single quote is plain", "it's", "it's"},
		{"backslash", `a\b`, `a\\b`},
		{"an entity is not decoded", "&amp;", "&amp;amp;"},
		{"ampersand", "a & b", "a &amp; b"},
		{"angle brackets", "a < b > c", "a &lt; b &gt; c"},
		{"underscores", "a_b_c", `a\_b\_c`},
		{"www autolink", "www.example.com", `www\.example\.com`},
		{"math", "$x$", `\$x\$`},
		{"superscript", "a^b", `a\^b`},
		{"attribute list", "{#id}", `\{\#id\}`},
		{"emoji code", ":smile:", `\:smile\:`},
		{"plus", "+1", `\+1`},
		{"a trailing backslash", `a\`, `a\\`},
		{"non-ASCII kept", "caf" + exRunes(0xe9) + " " + exRunes(0x4e2d, 0x6587), "caf" + exRunes(0xe9) + " " + exRunes(0x4e2d, 0x6587)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mdText(tc.in)
			if got != tc.want {
				t.Errorf("mdText(%q) = %q, want %q", tc.in, got, tc.want)
			}
			mdCheckSafe(t, tc.in, got)
		})
	}
}

// TestMDTextTroublemakers: blank-looking characters become one space, and
// characters that are only unusual are kept.
func TestMDTextTroublemakers(t *testing.T) {
	for _, tc := range mdTroublemakers {
		t.Run(tc.name, func(t *testing.T) {
			got := mdText(tc.in)
			if got != tc.want {
				t.Errorf("mdText(%q) = %q, want %q", tc.in, got, tc.want)
			}
			mdCheckSafe(t, tc.in, got)
		})
	}
}

// TestMDTextEveryASCIIByte runs the property over every ASCII byte alone, at
// the start, in the middle and at the end of a string, and over every pair of
// bytes (the two together make "![", "](", "1." and the like).
func TestMDTextEveryASCIIByte(t *testing.T) {
	for b := 0; b < 128; b++ {
		c := string(rune(b))
		for _, in := range []string{c, c + "x", "x" + c, "x" + c + "y", c + c + c} {
			mdCheckSafe(t, in, mdText(in))
		}
	}
	for a := 0; a < 128; a++ {
		for b := 0; b < 128; b++ {
			in := string(rune(a)) + string(rune(b))
			mdCheckSafe(t, in, mdText(in))
			in = "x" + in + "y"
			mdCheckSafe(t, in, mdText(in))
		}
	}
}

// TestMDTextEverySetMemberIsEscaped: each member of the set comes out after a
// backslash, in every position, and every ASCII punctuation character that is
// not a member comes out as it went in (except the three entities), so the set
// is exactly what the comment says.
func TestMDTextEverySetMemberIsEscaped(t *testing.T) {
	for b := 33; b < 127; b++ {
		c := string(rune(b))
		got := mdText("a" + c + "b")
		switch {
		case c == "<" || c == ">" || c == "&":
			if want := "a" + mdEntities[rune(b)] + "b"; got != want {
				t.Errorf("mdText(%q) = %q, want %q", c, got, want)
			}
		case strings.IndexByte(mdBackslashed, byte(b)) >= 0:
			if want := "a\\" + c + "b"; got != want {
				t.Errorf("mdText(%q) = %q, want %q", c, got, want)
			}
		default:
			if want := "a" + c + "b"; got != want {
				t.Errorf("mdText(%q) = %q, want %q (not in the set, so unchanged)", c, got, want)
			}
		}
	}
	// The set is the documented one: no repeats, all ASCII punctuation.
	seen := map[rune]bool{}
	for _, r := range mdBackslashed {
		if seen[r] || r < 33 || r > 126 || ('0' <= r && r <= '9') || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') {
			t.Errorf("%q is repeated or is not ASCII punctuation", r)
		}
		seen[r] = true
	}
}

// TestMDTextHostileTable runs the property over the hostile table, alone and
// inside each of the contexts the renderer puts an agent string in, and checks
// that no output starts a block or adds a line.
func TestMDTextHostileTable(t *testing.T) {
	for _, in := range mdHostile {
		out := mdText(in)
		mdCheckSafe(t, in, out)
		if strings.ContainsAny(out, "\n\r") {
			t.Errorf("mdText(%q) = %q holds a line break", in, out)
		}
		if k := mdBlockStart(out); k != "" {
			t.Errorf("mdText(%q) = %q starts a %s", in, out, k)
		}
		// In a table cell the string stays in its cell.
		var w mdWriter
		w.table([]string{"A", "B"}, [][]string{{out, "x"}})
		lines := strings.Split(strings.TrimRight(w.String(), "\n"), "\n")
		if len(lines) != 3 {
			t.Errorf("a table with %q has %d lines, want 3: %q", in, len(lines), lines)
		}
		if got := len(mdUnescapedBars(lines[2])); got != 3 {
			t.Errorf("a table row with %q has %d cell borders, want 3: %q", in, got, lines[2])
		}
		// As a heading or a list item it is one line of one block.
		w = mdWriter{}
		w.heading(3, out)
		w.bullet(1, out)
		w.para("The agent says: " + out)
		lines = strings.Split(strings.TrimRight(w.String(), "\n"), "\n")
		if len(lines) != 4 || !strings.HasPrefix(lines[0], "### ") || lines[1] != "" || !strings.HasPrefix(lines[2], "  - ") || !strings.HasPrefix(lines[3], "The agent says: ") {
			t.Errorf("a heading, an item and a paragraph with %q are %q", in, lines)
		}
	}
}

// mdUnescapedBars returns the positions of the bars in a table row that are
// not escaped.
func mdUnescapedBars(row string) []int {
	var at []int
	for i := 0; i < len(row); i++ {
		switch row[i] {
		case '\\':
			i++
		case '|':
			at = append(at, i)
		}
	}
	return at
}

// TestMDBlockStartClassifier proves the classifier is not vacuous: it sees the
// block starts in the raw hostile strings that carry one.
func TestMDBlockStartClassifier(t *testing.T) {
	for in, want := range map[string]string{
		"# Injected":         "heading",
		"###### six":         "heading",
		"- item":             "bullet",
		"+ item":             "bullet",
		"* item":             "bullet",
		"1. one":             "ordered item",
		"12) twelve":         "ordered item",
		"> quote":            "block quote",
		"<div>":              "raw html",
		"```go":              "fence",
		"~~~":                "fence",
		"---":                "thematic break or setext underline",
		"=====":              "thematic break or setext underline",
		"***":                "thematic break or setext underline",
		"| a | b |":          "table row",
		"[ref]: http://e/":   "link reference definition",
		"    code":           "indented code",
		"plain words":        "",
		"a - b":              "",
		"3 apples":           "",
		"1.5 is not a list":  "",
		"#hashtag":           "",
		`\# escaped heading`: "",
	} {
		if got := mdBlockStart(in); got != want {
			t.Errorf("mdBlockStart(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMDTextUnicodeTroublemakersTable is the troublemaker table inside the
// contexts: none of them lets a line break through.
func TestMDTextUnicodeTroublemakersTable(t *testing.T) {
	for _, tc := range mdTroublemakers {
		out := mdText("# " + tc.in)
		if strings.ContainsAny(out, "\n\r"+exRunes(0x2028, 0x2029, 0x85)) {
			t.Errorf("%s: %q holds a line break", tc.name, out)
		}
		if k := mdBlockStart(out); k != "" {
			t.Errorf("%s: %q starts a %s", tc.name, out, k)
		}
	}
}

// TestMDTextFuzz runs the property over strings put together from the
// characters that matter, with a fixed seed so a failure repeats.
func TestMDTextFuzz(t *testing.T) {
	pieces := []string{
		"<", ">", "&", "`", "\"", "\\", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", "!", "|", "~", ":", "=", ".", "$", "^",
		"\n", "\r", "\t", " ", "  ", exRunes(0xa0), exRunes(0x200b), exRunes(0x202e), exRunes(0x2028), "\xff", "\x00", "http://", "www.", "@", "1.", "1)", "```", "---", "![", "](",
		"a", "Z", "9", exRunes(0xe9), exRunes(0x4e2d), exRunes(0x1f600), "&amp;", "&lt;", "<script>", "\n",
	}
	rng := rand.New(rand.NewSource(20261115))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := rng.Intn(12); n >= 0; n-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		in := b.String()
		out := mdText(in)
		mdCheckSafe(t, in, out)
		if k := mdBlockStart(out); k != "" {
			t.Fatalf("mdText(%q) = %q starts a %s", in, out, k)
		}
		if t.Failed() {
			return
		}
	}
}

// TestMDWords: a closed word an agent wrote with underscores reads with spaces,
// and is escaped like any other text.
func TestMDWords(t *testing.T) {
	for in, want := range map[string]string{
		"end_user":           "end user",
		"accepted_by_design": "accepted by design",
		"a_b*c":              `a b\*c`,
		"":                   "",
	} {
		if got := mdWords(in); got != want {
			t.Errorf("mdWords(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMDWriterTablePads: a row shorter than the header is padded, a longer one
// is cut, so a table never breaks.
func TestMDWriterTablePads(t *testing.T) {
	var w mdWriter
	w.table([]string{"A", "B"}, [][]string{{"1"}, {"1", "2", "3"}, {}})
	want := "| A | B |\n| --- | --- |\n| 1 |  |\n| 1 | 2 |\n|  |  |\n\n"
	if w.String() != want {
		t.Errorf("table = %q, want %q", w.String(), want)
	}
}

// exBackslash is one backslash, for tables whose wanted text is easier to read with it
// named.
const exBackslash = "\x5c"
