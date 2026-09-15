package loc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// classSymbols renders a []LineClass as the compact per-line alphabet the
// golden corpus uses: 'c' code, '#' comment, '_' blank, '?' unknown.
func classSymbols(classes []LineClass) string {
	var b strings.Builder
	for _, c := range classes {
		switch c {
		case ClassCode:
			b.WriteByte('c')
		case ClassComment:
			b.WriteByte('#')
		case ClassBlank:
			b.WriteByte('_')
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

// TestClassifyLines is the row-per-case table for the line lexer.
func TestClassifyLines(t *testing.T) {
	cases := []struct {
		name string
		lang Lang
		text string
		want string
		conf Confidence
	}{
		// --- shape of the input -------------------------------------
		{"empty text", LangGo, "", "", ConfidenceHigh},
		{"single newline is one blank line", LangGo, "\n", "_", ConfidenceHigh},
		{"trailing newline adds no line", LangGo, "package main\n", "c", ConfidenceHigh},
		{"no trailing newline", LangGo, "package main", "c", ConfidenceHigh},
		{"crlf is tolerated", LangGo, "package main\r\n\r\n// c\r\n", "c_#", ConfidenceHigh},
		{"whitespace only line is blank", LangGo, "a := 1\n   \t \nb := 2\n", "c_c", ConfidenceHigh},

		// --- comment basics ------------------------------------------
		{"line comment alone", LangGo, "// hello\n", "#", ConfidenceHigh},
		{"line comment after code is code", LangGo, "x := 1 // hello\n", "c", ConfidenceHigh},
		{"block on one line alone", LangGo, "/* hello */\n", "#", ConfidenceHigh},
		{"block on one line after code", LangGo, "x := 1 /* hi */\n", "c", ConfidenceHigh},
		{"block opened after code is code", LangGo, "x := 1 /* hi\nstill\n*/\n", "c##", ConfidenceHigh},
		{"blank line inside block is comment", LangGo, "/* a\n\nb */\n", "###", ConfidenceHigh},
		{"code after block close on same line", LangGo, "/* a */ x := 1\n", "c", ConfidenceHigh},

		// --- strings shield comment tokens ---------------------------
		{"hash in python string", LangPython, "s = \"# not a comment\"\n", "c", ConfidenceHigh},
		{"hash in shell string", LangShell, "echo \"# nope\"\n", "c", ConfidenceHigh},
		{"slashes in js string", LangJavaScript, "const u = \"https://x\";\n", "c", ConfidenceHigh},
		{"dashes in sql string", LangSQL, "SELECT '-- nope';\n", "c", ConfidenceHigh},
		{"escaped quote inside string", LangGo, "s := \"a\\\" // b\"\n", "c", ConfidenceHigh},

		// --- language specifics --------------------------------------
		{"c preprocessor is code", LangC, "#include <stdio.h>\n#define X 1\n#if A\n#pragma once\n", "cccc", ConfidenceHigh},
		{"cpp preprocessor is code", LangCPP, "#include <vector>\n", "c", ConfidenceHigh},
		{"csharp preprocessor is code", LangCSharp, "#region A\n", "c", ConfidenceHigh},
		{"sql line comment", LangSQL, "-- hi\nSELECT 1;\n", "#c", ConfidenceHigh},
		{"sql block comment", LangSQL, "/* a\nb */\nSELECT 1;\n", "##c", ConfidenceHigh},
		{"markdown hash is a heading not a comment", LangMarkdown, "# Title\n", "c", ConfidenceHigh},
		{"html comment", LangHTML, "<!-- a\nb -->\n<p>x</p>\n", "##c", ConfidenceHigh},
		{"jsx brace comment", LangJSX, "  {/* hi */}\n", "#", ConfidenceHigh},
		{"lua block comment", LangLua, "--[[ a\nb ]]\nprint(1)\n", "##c", ConfidenceHigh},
		{"lua nested index is not a stray close", LangLua, "local x = t[t[1]]\n", "c", ConfidenceHigh},
		{"ruby anchored block comment", LangRuby, "=begin\nbody\n=end\nx = 1\n", "###c", ConfidenceHigh},
		{"haskell block comment", LangHaskell, "{- a\nb -}\nmain = pure ()\n", "##c", ConfidenceHigh},
		{"vb apostrophe comment", LangVB, "' hi\nDim x\n", "#c", ConfidenceHigh},
		{"vb REM is anchored and case-insensitive", LangVB, "rem hi\nDim x\n", "#c", ConfidenceHigh},

		// --- python docstring convention -----------------------------
		{"bare docstring one line is comment", LangPython, "\"\"\"Doc.\"\"\"\n", "#", ConfidenceHigh},
		{"bare docstring multi line is comment", LangPython, "\"\"\"Doc\nmore\n\"\"\"\nx = 1\n", "###c", ConfidenceHigh},
		{"assigned triple string is code", LangPython, "s = \"\"\"Doc\nmore\n\"\"\"\n", "ccc", ConfidenceHigh},
		{"indented docstring", LangPython, "def f():\n    \"\"\"Doc.\"\"\"\n    return 1\n", "c#c", ConfidenceHigh},

		// --- multi-line strings --------------------------------------
		{"go raw string spans lines", LangGo, "s := `a\n// not a comment\nb`\nx := 1\n", "cccc", ConfidenceHigh},
		{"js template literal spans lines", LangJavaScript, "const s = `a\n// nope\nb`;\n", "ccc", ConfidenceHigh},

		// --- heredocs -------------------------------------------------
		{"shell heredoc body is code", LangShell, "cat <<EOF\n# data\nEOF\necho ok\n", "cccc", ConfidenceHigh},
		{"shell quoted heredoc", LangShell, "cat <<'EOF'\n# data\nEOF\n", "ccc", ConfidenceHigh},
		{"shell dash heredoc allows indent", LangShell, "cat <<-EOF\n\t# data\n\tEOF\necho ok\n", "cccc", ConfidenceHigh},
		{"ruby squiggly heredoc", LangRuby, "t = <<~TXT\n  # data\nTXT\nputs t\n", "cccc", ConfidenceHigh},
		{"ruby append operator is not a heredoc", LangRuby, "arr << item\n# real comment\n", "c#", ConfidenceHigh},
		{"shell shift is not a heredoc", LangShell, "n=$((1 << k))\n# real comment\n", "c#", ConfidenceHigh},
		{"php heredoc", LangPHP, "$t = <<<EOT\n# data\nEOT;\necho 1;\n", "cccc", ConfidenceHigh},

		// --- fragment boundaries -------------------------------------
		{"unterminated block", LangGo, "x := 1\n/* open\nmore\n", "c??", ConfidenceMedium},
		{"unterminated block after code on the same line", LangGo, "x := 1 /* open\nmore\n", "??", ConfidenceMedium},
		{"stray close retro-unknowns the prefix", LangGo, "still comment\n*/\nx := 1\n", "??c", ConfidenceMedium},
		{"unterminated raw string", LangGo, "s := `a\nb\n", "??", ConfidenceMedium},
		{"unterminated template literal", LangTypeScript, "const s = `a\nb\n", "??", ConfidenceMedium},
		{"unterminated docstring", LangPython, "\"\"\"Doc\nmore\n", "??", ConfidenceMedium},
		{"blank line inside an unresolved block is unknown not blank", LangGo, "/* open\n\nmore\n", "???", ConfidenceMedium},

		// --- unknown language ----------------------------------------
		{"unknown language", LangUnknown, "x := 1\n\ny := 2\n", "?_?", ConfidenceLow},
		{"unknown language empty", LangUnknown, "", "", ConfidenceHigh},
		{"text has a table and stays high", LangText, "hello\n\nworld\n", "c_c", ConfidenceHigh},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, conf := ClassifyLines(tc.lang, tc.text)
			if s := classSymbols(got); s != tc.want {
				t.Errorf("ClassifyLines(%q, %q) classes = %q, want %q", tc.lang, tc.text, s, tc.want)
			}
			if conf != tc.conf {
				t.Errorf("ClassifyLines(%q, %q) confidence = %q, want %q", tc.lang, tc.text, conf, tc.conf)
			}
		})
	}
}

// TestClassifyLinesLineCount pins that the returned slice always has one
// entry per split line.
func TestClassifyLinesLineCount(t *testing.T) {
	cases := []struct {
		name string
		text string
		want int
	}{
		{"empty", "", 0},
		{"one line no newline", "a", 1},
		{"one line with newline", "a\n", 1},
		{"two lines", "a\nb", 2},
		{"two lines trailing newline", "a\nb\n", 2},
		{"blank at end", "a\n\n", 2},
		{"crlf", "a\r\nb\r\n", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := ClassifyLines(LangGo, tc.text)
			if len(got) != tc.want {
				t.Errorf("len(ClassifyLines(LangGo, %q)) = %d, want %d", tc.text, len(got), tc.want)
			}
		})
	}
}

// corpusLangs maps a golden fixture's filename stem to the language it is
// classified with. Fragment fixtures under testdata/lang/fragments carry
// a sibling `.lang` file instead, because their names describe the
// boundary case rather than a language.
var corpusLangs = map[string]Lang{
	"go":         LangGo,
	"python":     LangPython,
	"javascript": LangJavaScript,
	"typescript": LangTypeScript,
	"ruby":       LangRuby,
	"shell":      LangShell,
	"sql":        LangSQL,
	"html":       LangHTML,
	"css":        LangCSS,
	"yaml":       LangYAML,
	"json":       LangJSON,
	"markdown":   LangMarkdown,
	"lua":        LangLua,
	"c":          LangC,
	"rust":       LangRust,
	"php":        LangPHP,
	"haskell":    LangHaskell,
}

// TestClassifyGoldenCorpus walks internal/loc/testdata/lang and checks
// every fixture against its expected classification.
//
// Corpus format. Each `<name>.txt` is a synthetic fixture (never real
// user content, never a real path). Its sibling `<name>.expected` holds
// ONE character per fixture line, all on a single line, in the alphabet
//
//	c = code   # = comment   _ = blank   ? = unknown
//
// Every language fixture carries at least a line comment, a block comment
// where the language has one, a comment-looking token inside a string, a
// blank line and real code. Fixtures under `fragments/` cover the
// boundary rules and carry a sibling `<name>.lang` naming the language;
// they are additionally required to report ConfidenceMedium unless the
// fixture is `crlf`, which must resolve cleanly at ConfidenceHigh.
func TestClassifyGoldenCorpus(t *testing.T) {
	root := filepath.Join("testdata", "lang")

	t.Run("languages", func(t *testing.T) {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("read corpus dir: %v", err)
		}
		seen := 0
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
				continue
			}
			stem := strings.TrimSuffix(e.Name(), ".txt")
			lang, ok := corpusLangs[stem]
			if !ok {
				t.Errorf("corpus fixture %q has no entry in corpusLangs", e.Name())
				continue
			}
			seen++
			t.Run(stem, func(t *testing.T) {
				checkFixture(t, filepath.Join(root, stem), lang, ConfidenceHigh)
			})
		}
		if seen != len(corpusLangs) {
			t.Errorf("classified %d language fixtures, corpusLangs declares %d", seen, len(corpusLangs))
		}
	})

	t.Run("fragments", func(t *testing.T) {
		fragDir := filepath.Join(root, "fragments")
		entries, err := os.ReadDir(fragDir)
		if err != nil {
			t.Fatalf("read fragments dir: %v", err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
				continue
			}
			stem := strings.TrimSuffix(e.Name(), ".txt")
			base := filepath.Join(fragDir, stem)
			raw, err := os.ReadFile(base + ".lang")
			if err != nil {
				t.Errorf("fragment %q has no .lang marker: %v", stem, err)
				continue
			}
			lang := Lang(strings.TrimSpace(string(raw)))
			want := ConfidenceMedium
			if stem == "crlf" {
				want = ConfidenceHigh
				// The fixture only exercises CRLF handling if git kept the
				// bytes intact (.gitattributes pins testdata/** -text).
				body, err := os.ReadFile(base + ".txt")
				if err != nil || !strings.Contains(string(body), "\r\n") {
					t.Fatalf("crlf fixture lost its CRLF line endings (git normalization?): err=%v", err)
				}
			}
			t.Run(stem, func(t *testing.T) {
				checkFixture(t, base, lang, want)
			})
		}
	})
}

// checkFixture classifies base+".txt" and diffs it against
// base+".expected", reporting the first differing line with its text.
func checkFixture(t *testing.T, base string, lang Lang, wantConf Confidence) {
	t.Helper()
	src, err := os.ReadFile(base + ".txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	expRaw, err := os.ReadFile(base + ".expected")
	if err != nil {
		t.Fatalf("read expectation: %v", err)
	}
	want := strings.TrimSpace(string(expRaw))

	classes, conf := ClassifyLines(lang, string(src))
	got := classSymbols(classes)
	lines := strings.Split(strings.TrimSuffix(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n"), "\n")

	if len(want) != len(classes) {
		t.Fatalf("%s: expectation has %d symbols but the fixture has %d lines\n got: %s\nwant: %s",
			base, len(want), len(classes), got, want)
	}
	for i := range classes {
		if got[i] != want[i] {
			t.Errorf("%s line %d: got %c, want %c\n  | %s", base, i+1, got[i], want[i], lines[i])
		}
	}
	if conf != wantConf {
		t.Errorf("%s: confidence = %q, want %q", base, conf, wantConf)
	}
}
