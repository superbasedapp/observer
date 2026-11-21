package codequality

import (
	"errors"
	"testing"
)

// Synthetic fixtures: no real project's report, no local path.

const goProfile = `mode: set
example.com/app/a.go:3.10,5.2 2 1
example.com/app/a.go:6.10,8.2 1 0
example.com/app/a.go:8.2,9.3 1 1
example.com/app/b.go:1.1,1.20 0 0
example.com/app/b.go:2.1,3.5 1 0
not a block line
`

const lcovInfo = `TN:
SF:src/a.ts
DA:1,1
DA:2,0
DA:3,5
LF:3
LH:2
end_of_record
SF:src/b.ts
LF:10
LH:4
end_of_record
SF:src/a.ts
DA:2,1
DA:4,0
DA:x,1
end_of_record
`

const coberturaXML = `<?xml version="1.0" ?>
<!DOCTYPE coverage SYSTEM "http://cobertura.sourceforge.net/xml/coverage-04.dtd">
<coverage line-rate="0.5" lines-valid="4" lines-covered="2">
 <sources><source>/src</source></sources>
 <packages><package name="pkg"><classes>
  <class name="A" filename="pkg/a.py">
   <methods><method name="f"><lines><line number="1" hits="1"/><line number="2" hits="0"/></lines></method></methods>
   <lines><line number="1" hits="1"/><line number="2" hits="0"/><line number="3" hits="2"/></lines>
  </class>
  <class name="A2" filename="pkg/a.py">
   <lines><line number="2" hits="3"/><line number="9" hits="0"/></lines>
  </class>
 </classes></package></packages>
</coverage>`

const coberturaTotalsOnly = `<coverage lines-valid="40" lines-covered="10"><packages/></coverage>`

const jacocoXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
<report name="app">
 <package name="com/example">
  <class name="com/example/A" sourcefilename="A.java"><counter type="LINE" missed="1" covered="2"/></class>
  <sourcefile name="A.java">
   <line nr="3" mi="0" ci="2" mb="0" cb="0"/>
   <line nr="4" mi="1" ci="0" mb="0" cb="0"/>
   <line nr="5" mi="0" ci="0" mb="0" cb="0"/>
   <line nr="6" mi="1" ci="1" mb="0" cb="0"/>
   <counter type="LINE" missed="1" covered="2"/>
  </sourcefile>
 </package>
 <counter type="LINE" missed="1" covered="2"/>
</report>`

const jacocoTotalsOnly = `<report name="x"><counter type="INSTRUCTION" missed="9" covered="9"/><counter type="LINE" missed="3" covered="7"/></report>`

func TestSniff(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Format
		ok   bool
	}{
		{"go set", goProfile, FormatGoCover, true},
		{"go atomic", "mode: atomic\n", FormatGoCover, true},
		{"lcov TN", lcovInfo, FormatLCOV, true},
		{"lcov SF first", "SF:a.c\nDA:1,1\nend_of_record\n", FormatLCOV, true},
		{"bom + whitespace", "\xef\xbb\xbf\n\nTN:\nSF:a\n", FormatLCOV, true},
		{"cobertura", coberturaXML, FormatCobertura, true},
		{"jacoco", jacocoXML, FormatJaCoCo, true},
		{"other xml", "<project><x/></project>", "", false},
		{"text", "hello world\n", "", false},
		{"mode other", "mode: fast\n", "", false},
		{"empty", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := Sniff([]byte(c.in))
			if got != c.want || ok != c.ok {
				t.Fatalf("Sniff = %q, %v; want %q, %v", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestParseCoverage(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		format     Format
		lines      int
		covered    int
		files      int
		totalsOnly bool
		skipped    int
		err        error
	}{
		// a.go lines 3-9 instrumented (3,4,5 covered; 6,7 not; 8 covered by
		// the third block; 9 covered); b.go 2-3 not covered, line 1 has no
		// statements.
		{name: "go profile folds blocks by line", in: goProfile, format: FormatGoCover, lines: 9, covered: 5, files: 2, skipped: 1},
		// a.ts: lines 1,2,3,4 (2 covered in the second record); b.ts LF/LH only.
		{name: "lcov merges records and uses LF/LH without DA", in: lcovInfo, format: FormatLCOV, lines: 14, covered: 7, files: 2, skipped: 1},
		// a.py: class lines 1,2,3 + second class 2,9; method lines ignored.
		{name: "cobertura counts class lines only", in: coberturaXML, format: FormatCobertura, lines: 4, covered: 3, files: 1},
		{name: "cobertura totals fallback", in: coberturaTotalsOnly, format: FormatCobertura, lines: 40, covered: 10, totalsOnly: true},
		// line 5 has no instructions (mi=ci=0) and is not instrumented.
		{name: "jacoco sourcefile lines", in: jacocoXML, format: FormatJaCoCo, lines: 3, covered: 2, files: 1},
		{name: "jacoco totals fallback", in: jacocoTotalsOnly, format: FormatJaCoCo, lines: 10, covered: 7, totalsOnly: true},
		{name: "unrecognized", in: "plain text", err: ErrUnrecognized},
		{name: "go profile with no blocks", in: "mode: set\n", err: ErrNoLines},
		{name: "lcov with no records", in: "TN:\n", err: ErrNoLines},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := ParseCoverage([]byte(c.in))
			if c.err != nil {
				if !errors.Is(err, c.err) {
					t.Fatalf("err = %v, want %v", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCoverage: %v", err)
			}
			if r.Format != c.format || r.Lines != c.lines || r.Covered != c.covered || len(r.Files) != c.files || r.TotalsOnly != c.totalsOnly || r.Skipped != c.skipped {
				t.Fatalf("got %+v; want format=%s lines=%d covered=%d files=%d totalsOnly=%v skipped=%d",
					r, c.format, c.lines, c.covered, c.files, c.totalsOnly, c.skipped)
			}
		})
	}
}

func TestParseJaCoCoPathJoinsPackage(t *testing.T) {
	r, err := ParseCoverage([]byte(jacocoXML))
	if err != nil {
		t.Fatal(err)
	}
	if r.Files[0].Path != "com/example/A.java" {
		t.Fatalf("path = %q", r.Files[0].Path)
	}
}

func TestParseCoberturaMalformedXML(t *testing.T) {
	_, err := ParseCoverage([]byte(`<coverage><packages><class filename="a"><lines><line number="1" hits="1">`))
	if err == nil {
		t.Fatal("want a parse error for truncated XML")
	}
}

func TestParseGoCoverRejectsHugeSpan(t *testing.T) {
	r, err := ParseCoverage([]byte("mode: set\na.go:1.1,999999.1 1 1\nb.go:1.1,2.1 1 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Lines != 2 || r.Skipped != 1 {
		t.Fatalf("got %+v", r)
	}
}
