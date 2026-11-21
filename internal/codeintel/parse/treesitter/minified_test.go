package treesitter

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
)

// minifiedBundle generates a single-line JavaScript file of about n bytes
// shaped like a minified vendor bundle: one IIFE holding thousands of small
// functions, each with a call, and no newline anywhere.
func minifiedBundle(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`!function(){"use strict";`)
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "function f%d(e){return g%d(e,function(){return e})}", i, i)
	}
	b.WriteString("}();")
	return b.Bytes()
}

// TestMinifiedBundleParseIsBounded is the ADR-0010 regression. Every
// definition and call excerpt used to copy the rest of its source line
// before clipping it to maxExcerpt, and the clipped string kept that copy
// alive. On a minified bundle (one 800 KB line, tens of thousands of
// records) a single parse allocated and kept gigabytes: the litemall
// tinymce.min.js (834 KB) took 9.7 GB and 51 s. The excerpts now copy at
// most maxExcerpt bytes each.
func TestMinifiedBundleParseIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("parses an 800 KB file")
	}
	p, warnings := New()
	if len(warnings) != 0 {
		t.Fatalf("New warnings: %v", warnings)
	}
	src := minifiedBundle(800 << 10)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	res, err := p.Parse(context.Background(), src, parse.LangJavaScript, "bundle.min.js")
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	records := len(res.Nodes) + len(res.Calls) + len(res.Imports)
	if len(res.Nodes) < 10000 || len(res.Calls) < 10000 {
		t.Fatalf("expected a record-dense parse, got %d nodes / %d calls", len(res.Nodes), len(res.Calls))
	}
	// Go-heap bytes allocated by the parse. Before the fix this was
	// records x (average rest-of-line length), about 40 GB here. Now it is
	// about 250 MiB, almost all of it wazero growing the guest's linear
	// memory and its JIT pools; the bound leaves headroom for a wazero
	// upgrade.
	alloc := after.TotalAlloc - before.TotalAlloc
	const limit = 512 << 20
	t.Logf("%d bytes, %d records, %d MiB allocated", len(src), records, alloc>>20)
	if alloc > limit {
		t.Fatalf("parse of a %d-byte single-line file allocated %d MiB (limit %d MiB)", len(src), alloc>>20, limit>>20)
	}
	for _, n := range res.Nodes {
		if len(n.Signature) > maxExcerpt {
			t.Fatalf("signature of %q is %d bytes, over maxExcerpt", n.Name, len(n.Signature))
		}
	}
	for _, c := range res.Calls {
		if len(c.RawText) > maxExcerpt {
			t.Fatalf("call %q raw text is %d bytes, over maxExcerpt", c.Name, len(c.RawText))
		}
	}
}

// oldExcerpt is the pre-ADR-0010 firstLineExcerpt, kept as the oracle for
// the bounded version on ordinary lines.
func oldExcerpt(src []byte, start int) string {
	end := start
	for end < len(src) && src[end] != '\n' {
		end++
	}
	return string(clipBytes([]byte(strings.TrimSpace(string(src[start:end]))), maxExcerpt))
}

// oldFullLine is the pre-ADR-0010 fullLineExcerpt oracle.
func oldFullLine(src []byte, off int) string {
	start := off
	for start > 0 && src[start-1] != '\n' {
		start--
	}
	return oldExcerpt(src, start)
}

func TestExcerptsMatchUnboundedOnOrdinaryLines(t *testing.T) {
	long := strings.Repeat("x", 3*maxExcerpt)
	cases := []struct {
		name string
		src  string
		off  int
	}{
		{"short line", "def f(a, b):\n    return a\n", 0},
		{"indented", "class A:\n    def m(self):  \n", 9},
		{"last line no newline", "fn main() { run() }", 3},
		{"crlf", "func F() {\r\n}\r\n", 0},
		{"exactly max", strings.Repeat("y", maxExcerpt) + "\n", 0},
		{"over max", long + "\nnext\n", 0},
		{"multibyte at cut", strings.Repeat("a", maxExcerpt-1) + "é tail\n", 0},
		{"long mid line", "import x from 'y'; " + long + "\n", 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := []byte(tc.src)
			if got, want := firstLineExcerpt(src, tc.off), oldExcerpt(src, tc.off); got != want {
				t.Fatalf("firstLineExcerpt = %q, want %q", got, want)
			}
			if got, want := fullLineExcerpt(src, tc.off), oldFullLine(src, tc.off); got != want {
				t.Fatalf("fullLineExcerpt = %q, want %q", got, want)
			}
		})
	}
}

// TestFullLineExcerptOnAVeryLongLineKeepsThePath covers the one place the
// bounded scan differs: an import deep inside a line longer than the scan
// window. The old excerpt was the first maxExcerpt bytes of the LINE (for a
// minified file, the top of the file) and did not contain the import at all.
func TestFullLineExcerptOnAVeryLongLineKeepsThePath(t *testing.T) {
	prefix := strings.Repeat("var a=1;", excerptScan)
	src := []byte(prefix + `import {x,y} from "./dep.js";var b=2;`)
	off := len(prefix) + len(`import {x,y} from `)
	got := fullLineExcerpt(src, off)
	if !strings.Contains(got, `"./dep.js"`) || !strings.Contains(got, "import {x,y}") {
		t.Fatalf("excerpt %q lost the import statement", got)
	}
	if len(got) > maxExcerpt {
		t.Fatalf("excerpt is %d bytes, over maxExcerpt", len(got))
	}
}
