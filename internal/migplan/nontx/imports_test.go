package nontx

import (
	"go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestPurePackage pins nontx free of I/O: the runner owns the SQL driver and
// every query; this package only decides (CLAUDE.md module rule 1).
func TestPurePackage(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{"fmt": true, "strings": true, "time": true, "unicode/utf8": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(gotoken.NewFileSet(), name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !allowed[path] {
				t.Errorf("%s imports %q; nontx must stay pure (allowed: fmt, strings, time, unicode/utf8)", name, path)
			}
		}
	}
}
