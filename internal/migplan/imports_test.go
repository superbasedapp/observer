package migplan

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestPurePackage pins migplan free of I/O: the runners own SQL and the
// embedded filesystems; this package only decides (CLAUDE.md module rule 1).
func TestPurePackage(t *testing.T) {
	allowed := map[string]bool{"fmt": true, "sort": true, "strconv": true, "strings": true}
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
		f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !allowed[path] {
				t.Errorf("%s imports %q; migplan must stay pure (allowed: fmt, sort, strconv, strings)", name, path)
			}
		}
	}
}
