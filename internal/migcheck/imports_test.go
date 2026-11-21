package migcheck

import (
	"go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestPurePackage pins migcheck free of I/O: tools/migcheck reads the
// migration directories and the shipped record; this package only decides
// (CLAUDE.md module rule 1).
func TestPurePackage(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"errors": true, "fmt": true, "sort": true, "strings": true, "unicode/utf8": true,
		// shipped is pure too: the record's types and its step-name rule.
		"github.com/marmutapp/superbased-observer/internal/migplan/shipped": true,
	}
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
				t.Errorf("%s imports %q; migcheck must stay pure (no file, database or network access)", name, path)
			}
		}
	}
}
