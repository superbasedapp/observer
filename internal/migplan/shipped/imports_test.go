package shipped

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestPurePackage pins shipped free of I/O: the invariant test reads the
// working tree and the generator reads git; this package only decides
// (CLAUDE.md module rule 1).
func TestPurePackage(t *testing.T) {
	allowed := map[string]bool{
		"bytes": true, "crypto/sha1": true, "encoding/hex": true, "encoding/json": true,
		"errors": true, "fmt": true, "sort": true, "strconv": true, "strings": true,
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
		f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !allowed[path] {
				t.Errorf("%s imports %q; shipped must stay pure (no file, git or network access)", name, path)
			}
		}
	}
}
