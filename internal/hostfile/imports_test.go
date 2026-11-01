package hostfile

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestNoNetworkOrDatabase: the editor is file I/O only.
func TestNoNetworkOrDatabase(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "database/sql" || p == "net/http" || p == "os/exec" || strings.Contains(p, "fsnotify") {
				t.Errorf("%s imports %s", e.Name(), p)
			}
		}
	}
}
