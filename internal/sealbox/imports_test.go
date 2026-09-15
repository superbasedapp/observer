package sealbox

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoImpureImports pins the package pure: no SQL, HTTP, fsnotify, logging,
// or third-party crypto — the same discipline as internal/routing and
// internal/cachetrack.
func TestNoImpureImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"database/sql", "net/http", "fsnotify", "log/slog", "golang.org/x/crypto", "github.com/"}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.HasPrefix(p, bad) {
					t.Errorf("%s imports %q — sealbox must stay pure stdlib crypto", e.Name(), p)
				}
			}
		}
	}
}
