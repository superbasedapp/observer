package sarifimport

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPureImports pins the package free of SQL, HTTP, process and
// filesystem access (doc.go).
func TestPureImports(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"database/sql", "net/http", "os/exec", "os", "io/fs", "github.com/fsnotify/fsnotify"}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			for _, b := range banned {
				if p == b {
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
	}
}
