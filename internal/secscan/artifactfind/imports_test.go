package artifactfind

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestPure pins the package free of I/O beyond the injected io/fs.FS: no
// os, no exec, no network, no database, no file watching.
func TestPure(t *testing.T) {
	forbidden := []string{"database/sql", "net", "net/http", "os", "os/exec", "syscall", "path/filepath", "github.com/fsnotify/fsnotify"}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), n, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if p == bad {
					t.Errorf("%s imports %s; artifactfind is pure", n, p)
				}
			}
		}
	}
}
