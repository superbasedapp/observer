package timebucket

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImportsPure pins timebucket as a pure package (CLAUDE.md module
// boundary #1): standard library only, and never database/sql, net/http or
// fsnotify. SQL lives in the callers; this package only renders expressions.
func TestPackageImportsPure(t *testing.T) {
	forbidden := []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify"}
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					t.Errorf("%s imports forbidden %q", f, p)
				}
			}
			if strings.Contains(p, ".") {
				t.Errorf("%s imports non-stdlib %q; timebucket is stdlib-only", f, p)
			}
		}
	}
}
