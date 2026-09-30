package coverage

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the package pure (CLAUDE.md rule 1): no
// database/sql, net/http, fsnotify, os, os/exec, and no observer package
// other than the integration registry (pure data) it derives from.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify", "os", "os/exec"}
	const observer = "github.com/marmutapp/superbased-observer/"
	allowed := map[string]bool{observer + "internal/integration": true}
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
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
				if p == bad {
					t.Errorf("%s imports forbidden %q", f, p)
				}
			}
			if strings.HasPrefix(p, observer) && !allowed[p] {
				t.Errorf("%s imports observer package %q (only internal/integration is allowed)", f, p)
			}
		}
	}
}
