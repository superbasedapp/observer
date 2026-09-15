package taskflow

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md
// §1): internal/taskflow is pure logic. It must not import
// database/sql, net/http, fsnotify, or the cost engine — I/O and cost
// pricing are injected at the store seam (internal/store/taskflow.go)
// and the phase-2 dashboard consumer, never here. Mirrors
// internal/predict/imports_test.go.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		"database/sql",
		"net/http",
		"os",
		"os/exec",
		"github.com/fsnotify/fsnotify",
		"github.com/marmutapp/superbased-observer/internal/intelligence/cost",
	}
	fset := token.NewFileSet()
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range af.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if path == bad {
					t.Errorf("%s imports forbidden %q — internal/taskflow must stay pure", f, bad)
				}
			}
		}
	}
}
