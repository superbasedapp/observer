package taskreport

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md
// §1): internal/taskreport is a cost/report BUILDER, not an I/O layer —
// all SQL lives in internal/store, all HTTP lives in
// internal/intelligence/dashboard, and nothing here watches files.
// Unlike internal/predict/internal/cachetrack's stricter cost-free
// pins, this package DELIBERATELY imports internal/intelligence/cost
// (its whole reason to exist — see doc.go) so that import is not
// forbidden here.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
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
					t.Errorf("%s imports forbidden %q — internal/taskreport must stay a pure builder over internal/store's I/O", f, bad)
				}
			}
		}
	}
}
