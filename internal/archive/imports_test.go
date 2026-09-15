package archive

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md §1):
// internal/archive is pure logic. The SQL for the HOT tables lives in
// internal/store, the SQL for the archive file lives in
// internal/archivestore, and internal/archivesvc composes the two — so this
// package must never import database/sql, net/http, or fsnotify.
//
// It must also not import internal/store or internal/archivestore: the row
// types defined HERE are what both sides speak, and a dependency in either
// direction would let one side's schema types leak across the seam.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
		"github.com/marmutapp/superbased-observer/internal/store",
		"github.com/marmutapp/superbased-observer/internal/archivestore",
		"github.com/marmutapp/superbased-observer/internal/db",
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
					t.Errorf("%s imports forbidden %q — internal/archive must stay pure", f, bad)
				}
			}
		}
	}
}
