package api

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestBoundaryImports pins the module discipline (plan §7 item 7, CLAUDE.md #4):
// the api package is the ONLY HTTP owner but must NOT own SQL — all database
// access goes through internal/cloudserver/store. So api may not import a
// Postgres driver or database/sql directly.
func TestBoundaryImports(t *testing.T) {
	forbidden := map[string]string{
		"database/sql":                    "SQL belongs in internal/cloudserver/store, not api",
		"github.com/jackc/pgx/v5":         "pgx belongs in internal/cloudserver/store, not api",
		"github.com/jackc/pgx/v5/pgxpool": "pgx belongs in internal/cloudserver/store, not api",
	}
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range af.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if why, bad := forbidden[path]; bad {
				t.Errorf("%s imports %q — %s", f, path, why)
			}
		}
	}
}
