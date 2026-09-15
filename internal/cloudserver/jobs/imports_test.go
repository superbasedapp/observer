package jobs

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestBoundaryImports pins that the jobs package (queue + worker) owns neither
// HTTP nor SQL: it composes the store seam and the queue interface. No net/http,
// no database/sql, no pgx here (plan §7 item 7, CLAUDE.md #2/#4).
func TestBoundaryImports(t *testing.T) {
	forbidden := map[string]string{
		"net/http":                "the worker owns no HTTP surface",
		"database/sql":            "SQL belongs in internal/cloudserver/store",
		"github.com/jackc/pgx/v5": "pgx belongs in internal/cloudserver/store",
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
