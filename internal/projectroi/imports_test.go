package projectroi

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md
// §1, spec §24.1, doc.go): internal/projectroi is pure logic. All I/O —
// loading prompts/edits/commits/turns/tasks/sessions and running git —
// is done by callers (internal/store/projectroi.go, internal/commitlog,
// the dashboard handler), so this package must never import
// database/sql, net/http, os/exec, fsnotify, internal/store or
// internal/commitlog.
func TestNoForbiddenImports(t *testing.T) {
	forbiddenExact := []string{
		"database/sql",
		"net/http",
		"os/exec",
		"github.com/fsnotify/fsnotify",
		"github.com/marmutapp/superbased-observer/internal/store",
		"github.com/marmutapp/superbased-observer/internal/commitlog",
	}
	forbiddenPrefix := []string{
		"github.com/marmutapp/superbased-observer/internal/adapter/",
		"modernc.org/sqlite",
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
			for _, bad := range forbiddenExact {
				if path == bad {
					t.Errorf("%s imports forbidden %q — internal/projectroi must stay pure", f, bad)
				}
			}
			for _, bad := range forbiddenPrefix {
				if strings.HasPrefix(path, bad) {
					t.Errorf("%s imports forbidden %q — internal/projectroi must stay pure", f, bad)
				}
			}
		}
	}
}
