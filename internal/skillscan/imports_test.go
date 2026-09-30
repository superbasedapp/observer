package skillscan

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md
// §1, doc.go): internal/skillscan is orchestration over injected
// funcs. All I/O - running the read-only VCS envelope and every store read/write -
// is
// injected via Options, so this package must never import database/sql,
// net/http, fsnotify, os/exec or internal/store.
func TestNoForbiddenImports(t *testing.T) {
	forbiddenExact := []string{
		"database/sql",
		"net/http",
		"os/exec",
		"github.com/fsnotify/fsnotify",
		"github.com/marmutapp/superbased-observer/internal/store",
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
					t.Errorf("%s imports forbidden %q — internal/skillscan must stay I/O-injected", f, bad)
				}
			}
		}
	}
}
