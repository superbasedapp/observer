package commitlog

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md
// §1, doc.go): internal/commitlog is pure logic over already-fetched git
// output. All I/O — the git exec itself, and every store read/write — is
// injected by its callers (internal/commitscan, internal/store), so this
// package must never import database/sql, net/http, fsnotify, os/exec or
// internal/store.
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
					t.Errorf("%s imports forbidden %q — internal/commitlog must stay pure", f, bad)
				}
			}
		}
	}
}
