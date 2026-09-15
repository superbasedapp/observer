package loc

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md
// §1, spec §24.1, doc.go): internal/loc is pure logic. All I/O is
// injected by its callers — the store seam (internal/store/loc.go) for
// live ingest and backfill, the dashboard/CLI for reads — so this package
// must never import database/sql, net/http, fsnotify, internal/store or
// any adapter. internal/codeintel is forbidden too: loc deliberately owns
// its OWN language table and denylist (plan §1, §3.1) and must not drift
// back onto codeintel's, which drops testdata/bin/build/target and has no
// docs or config bucket.
func TestNoForbiddenImports(t *testing.T) {
	forbiddenExact := []string{
		"database/sql",
		"net/http",
		"os/exec",
		"github.com/fsnotify/fsnotify",
		"github.com/marmutapp/superbased-observer/internal/store",
		"github.com/marmutapp/superbased-observer/internal/models",
	}
	forbiddenPrefix := []string{
		"github.com/marmutapp/superbased-observer/internal/adapter/",
		"github.com/marmutapp/superbased-observer/internal/codeintel",
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
					t.Errorf("%s imports forbidden %q — internal/loc must stay pure", f, bad)
				}
			}
			for _, bad := range forbiddenPrefix {
				if strings.HasPrefix(path, bad) {
					t.Errorf("%s imports forbidden %q — internal/loc must stay pure", f, bad)
				}
			}
		}
	}
}
