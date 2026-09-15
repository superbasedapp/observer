package routeattest_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenImports are the infrastructure packages routeattest must never
// reach for (CLAUDE.md "Module Boundaries & Anti-Spaghetti Discipline" rule
// 1; design §3.3: routeattest is pure logic — I/O is injected via
// TrafficSource, and the config-lane file reads live in
// internal/proxyroute, called through it as plain function values).
// Mirrors internal/routing/imports_test.go and internal/codeintel's
// imports_test.go.
var forbiddenImports = []string{
	"database/sql",
	"net/http",
	"github.com/fsnotify/fsnotify",
	"github.com/marmutapp/superbased-observer/internal/store",
	"github.com/marmutapp/superbased-observer/internal/db",
	"github.com/marmutapp/superbased-observer/internal/proxy",
	"github.com/marmutapp/superbased-observer/internal/watcher",
	"github.com/marmutapp/superbased-observer/internal/adapter",
}

// TestPackageImports_Bounded walks every non-test .go file in
// internal/routeattest and fails if any reaches for a forbidden import.
// Failing this test is a design defect — the failure names the file and
// the offending import.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(cwd, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbiddenImports {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					rel, _ := filepath.Rel(cwd, path)
					t.Errorf("%s: forbidden import %q (internal/routeattest must stay pure — see doc.go)", filepath.ToSlash(rel), p)
				}
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", cwd, walkErr)
	}
}
