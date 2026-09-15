package orgbudget

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImports_Bounded pins the module boundary (CLAUDE.md #1): the
// composition layer is PURE. No SQL, no HTTP, no fsnotify, no filesystem, no
// process execution — and, among observer packages, ONLY internal/orgcontract
// (the shared wire shape) and internal/govern (the numeric lowering
// primitives). In particular NOT internal/config, internal/store,
// internal/guard or internal/policy: this package must be composable from any
// of them without an import cycle and without dragging the config graph into a
// pure test.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()

	allowedObserver := map[string]bool{
		"github.com/marmutapp/superbased-observer/internal/orgcontract": true,
		"github.com/marmutapp/superbased-observer/internal/govern":      true,
	}
	forbiddenExact := []string{
		"os", "os/exec", "io", "io/ioutil", "path/filepath",
		"net/http", "database/sql", "github.com/fsnotify/fsnotify",
	}
	const observerPrefix = "github.com/marmutapp/superbased-observer/"

	fset := token.NewFileSet()
	for _, path := range nonTestSourceFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(p, observerPrefix) && !allowedObserver[p] {
				t.Errorf("%s: forbidden observer import %q — orgbudget may import only orgcontract + govern",
					filepath.Base(path), p)
			}
			for _, bad := range forbiddenExact {
				if p == bad {
					t.Errorf("%s: forbidden I/O import %q (CLAUDE.md #1 — this package is pure)",
						filepath.Base(path), p)
				}
			}
		}
	}
}

// nonTestSourceFiles lists the package's non-test .go files.
func nonTestSourceFiles(t *testing.T) []string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(cwd, "*.go"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	var out []string
	for _, m := range matches {
		if !strings.HasSuffix(m, "_test.go") {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		t.Fatal("no non-test source files found")
	}
	return out
}
