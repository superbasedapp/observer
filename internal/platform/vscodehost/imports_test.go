package vscodehost

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImports_Bounded pins the module-boundary discipline (CLAUDE.md
// "Module Boundaries" #1): vscodehost is PURE — no database/sql, net/http,
// os/exec, or fsnotify, and no dependency on any consumer adapter. Unlike a
// forbidden-list check, this is an ALLOW-list: only path/filepath, runtime,
// os (for os.Getenv("APPDATA") only), strings, and
// internal/platform/crossmount (the HomeRoot type this package resolves
// paths against) may appear in a non-test source file's import block. Any
// other import — stdlib or internal — fails the test, so a future edit that
// reaches for more than this package needs is caught immediately rather
// than drifting into a hot-path dependency.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()

	allowed := map[string]bool{
		"path/filepath": true,
		"runtime":       true,
		"os":            true,
		"strings":       true,
		"github.com/marmutapp/superbased-observer/internal/platform/crossmount": true,
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(cwd, "*.go"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no source files in %s", cwd)
	}

	fset := token.NewFileSet()
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if !allowed[p] {
				t.Errorf("%s: import %q is not in the vscodehost allow-list — this package must stay pure (CLAUDE.md Module Boundaries #1)", filepath.Base(path), p)
			}
		}
	}
}
