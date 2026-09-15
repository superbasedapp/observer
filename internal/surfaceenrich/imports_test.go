package surfaceenrich

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImports_Bounded pins the module-boundary discipline
// (CLAUDE.md "Module Boundaries" #1): surfaceenrich imports no
// database/sql, net/http, os/exec or fsnotify and no adapter/store
// package — both store seams and the filesystem are injected funcs.
// ALLOW-list: the stdlib it needs plus models and the two platform
// helpers.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()

	allowed := map[string]bool{
		"context":       true,
		"log/slog":      true,
		"os":            true,
		"path/filepath": true,
		"strings":       true,
		"sync":          true,
		"time":          true,
		"github.com/marmutapp/superbased-observer/internal/models":                 true,
		"github.com/marmutapp/superbased-observer/internal/platform/crossmount":    true,
		"github.com/marmutapp/superbased-observer/internal/platform/jetbrainshost": true,
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
				t.Errorf("%s: import %q is not in the surfaceenrich allow-list — inject it (CLAUDE.md Module Boundaries #1)", filepath.Base(path), p)
			}
		}
	}
}
