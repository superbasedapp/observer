package codeintel_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// purePackages are the codeintel subpackages that MUST stay free of
// infrastructure dependencies (CLAUDE.md "Module Boundaries & Anti-
// Spaghetti Discipline" rule 1; plan §3.1). They take bytes / plain
// graph data in and return plain data out; all I/O is injected. The
// I/O-bearing packages (index, surface) and the facade root are
// deliberately EXCLUDED — they are the seams, not the core.
var purePackages = []string{
	"parse",
	"resolve",
	"semantic",
	"analyze",
	"query",
}

// forbiddenImports are the infrastructure packages and sibling
// subsystems a pure codeintel package must never reach for. Logic is
// written against injected interfaces and plain data instead.
var forbiddenImports = []string{
	"database/sql",
	"net/http",
	"github.com/fsnotify/fsnotify",
	"github.com/marmutapp/superbased-observer/internal/store",
	"github.com/marmutapp/superbased-observer/internal/db",
	"github.com/marmutapp/superbased-observer/internal/proxy",
	"github.com/marmutapp/superbased-observer/internal/adapter",
	"github.com/marmutapp/superbased-observer/internal/watcher",
	"github.com/marmutapp/superbased-observer/internal/hook",
	"github.com/marmutapp/superbased-observer/internal/mcp",
	"github.com/marmutapp/superbased-observer/internal/config",
	"github.com/marmutapp/superbased-observer/internal/compression",
}

// TestPureSubpackageImports_Bounded walks every non-test .go file under
// the pure subpackages (recursively, so parse/treesitter, parse/goast,
// parse/heuristic, parse/queries etc. are covered as they land) and
// fails if any reaches for a forbidden import. Mirrors
// internal/routing/imports_test.go. A failure is a design defect — it
// names the file and the offending import.
func TestPureSubpackageImports_Bounded(t *testing.T) {
	t.Parallel()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	fset := token.NewFileSet()
	for _, pkg := range purePackages {
		root := filepath.Join(cwd, pkg)
		if _, statErr := os.Stat(root); statErr != nil {
			continue // package not created yet — nothing to enforce
		}
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
						t.Errorf("%s: forbidden import %q (codeintel pure-core boundary, plan §3.1)", filepath.ToSlash(rel), p)
					}
				}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", root, walkErr)
		}
	}
}
