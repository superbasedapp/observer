package mcpintel

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the P11 purity rule (doc3 §11.12b, R10.12,
// CLAUDE.md module discipline #1) for internal/mcpintel AND every
// subpackage beneath it (walked recursively, so a new subpackage is covered
// with no edit here). A mcpintel package must not reach a database, the
// network, the filesystem watcher, or a store / org-server package: the
// store seams import mcpintel, never the reverse. It must also not reuse
// internal/intelligence/discover, which imports SQL (R10.12).
func TestNoForbiddenImports(t *testing.T) {
	const module = "github.com/marmutapp/superbased-observer/"
	forbidden := []string{
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
		module + "internal/store",
		module + "internal/db",
		module + "internal/orgserver",
		module + "internal/intelligence/discover",
	}
	fset := token.NewFileSet()
	seen := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		af, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		seen++
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					t.Errorf("%s imports forbidden %q - internal/mcpintel/** must stay pure (doc3 §11.12b)", path, p)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if seen == 0 {
		t.Fatal("walked no non-test Go files; the purity pin would be vacuous")
	}
}
