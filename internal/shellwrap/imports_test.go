package shellwrap

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImports_Bounded pins the module boundary (CLAUDE.md "Module
// Boundaries" #1): shellwrap is PURE. Non-test files must not import
// database/sql, net/http, os, os/exec, path/filepath (it follows the BUILD
// host, not the target OS) or fsnotify, and the only observer package they
// may import is internal/integration (the WrappedCommandFor seam).
func TestPackageImports_Bounded(t *testing.T) {
	forbidden := map[string]bool{
		"database/sql": true, "net/http": true, "os": true, "os/exec": true,
		"path/filepath": true, "github.com/fsnotify/fsnotify": true,
	}
	const allowedInternal = "github.com/marmutapp/superbased-observer/internal/integration"
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(cwd, "*.go"))
	fset := token.NewFileSet()
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if forbidden[p] {
				t.Errorf("%s: forbidden import %q", filepath.Base(path), p)
			}
			if strings.HasPrefix(p, "github.com/marmutapp/superbased-observer/internal/") && p != allowedInternal {
				t.Errorf("%s: forbidden observer import %q", filepath.Base(path), p)
			}
		}
	}
}
