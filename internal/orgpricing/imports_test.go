package orgpricing

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This package is PURE. The rule is not stylistic: the whole reason it exists
// is that the daemon and a one-shot CLI must reach the SAME answer, and a
// package that could read a database or a clock would be able to reach two.
func TestOrgPricingImportsStayPure(t *testing.T) {
	t.Parallel()
	forbidden := []string{
		"database/sql", "net/http", "os/exec",
		"github.com/fsnotify/fsnotify",
		"github.com/marmutapp/superbased-observer/internal/store",
		"github.com/marmutapp/superbased-observer/internal/orgclient",
		"github.com/marmutapp/superbased-observer/internal/intelligence/cost",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if path == bad {
					t.Errorf("%s imports %q — this package resolves a rule, it does not fetch anything", name, path)
				}
			}
		}
	}
}
