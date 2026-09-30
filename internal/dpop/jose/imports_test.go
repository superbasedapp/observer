package jose

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the purity discipline (doc3 §2.1/§2.2,
// CLAUDE.md module boundaries): internal/dpop/jose is stdlib-only and a leaf.
func TestNoForbiddenImports(t *testing.T) {
	const modulePrefix = "github.com/marmutapp/superbased-observer/"
	forbidden := map[string]bool{
		"database/sql":                 true,
		"net/http":                     true,
		"net":                          true,
		"os":                           true,
		"os/exec":                      true,
		"io/fs":                        true,
		"github.com/fsnotify/fsnotify": true,
	}
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if forbidden[p] {
				t.Errorf("%s imports forbidden %q - jose must stay pure", f, p)
			}
			if strings.HasPrefix(p, modulePrefix) {
				t.Errorf("%s imports module package %q - jose must be stdlib-only", f, p)
			}
			if strings.Contains(p, ".") && !strings.HasPrefix(p, modulePrefix) {
				t.Errorf("%s imports third-party %q - jose must be stdlib-only", f, p)
			}
		}
	}
}
