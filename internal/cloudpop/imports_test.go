package cloudpop

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the purity discipline (plan §6 CI-P2, CLAUDE.md
// §1): internal/cloudpop is stdlib-only. It may import NO other package in this
// module and none of the dangerous I/O surfaces below. Both sides of the wire
// depend on this package, so it must stay a leaf.
func TestNoForbiddenImports(t *testing.T) {
	const modulePrefix = "github.com/marmutapp/superbased-observer/"
	forbidden := map[string]bool{
		"database/sql":                 true,
		"net/http":                     true,
		"net":                          true,
		"os":                           true,
		"io/fs":                        true,
		"os/exec":                      true,
		"github.com/fsnotify/fsnotify": true,
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
			if forbidden[path] {
				t.Errorf("%s imports forbidden %q — cloudpop must stay pure", f, path)
			}
			if strings.HasPrefix(path, modulePrefix) {
				t.Errorf("%s imports internal package %q — cloudpop must be stdlib-only", f, path)
			}
		}
	}
}
