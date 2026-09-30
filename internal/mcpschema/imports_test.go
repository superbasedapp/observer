package mcpschema

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md
// module rule 1): internal/mcpschema is pure logic over bytes it is handed -
// no database/sql, net/http, fsnotify, and no reuse of internal/guard/mcpsec
// (which it EXTENDS rather than wraps, plan section 11.4).
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
		"github.com/marmutapp/superbased-observer/internal/guard/mcpsec",
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
			for _, bad := range forbidden {
				if path == bad {
					t.Errorf("%s imports forbidden %q", f, bad)
				}
			}
			if strings.HasPrefix(path, "github.com/marmutapp/superbased-observer/") {
				t.Errorf("%s imports %q - mcpschema must stay a leaf", f, path)
			}
		}
	}
}
