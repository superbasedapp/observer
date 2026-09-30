package mcpegress

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the boundary: mcpegress is the egress client
// (net/http by nature) but never a store (database/sql), never fsnotify, and
// never a consumer of the packages that consume IT (internal/mcpgw*,
// internal/orgserver*, internal/aigateway, internal/guard) - the plan's
// mcpegress_boundary_test direction.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{"database/sql", "github.com/fsnotify/fsnotify"}
	forbiddenPrefixes := []string{
		"github.com/marmutapp/superbased-observer/internal/mcpgw",
		"github.com/marmutapp/superbased-observer/internal/orgserver",
		"github.com/marmutapp/superbased-observer/internal/aigateway",
		"github.com/marmutapp/superbased-observer/internal/guard",
		"github.com/marmutapp/superbased-observer/internal/store",
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
			for _, p := range forbiddenPrefixes {
				if strings.HasPrefix(path, p) {
					t.Errorf("%s imports %q - mcpegress must not depend on its consumers", f, path)
				}
			}
		}
	}
}
