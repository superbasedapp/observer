package pricewire

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestImportsArePure pins the module boundary (CLAUDE.md "core logic lives in
// a pure package"): the projection is a field copy between two vocabularies
// and imports only the wire contract, the cost engine's types and the
// standard library.
func TestImportsArePure(t *testing.T) {
	allowed := map[string]bool{
		"time": true,
		"github.com/marmutapp/superbased-observer/internal/intelligence/cost": true,
		"github.com/marmutapp/superbased-observer/internal/orgcontract":       true,
		"github.com/marmutapp/superbased-observer/internal/reprice":           true,
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
		file, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if !allowed[path] {
				t.Errorf("%s imports %q: pricewire is a pure projection", f, path)
			}
		}
	}
}
