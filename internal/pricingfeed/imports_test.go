package pricingfeed

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md §1 /
// the plan's Wave 0 gate): internal/pricingfeed is the PURE shared contract.
// It must not import database/sql (the node cache + org bookkeeping live in the
// Wave N/O store seams), net/http (the opt-in fetch lane lives behind the Wave
// N egress seam, pinned separately by tests/invariant), fsnotify, or os/exec.
// Its only non-stdlib dependency is internal/orgcontract, for the embedded row
// type.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
		"os/exec",
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
					t.Errorf("%s imports forbidden %q — internal/pricingfeed must stay pure", f, bad)
				}
			}
		}
	}
}
