package integration

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline this package's
// doc.go has always CLAIMED but nothing enforced (MOD-1, codebase audit
// 2026-09-16 — internal/integration was documented as a pinned pure package
// yet carried no imports_test.go, unlike the 103 packages that do).
//
// internal/integration is pure data + lookups: one Capability row per adapter
// describing how it integrates. Every consumer (cmd/observer's init/register,
// internal/hook, internal/diag) owns the I/O and dispatches on capability
// SHAPE. A database/sql, net/http, os/exec or fsnotify import here would mean
// the registry had started DOING something instead of DESCRIBING it — the
// exact regression the table was introduced to prevent.
//
// os/exec is in the set as well as the usual three: this package decides which
// binary a launcher would run, and the temptation to probe or spawn it from
// the table itself is real. The probe belongs at the boundary.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		"database/sql",
		"net/http",
		"os/exec",
		"github.com/fsnotify/fsnotify",
	}
	fset := token.NewFileSet()
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no .go files found — the pin would be vacuous")
	}
	scanned := 0
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		scanned++
		for _, imp := range af.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if path == bad {
					t.Errorf("%s imports forbidden %q — internal/integration must stay pure data + lookups", f, bad)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no non-test .go files scanned — the pin would be vacuous")
	}
}
