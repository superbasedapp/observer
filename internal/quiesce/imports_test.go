package quiesce

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module boundary (CLAUDE.md §1). This
// package counts and waits. It must never learn what a request, a PTY or an
// update IS, because the moment it does, the drain rule stops being
// unit-testable and starts needing a live proxy to exercise.
//
// database/sql / net/http / os/exec / fsnotify are the same four the
// internal/update and internal/announce pins forbid, for the same reason.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		"database/sql",
		"net/http",
		"net",
		"os/exec",
		"github.com/fsnotify/fsnotify",
	}
	fset := token.NewFileSet()
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no Go files found — the pin would pass vacuously")
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
					t.Errorf("%s imports forbidden %q — internal/quiesce must stay pure", f, bad)
				}
			}
		}
	}
}
