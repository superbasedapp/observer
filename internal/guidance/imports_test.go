package guidance

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// osAdapterFile is the single file allowed to touch the real filesystem.
// Everything else in the package receives its I/O through the injected
// [FS] seam.
const osAdapterFile = "fs_os.go"

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md
// §1, the internal/predict precedent): internal/guidance is pure logic.
// It must not import database/sql, net/http, fsnotify — or os, outside
// the one adapter file. A guidance feature that wants to touch a DB adds
// a store seam (internal/store/guidance.go), never an import here.
func TestNoForbiddenImports(t *testing.T) {
	t.Parallel()
	forbidden := []string{
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
		"github.com/marmutapp/superbased-observer/internal/store",
		"github.com/marmutapp/superbased-observer/internal/db",
	}
	// os and its path sibling are allowed ONLY in the adapter.
	adapterOnly := []string{"os", "path/filepath"}

	fset := token.NewFileSet()
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no source files found — the guard would be vacuous")
	}
	sawAdapter := false
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		if f == osAdapterFile {
			sawAdapter = true
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range af.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if path == bad {
					t.Errorf("%s imports forbidden %q — internal/guidance must stay pure", f, bad)
				}
			}
			if f == osAdapterFile {
				continue
			}
			for _, bad := range adapterOnly {
				if path == bad {
					t.Errorf("%s imports %q — filesystem access belongs in %s, reached through the FS seam",
						f, bad, osAdapterFile)
				}
			}
		}
	}
	if !sawAdapter {
		t.Fatalf("%s is missing — the adapter-only allowance points at nothing", osAdapterFile)
	}
}
