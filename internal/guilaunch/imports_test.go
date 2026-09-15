package guilaunch

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImports_Bounded enforces the module-boundary discipline
// (CLAUDE.md "Module Boundaries" #1): guilaunch is PURE — every host fact
// arrives as DATA on Inputs, and the package spawns nothing. Non-test source
// files must not reach for infrastructure (database/sql, net/http, os, os/exec,
// fsnotify), and the ONLY observer-internal import allowed is
// internal/integration (the registry DATA the composition dispatches on — the
// same allowance internal/toolresolve makes). A failure names the file and the
// offending import.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"database/sql",
		"net/http",
		"os",
		"os/exec",
		"github.com/fsnotify/fsnotify",
	}
	const allowedInternal = "github.com/marmutapp/superbased-observer/internal/integration"
	const internalPrefix = "github.com/marmutapp/superbased-observer/internal/"

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(cwd, "*.go"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no source files in %s", cwd)
	}

	fset := token.NewFileSet()
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if p == bad {
					t.Errorf("%s: forbidden import %q (guilaunch is pure — host facts arrive as data on Inputs)", filepath.Base(path), p)
				}
			}
			if strings.HasPrefix(p, internalPrefix) && p != allowedInternal {
				t.Errorf("%s: forbidden observer-internal import %q (only internal/integration allowed)", filepath.Base(path), p)
			}
		}
	}
}
