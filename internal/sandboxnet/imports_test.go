package sandboxnet

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImports_Bounded enforces the module-boundary discipline
// (CLAUDE.md "Module Boundaries" #1): sandboxnet is the network code of the
// sandbox egress tier and nothing else. Non-test source files must not reach
// for a database, spawn processes (process spawning lives in cmd/observer),
// watch files, or import any observer-internal package. A failure names the
// file and the offending import.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"database/sql",
		"os/exec",
		"github.com/fsnotify/fsnotify",
	}
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
					t.Errorf("%s: forbidden import %q (sandboxnet is network code only; spawning lives in cmd)", filepath.Base(path), p)
				}
			}
			if strings.HasPrefix(p, internalPrefix) {
				t.Errorf("%s: forbidden observer-internal import %q (sandboxnet imports no internal package)", filepath.Base(path), p)
			}
		}
	}
}
