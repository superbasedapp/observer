package configschema

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImports_Bounded pins the purity boundary (CLAUDE.md "Module
// Boundaries" #1): configschema describes and classifies config.Config and
// does nothing else. Non-test files must not import I/O or infrastructure
// packages, and the ONLY observer-internal import allowed is internal/config
// (the type being described). Everything I/O-shaped — reading the file,
// serving the schema, writing patches — lives in internal/config,
// internal/intelligence/dashboard and web/cfgschema.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"os",
		"os/exec",
		"io/fs",
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
	}
	const internalPrefix = "github.com/marmutapp/superbased-observer/internal/"
	const allowedInternal = internalPrefix + "config"

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
					t.Errorf("%s: forbidden import %q (configschema is pure)", filepath.Base(path), p)
				}
			}
			if strings.HasPrefix(p, internalPrefix) && p != allowedInternal {
				t.Errorf("%s: forbidden observer-internal import %q (only internal/config is allowed)", filepath.Base(path), p)
			}
		}
	}
}
