package sshprofile

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImports_Bounded enforces the module-boundary discipline
// (CLAUDE.md "Module Boundaries" #1): sshprofile is PURE — validation and argv
// composition only. It must not reach for infrastructure (database/sql,
// net/http, os/exec, fsnotify) and must not import any observer-internal
// package: the profile DATA crosses the seam as plain fields and the argv
// leaves as a plain []string.
//
// os IS permitted (ValidateWithFS stats the key path — never opens it),
// mirroring internal/sandbox's allowance for its readiness probe. os/exec is
// NOT: this package composes an argv, it never runs one.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"database/sql",
		"net/http",
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
					t.Errorf("%s: forbidden import %q (sshprofile is pure — it composes an argv, it never runs one)", filepath.Base(path), p)
				}
			}
			if strings.HasPrefix(p, internalPrefix) {
				t.Errorf("%s: forbidden observer-internal import %q (sshprofile imports no internal package)", filepath.Base(path), p)
			}
		}
	}
}
