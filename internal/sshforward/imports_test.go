package sshforward

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImports_Bounded enforces the module-boundary discipline
// (CLAUDE.md "Module Boundaries" #1).
//
// sshforward is a PROCESS-LIFECYCLE package, so unlike sshprofile it is allowed
// os/exec and net — it starts the ssh child and probes the loopback port it
// binds, following internal/termsession's Spawner precedent. What it must never
// grow is a second concern: no database/sql (a forward is in-memory state, not
// a table), no net/http (it opens a port for the BROWSER to use, it never
// speaks HTTP itself, and the moment it did it would be proxying the remote
// dashboard — explicitly not this feature), and no fsnotify.
//
// The only observer-internal import permitted is the pure sshprofile package:
// the profile DATA arrives as plain fields and the argv leaves as a plain
// []string, so importing config, store, or the dashboard here would mean this
// package had started making decisions that belong to somebody else.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
	}
	const internalPrefix = "github.com/marmutapp/superbased-observer/internal/"
	allowedInternal := map[string]bool{
		internalPrefix + "sshprofile": true,
	}

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
					t.Errorf("%s: forbidden import %q (sshforward owns process lifecycle only — it never stores, and never speaks HTTP to the forwarded dashboard)", filepath.Base(path), p)
				}
			}
			if strings.HasPrefix(p, internalPrefix) && !allowedInternal[p] {
				t.Errorf("%s: forbidden observer-internal import %q (only the pure sshprofile package may be imported here)", filepath.Base(path), p)
			}
		}
	}
}
