package cloudevidence

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the purity discipline (plan §6 CI-P1 / CLAUDE.md
// §1): internal/cloudevidence may import ONLY internal/cloudcontract,
// internal/scrub, internal/dataauthority, and stdlib. Any other internal
// package — and any file/network/db/process surface — is forbidden. The
// reverse-boundary pin keeps hosted (store/server/client) packages out of node
// ingest by keeping the import set closed. Modeled on
// internal/dataauthority/imports_test.go.
func TestNoForbiddenImports(t *testing.T) {
	const modulePrefix = "github.com/marmutapp/superbased-observer/"
	allowedInternal := map[string]bool{
		"github.com/marmutapp/superbased-observer/internal/cloudcontract": true,
		"github.com/marmutapp/superbased-observer/internal/scrub":         true,
		"github.com/marmutapp/superbased-observer/internal/dataauthority": true,
	}
	forbidden := map[string]bool{
		"database/sql":                 true,
		"net/http":                     true,
		"net":                          true,
		"os":                           true,
		"io/fs":                        true,
		"os/exec":                      true,
		"github.com/fsnotify/fsnotify": true,
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
			if forbidden[path] {
				t.Errorf("%s imports forbidden %q — cloudevidence must stay pure", f, path)
			}
			if strings.HasPrefix(path, modulePrefix) && !allowedInternal[path] {
				t.Errorf("%s imports internal package %q — cloudevidence may import only cloudcontract, scrub, dataauthority", f, path)
			}
		}
	}
}
