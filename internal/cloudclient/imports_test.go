package cloudclient

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the dependency boundary (plan §6 CI-P2, CLAUDE.md
// §1): internal/cloudclient may import only stdlib plus cloudpop, cloudcred,
// cloudcontract, and cloudevidence. It must NOT reach into internal/store,
// internal/config, database/sql, or fsnotify.
func TestNoForbiddenImports(t *testing.T) {
	const modulePrefix = "github.com/marmutapp/superbased-observer/"
	allowedInternal := map[string]bool{
		modulePrefix + "internal/cloudpop":      true,
		modulePrefix + "internal/cloudcred":     true,
		modulePrefix + "internal/cloudcontract": true,
		modulePrefix + "internal/cloudevidence": true,
	}
	forbidden := map[string]bool{
		"database/sql":                   true,
		"github.com/fsnotify/fsnotify":   true,
		modulePrefix + "internal/store":  true,
		modulePrefix + "internal/config": true,
		modulePrefix + "internal/db":     true,
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
				t.Errorf("%s imports forbidden %q", f, path)
			}
			if strings.HasPrefix(path, modulePrefix) && !allowedInternal[path] {
				t.Errorf("%s imports internal package %q — cloudclient allows only cloudpop/cloudcred/cloudcontract/cloudevidence", f, path)
			}
		}
	}
}
