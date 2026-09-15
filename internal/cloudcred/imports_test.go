package cloudcred

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the purity discipline (plan §6 CI-P2, CLAUDE.md
// §1): internal/cloudcred imports only stdlib plus the keychain library the org
// bearer store uses (github.com/zalando/go-keyring). No other internal package,
// no database/sql, net/http, or fsnotify.
func TestNoForbiddenImports(t *testing.T) {
	const modulePrefix = "github.com/marmutapp/superbased-observer/"
	allowedThirdParty := map[string]bool{
		"github.com/zalando/go-keyring": true,
	}
	forbidden := map[string]bool{
		"database/sql":                 true,
		"net/http":                     true,
		"net":                          true,
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
				t.Errorf("%s imports forbidden %q", f, path)
			}
			if strings.HasPrefix(path, modulePrefix) {
				t.Errorf("%s imports internal package %q — cloudcred must not depend on other internal packages", f, path)
			}
			if !strings.HasPrefix(path, modulePrefix) && strings.Contains(path, ".") && !allowedThirdParty[path] {
				t.Errorf("%s imports third-party %q — cloudcred allows only go-keyring", f, path)
			}
		}
	}
}
