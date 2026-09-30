package dpop

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImportsBounded pins doc3 §2.1: internal/dpop is pure - no
// database/sql, net/http, fsnotify - and never imports internal/agentid (the
// agentid<->dpop cycle guard). Its only module import is internal/dpop/jose.
func TestPackageImportsBounded(t *testing.T) {
	const module = "github.com/marmutapp/superbased-observer/"
	forbidden := []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify", module + "internal/agentid"}
	allowedModule := map[string]bool{module + "internal/dpop/jose": true}
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					t.Errorf("%s imports forbidden %q (doc3 §2.1)", f, p)
				}
			}
			if strings.HasPrefix(p, module) && !allowedModule[p] {
				t.Errorf("%s imports module package %q; dpop may import only internal/dpop/jose", f, p)
			}
		}
	}
}
