package agentid

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImportsBounded pins doc3 §2.1/§2.2: internal/agentid is pure -
// no database/sql, net/http, fsnotify, and no internal/orgserver/* (the
// store and HTTP seams are injected). Allowed module imports: internal/dpop
// and its subpackages only.
func TestPackageImportsBounded(t *testing.T) {
	const module = "github.com/marmutapp/superbased-observer/"
	forbidden := []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify", module + "internal/orgserver", module + "internal/store", module + "internal/proxy"}
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
			if strings.HasPrefix(p, module) && p != module+"internal/dpop" && !strings.HasPrefix(p, module+"internal/dpop/") {
				t.Errorf("%s imports module package %q; agentid may import only internal/dpop/...", f, p)
			}
		}
	}
}
