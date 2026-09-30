package mcprelay

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImportsBounded pins the reverse-import boundary (doc3 §11.7
// "reverse-import boundary (no orgserver/mcpgw import)"): the node relay
// never imports internal/orgserver or internal/mcpgw, and - a relay that
// owns net/http and os/exec by nature - never database/sql or fsnotify.
func TestPackageImportsBounded(t *testing.T) {
	const module = "github.com/marmutapp/superbased-observer/"
	forbidden := []string{"database/sql", "github.com/fsnotify/fsnotify", module + "internal/orgserver", module + "internal/mcpgw", module + "internal/store"}
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
					t.Errorf("%s imports forbidden %q", f, p)
				}
			}
		}
	}
}
