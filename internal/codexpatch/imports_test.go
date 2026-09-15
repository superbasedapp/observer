package codexpatch

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// adapterImportPrefix is the import path prefix of every platform
// adapter. codexpatch was extracted OUT of internal/adapter/codex so two
// owners could share one decoder; importing an adapter back would
// re-create the cycle the extraction removed.
const adapterImportPrefix = "github.com/marmutapp/superbased-observer/internal/adapter/"

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md
// §1 / spec §24.1): internal/codexpatch is pure logic over a program
// STRING. It must not import database/sql, net/http, or fsnotify — it
// is handed text and hands back text — and it must not import any
// adapter package, because the adapters are its callers.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
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
			for _, bad := range forbidden {
				if path == bad {
					t.Errorf("%s imports forbidden %q — internal/codexpatch must stay pure", f, bad)
				}
			}
			if strings.HasPrefix(path, adapterImportPrefix) {
				t.Errorf("%s imports adapter package %q — internal/codexpatch is the "+
					"SHARED decoder the adapters call, never the other way round", f, path)
			}
		}
	}
}
