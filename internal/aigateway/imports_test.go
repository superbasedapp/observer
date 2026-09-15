package aigateway

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md
// module rule #1, design §2.2): the aigateway root package is pure logic.
// It must not import database/sql, net/http, or fsnotify — those I/O
// capabilities are injected through the interfaces in store.go and
// implemented in the gwstore / gwhttp subpackages. It must also never
// import internal/proxy (the reverse-import rule's near side) or any
// internal/orgserver package: org-server identity and budget state are
// INJECTED so the v1.5 standalone-binary split stays mechanical.
//
// The reverse direction — internal/proxy never importing aigateway or
// orgserver — is pinned by tests/invariant/aigateway_boundary_test.go.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
		"github.com/marmutapp/superbased-observer/internal/proxy",
	}
	forbiddenPrefixes := []string{
		"github.com/marmutapp/superbased-observer/internal/orgserver",
		"github.com/marmutapp/superbased-observer/internal/proxy/",
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
					t.Errorf("%s imports forbidden %q — internal/aigateway root must stay pure (I/O is injected)", f, bad)
				}
			}
			for _, pre := range forbiddenPrefixes {
				if strings.HasPrefix(path, pre) {
					t.Errorf("%s imports %q — the aigateway core must not depend on internal/orgserver or internal/proxy (inject the state instead)", f, path)
				}
			}
		}
	}
}
