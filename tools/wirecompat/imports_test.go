package main

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// recorderInternalImports are the only repository packages the recorder may
// import. record.sh builds these files inside a checkout of every release in
// the D-30 window, so each package here (and every identifier the recorder
// uses from it) must already exist at the oldest recorded tag, v1.31.0.
// Adding a package means checking it with `git show v1.31.0:<path>` first.
var recorderInternalImports = map[string]bool{
	"github.com/marmutapp/superbased-observer/internal/config":    true,
	"github.com/marmutapp/superbased-observer/internal/db":        true,
	"github.com/marmutapp/superbased-observer/internal/models":    true,
	"github.com/marmutapp/superbased-observer/internal/orgclient": true,
	"github.com/marmutapp/superbased-observer/internal/store":     true,
}

// TestRecorderImportsOnlyStableNodePackages pins the recorder's repository
// imports to recorderInternalImports and its third-party imports to none.
func TestRecorderImportsOnlyStableNodePackages(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	const module = "github.com/marmutapp/superbased-observer/"
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, im := range f.Imports {
			path, _ := strconv.Unquote(im.Path.Value)
			switch {
			case strings.HasPrefix(path, module):
				if !recorderInternalImports[path] {
					t.Errorf("%s imports %s; the recorder must build at v1.31.0, see recorderInternalImports", name, path)
				}
			case strings.Contains(strings.SplitN(path, "/", 2)[0], "."):
				t.Errorf("%s imports the third-party package %s; use the standard library", name, path)
			}
		}
	}
}
