package settingsgate

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestPackageImportsArePure pins settingsgate pure: no SQL, HTTP, os, exec
// or file watching (CLAUDE.md module rule 1).
func TestPackageImportsArePure(t *testing.T) {
	forbidden := []string{"database/sql", "net/http", "os", "os/exec", "github.com/fsnotify/fsnotify"}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			for _, bad := range forbidden {
				if p == bad {
					t.Errorf("%s imports %s; settingsgate must stay pure", f, p)
				}
			}
		}
	}
}
