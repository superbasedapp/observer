package community

import (
	"go/build"
	"strings"
	"testing"
)

// TestPackageIsPure pins that the community registry stays a pure-logic package:
// no database/sql, no net/http, no fsnotify. SQL lives in internal/cloudserver/
// store; HTTP in internal/cloudserver/api. (CLAUDE.md module-boundary rule #1.)
func TestPackageIsPure(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("ImportDir: %v", err)
	}
	forbidden := []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify"}
	for _, imp := range pkg.Imports {
		for _, f := range forbidden {
			if imp == f || strings.HasPrefix(imp, f+"/") {
				t.Errorf("community imports forbidden package %q — keep it pure", imp)
			}
		}
	}
}
