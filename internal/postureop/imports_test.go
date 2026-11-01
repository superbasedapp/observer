package postureop

import (
	"go/build"
	"strings"
	"testing"
)

// TestStdlibOnly pins postureop a pure leaf: standard library only, so both
// the policy layer and internal/config can import it (JSP-1 R7).
func TestStdlibOnly(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		if strings.Contains(strings.SplitN(imp, "/", 2)[0], ".") {
			t.Errorf("postureop imports %q; it must stay standard library only", imp)
		}
	}
	for _, forbidden := range []string{"database/sql", "net/http", "os/exec"} {
		for _, imp := range pkg.Imports {
			if imp == forbidden {
				t.Errorf("postureop imports %q", imp)
			}
		}
	}
}
