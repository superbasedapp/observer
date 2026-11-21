package managedconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestImportsAndNoRedirection pins the package's two promises (plan 6.2.2
// rev N2): the decision files are pure, and nothing in the package can be
// redirected by a flag, an environment variable or the config loader.
func TestImportsAndNoRedirection(t *testing.T) {
	pureFiles := map[string]bool{"ceiling.go": true, "attach.go": true, "acl.go": true, "load.go": true, "doc.go": true}
	pureForbidden := []string{"os", "os/exec", "syscall", "golang.org/x/sys", "unsafe"}
	execAllowed := map[string]bool{"source_darwin.go": true}

	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql", "net/http", "flag",
			"github.com/fsnotify/fsnotify",
			"github.com/spf13/cobra", "github.com/spf13/viper",
			"github.com/marmutapp/superbased-observer/internal/config",
			"github.com/marmutapp/superbased-observer/internal/store",
		},
		// Per-file rules: the decision files stay pure, and only the darwin
		// source may exec.
		Custom: func(file, p string) string {
			base := filepath.Base(file)
			var bad []string
			if pureFiles[base] {
				bad = append(bad, pureForbidden...)
			}
			if !execAllowed[base] {
				bad = append(bad, "os/exec")
			}
			for _, b := range bad {
				if p == b || strings.HasPrefix(p, b+"/") {
					return "forbidden in " + base
				}
			}
			return ""
		},
		Reason: "managedconfig decision files are pure; only source_darwin.go may exec",
	})

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
		for _, needle := range []string{"Getenv(", "LookupEnv(", "Environ(", "os.Args", "UserHomeDir(", "UserConfigDir("} {
			if strings.Contains(string(src), needle) {
				t.Errorf("%s uses %s: the ceiling source must be a fixed location nothing can redirect", f, needle)
			}
		}
	}
}
