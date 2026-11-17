package ccfixture

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/oteldirect/ccfixture to building OTLP
// batches only: no database, network, file system or process access, and no
// other package of this module (its parent's own pin covers it recursively;
// this is the package's own statement, structcheck S9).
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Dirs: []string{"."},
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os",
			"os/exec",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		Reason:            "internal/oteldirect/ccfixture is a pure test fixture builder",
	})
}
