package compile_test

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the purity contract doc.go states: the
// translators turn the effective rule table and existing config bytes into
// new bytes and perform no I/O. Reading and writing the native config files,
// pinning artifacts and emitting R-204 events live in cmd/observer.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net",
			"os",
			"io/ioutil",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/config",
		},
		Reason: "internal/guard/compile performs no I/O (doc.go purity contract)",
	})
}
