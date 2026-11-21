package secreach

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/secreach pure (CLAUDE.md "Module
// Boundaries" rule 1): the import list and the advisory records are handed
// in, so the package opens no file, database, process or connection.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		StdlibOnly: true,
		Forbidden: []string{
			"database/sql",
			"net/http",
			"os",
			"os/exec",
			"io/ioutil",
			"io/fs",
			"path/filepath",
			"github.com/fsnotify/fsnotify",
		},
		Reason: "internal/secreach must stay pure: the import list and the records are injected",
	})
}
