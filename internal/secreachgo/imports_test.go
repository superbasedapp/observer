package secreachgo

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/secreachgo pure: the binary, the
// records and govulncheck's stream are injected, so the package opens no
// file, database, process or connection, and it never links x/vuln itself.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
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
		ForbiddenTrees: []string{"golang.org/x/vuln"},
		Reason:         "internal/secreachgo must stay pure: the binary, the records and the stream are injected",
	})
}
