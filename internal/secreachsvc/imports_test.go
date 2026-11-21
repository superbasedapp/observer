package secreachsvc

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the seam's reach: it reads the project's
// files and the codeintel index through the store's read, and nothing
// else. No network, no process, no SQL of its own.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os/exec",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenTrees: []string{"net/http"},
		Reason:         "internal/secreachsvc reads local files only: no network, no process, no SQL of its own",
	})
}
