package proccapture

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Pure pins proccapture as a pure decision package: the
// capture runtime, the store and the dashboard all import it, so it carries no
// I/O of its own and no feature package.
func TestPackageImports_Pure(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net/http", "os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
		},
		StdlibOnly: true,
		Reason:     "proccapture is the pure capture-budget core; I/O is injected by its callers",
	})
}
