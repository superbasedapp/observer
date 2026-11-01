package opengrep

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the driver free of its own I/O: the
// runner, the state, the tree listing and the file read are injected.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os",
			"os/exec",
			"syscall",
			"github.com/fsnotify/fsnotify",
		},
		Reason: "the opengrep driver does no I/O of its own; Env injects it",
	})
}
