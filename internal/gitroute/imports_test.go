package gitroute

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the router as pure: every read of the host
// and the one exec (`git.exe --version`) are injected through Env, and the
// git runs themselves stay in internal/gitview.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"net",
			"os",
			"os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/gitview",
		},
		Reason: "internal/gitroute is pure: the host reads and the exec are injected (R3-86)",
	})
}
