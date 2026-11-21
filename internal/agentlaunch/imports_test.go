package agentlaunch

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins agentlaunch pure: request validation and
// the backend choice table over plain data, no I/O of its own.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Allowed: []string{
			"github.com/marmutapp/superbased-observer/internal/integration",
			"github.com/marmutapp/superbased-observer/internal/sandboxvocab",
			// the owner of the source vocabulary and the branch and remote
			// URL rules (pure: no os/exec, no network).
			"github.com/marmutapp/superbased-observer/internal/workspace",
			// the owner of the run initiator vocabulary (lane cli-2; pure).
			"github.com/marmutapp/superbased-observer/internal/termrun",
			"github.com/marmutapp/superbased-observer/internal/testsupport/importpin",
		},
		Reason: "agentlaunch is a pure decision package",
	})
}
