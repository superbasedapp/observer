package sandboxopenshell

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the OpenShell planner pure: every exec,
// file and socket call belongs to the driver files in cmd/observer (CLAUDE.md
// Module Boundaries #1; OpenShell build plan 05 section 2).
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		Allowed: []string{
			"github.com/marmutapp/superbased-observer/internal/sandboxbackend",
			"github.com/marmutapp/superbased-observer/internal/sandboxcidr",
			"github.com/marmutapp/superbased-observer/internal/sandboxselect",
			"github.com/marmutapp/superbased-observer/internal/sandboxvocab",
		},
		StdlibOnly: true,
		Reason:     "the OpenShell planner is pure; the CLI calls, the policy file and the probe I/O are the driver's",
	})
}
