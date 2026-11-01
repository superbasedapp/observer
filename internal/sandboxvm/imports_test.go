package sandboxvm

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the microVM planner pure (CLAUDE.md
// Module Boundaries #1): the VMM, the processes and every file are the cmd
// layer's and internal/sandboxvmm's.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Reason:     "the microVM planner is pure; the VMM, its sockets and every file are injected",
	})
}
