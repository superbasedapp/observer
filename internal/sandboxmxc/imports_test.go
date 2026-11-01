package sandboxmxc

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the MXC planner pure (CLAUDE.md Module
// Boundaries #1): the C ABI, the files, the port and the process are all
// the caller's.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "unsafe", "golang.org/x/sys/windows", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Allowed:    []string{"github.com/marmutapp/superbased-observer/internal/sandboxvocab"},
		Reason:     "the MXC planner is pure; the C ABI loader, the files and the port are injected",
	})
}
