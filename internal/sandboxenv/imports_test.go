package sandboxenv

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the environment allow-list pure (CLAUDE.md
// Module Boundaries #1): the environment is the caller's to read and set.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "unsafe", "golang.org/x/sys/windows", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Reason:     "the box environment allow-list is pure; the environment is read and set by the backends",
	})
}
