package sandboxapple

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the Apple container planner pure: the CLI
// and every I/O call are the cmd layer's (CLAUDE.md Module Boundaries #1).
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		// The in-guest mount check's parser and judge are the shared pure
		// sandbox package's (lane SBX-P4, guestmounts.go).
		Allowed: []string{"github.com/marmutapp/superbased-observer/internal/sandbox"},
		Reason:  "the Apple container planner is pure; the container CLI and every I/O call are injected",
	})
}
