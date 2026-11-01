package sandboxsbpl

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the Seatbelt planner pure: every process,
// file and socket call is the cmd layer's (CLAUDE.md Module Boundaries #1).
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Allowed: []string{
			// the shared bind and protect tables (pure, imports nothing of
			// Observer's own)
			"github.com/marmutapp/superbased-observer/internal/sandbox",
		},
		Reason: "the Seatbelt planner is pure; sandbox-exec and every I/O call are injected",
	})
}
