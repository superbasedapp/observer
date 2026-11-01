package sandboxlandlock

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the Landlock planner pure: every syscall
// and file call is the cmd layer's (CLAUDE.md Module Boundaries #1).
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "golang.org/x/sys/unix", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Reason:     "the Landlock planner is pure; the Landlock syscalls, the self-test and the exec are injected",
	})
}
