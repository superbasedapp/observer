package sandboxwslc

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Reason:     "the wslc planner is pure; the CLI, its output and the terminal are the caller's",
	})
}
