package sandboxhcs

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os/exec", "github.com/fsnotify/fsnotify"},
		Allowed:    []string{"golang.org/x/sys/windows"},
		StdlibOnly: true,
		Reason:     "the HCS planner is pure and its loader loads one system library lazily, nothing else",
	})
}
