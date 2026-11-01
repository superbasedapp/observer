package sandboxmxcdll

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the C ABI boundary narrow: no network,
// no exec, no database; the only observer-internal import is the pure
// planner whose facts it fills.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "net", "os/exec", "github.com/fsnotify/fsnotify"},
		Allowed: []string{
			"github.com/marmutapp/superbased-observer/internal/sandboxmxc",
			"golang.org/x/sys/windows",
			"golang.org/x/sys/windows/registry",
		},
		StdlibOnly: true,
		Reason:     "the MXC C ABI boundary loads one pinned library and nothing else",
	})
}
