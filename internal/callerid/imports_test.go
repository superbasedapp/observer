package callerid

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins callerid pure: the decision table and the
// procfs parsers over bytes, no I/O of their own.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Allowed:    []string{"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"},
		Reason:     "callerid is a pure decision package",
	})
}
