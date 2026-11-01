package isolation

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins isolation pure: it composes argv and
// never starts a process, opens a database, a socket or a watch.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "net", "os/exec", "github.com/fsnotify/fsnotify"},
		Reason:    "isolation is pure; the runner's executor starts bwrap",
	})
}
