package sandboxremote

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the remote core pure: no network, SQL,
// process or watcher import, and no observer-internal package but the
// neutral vocabulary leaf.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "crypto/tls", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Allowed:    []string{"github.com/marmutapp/superbased-observer/internal/sandboxvocab"},
		Reason:     "the remote sandbox core is pure: the wire clients and the cmd layer do every I/O",
	})
}
