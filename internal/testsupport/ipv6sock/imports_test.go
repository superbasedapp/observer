package ipv6sock

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins ipv6sock to the standard library: it opens
// one probe socket and skips a test, so it has no reason to reach a
// database, an HTTP client, a subprocess or any package of this module.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "os/exec", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Reason:     "ipv6sock is test support that probes one socket with the standard library",
	})
}
