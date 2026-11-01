package sandboxengine

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the Engine API client a boundary: it
// speaks HTTP on a unix socket and nothing else (no exec, no database, no
// file watching), and its only observer-internal import is the pure planner
// whose types it fills.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "os/exec", "github.com/fsnotify/fsnotify", "crypto/tls"},
		StdlibOnly: true,
		Allowed:    []string{"github.com/marmutapp/superbased-observer/internal/sandboxoci"},
		Reason:     "the Engine API client is hand-written over a unix socket (no Docker or Podman module, no TLS, no exec)",
	})
}
