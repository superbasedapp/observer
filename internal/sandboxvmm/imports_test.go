package sandboxvmm

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the VMM client a boundary: HTTP on a unix
// socket through an injected dialer, and the pure planner whose types it
// fills, nothing else.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "os/exec", "github.com/fsnotify/fsnotify", "crypto/tls"},
		StdlibOnly: true,
		Allowed:    []string{"github.com/marmutapp/superbased-observer/internal/sandboxvm"},
		Reason:     "the Cloud Hypervisor client is hand-written over an injected unix dialer (no VMM module, no TLS, no exec)",
	})
}
