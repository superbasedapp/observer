package sandboxkey

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the model-key rules pure (CLAUDE.md
// Module Boundaries #1): the key store, the files and the proxy are the
// caller's, and the package imports nothing of the injection code.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Reason:     "the model-key rules are pure; the keystore, the files and the proxy are injected",
	})
}
