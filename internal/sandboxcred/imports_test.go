package sandboxcred

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the injection decisions pure (CLAUDE.md
// Module Boundaries #1): the key store, the files and the proxy are the
// caller's.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		// The pure model-key rules it re-exports (keyalias.go), and the pure
		// paste rule it shares with `observer sdk use-key` (pastedkey.go).
		Allowed: []string{"github.com/marmutapp/superbased-observer/internal/sandboxkey", "github.com/marmutapp/superbased-observer/internal/pastedsecret"},
		Reason:  "the credential injection rules are pure; the keystore, run files and proxy are injected",
	})
}
