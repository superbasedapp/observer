package daemonstart

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins daemonstart pure: decision tables and copy
// over plain data; the dial, the exec, the start lock and every file read
// live in cmd/observer (launch_autostart.go).
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Allowed: []string{
			"github.com/marmutapp/superbased-observer/internal/testsupport/importpin",
		},
		Reason: "daemonstart is a pure decision package",
	})
}
