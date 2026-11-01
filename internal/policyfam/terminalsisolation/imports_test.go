package terminalsisolation

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the family compiler pure: plain bytes in, a
// compiled spec out, over the sandbox registry and vocabulary only.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Allowed: []string{
			"github.com/marmutapp/superbased-observer/internal/sandboxbackend",
			"github.com/marmutapp/superbased-observer/internal/sandboxvocab",
		},
		Reason: "the terminals.isolation compiler is a pure decoder",
	})
}
