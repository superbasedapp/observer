package pastedsecret

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports keeps the paste rule pure: standard library only,
// no file, network, database or process access.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Reason:     "internal/pastedsecret is a pure rule shared by the secret prompts",
	})
}
