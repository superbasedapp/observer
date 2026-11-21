package sandboxseccomp

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the package pure: the assembler and the
// tables need nothing past encoding/binary and fmt.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "unsafe", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Reason:     "the seccomp profile and assembler are pure; the cmd seams own loading and read-back",
	})
}
